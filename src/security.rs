//! Secrets, sessions and TLS: the parts that decide who gets in.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

/// Shortest token accepted. A short token is guessable over a network, and this
/// is the only thing standing between the internet and every captured email.
pub const MIN_TOKEN_LEN: usize = 16;

const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_SESSIONS: usize = 1024;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the operating system's random source is unavailable");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh random token, 256 bits as hex.
pub fn generate_token() -> String {
    hex(&random_bytes::<32>())
}

/// Compares secrets without leaking, through timing, how much of a guess was
/// right. Both sides are keyed-hashed first, so neither the position of the
/// first differing byte nor the secret's length shows.
pub struct SecretComparer {
    key: hmac::Key,
}

impl Default for SecretComparer {
    fn default() -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &random_bytes::<32>()),
        }
    }
}

impl SecretComparer {
    pub fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        let expected = hmac::sign(&self.key, b);
        hmac::verify(&self.key, a, expected.as_ref()).is_ok()
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    /// Parse `user:password`. The password may itself contain colons.
    pub fn parse(value: &str) -> Result<Self> {
        let (username, password) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("SMTP credentials must be `user:password`"))?;
        if username.is_empty() || password.is_empty() {
            bail!("SMTP credentials must have a user and a password");
        }
        Ok(Self {
            username: username.to_string(),
            password: password.to_string(),
        })
    }
}

// Keep secrets out of `{:?}` output, where they would end up in logs.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Access control for the HTTP side: the API token, and the browser sessions
/// opened by presenting it.
pub struct Auth {
    token: String,
    comparer: SecretComparer,
    sessions: Mutex<HashMap<String, Instant>>,
}

impl Auth {
    pub fn new(token: String) -> Result<Self> {
        if token.len() < MIN_TOKEN_LEN {
            bail!(
                "the auth token must be at least {MIN_TOKEN_LEN} characters; \
                 `emailulator token` generates a strong one"
            );
        }
        Ok(Self {
            token,
            comparer: SecretComparer::default(),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn token_matches(&self, candidate: &str) -> bool {
        self.comparer
            .eq(candidate.as_bytes(), self.token.as_bytes())
    }

    /// Open a browser session and return its id, the cookie value.
    pub fn open_session(&self) -> String {
        let id = hex(&random_bytes::<32>());
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.retain(|_, expires| *expires > now);
        if sessions.len() >= MAX_SESSIONS {
            // Full of live sessions: drop the one closest to expiry.
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, e)| **e)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(id.clone(), now + SESSION_TTL);
        id
    }

    pub fn session_valid(&self, id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions
            .get(id)
            .is_some_and(|expires| *expires > Instant::now())
    }

    pub fn close_session(&self, id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(id);
    }

    pub fn session_ttl(&self) -> Duration {
        SESSION_TTL
    }
}

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Load a PEM certificate chain and private key into a TLS acceptor.
/// `alpn` lists the protocols to offer, most preferred first.
pub fn tls_acceptor(files: &TlsFiles, alpn: &[&[u8]]) -> Result<TlsAcceptor> {
    let certs = load_certs(&files.cert)?;
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|e| anyhow!("reading TLS key {}: {e}", files.key.display()))?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("configuring TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the TLS certificate and key do not form a usable pair")?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow!("reading TLS certificate {}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("reading TLS certificate {}: {e}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparer_matches_only_equal_secrets() {
        let comparer = SecretComparer::default();
        assert!(comparer.eq(b"correct horse", b"correct horse"));
        assert!(!comparer.eq(b"correct horse", b"correct hors"));
        assert!(!comparer.eq(b"", b"x"));
    }

    #[test]
    fn short_tokens_are_refused() {
        assert!(Auth::new("hunter2".into()).is_err());
        assert!(Auth::new(generate_token()).is_ok());
    }

    #[test]
    fn sessions_open_validate_and_close() {
        let auth = Auth::new(generate_token()).unwrap();
        let id = auth.open_session();
        assert!(auth.session_valid(&id));
        assert!(!auth.session_valid("not-a-session"));
        auth.close_session(&id);
        assert!(!auth.session_valid(&id));
    }

    #[test]
    fn credentials_parse_and_redact() {
        let creds = Credentials::parse("app:pa:ss").unwrap();
        assert_eq!(creds.username, "app");
        assert_eq!(creds.password, "pa:ss");
        assert!(!format!("{creds:?}").contains("pa:ss"));
        assert!(Credentials::parse("nopassword").is_err());
        assert!(Credentials::parse(":x").is_err());
    }
}
