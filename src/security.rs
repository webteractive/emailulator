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

/// What every inbox API key starts with, so one is recognizable on sight and a
/// mistyped or revoked key can be told from a placeholder password.
pub const API_KEY_PREFIX: &str = "emu_";

/// A fresh inbox API key: the prefix and 192 random bits as hex.
pub fn generate_api_key() -> String {
    format!("{API_KEY_PREFIX}{}", hex(&random_bytes::<24>()))
}

/// A fresh inbox id. Random rather than derived from the name, so renaming an
/// inbox never changes what applications sign in with.
pub fn generate_inbox_id() -> String {
    format!("ibx_{}", hex(&random_bytes::<5>()))
}

/// What is stored for an API key instead of the key. The key is long and
/// random, so a plain SHA-256 is enough: there is nothing to brute-force.
pub fn hash_api_key(key: &str) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, key.as_bytes()).as_ref())
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

/// What a caller may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Every inbox, and the management of inboxes and their keys.
    Admin,
    /// The messages of one inbox, and nothing else.
    Inbox(String),
}

impl Access {
    /// The inbox this access is confined to, if it is confined.
    pub fn inbox(&self) -> Option<&str> {
        match self {
            Access::Admin => None,
            Access::Inbox(inbox) => Some(inbox),
        }
    }
}

/// An inbox's API key as something that outlives one request holds it: by
/// its hash, never the key itself, with the inbox it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxKey {
    pub inbox: String,
    pub hash: String,
}

/// A browser session. One opened with an inbox's API key keeps that key's
/// hash, and the key is checked again on every request, so the session ends
/// with its key however the key was revoked or replaced, including from the
/// command line, which cannot reach this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Session {
    Admin,
    Inbox(InboxKey),
}

impl Session {
    pub fn access(&self) -> Access {
        match self {
            Session::Admin => Access::Admin,
            Session::Inbox(key) => Access::Inbox(key.inbox.clone()),
        }
    }
}

/// How a caller identified itself, kept so that a request which outlives its
/// own authorization, such as an event stream or a long tool call, can check
/// that the caller still may. Checking it reads; it never records a use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Nothing that can be withdrawn while the server runs: no credential on a
    /// server that asks for none, or the admin token.
    Standing,
    /// An inbox's API key, presented with the request.
    Key(InboxKey),
    /// A browser session, by its id.
    Session(String),
}

/// Access control for the HTTP side: the admin token, and the browser sessions
/// opened by presenting it or an inbox's API key.
pub struct Auth {
    token: Option<String>,
    comparer: SecretComparer,
    sessions: Mutex<HashMap<String, (Instant, Session)>>,
}

impl Auth {
    /// `token` is the admin token. Without one, anyone who can reach the
    /// server is an admin, which is only allowed on a loopback listener.
    pub fn new(token: Option<String>) -> Result<Self> {
        if token
            .as_ref()
            .is_some_and(|token| token.len() < MIN_TOKEN_LEN)
        {
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

    /// Whether callers must identify themselves at all.
    pub fn required(&self) -> bool {
        self.token.is_some()
    }

    pub fn is_admin_token(&self, candidate: &str) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| self.comparer.eq(candidate.as_bytes(), token.as_bytes()))
    }

    /// Open a browser session and return its id, the cookie value.
    pub fn open_session(&self, session: Session) -> String {
        let id = hex(&random_bytes::<32>());
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.retain(|_, (expires, _)| *expires > now);
        if sessions.len() >= MAX_SESSIONS {
            // Full of live sessions: drop the one closest to expiry.
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, (e, _))| *e)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(id.clone(), (now + SESSION_TTL, session));
        id
    }

    pub fn session(&self, id: &str) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions
            .get(id)
            .filter(|(expires, _)| *expires > Instant::now())
            .map(|(_, session)| session.clone())
    }

    pub fn close_session(&self, id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(id);
    }

    /// End every session confined to `inbox`: its key was revoked or it is gone.
    pub fn close_inbox_sessions(&self, inbox: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (_, session)| session.access().inbox() != Some(inbox));
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
    fn api_keys_are_distinct_and_hash_stably() {
        let (a, b) = (generate_api_key(), generate_api_key());
        assert!(a.starts_with(API_KEY_PREFIX) && a.len() == API_KEY_PREFIX.len() + 48);
        assert_ne!(a, b);
        assert_eq!(hash_api_key(&a), hash_api_key(&a));
        assert_ne!(hash_api_key(&a), hash_api_key(&b));
        assert!(
            !hash_api_key(&a).contains(&a[4..]),
            "the hash does not contain the key"
        );
    }

    #[test]
    fn short_tokens_are_refused() {
        assert!(Auth::new(Some("hunter2".into())).is_err());
        assert!(Auth::new(Some(generate_token())).is_ok());
        assert!(Auth::new(None).is_ok());
    }

    #[test]
    fn the_admin_token_is_recognized_only_when_there_is_one() {
        let token = generate_token();
        let auth = Auth::new(Some(token.clone())).unwrap();
        assert!(auth.required());
        assert!(auth.is_admin_token(&token));
        assert!(!auth.is_admin_token("something else"));

        let open = Auth::new(None).unwrap();
        assert!(!open.required());
        assert!(!open.is_admin_token(""), "no token is not an empty token");
    }

    #[test]
    fn sessions_carry_their_access_and_close() {
        let auth = Auth::new(Some(generate_token())).unwrap();
        let as_admin = Session::Admin;
        let as_billing = Session::Inbox(InboxKey {
            inbox: "billing".into(),
            hash: hash_api_key("emu_billing"),
        });
        let admin = auth.open_session(as_admin.clone());
        let scoped = auth.open_session(as_billing.clone());
        assert_eq!(auth.session(&admin), Some(as_admin.clone()));
        assert_eq!(auth.session(&scoped), Some(as_billing));
        assert_eq!(auth.session("not-a-session"), None);

        auth.close_inbox_sessions("billing");
        assert_eq!(
            auth.session(&scoped),
            None,
            "revoking a key ends its sessions"
        );
        assert_eq!(auth.session(&admin), Some(as_admin));
        auth.close_session(&admin);
        assert_eq!(auth.session(&admin), None);
    }
}
