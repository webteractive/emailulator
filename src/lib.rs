//! emailulator: a development email catcher.
//!
//! Mail comes in over SMTP or the HTTP API and is stored, never delivered. It
//! goes out through the web UI, the REST API and an MCP server. The binary is a
//! thin shell over this library, and the desktop app embeds it the same way.

pub mod check;
pub mod compose;
pub mod http;
pub mod mcp;
pub mod model;
pub mod parse;
pub mod security;
pub mod smtp;
pub mod store;
pub mod update;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::http::{HttpConfig, ServerInfo};
use crate::security::{Auth, TlsFiles};
use crate::smtp::SmtpConfig;
use crate::store::{Limits, Store};

pub const DB_FILE: &str = "emailulator.db";

/// Where messages are kept when no directory is given.
pub fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("emailulator")
}

/// Open the message store in `data_dir`, or in memory when there is none.
pub fn open_store(data_dir: Option<&Path>, limits: Limits) -> Result<Store> {
    let path = data_dir.map(|dir| dir.join(DB_FILE));
    Store::open(path.as_deref(), limits)
}

#[derive(Debug, Clone)]
pub struct Config {
    pub smtp_addr: SocketAddr,
    pub http_addr: SocketAddr,
    /// `None` keeps messages in memory only.
    pub data_dir: Option<PathBuf>,
    pub limits: Limits,
    pub max_message_size: usize,
    /// The admin token: every inbox, and the management of inboxes and keys.
    /// When set, the API, MCP endpoint and web UI need it or an inbox API key.
    pub auth_token: Option<String>,
    /// Inbox ids and keys to make valid at startup, creating the inboxes as
    /// needed. Lets a deployment hand an application its key through
    /// configuration instead of minting one by hand.
    pub provision: Vec<(String, String)>,
    /// Permit an HTTP listener that is reachable from other machines and has
    /// no auth token.
    pub allow_anonymous_http: bool,
    /// Refuse to start without the admin token even on a loopback listener.
    /// Behind a reverse proxy on the same machine every request arrives from
    /// loopback, and a proxy that does not pass the `Host` header through
    /// would otherwise serve every captured email to whoever reaches it.
    pub require_auth_token: bool,
    /// Let an SMTP listener that is reachable from other machines accept mail
    /// from clients that do not authenticate with an inbox key.
    pub allow_anonymous_smtp: bool,
    /// The host the web UI tells applications to reach SMTP by. Behind a proxy
    /// the page's own host may carry only HTTP, so a deployment names the one
    /// that reaches the SMTP listener.
    pub smtp_host: Option<String>,
    /// Enables HTTPS and SMTP STARTTLS.
    pub tls: Option<TlsFiles>,
    pub ui: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            smtp_addr: SocketAddr::from(([127, 0, 0, 1], 1025)),
            http_addr: SocketAddr::from(([127, 0, 0, 1], 8025)),
            data_dir: Some(default_data_dir()),
            limits: Limits::default(),
            max_message_size: 25 * 1024 * 1024,
            auth_token: None,
            provision: Vec::new(),
            allow_anonymous_http: false,
            require_auth_token: false,
            allow_anonymous_smtp: false,
            smtp_host: None,
            tls: None,
            ui: true,
        }
    }
}

impl Config {
    /// Whether SMTP clients must authenticate with an inbox id and API key.
    /// On a loopback listener they need not, and their mail goes to the
    /// default inbox; anywhere else they must, unless the operator says
    /// outright that the network is trusted.
    pub fn smtp_requires_auth(&self) -> bool {
        !self.smtp_addr.ip().is_loopback() && !self.allow_anonymous_smtp
    }

    /// The host the web UI gives applications for SMTP: the one configured,
    /// or else the listener's address. A listener on every interface has no
    /// one address to give, and the UI falls back to the host it was loaded
    /// from.
    pub fn advertised_smtp_host(&self) -> Option<String> {
        if let Some(host) = &self.smtp_host {
            return Some(host.clone());
        }
        let ip = self.smtp_addr.ip();
        (!ip.is_unspecified()).then(|| ip.to_string())
    }

    /// Refuse a configuration that would expose captured mail to a network,
    /// and return warnings for the ones that are merely risky.
    ///
    /// A listener on a loopback address is reachable only from this machine
    /// and needs nothing. On any other address HTTP needs the admin token,
    /// unless the operator says outright that the network is trusted.
    pub fn check(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        let http_exposed = !self.http_addr.ip().is_loopback();
        let smtp_exposed = !self.smtp_addr.ip().is_loopback();

        if self.require_auth_token && self.auth_token.is_none() {
            bail!(
                "an auth token is required (--require-auth-token) but none is set.\n\
                 Set EMAILULATOR_AUTH_TOKEN (generate one with `emailulator token`)."
            );
        }
        if http_exposed && self.auth_token.is_none() {
            if !self.allow_anonymous_http {
                bail!(
                    "the HTTP listener on {} is reachable from other machines but has no auth \
                     token, so anyone who can reach it could read every captured email.\n\
                     Set EMAILULATOR_AUTH_TOKEN (generate one with `emailulator token`), or pass \
                     --allow-anonymous-http if this network is trusted.",
                    self.http_addr
                );
            }
            warnings.push(format!(
                "HTTP on {} has no auth token: anyone who can reach it can read all captured mail",
                self.http_addr
            ));
        }
        if smtp_exposed && self.allow_anonymous_smtp {
            warnings.push(format!(
                "SMTP on {} accepts mail from anyone who can reach it, into the default inbox",
                self.smtp_addr
            ));
        }
        if self.tls.is_none() {
            if http_exposed && self.auth_token.is_some() {
                warnings.push(
                    "HTTP is served without TLS: put it behind a TLS-terminating proxy or pass \
                     --tls-cert and --tls-key, or tokens and keys cross the network in the clear"
                        .into(),
                );
            }
            if smtp_exposed {
                warnings.push(
                    "SMTP has no STARTTLS: inbox keys and mail cross the network in the clear \
                     unless --tls-cert and --tls-key are set"
                        .into(),
                );
            }
        }
        Ok(warnings)
    }
}

/// Whether something already answers on `addr`. A plain bind does not find
/// out: where one program holds a port on every address, another may still
/// bind it on a specific one, and would then take the first one's loopback
/// traffic without either noticing.
async fn port_answers(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    let target = if addr.ip().is_unspecified() {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), addr.port())
    } else {
        addr
    };
    let attempt = tokio::net::TcpStream::connect(target);
    matches!(
        tokio::time::timeout(std::time::Duration::from_millis(500), attempt).await,
        Ok(Ok(_))
    )
}

/// A configured server with both listeners bound, ready to serve.
pub struct Emailulator {
    store: Arc<Store>,
    smtp: TcpListener,
    http: TcpListener,
    smtp_config: SmtpConfig,
    http_config: HttpConfig,
    http_tls: Option<TlsAcceptor>,
    warnings: Vec<String>,
}

impl Emailulator {
    /// Validate the configuration, open the store and bind both ports.
    /// Must be called inside a Tokio runtime.
    pub async fn bind(config: Config) -> Result<Self> {
        let warnings = config.check()?;
        let auth = Arc::new(Auth::new(config.auth_token.clone())?);
        let smtp_auth_required = config.smtp_requires_auth();

        let (smtp_tls, http_tls) = match &config.tls {
            Some(files) => (
                Some(security::tls_acceptor(files, &[])?),
                Some(security::tls_acceptor(files, &[b"http/1.1"])?),
            ),
            None => (None, None),
        };

        let store = Arc::new(open_store(config.data_dir.as_deref(), config.limits)?);
        for (inbox, key) in &config.provision {
            store
                .provision_key(inbox, key)
                .with_context(|| format!("provisioning a key for the `{inbox}` inbox"))?;
        }

        for (what, addr) in [("SMTP", config.smtp_addr), ("HTTP", config.http_addr)] {
            if port_answers(addr).await {
                bail!(
                    "something is already listening on port {} ({what}); is another mail catcher \
                     running? Stop it, or choose a different address for this one",
                    addr.port()
                );
            }
        }

        let smtp = TcpListener::bind(config.smtp_addr)
            .await
            .with_context(|| format!("binding the SMTP listener to {}", config.smtp_addr))?;
        let http = TcpListener::bind(config.http_addr)
            .await
            .with_context(|| format!("binding the HTTP listener to {}", config.http_addr))?;

        let info = ServerInfo {
            name: "emailulator",
            version: env!("CARGO_PKG_VERSION"),
            smtp_host: config.advertised_smtp_host(),
            smtp_port: smtp.local_addr()?.port(),
            smtp_starttls: smtp_tls.is_some(),
            smtp_auth_required,
            http_tls: http_tls.is_some(),
            auth_required: auth.required(),
            max_message_size: config.max_message_size,
            max_messages: config.limits.max_messages,
        };

        Ok(Self {
            store,
            smtp,
            http,
            smtp_config: SmtpConfig {
                max_message_size: config.max_message_size,
                require_auth: smtp_auth_required,
                tls: smtp_tls,
                ..SmtpConfig::default()
            },
            http_config: HttpConfig {
                auth,
                info,
                ui: config.ui,
                loopback: config.http_addr.ip().is_loopback(),
            },
            http_tls,
            warnings,
        })
    }

    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    pub fn smtp_addr(&self) -> SocketAddr {
        self.smtp
            .local_addr()
            .expect("a bound listener has an address")
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.http
            .local_addr()
            .expect("a bound listener has an address")
    }

    pub fn info(&self) -> &ServerInfo {
        &self.http_config.info
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Serve until either listener fails.
    pub async fn serve(self) -> Result<()> {
        let router = http::router(self.store.clone(), self.http_config);
        tokio::select! {
            result = smtp::serve(self.smtp, self.store, self.smtp_config) => result.context("SMTP server stopped"),
            result = http::serve(self.http, self.http_tls, router) => result.context("HTTP server stopped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exposed() -> Config {
        Config {
            smtp_addr: "0.0.0.0:1025".parse().unwrap(),
            http_addr: "0.0.0.0:8025".parse().unwrap(),
            data_dir: None,
            ..Config::default()
        }
    }

    #[test]
    fn loopback_needs_no_credentials() {
        let config = Config {
            data_dir: None,
            ..Config::default()
        };
        assert!(config.check().unwrap().is_empty());
    }

    #[test]
    fn exposed_http_needs_the_admin_token() {
        let error = exposed().check().unwrap_err().to_string();
        assert!(error.contains("EMAILULATOR_AUTH_TOKEN"), "{error}");

        let mut config = exposed();
        config.auth_token = Some(security::generate_token());
        let warnings = config.check().unwrap();
        assert_eq!(warnings.len(), 2, "both listeners lack TLS: {warnings:?}");
    }

    #[test]
    fn exposed_smtp_requires_an_inbox_key_unless_told_otherwise() {
        let local = Config {
            data_dir: None,
            ..Config::default()
        };
        assert!(!local.smtp_requires_auth(), "this machine needs no key");

        let mut config = exposed();
        assert!(config.smtp_requires_auth());
        config.allow_anonymous_smtp = true;
        assert!(!config.smtp_requires_auth());
    }

    #[test]
    fn anonymous_exposure_must_be_asked_for() {
        let mut config = exposed();
        config.allow_anonymous_http = true;
        config.allow_anonymous_smtp = true;
        let warnings = config.check().unwrap();
        assert_eq!(
            warnings.len(),
            3,
            "open HTTP, open SMTP, no STARTTLS: {warnings:?}"
        );
    }

    #[test]
    fn the_smtp_host_shown_is_the_configured_one_or_the_listeners() {
        let local = Config {
            data_dir: None,
            ..Config::default()
        };
        assert_eq!(local.advertised_smtp_host().as_deref(), Some("127.0.0.1"));

        let mut everywhere = exposed();
        assert_eq!(
            everywhere.advertised_smtp_host(),
            None,
            "every interface leaves it to the page's host"
        );
        everywhere.smtp_host = Some("smtp.example.test".into());
        assert_eq!(
            everywhere.advertised_smtp_host().as_deref(),
            Some("smtp.example.test")
        );
    }

    #[test]
    fn a_required_token_is_required_on_loopback_too() {
        let mut config = Config {
            data_dir: None,
            require_auth_token: true,
            ..Config::default()
        };
        let error = config.check().unwrap_err().to_string();
        assert!(error.contains("EMAILULATOR_AUTH_TOKEN"), "{error}");

        config.auth_token = Some(security::generate_token());
        assert!(config.check().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_port_something_else_answers_on_is_refused() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            smtp_addr: taken.local_addr().unwrap(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: None,
            ..Config::default()
        };
        let error = Emailulator::bind(config).await.err().unwrap().to_string();
        assert!(error.contains("already listening"), "{error}");
    }

    #[tokio::test]
    async fn keys_given_in_configuration_are_valid_from_the_start() {
        let config = Config {
            smtp_addr: "127.0.0.1:0".parse().unwrap(),
            http_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: None,
            provision: vec![("orders".into(), "a-key-from-the-deployment".into())],
            ..Config::default()
        };
        let server = Emailulator::bind(config).await.unwrap();
        let store = server.store();
        assert_eq!(
            store
                .inbox_for_key("a-key-from-the-deployment")
                .unwrap()
                .as_deref(),
            Some("orders")
        );
    }
}
