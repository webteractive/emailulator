//! emailulator: a development email catcher.
//!
//! Mail comes in over SMTP or the HTTP API and is stored, never delivered. It
//! goes out through the web UI, the REST API and an MCP server. The binary is a
//! thin shell over this library, and the desktop app embeds it the same way.

pub mod compose;
pub mod http;
pub mod mcp;
pub mod model;
pub mod parse;
pub mod security;
pub mod smtp;
pub mod store;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::http::{HttpConfig, ServerInfo};
use crate::security::{Auth, Credentials, TlsFiles};
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
    /// Required by the API, MCP endpoint and web UI when set.
    pub auth_token: Option<String>,
    /// Required of SMTP clients when set.
    pub smtp_credentials: Option<Credentials>,
    /// Permit an HTTP listener that is reachable from other machines and has
    /// no auth token.
    pub allow_anonymous_http: bool,
    /// Permit an SMTP listener that is reachable from other machines and
    /// accepts mail from anyone.
    pub allow_anonymous_smtp: bool,
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
            smtp_credentials: None,
            allow_anonymous_http: false,
            allow_anonymous_smtp: false,
            tls: None,
            ui: true,
        }
    }
}

impl Config {
    /// Refuse configurations that would expose captured mail, or an open mail
    /// sink, to a network. Returns warnings for the ones that are merely risky.
    ///
    /// A listener on a loopback address is reachable only from this machine and
    /// needs nothing. Any other address needs credentials, unless the operator
    /// says outright that the network is trusted.
    pub fn check(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        let http_exposed = !self.http_addr.ip().is_loopback();
        let smtp_exposed = !self.smtp_addr.ip().is_loopback();

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
        if smtp_exposed && self.smtp_credentials.is_none() {
            if !self.allow_anonymous_smtp {
                bail!(
                    "the SMTP listener on {} is reachable from other machines but accepts mail \
                     from anyone.\nSet EMAILULATOR_SMTP_AUTH=user:password, or pass \
                     --allow-anonymous-smtp if this network is trusted.",
                    self.smtp_addr
                );
            }
            warnings.push(format!(
                "SMTP on {} accepts mail from anyone who can reach it",
                self.smtp_addr
            ));
        }
        if self.tls.is_none() {
            if http_exposed && self.auth_token.is_some() {
                warnings.push(
                    "HTTP is served without TLS: put it behind a TLS-terminating proxy or pass \
                     --tls-cert and --tls-key, or the auth token crosses the network in the clear"
                        .into(),
                );
            }
            if smtp_exposed && self.smtp_credentials.is_some() {
                warnings.push(
                    "SMTP has no STARTTLS: credentials and mail cross the network in the clear \
                     unless --tls-cert and --tls-key are set"
                        .into(),
                );
            }
        }
        Ok(warnings)
    }
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
        let auth = config
            .auth_token
            .clone()
            .map(Auth::new)
            .transpose()?
            .map(Arc::new);

        let (smtp_tls, http_tls) = match &config.tls {
            Some(files) => (
                Some(security::tls_acceptor(files, &[])?),
                Some(security::tls_acceptor(files, &[b"http/1.1"])?),
            ),
            None => (None, None),
        };

        let store = Arc::new(open_store(config.data_dir.as_deref(), config.limits)?);

        let smtp = TcpListener::bind(config.smtp_addr)
            .await
            .with_context(|| format!("binding the SMTP listener to {}", config.smtp_addr))?;
        let http = TcpListener::bind(config.http_addr)
            .await
            .with_context(|| format!("binding the HTTP listener to {}", config.http_addr))?;

        let info = ServerInfo {
            name: "emailulator",
            version: env!("CARGO_PKG_VERSION"),
            smtp_port: smtp.local_addr()?.port(),
            smtp_starttls: smtp_tls.is_some(),
            smtp_auth_required: config.smtp_credentials.is_some(),
            http_tls: http_tls.is_some(),
            auth_required: auth.is_some(),
            max_message_size: config.max_message_size,
            max_messages: config.limits.max_messages,
        };

        Ok(Self {
            store,
            smtp,
            http,
            smtp_config: SmtpConfig {
                max_message_size: config.max_message_size,
                credentials: config.smtp_credentials,
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
    fn exposed_listeners_need_credentials() {
        let error = exposed().check().unwrap_err().to_string();
        assert!(error.contains("EMAILULATOR_AUTH_TOKEN"), "{error}");

        let mut config = exposed();
        config.auth_token = Some(security::generate_token());
        let error = config.check().unwrap_err().to_string();
        assert!(error.contains("EMAILULATOR_SMTP_AUTH"), "{error}");

        config.smtp_credentials = Some(Credentials::parse("app:secret").unwrap());
        let warnings = config.check().unwrap();
        assert_eq!(warnings.len(), 2, "both listeners lack TLS: {warnings:?}");
    }

    #[test]
    fn anonymous_exposure_must_be_asked_for() {
        let mut config = exposed();
        config.allow_anonymous_http = true;
        config.allow_anonymous_smtp = true;
        let warnings = config.check().unwrap();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }
}
