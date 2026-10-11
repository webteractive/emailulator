//! The SMTP listener.
//!
//! A sink, never a relay: every accepted message is stored and nothing is sent
//! onward. Supports the extensions real mailers probe for — SIZE, 8BITMIME,
//! SMTPUTF8, PIPELINING, AUTH PLAIN/LOGIN and STARTTLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::compose::valid_address;
use crate::model::Source;
use crate::security::{Credentials, SecretComparer};
use crate::store::{Incoming, Store};

const MAX_COMMAND_LINE: usize = 4096;
const MAX_BAD_COMMANDS: usize = 10;
const MAX_AUTH_FAILURES: usize = 3;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct SmtpConfig {
    /// Name given in the greeting.
    pub hostname: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    /// Pause after a failed AUTH, to slow password guessing.
    pub auth_failure_delay: Duration,
    /// When set, clients must authenticate with these before sending.
    pub credentials: Option<Credentials>,
    /// When set, STARTTLS is offered.
    pub tls: Option<TlsAcceptor>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "emailulator".into(),
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_connections: 100,
            idle_timeout: Duration::from_secs(120),
            auth_failure_delay: Duration::from_secs(1),
            credentials: None,
            tls: None,
        }
    }
}

struct Context {
    store: Arc<Store>,
    config: SmtpConfig,
    comparer: SecretComparer,
}

pub async fn serve(listener: TcpListener, store: Arc<Store>, config: SmtpConfig) -> Result<()> {
    let slots = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let context = Arc::new(Context {
        store,
        config,
        comparer: SecretComparer::default(),
    });
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Usually file-descriptor exhaustion; back off instead of spinning.
                tracing::warn!(%error, "SMTP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tokio::spawn(async move {
                let _ = stream
                    .write_all(b"421 4.7.0 Too many connections, try again later\r\n")
                    .await;
            });
            continue;
        };
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(error) = connection(stream, peer, &context).await {
                tracing::debug!(%peer, %error, "SMTP connection ended with an error");
            }
            drop(slot);
        });
    }
}

async fn connection(stream: TcpStream, peer: SocketAddr, context: &Context) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let greeting = format!("220 {} ESMTP emailulator\r\n", context.config.hostname);
    reader.get_mut().write_all(greeting.as_bytes()).await?;

    if session(&mut reader, peer, context, false).await? == Outcome::StartTls {
        // Anything already buffered was sent in the clear after STARTTLS. Reading
        // it as if it had arrived under TLS is the classic command-injection
        // hole (RFC 3207 section 6), so such a client is dropped.
        if !reader.buffer().is_empty() {
            return Ok(());
        }
        let acceptor = context
            .config
            .tls
            .clone()
            .expect("STARTTLS is offered only with TLS configured");
        let stream = reader.into_inner();
        let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await??;
        let mut reader = BufReader::new(tls);
        session(&mut reader, peer, context, true).await?;
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
enum Outcome {
    Closed,
    StartTls,
}

enum Line {
    Data,
    TooLong,
    Eof,
}

/// Read one line into `line`, without its terminator. A line longer than `max`
/// is consumed to its end and reported, so the stream stays in sync.
async fn read_line<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Line> {
    line.clear();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(Line::Eof);
        }
        let (chunk, done) = match available.iter().position(|b| *b == b'\n') {
            Some(newline) => (newline + 1, true),
            None => (available.len(), false),
        };
        if too_long || line.len() + chunk > max + 2 {
            too_long = true;
            line.clear();
        } else {
            line.extend_from_slice(&available[..chunk]);
        }
        reader.consume(chunk);
        if done {
            break;
        }
    }
    if too_long {
        return Ok(Line::TooLong);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Line::Data)
}

struct Session<'a, S> {
    reader: &'a mut BufReader<S>,
    context: &'a Context,
    peer: SocketAddr,
    secure: bool,
    authenticated: bool,
    auth_failures: usize,
    bad_commands: usize,
    mail_from: Option<String>,
    recipients: Vec<String>,
    line: Vec<u8>,
}

/// The path from `MAIL FROM:<path> params` or `RCPT TO:<path> params`, and the
/// parameters after it.
fn path_and_params(rest: &str) -> Option<(String, &str)> {
    let rest = rest.trim_start();
    if let Some(inner) = rest.strip_prefix('<') {
        let (path, params) = inner.split_once('>')?;
        // Drop a source route such as `@relay:user@host`.
        let path = path.rsplit_once(':').map_or(path, |(_, p)| p);
        Some((path.trim().to_string(), params.trim()))
    } else {
        let (path, params) = rest.split_once(' ').unwrap_or((rest, ""));
        Some((path.trim().to_string(), params.trim()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<'_, S> {
    async fn reply(&mut self, text: &str) -> std::io::Result<()> {
        let stream = self.reader.get_mut();
        stream.write_all(text.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await
    }

    /// Read a line, or `None` when the client is gone, idle, or sent a line too
    /// long to be a command.
    async fn next_line(&mut self, max: usize) -> std::io::Result<Option<String>> {
        let idle = self.context.config.idle_timeout;
        match tokio::time::timeout(idle, read_line(self.reader, &mut self.line, max)).await {
            Err(_) => {
                self.reply("421 4.4.2 Idle too long, closing").await?;
                Ok(None)
            }
            Ok(Err(error)) => Err(error),
            Ok(Ok(Line::Eof)) => Ok(None),
            Ok(Ok(Line::TooLong)) => {
                self.reply("500 5.5.6 Line too long").await?;
                Ok(None)
            }
            Ok(Ok(Line::Data)) => Ok(Some(String::from_utf8_lossy(&self.line).into_owned())),
        }
    }

    /// Credentials are accepted only where they cannot be read off the wire:
    /// under TLS, from this machine, or when no TLS was configured at all, in
    /// which case the operator has chosen a network they trust.
    fn auth_available(&self) -> bool {
        self.secure || self.context.config.tls.is_none() || self.peer.ip().is_loopback()
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
    }

    async fn ehlo(&mut self) -> std::io::Result<()> {
        let config = &self.context.config;
        let mut lines = vec![
            format!("{} greets {}", config.hostname, self.peer.ip()),
            format!("SIZE {}", config.max_message_size),
            "8BITMIME".to_string(),
            "SMTPUTF8".to_string(),
            "PIPELINING".to_string(),
            "ENHANCEDSTATUSCODES".to_string(),
        ];
        if config.tls.is_some() && !self.secure {
            lines.push("STARTTLS".to_string());
        }
        if self.auth_available() {
            lines.push("AUTH PLAIN LOGIN".to_string());
        }
        let last = lines.len() - 1;
        let mut reply = String::new();
        for (i, line) in lines.iter().enumerate() {
            reply.push_str(if i == last { "250 " } else { "250-" });
            reply.push_str(line);
            if i != last {
                reply.push_str("\r\n");
            }
        }
        self.reply(&reply).await
    }

    /// Returns `false` when the connection should close.
    async fn auth(&mut self, args: &str) -> std::io::Result<bool> {
        if self.authenticated {
            self.reply("503 5.5.1 Already authenticated").await?;
            return Ok(true);
        }
        if !self.auth_available() {
            self.reply("538 5.7.11 Encryption required: issue STARTTLS first")
                .await?;
            return Ok(true);
        }
        let (mechanism, initial) = args.split_once(' ').unwrap_or((args, ""));
        let decode = |value: &str| BASE64.decode(value.trim()).ok();

        let supplied: Option<(String, String)> = match mechanism.to_ascii_uppercase().as_str() {
            "PLAIN" => {
                let response = if initial.is_empty() {
                    self.reply("334 ").await?;
                    match self.next_line(MAX_COMMAND_LINE).await? {
                        Some(line) => line,
                        None => return Ok(false),
                    }
                } else {
                    initial.to_string()
                };
                // authzid NUL authcid NUL password
                decode(&response).and_then(|bytes| {
                    let mut parts = bytes.split(|b| *b == 0);
                    let _authzid = parts.next()?;
                    let user = String::from_utf8(parts.next()?.to_vec()).ok()?;
                    let pass = String::from_utf8(parts.next()?.to_vec()).ok()?;
                    Some((user, pass))
                })
            }
            "LOGIN" => {
                let user = if initial.is_empty() {
                    self.reply("334 VXNlcm5hbWU6").await?;
                    match self.next_line(MAX_COMMAND_LINE).await? {
                        Some(line) => line,
                        None => return Ok(false),
                    }
                } else {
                    initial.to_string()
                };
                self.reply("334 UGFzc3dvcmQ6").await?;
                let Some(pass) = self.next_line(MAX_COMMAND_LINE).await? else {
                    return Ok(false);
                };
                decode(&user).zip(decode(&pass)).and_then(|(user, pass)| {
                    Some((String::from_utf8(user).ok()?, String::from_utf8(pass).ok()?))
                })
            }
            _ => {
                self.reply("504 5.5.4 Unsupported authentication mechanism")
                    .await?;
                return Ok(true);
            }
        };

        let Some((user, pass)) = supplied else {
            self.reply("501 5.5.2 Malformed authentication response")
                .await?;
            return Ok(true);
        };

        let accepted = match &self.context.config.credentials {
            // Nothing configured: accept whatever the application was set up
            // with, so a placeholder username and password just work.
            None => true,
            Some(expected) => {
                let comparer = &self.context.comparer;
                // Evaluate both so a wrong username costs the same as a wrong password.
                let user_ok = comparer.eq(user.as_bytes(), expected.username.as_bytes());
                let pass_ok = comparer.eq(pass.as_bytes(), expected.password.as_bytes());
                user_ok & pass_ok
            }
        };

        if accepted {
            self.authenticated = true;
            self.reply("235 2.7.0 Authentication successful").await?;
            return Ok(true);
        }
        self.auth_failures += 1;
        tracing::warn!(peer = %self.peer, "SMTP authentication failed");
        tokio::time::sleep(self.context.config.auth_failure_delay).await;
        if self.auth_failures >= MAX_AUTH_FAILURES {
            self.reply("421 4.7.0 Too many failed authentication attempts")
                .await?;
            return Ok(false);
        }
        self.reply("535 5.7.8 Authentication credentials invalid")
            .await?;
        Ok(true)
    }

    async fn mail(&mut self, rest: &str) -> std::io::Result<()> {
        if self.context.config.credentials.is_some() && !self.authenticated {
            return self.reply("530 5.7.0 Authentication required").await;
        }
        if self.mail_from.is_some() {
            return self.reply("503 5.5.1 Sender already given").await;
        }
        let Some((path, params)) = path_and_params(rest) else {
            return self.reply("501 5.5.2 Syntax: MAIL FROM:<address>").await;
        };
        // The null sender `<>` is legal: it is how bounces are sent.
        if !path.is_empty() && !valid_address(&path) {
            return self.reply("553 5.1.7 Sender address is not valid").await;
        }
        for param in params.split_whitespace() {
            if let Some(size) = param.to_ascii_uppercase().strip_prefix("SIZE=")
                && size
                    .parse::<usize>()
                    .is_ok_and(|n| n > self.context.config.max_message_size)
            {
                return self.reply("552 5.3.4 Message size exceeds the limit").await;
            }
        }
        self.mail_from = Some(path);
        self.reply("250 2.1.0 Ok").await
    }

    async fn rcpt(&mut self, rest: &str) -> std::io::Result<()> {
        if self.mail_from.is_none() {
            return self.reply("503 5.5.1 MAIL first").await;
        }
        let Some((path, _)) = path_and_params(rest) else {
            return self.reply("501 5.5.2 Syntax: RCPT TO:<address>").await;
        };
        if !valid_address(&path) {
            return self.reply("553 5.1.3 Recipient address is not valid").await;
        }
        if self.recipients.len() >= self.context.config.max_recipients {
            return self.reply("452 4.5.3 Too many recipients").await;
        }
        self.recipients.push(path);
        self.reply("250 2.1.5 Ok").await
    }

    /// Returns `false` when the connection should close.
    async fn data(&mut self) -> std::io::Result<bool> {
        if self.recipients.is_empty() {
            self.reply("503 5.5.1 RCPT first").await?;
            return Ok(true);
        }
        self.reply("354 End data with <CR><LF>.<CR><LF>").await?;

        let max = self.context.config.max_message_size;
        let idle = self.context.config.idle_timeout;
        let mut message: Vec<u8> = Vec::new();
        let mut too_large = false;
        loop {
            // An oversized message is read to its end rather than cut off, so
            // the client gets a clean rejection and the stream stays in sync.
            match tokio::time::timeout(idle, read_line(self.reader, &mut self.line, max)).await {
                Err(_) => {
                    self.reply("421 4.4.2 Idle too long, closing").await?;
                    return Ok(false);
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(Line::Eof)) => return Ok(false),
                Ok(Ok(Line::TooLong)) => too_large = true,
                Ok(Ok(Line::Data)) => {
                    if self.line == b"." {
                        break;
                    }
                    // Undo dot-stuffing: a leading dot was doubled by the sender.
                    let line = match self.line.first() {
                        Some(b'.') => &self.line[1..],
                        _ => &self.line[..],
                    };
                    if too_large || message.len() + line.len() + 2 > max {
                        too_large = true;
                        message = Vec::new();
                    } else {
                        message.extend_from_slice(line);
                        message.extend_from_slice(b"\r\n");
                    }
                }
            }
        }

        if too_large {
            self.reset_transaction();
            self.reply("552 5.3.4 Message size exceeds the limit")
                .await?;
            return Ok(true);
        }

        let incoming = Incoming {
            raw: message,
            envelope_from: self.mail_from.take().filter(|f| !f.is_empty()),
            envelope_to: std::mem::take(&mut self.recipients),
            source: Source::Smtp,
        };
        let store = self.context.store.clone();
        match tokio::task::spawn_blocking(move || store.insert(incoming)).await {
            Ok(Ok(summary)) => {
                tracing::info!(
                    id = summary.id,
                    peer = %self.peer,
                    recipients = summary.mailboxes.len(),
                    size = summary.size,
                    "message received over SMTP"
                );
                self.reply(&format!("250 2.0.0 Ok: stored as {}", summary.id))
                    .await?;
            }
            Ok(Err(error)) => {
                tracing::error!(%error, "storing a message failed");
                self.reply("451 4.3.0 Could not store the message").await?;
            }
            Err(error) => {
                tracing::error!(%error, "storing a message panicked");
                self.reply("451 4.3.0 Could not store the message").await?;
            }
        }
        Ok(true)
    }

    async fn run(&mut self) -> std::io::Result<Outcome> {
        loop {
            let Some(line) = self.next_line(MAX_COMMAND_LINE).await? else {
                return Ok(Outcome::Closed);
            };
            let (verb, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let verb = verb.to_ascii_uppercase();
            let rest = rest.trim();

            match verb.as_str() {
                "EHLO" => {
                    self.reset_transaction();
                    self.ehlo().await?;
                }
                "HELO" => {
                    self.reset_transaction();
                    let hello = format!("250 {}", self.context.config.hostname);
                    self.reply(&hello).await?;
                }
                "STARTTLS" => {
                    if self.context.config.tls.is_none() || self.secure {
                        self.reply("502 5.5.1 STARTTLS is not available").await?;
                    } else {
                        self.reply("220 2.0.0 Ready to start TLS").await?;
                        return Ok(Outcome::StartTls);
                    }
                }
                "AUTH" => {
                    if !self.auth(rest).await? {
                        return Ok(Outcome::Closed);
                    }
                }
                "MAIL" if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case("FROM:") => {
                    self.mail(&rest[5..]).await?;
                }
                "RCPT" if rest.len() >= 3 && rest[..3].eq_ignore_ascii_case("TO:") => {
                    self.rcpt(&rest[3..]).await?;
                }
                "DATA" => {
                    if !self.data().await? {
                        return Ok(Outcome::Closed);
                    }
                }
                "RSET" => {
                    self.reset_transaction();
                    self.reply("250 2.0.0 Ok").await?;
                }
                "NOOP" => self.reply("250 2.0.0 Ok").await?,
                "VRFY" => {
                    self.reply("252 2.1.5 Cannot verify, but will accept the message")
                        .await?
                }
                "HELP" => {
                    self.reply("214 2.0.0 emailulator catches mail; it delivers none")
                        .await?
                }
                "QUIT" => {
                    self.reply("221 2.0.0 Bye").await?;
                    return Ok(Outcome::Closed);
                }
                // An HTTP request on the SMTP port is a browser being steered
                // here by a web page. Do not let it keep talking.
                "GET" | "POST" | "PUT" | "HEAD" | "OPTIONS" | "DELETE" | "PATCH" | "CONNECT" => {
                    return Ok(Outcome::Closed);
                }
                _ => {
                    self.bad_commands += 1;
                    if self.bad_commands >= MAX_BAD_COMMANDS {
                        self.reply("421 4.7.0 Too many errors, closing").await?;
                        return Ok(Outcome::Closed);
                    }
                    self.reply("500 5.5.2 Command not recognized").await?;
                }
            }
        }
    }
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    peer: SocketAddr,
    context: &Context,
    secure: bool,
) -> std::io::Result<Outcome> {
    let mut session = Session {
        reader,
        context,
        peer,
        secure,
        authenticated: false,
        auth_failures: 0,
        bad_commands: 0,
        mail_from: None,
        recipients: Vec::new(),
        line: Vec::new(),
    };
    session.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn start(config: SmtpConfig) -> (SocketAddr, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, store.clone(), config));
        (addr, store)
    }

    /// Send `script` in one write and return everything the server said.
    async fn converse(addr: SocketAddr, script: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(script.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
    }

    const MESSAGE: &str = "EHLO test\r\nMAIL FROM:<a@x.test> SIZE=100\r\nRCPT TO:<b@x.test>\r\n\
        RCPT TO:<c@x.test>\r\nDATA\r\nFrom: a@x.test\r\nTo: b@x.test\r\nSubject: Hi\r\n\r\n\
        line one\r\n..leading dot\r\n.\r\nQUIT\r\n";

    #[tokio::test]
    async fn accepts_a_pipelined_message() {
        let (addr, store) = start(SmtpConfig::default()).await;
        let reply = converse(addr, MESSAGE).await;
        assert!(reply.starts_with("220 "), "{reply}");
        assert!(reply.contains("250 2.0.0 Ok: stored as 1"), "{reply}");
        assert!(reply.contains("221 2.0.0 Bye"), "{reply}");

        let detail = store.get(1).unwrap().unwrap();
        assert_eq!(detail.summary.subject, "Hi");
        assert_eq!(detail.summary.mailboxes, vec!["b@x.test", "c@x.test"]);
        assert_eq!(detail.envelope_from.as_deref(), Some("a@x.test"));
        let text = detail.text.unwrap();
        assert!(
            text.contains("line one\r\n.leading dot"),
            "dot-stuffing undone: {text:?}"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_messages_and_stays_in_sync() {
        let config = SmtpConfig {
            max_message_size: 64,
            ..SmtpConfig::default()
        };
        let (addr, store) = start(config).await;
        let body = "x".repeat(500);
        let script = format!(
            "EHLO t\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n{body}\r\n.\r\nNOOP\r\nQUIT\r\n"
        );
        let reply = converse(addr, &script).await;
        assert!(reply.contains("552 5.3.4"), "{reply}");
        assert!(
            reply.contains("250 2.0.0 Ok\r\n221"),
            "NOOP still understood: {reply}"
        );
        assert_eq!(store.stats().unwrap().total, 0);

        let reply = converse(addr, "MAIL FROM:<a@x.test> SIZE=9999\r\nQUIT\r\n").await;
        assert!(
            reply.contains("552 5.3.4"),
            "declared size is checked up front: {reply}"
        );
    }

    #[tokio::test]
    async fn requires_configured_credentials() {
        let config = SmtpConfig {
            credentials: Some(Credentials::parse("app:secret-pass").unwrap()),
            ..SmtpConfig::default()
        };
        let (addr, store) = start(config).await;

        let reply = converse(addr, "EHLO t\r\nMAIL FROM:<a@x.test>\r\nQUIT\r\n").await;
        assert!(reply.contains("530 5.7.0"), "{reply}");

        let good = BASE64.encode("\0app\0secret-pass");
        let script = format!(
            "EHLO t\r\nAUTH PLAIN {good}\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n\
             Subject: ok\r\n\r\nbody\r\n.\r\nQUIT\r\n"
        );
        let reply = converse(addr, &script).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        assert_eq!(store.stats().unwrap().total, 1);
    }

    #[tokio::test]
    async fn drops_clients_after_repeated_bad_credentials() {
        let config = SmtpConfig {
            auth_failure_delay: Duration::ZERO,
            credentials: Some(Credentials::parse("app:secret-pass").unwrap()),
            ..SmtpConfig::default()
        };
        let (addr, _store) = start(config).await;
        let bad = BASE64.encode("\0app\0wrong");
        let script = format!("AUTH PLAIN {bad}\r\n").repeat(5);
        let reply = converse(addr, &script).await;
        assert_eq!(reply.matches("535 5.7.8").count(), 2, "{reply}");
        assert!(reply.contains("421 4.7.0 Too many failed"), "{reply}");
    }

    #[tokio::test]
    async fn accepts_any_login_when_no_credentials_are_configured() {
        let (addr, _store) = start(SmtpConfig::default()).await;
        let user = BASE64.encode("whoever");
        let pass = BASE64.encode("whatever");
        let reply = converse(addr, &format!("AUTH LOGIN\r\n{user}\r\n{pass}\r\nQUIT\r\n")).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
    }

    #[tokio::test]
    async fn enforces_command_order_and_recipient_limits() {
        let config = SmtpConfig {
            max_recipients: 1,
            ..SmtpConfig::default()
        };
        let (addr, _store) = start(config).await;
        let reply = converse(
            addr,
            "RCPT TO:<b@x.test>\r\nDATA\r\nMAIL FROM:<>\r\nRCPT TO:<not-an-address>\r\n\
             RCPT TO:<b@x.test>\r\nRCPT TO:<c@x.test>\r\nQUIT\r\n",
        )
        .await;
        let codes: Vec<&str> = reply.lines().map(|l| &l[..3]).collect();
        assert_eq!(
            codes,
            vec!["220", "503", "503", "250", "553", "250", "452", "221"],
            "{reply}"
        );
    }

    #[tokio::test]
    async fn hangs_up_on_http_requests() {
        let (addr, _store) = start(SmtpConfig::default()).await;
        let reply = converse(
            addr,
            "POST / HTTP/1.1\r\nHost: x\r\n\r\nMAIL FROM:<a@x.test>\r\n",
        )
        .await;
        assert_eq!(reply.lines().count(), 1, "only the greeting: {reply}");
    }

    #[tokio::test]
    async fn turns_connections_away_at_the_limit() {
        let config = SmtpConfig {
            max_connections: 1,
            ..SmtpConfig::default()
        };
        let (addr, _store) = start(config).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut greeting = [0u8; 4];
        first.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"220 ");

        let reply = converse(addr, "").await;
        assert!(
            reply.starts_with("421 4.7.0 Too many connections"),
            "{reply}"
        );
    }
}
