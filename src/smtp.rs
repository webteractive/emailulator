//! The SMTP listener.
//!
//! A sink, never a relay: every accepted message is stored and nothing is sent
//! onward. Supports the extensions real mailers probe for — SIZE, 8BITMIME,
//! SMTPUTF8, PIPELINING, AUTH PLAIN/LOGIN and STARTTLS.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::compose::valid_address;
use crate::model::Source;
use crate::security::API_KEY_PREFIX;
use crate::store::{DEFAULT_INBOX, Incoming, Store};

const MAX_COMMAND_LINE: usize = 4096;
/// Commands refused with a permanent (5xx) error before the client is dropped.
const MAX_ERRORS: usize = 10;
const MAX_AUTH_FAILURES: usize = 3;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Addresses remembered for failed logins. Past this, new addresses go
/// untracked rather than memory growing without bound.
const MAX_TRACKED_PEERS: usize = 10_000;
const LOCKED_OUT: &str = "421 4.7.0 Too many failed authentication attempts, try again later";

pub struct SmtpConfig {
    /// Name given in the greeting.
    pub hostname: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_connections: usize,
    /// Connections one public address may hold at once.
    pub max_connections_per_ip: usize,
    /// How long a client may stay silent mid-command, and the longest one
    /// command line may take to arrive.
    pub idle_timeout: Duration,
    /// The longest a message body may take to arrive, however steadily it is
    /// sent.
    pub data_timeout: Duration,
    /// Pause after a failed AUTH, to slow password guessing.
    pub auth_failure_delay: Duration,
    /// Failed AUTH attempts one public address may make, across all its
    /// connections, before it is refused for the rest of `auth_lockout`.
    pub max_auth_failures_per_ip: usize,
    pub auth_lockout: Duration,
    /// When set, a client must authenticate as an inbox before sending: the
    /// inbox id as username, one of its API keys as password. When clear,
    /// mail sent without authenticating goes to the default inbox.
    pub require_auth: bool,
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
            max_connections_per_ip: 10,
            idle_timeout: Duration::from_secs(120),
            data_timeout: Duration::from_secs(600),
            auth_failure_delay: Duration::from_secs(1),
            max_auth_failures_per_ip: 10,
            auth_lockout: Duration::from_secs(15 * 60),
            require_auth: false,
            tls: None,
        }
    }
}

struct Context {
    store: Arc<Store>,
    config: SmtpConfig,
    peers: Arc<Peers>,
}

/// What is known about the addresses talking to this server: how many
/// connections each holds and how many logins each has failed.
///
/// Every address is counted except the operator's own networks (see
/// `own_network`), where a Docker bridge or a parallel test suite can rightly
/// open many connections at once. An IPv6 client is counted by its /64, since
/// one host can have that many.
#[derive(Default)]
struct Peers {
    connections: Mutex<HashMap<IpAddr, usize>>,
    failures: Mutex<HashMap<IpAddr, Failures>>,
}

struct Failures {
    count: usize,
    since: Instant,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether an address is on a network the operator runs: this machine, a
/// private or link-local network, or shared address space (100.64.0.0/10, as
/// Tailscale uses). Only these are exempt, so an unusual but routable range,
/// such as Teredo's, is limited like any other.
fn own_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// The key an address is counted under, or `None` for one not counted.
fn peer_key(ip: IpAddr) -> Option<IpAddr> {
    let ip = ip.to_canonical();
    if own_network(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    })
}

/// One connection's place in its address's count, given back on drop.
struct PeerSlot {
    peers: Arc<Peers>,
    key: Option<IpAddr>,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let Some(key) = self.key else { return };
        let mut connections = lock(&self.peers.connections);
        if let Some(count) = connections.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                connections.remove(&key);
            }
        }
    }
}

impl Peers {
    /// A place for one more connection from `ip`, or `None` at its limit.
    fn admit(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<PeerSlot> {
        let key = peer_key(ip);
        if let Some(key) = key {
            let mut connections = lock(&self.connections);
            let count = connections.entry(key).or_insert(0);
            if *count >= max.max(1) {
                return None;
            }
            *count += 1;
        }
        Some(PeerSlot {
            peers: self.clone(),
            key,
        })
    }

    fn locked_out(&self, ip: IpAddr, config: &SmtpConfig) -> bool {
        let Some(key) = peer_key(ip) else {
            return false;
        };
        lock(&self.failures).get(&key).is_some_and(|f| {
            f.count >= config.max_auth_failures_per_ip && f.since.elapsed() < config.auth_lockout
        })
    }

    /// Count a failed login from `ip`; `true` once that locks the address out.
    fn record_failure(&self, ip: IpAddr, config: &SmtpConfig) -> bool {
        let Some(key) = peer_key(ip) else {
            return false;
        };
        let now = Instant::now();
        let mut failures = lock(&self.failures);
        if !failures.contains_key(&key) && failures.len() >= MAX_TRACKED_PEERS {
            failures.retain(|_, f| now.duration_since(f.since) < config.auth_lockout);
            if failures.len() >= MAX_TRACKED_PEERS {
                return false;
            }
        }
        let entry = failures.entry(key).or_insert(Failures {
            count: 0,
            since: now,
        });
        if now.duration_since(entry.since) >= config.auth_lockout {
            *entry = Failures {
                count: 0,
                since: now,
            };
        }
        entry.count += 1;
        entry.count >= config.max_auth_failures_per_ip
    }
}

/// Turn a connection away with one reply line, without holding up accepting.
fn refuse(mut stream: TcpStream, reply: &'static str) {
    tokio::spawn(async move {
        let _ = stream.write_all(reply.as_bytes()).await;
        let _ = stream.write_all(b"\r\n").await;
    });
}

pub async fn serve(listener: TcpListener, store: Arc<Store>, config: SmtpConfig) -> Result<()> {
    let slots = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let context = Arc::new(Context {
        store,
        config,
        peers: Arc::default(),
    });
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Usually file-descriptor exhaustion; back off instead of spinning.
                tracing::warn!(%error, "SMTP accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if context.peers.locked_out(peer.ip(), &context.config) {
            refuse(stream, LOCKED_OUT);
            continue;
        }
        let Some(peer_slot) = context
            .peers
            .admit(peer.ip(), context.config.max_connections_per_ip)
        else {
            refuse(
                stream,
                "421 4.7.0 Too many connections from your address, try again later",
            );
            continue;
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            refuse(stream, "421 4.7.0 Too many connections, try again later");
            continue;
        };
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(error) = connection(stream, peer, &context).await {
                tracing::debug!(%peer, %error, "SMTP connection ended with an error");
            }
            drop(slot);
            drop(peer_slot);
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
    /// The inbox this client authenticated as, and so delivers into.
    inbox: Option<String>,
    auth_failures: usize,
    /// Commands refused with a permanent error.
    errors: usize,
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
        if text.starts_with('5') {
            self.errors += 1;
        }
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
        // Checked here as well as on connecting, so connections opened before
        // the lockout cannot keep guessing.
        if self
            .context
            .peers
            .locked_out(self.peer.ip(), &self.context.config)
        {
            self.reply(LOCKED_OUT).await?;
            return Ok(false);
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

        // The username names an inbox and the password is one of its keys.
        let store = self.context.store.clone();
        let key = pass.clone();
        let owner = match tokio::task::spawn_blocking(move || store.inbox_for_key(&key)).await {
            Ok(Ok(owner)) => owner,
            _ => {
                tracing::error!("looking up an API key failed");
                self.reply("454 4.7.0 Temporary authentication failure")
                    .await?;
                return Ok(true);
            }
        };
        let accepted = match owner {
            // A key opens only the inbox it belongs to; presenting it with
            // another inbox's id is a misconfiguration worth refusing loudly.
            Some(inbox) if inbox == user => Some(Some(inbox)),
            Some(_) => None,
            // Not a key at all. Where authentication is optional, accept the
            // placeholder credentials an application was set up with and file
            // its mail in the default inbox. Something shaped like a key is a
            // mistyped or revoked one, and quietly misfiling that would hide it.
            None if !self.context.config.require_auth && !pass.starts_with(API_KEY_PREFIX) => {
                Some(None)
            }
            None => None,
        };

        if let Some(inbox) = accepted {
            self.authenticated = true;
            self.inbox = inbox;
            self.reply("235 2.7.0 Authentication successful").await?;
            return Ok(true);
        }
        self.auth_failures += 1;
        // One stable line per failure, naming the address and nothing the
        // client typed, so a log watcher such as fail2ban can match it.
        let ip = self.peer.ip().to_canonical();
        tracing::warn!(%ip, "SMTP authentication failed");
        let locked_out = self.context.peers.record_failure(ip, &self.context.config);
        if locked_out {
            tracing::warn!(%ip, "SMTP address locked out after repeated authentication failures");
        }
        tokio::time::sleep(self.context.config.auth_failure_delay).await;
        if locked_out || self.auth_failures >= MAX_AUTH_FAILURES {
            self.reply(LOCKED_OUT).await?;
            return Ok(false);
        }
        self.reply("535 5.7.8 Authentication credentials invalid")
            .await?;
        Ok(true)
    }

    async fn mail(&mut self, rest: &str) -> std::io::Result<()> {
        if self.context.config.require_auth && !self.authenticated {
            return self
                .reply("530 5.7.0 Authentication required: inbox id and API key")
                .await;
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
        let deadline = Instant::now() + self.context.config.data_timeout;
        let mut message: Vec<u8> = Vec::new();
        let mut too_large = false;
        loop {
            // An oversized message is read to its end rather than cut off, so
            // the client gets a clean rejection and the stream stays in sync.
            // The deadline bounds how long that, or a trickle, can go on.
            let wait = deadline.min(Instant::now() + idle);
            let read = read_line(self.reader, &mut self.line, max);
            match tokio::time::timeout_at(wait, read).await {
                Err(_) if wait == deadline => {
                    self.reply("421 4.4.2 Message took too long to arrive, closing")
                        .await?;
                    return Ok(false);
                }
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
            inbox: self
                .inbox
                .clone()
                .unwrap_or_else(|| DEFAULT_INBOX.to_string()),
            envelope_from: self.mail_from.take().filter(|f| !f.is_empty()),
            envelope_to: std::mem::take(&mut self.recipients),
            source: Source::Smtp,
            tags: Default::default(),
        };
        let store = self.context.store.clone();
        match tokio::task::spawn_blocking(move || store.insert(incoming)).await {
            Ok(Ok(summary)) => {
                tracing::info!(
                    id = summary.id,
                    peer = %self.peer,
                    inbox = %summary.inbox,
                    recipients = summary.recipients.len(),
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
                _ => self.reply("500 5.5.2 Command not recognized").await?,
            }
            if self.errors >= MAX_ERRORS {
                self.reply("421 4.7.0 Too many errors, closing").await?;
                return Ok(Outcome::Closed);
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
        inbox: None,
        auth_failures: 0,
        errors: 0,
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
        assert_eq!(detail.summary.recipients, vec!["b@x.test", "c@x.test"]);
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
        assert_eq!(store.stats(None).unwrap().total, 0);

        let reply = converse(addr, "MAIL FROM:<a@x.test> SIZE=9999\r\nQUIT\r\n").await;
        assert!(
            reply.contains("552 5.3.4"),
            "declared size is checked up front: {reply}"
        );
    }

    fn plain(user: &str, pass: &str) -> String {
        BASE64.encode(format!("\0{user}\0{pass}"))
    }

    const BODY: &str = "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n\
        Subject: ok\r\n\r\nbody\r\n.\r\nQUIT\r\n";

    #[tokio::test]
    async fn an_inbox_id_and_its_key_deliver_into_that_inbox() {
        let config = SmtpConfig {
            require_auth: true,
            auth_failure_delay: Duration::ZERO,
            ..SmtpConfig::default()
        };
        let (addr, store) = start(config).await;
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        let (_, key) = store.create_key("billing", "app").unwrap();

        let reply = converse(addr, "EHLO t\r\nMAIL FROM:<a@x.test>\r\nQUIT\r\n").await;
        assert!(
            reply.contains("530 5.7.0"),
            "sending needs authentication: {reply}"
        );

        let script = format!("EHLO t\r\nAUTH PLAIN {}\r\n{BODY}", plain("billing", &key));
        let reply = converse(addr, &script).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        assert_eq!(store.stats(Some("billing")).unwrap().total, 1);
        assert_eq!(store.stats(None).unwrap().total, 1, "and nowhere else");

        // The same key under another inbox's id, or no inbox's, opens nothing.
        for user in ["marketing", "default", "", "nobody"] {
            let script = format!("EHLO t\r\nAUTH PLAIN {}\r\n{BODY}", plain(user, &key));
            let reply = converse(addr, &script).await;
            assert!(reply.contains("535 5.7.8"), "as {user:?}: {reply}");
            assert!(reply.contains("530 5.7.0"), "as {user:?}: {reply}");
        }
        assert_eq!(store.stats(None).unwrap().total, 1);

        // AUTH LOGIN carries the same pair.
        let script = format!(
            "AUTH LOGIN\r\n{}\r\n{}\r\n{BODY}",
            BASE64.encode("billing"),
            BASE64.encode(&key)
        );
        let reply = converse(addr, &script).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        assert_eq!(store.stats(Some("billing")).unwrap().total, 2);
    }

    #[tokio::test]
    async fn drops_clients_after_repeated_bad_credentials() {
        let config = SmtpConfig {
            require_auth: true,
            auth_failure_delay: Duration::ZERO,
            ..SmtpConfig::default()
        };
        let (addr, _store) = start(config).await;
        let script = format!("AUTH PLAIN {}\r\n", plain("default", "wrong")).repeat(5);
        let reply = converse(addr, &script).await;
        assert_eq!(reply.matches("535 5.7.8").count(), 2, "{reply}");
        assert!(reply.contains("421 4.7.0 Too many failed"), "{reply}");
    }

    #[tokio::test]
    async fn without_required_auth_mail_goes_to_the_default_inbox() {
        let config = SmtpConfig {
            auth_failure_delay: Duration::ZERO,
            ..SmtpConfig::default()
        };
        let (addr, store) = start(config).await;
        store.create_inbox("billing").unwrap();
        let (_, key) = store.create_key("billing", "app").unwrap();

        // No AUTH at all, and the placeholder credentials an app ships with.
        converse(addr, BODY).await;
        let script = format!("AUTH PLAIN {}\r\n{BODY}", plain("whoever", "whatever"));
        let reply = converse(addr, &script).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        assert_eq!(store.stats(Some(DEFAULT_INBOX)).unwrap().total, 2);

        // A real key still routes to its inbox.
        let script = format!("AUTH PLAIN {}\r\n{BODY}", plain("billing", &key));
        converse(addr, &script).await;
        assert_eq!(store.stats(Some("billing")).unwrap().total, 1);

        // Something shaped like a key that is not one is refused, not misfiled.
        let script = format!(
            "AUTH PLAIN {}\r\n{BODY}",
            plain("billing", "emu_0000revoked")
        );
        let reply = converse(addr, &script).await;
        assert!(reply.contains("535 5.7.8"), "{reply}");
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

    /// A context as `serve` builds it, for driving sessions directly.
    fn context(config: SmtpConfig) -> (Arc<Context>, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        let context = Arc::new(Context {
            store: store.clone(),
            config,
            peers: Arc::default(),
        });
        (context, store)
    }

    /// Run `script` through a session as if it came from `peer`, which a test
    /// cannot otherwise do from anywhere but loopback.
    async fn converse_as(context: &Arc<Context>, peer: &str, script: &str) -> String {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer: SocketAddr = peer.parse().unwrap();
        let context = context.clone();
        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(server);
            let _ = session(&mut reader, peer, &context, false).await;
        });
        let (mut read, mut write) = tokio::io::split(client);
        write.write_all(script.as_bytes()).await.unwrap();
        write.shutdown().await.unwrap();
        let mut reply = String::new();
        read.read_to_string(&mut reply).await.unwrap();
        server.await.unwrap();
        reply
    }

    /// A TLS acceptor with no certificate. Enough to make STARTTLS a
    /// configured option; no handshake is ever completed with it.
    fn tls_without_a_certificate() -> TlsAcceptor {
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
        use tokio_rustls::rustls::sign::CertifiedKey;

        #[derive(Debug)]
        struct NoCertificate;
        impl ResolvesServerCert for NoCertificate {
            fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                None
            }
        }
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        TlsAcceptor::from(Arc::new(config))
    }

    #[tokio::test]
    async fn refuses_auth_in_the_clear_once_tls_is_configured() {
        let (context, store) = context(SmtpConfig {
            require_auth: true,
            auth_failure_delay: Duration::ZERO,
            tls: Some(tls_without_a_certificate()),
            ..SmtpConfig::default()
        });
        store.create_inbox("billing").unwrap();
        let (_, key) = store.create_key("billing", "app").unwrap();

        // Even a client that ignores EHLO and sends a valid pair in the clear
        // is refused before the credentials are looked at.
        let script = format!("EHLO t\r\nAUTH PLAIN {}\r\n{BODY}", plain("billing", &key));
        let reply = converse_as(&context, "203.0.113.5:40000", &script).await;
        assert!(reply.contains("STARTTLS"), "offered: {reply}");
        assert!(!reply.contains("AUTH PLAIN"), "not advertised: {reply}");
        assert!(reply.contains("538 5.7.11"), "{reply}");
        assert!(!reply.contains("235"), "{reply}");
        assert!(reply.contains("530 5.7.0"), "{reply}");
        let script = format!(
            "AUTH LOGIN\r\n{}\r\n{}\r\nQUIT\r\n",
            BASE64.encode("billing"),
            BASE64.encode(&key)
        );
        let reply = converse_as(&context, "203.0.113.5:40001", &script).await;
        assert!(reply.starts_with("538 5.7.11"), "{reply}");
        assert_eq!(store.stats(None).unwrap().total, 0);
    }

    #[tokio::test]
    async fn locks_out_an_address_that_keeps_failing_across_connections() {
        let (context, store) = context(SmtpConfig {
            require_auth: true,
            auth_failure_delay: Duration::ZERO,
            max_auth_failures_per_ip: 4,
            ..SmtpConfig::default()
        });
        store.create_inbox("billing").unwrap();
        let (_, key) = store.create_key("billing", "app").unwrap();
        let wrong = format!("AUTH PLAIN {}\r\n", plain("billing", "wrong"));
        let right = format!("AUTH PLAIN {}\r\n{BODY}", plain("billing", &key));

        let reply = converse_as(&context, "1.1.1.1:40000", &wrong.repeat(3)).await;
        assert_eq!(reply.matches("535 5.7.8").count(), 2, "{reply}");
        // The fourth failure, on a fresh connection, locks the address.
        let reply = converse_as(&context, "1.1.1.1:40001", &wrong).await;
        assert!(reply.starts_with(LOCKED_OUT), "{reply}");
        // Now even the right key is turned away from that address,
        let reply = converse_as(&context, "1.1.1.1:40002", &right).await;
        assert!(reply.starts_with(LOCKED_OUT), "{reply}");
        assert!(
            context
                .peers
                .locked_out("1.1.1.1".parse().unwrap(), &context.config)
        );
        // but not from another,
        let reply = converse_as(&context, "9.9.9.9:40000", &right).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        // nor from a private network, which is the operator's own.
        converse_as(&context, "10.0.0.5:40000", &wrong.repeat(3)).await;
        converse_as(&context, "10.0.0.5:40001", &wrong.repeat(3)).await;
        let reply = converse_as(&context, "10.0.0.5:40002", &right).await;
        assert!(reply.contains("235 2.7.0"), "{reply}");
        assert_eq!(store.stats(Some("billing")).unwrap().total, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lockout_ends_after_its_window() {
        let config = SmtpConfig {
            max_auth_failures_per_ip: 2,
            ..SmtpConfig::default()
        };
        let peers = Peers::default();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!peers.record_failure(ip, &config));
        assert!(peers.record_failure(ip, &config));
        assert!(peers.locked_out(ip, &config));
        tokio::time::advance(config.auth_lockout).await;
        assert!(!peers.locked_out(ip, &config));
        assert!(!peers.record_failure(ip, &config), "a fresh window");
    }

    #[test]
    fn counts_connections_per_public_address() {
        let peers = Arc::new(Peers::default());
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let first = peers.admit(ip, 2).unwrap();
        let _second = peers.admit(ip, 2).unwrap();
        assert!(peers.admit(ip, 2).is_none(), "at the limit");
        assert!(peers.admit("9.9.9.9".parse().unwrap(), 2).is_some());
        drop(first);
        assert!(peers.admit(ip, 2).is_some(), "a place is given back");

        // One IPv6 host holds a whole /64, so that is what is counted.
        let _a = peers.admit("2606:4700::1".parse().unwrap(), 1).unwrap();
        assert!(
            peers
                .admit("2606:4700::ffff:2".parse().unwrap(), 1)
                .is_none()
        );
        assert!(
            peers
                .admit("2606:4700:0:1::1".parse().unwrap(), 1)
                .is_some()
        );
        // A mapped IPv4 address is that address.
        let _b = peers.admit("8.8.4.4".parse().unwrap(), 1).unwrap();
        assert!(peers.admit("::ffff:8.8.4.4".parse().unwrap(), 1).is_none());

        // Routable special-purpose ranges, such as Teredo's, are limited too.
        let _t = peers
            .admit("2001:0:4136:e378::1".parse().unwrap(), 1)
            .unwrap();
        assert!(
            peers
                .admit("2001:0:4136:e378::2".parse().unwrap(), 1)
                .is_none()
        );

        // The operator's own networks are not limited.
        let own = [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.0.0.5",
            "172.17.0.1",
            "192.168.1.2",
            "169.254.1.1",
            "100.100.1.1",
            "fd00::1",
            "fe80::1",
        ];
        for ip in own {
            let ip: IpAddr = ip.parse().unwrap();
            let held: Vec<_> = (0..20).map(|_| peers.admit(ip, 1).unwrap()).collect();
            assert_eq!(held.len(), 20);
        }
    }

    #[tokio::test]
    async fn drops_clients_that_keep_making_errors() {
        let config = SmtpConfig {
            require_auth: true,
            ..SmtpConfig::default()
        };
        let (addr, _store) = start(config).await;
        // Recognised commands count too, not only unknown ones.
        let reply = converse(addr, &"MAIL FROM:<a@x.test>\r\n".repeat(20)).await;
        assert_eq!(reply.matches("530 5.7.0").count(), MAX_ERRORS, "{reply}");
        assert!(
            reply.ends_with("421 4.7.0 Too many errors, closing\r\n"),
            "{reply}"
        );
    }

    #[tokio::test]
    async fn a_message_body_has_a_deadline_however_steadily_it_trickles() {
        let config = SmtpConfig {
            data_timeout: Duration::from_millis(300),
            ..SmtpConfig::default()
        };
        let (addr, store) = start(config).await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut read, mut write) = stream.into_split();
        // A line every 50ms never trips the idle timeout, only the deadline.
        let writer = tokio::spawn(async move {
            write
                .write_all(b"EHLO t\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n")
                .await?;
            for _ in 0..40 {
                write.write_all(b"still sending\r\n").await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            std::io::Result::Ok(())
        });
        let mut reply = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(n @ 1..) = read.read(&mut chunk).await {
            reply.extend_from_slice(&chunk[..n]);
        }
        writer.abort();
        let reply = String::from_utf8_lossy(&reply);
        assert!(
            reply.contains("421 4.4.2 Message took too long to arrive"),
            "{reply}"
        );
        assert_eq!(store.stats(None).unwrap().total, 0);
    }
}
