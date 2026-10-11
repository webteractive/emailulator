#[cfg(all(feature = "desktop", any(target_os = "macos", target_os = "windows")))]
mod desktop;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use emailulator::mcp::{self, Mcp};
use emailulator::security::{self, Access, TlsFiles};
use emailulator::store::Limits;
use emailulator::{Config, Emailulator, default_data_dir, open_store};

/// Set by build.rs: the crate version plus the commit and its date.
const VERSION: &str = env!("EMAILULATOR_VERSION");

#[derive(Parser)]
#[command(
    name = "emailulator",
    version = VERSION,
    about = "Catch the email your app sends in development. Nothing is ever delivered.",
    long_about = "Catch the email your app sends in development. Nothing is ever delivered.\n\n\
        `emailulator run` starts the SMTP and HTTP servers. Point an application's SMTP \
        settings at it, or POST messages to its HTTP API, then read them in the web UI, over \
        the REST API, or from an agent through MCP.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the SMTP and HTTP servers
    #[command(long_about = "Start the SMTP and HTTP servers.\n\n\
            With no options it listens on this machine only and needs no credentials. On any \
            other address it refuses to start without an auth token and SMTP credentials. \
            Every option can also be set through the environment variable shown beside it.")]
    Run(Box<RunArgs>),
    /// Open the desktop app
    #[command(
        long_about = "Open the desktop app: the web UI in a window of its own. It runs the SMTP \
            and HTTP servers itself, on this machine only, so there is nothing else to start. \
            If the usual ports are taken, by `emailulator run` or another mail catcher, it \
            moves to 1026 and 8026, then 2525 and 8525, then 2526 and 8526.\n\n\
            The app is part of this program on macOS. The Linux build is the server alone and \
            has no app; use the web UI from `emailulator run` there."
    )]
    App(AppArgs),
    /// Create, list and delete inboxes in the message store on this machine
    #[command(subcommand)]
    Inbox(InboxCommand),
    /// Create, list and revoke the API keys of an inbox
    #[command(subcommand)]
    Key(KeyCommand),
    /// Serve MCP over stdio, reading the message store on this machine
    Mcp(McpArgs),
    /// Print a new random auth token
    Token,
    /// Exit 0 if a running server answers on both ports (for container health checks)
    Healthcheck(HealthArgs),
    /// Print the version
    Version,
}

#[derive(Subcommand)]
enum InboxCommand {
    /// List inboxes with their message and key counts
    List(ListArgs),
    /// Create an inbox and print its generated id and first API key
    Create {
        /// What to call the inbox, such as "Billing app"
        name: String,
        /// What the inbox is for
        #[arg(long, default_value = "")]
        description: String,
        #[command(flatten)]
        output: ListArgs,
    },
    /// Delete an inbox with all its messages and keys
    Delete {
        /// The inbox's id or name
        inbox: String,
        #[command(flatten)]
        store: StoreArgs,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// List an inbox's keys, or every key. Keys themselves are never shown again,
    /// except the default inbox's starter key until it is regenerated
    List {
        /// Only this inbox's keys, by its id or name
        inbox: Option<String>,
        #[command(flatten)]
        output: ListArgs,
    },
    /// Create an API key for an inbox and print it, once
    Create {
        /// The inbox's id or name
        inbox: String,
        /// What the key is for, to tell keys apart later
        #[arg(long, default_value = "")]
        label: String,
        #[command(flatten)]
        output: ListArgs,
    },
    /// Replace a key's value, keeping its id and label, and print the new one, once.
    /// The old value stops working at once
    Regenerate {
        /// The key's id, as `key list` shows
        id: i64,
        #[command(flatten)]
        output: ListArgs,
    },
    /// Revoke a key by the id `key list` shows
    Revoke {
        id: i64,
        #[command(flatten)]
        store: StoreArgs,
    },
}

#[derive(Args, Clone)]
struct ListArgs {
    #[command(flatten)]
    store: StoreArgs,
    /// Print JSON, for scripts and agents
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone)]
struct McpArgs {
    #[command(flatten)]
    store: StoreArgs,
    /// Confine the session to this inbox, by id or name, as its API key would;
    /// all inboxes otherwise
    #[arg(long, env = "EMAILULATOR_INBOX", value_name = "INBOX")]
    inbox: Option<String>,
}

#[derive(Args, Clone)]
struct StoreArgs {
    /// Directory holding the message database [default: the platform data directory]
    #[arg(long, env = "EMAILULATOR_DATA_DIR", value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct AppArgs {
    /// Address for the app's SMTP listener [default: 127.0.0.1:1025]
    #[arg(long, env = "EMAILULATOR_SMTP_ADDR", value_name = "ADDR")]
    smtp_addr: Option<SocketAddr>,

    /// Address for the app's HTTP listener [default: 127.0.0.1:8025]
    #[arg(long, env = "EMAILULATOR_HTTP_ADDR", value_name = "ADDR")]
    http_addr: Option<SocketAddr>,

    #[command(flatten)]
    store: StoreArgs,

    /// Stay attached to this terminal instead of returning once the app is open
    #[arg(long)]
    foreground: bool,
}

#[derive(Args, Clone)]
struct HealthArgs {
    /// SMTP address the server listens on
    #[arg(
        long,
        env = "EMAILULATOR_SMTP_ADDR",
        default_value = "127.0.0.1:1025",
        value_name = "ADDR"
    )]
    smtp_addr: SocketAddr,
    /// HTTP address the server listens on
    #[arg(
        long,
        env = "EMAILULATOR_HTTP_ADDR",
        default_value = "127.0.0.1:8025",
        value_name = "ADDR"
    )]
    http_addr: SocketAddr,
}

#[derive(Args, Clone)]
struct RunArgs {
    /// Address for the SMTP listener
    #[arg(
        long,
        env = "EMAILULATOR_SMTP_ADDR",
        default_value = "127.0.0.1:1025",
        value_name = "ADDR"
    )]
    smtp_addr: SocketAddr,

    /// Address for the HTTP listener: web UI, API and MCP
    #[arg(
        long,
        env = "EMAILULATOR_HTTP_ADDR",
        default_value = "127.0.0.1:8025",
        value_name = "ADDR"
    )]
    http_addr: SocketAddr,

    #[command(flatten)]
    store: StoreArgs,

    /// Keep messages in memory only; they are gone when the server stops
    #[arg(long, env = "EMAILULATOR_MEMORY", conflicts_with = "data_dir")]
    memory: bool,

    /// Token required by the API, MCP endpoint and web UI.
    /// Prefer the environment variable or --auth-token-file: an argument is visible to
    /// every user of the machine in the process list
    #[arg(
        long,
        env = "EMAILULATOR_AUTH_TOKEN",
        hide_env_values = true,
        value_name = "TOKEN"
    )]
    auth_token: Option<String>,

    /// Read the auth token from a file, such as a mounted secret
    #[arg(
        long,
        env = "EMAILULATOR_AUTH_TOKEN_FILE",
        value_name = "FILE",
        conflicts_with = "auth_token"
    )]
    auth_token_file: Option<PathBuf>,

    /// Inbox keys to make valid at startup, as inbox=key pairs separated by commas;
    /// each inbox is created if missing. For handing an application its key through
    /// a deployment's configuration. Mint keys by hand with `emailulator key create`
    #[arg(
        long,
        env = "EMAILULATOR_PROVISION",
        hide_env_values = true,
        value_delimiter = ',',
        value_parser = parse_provision,
        value_name = "INBOX=KEY"
    )]
    provision: Vec<(String, String)>,

    /// Serve HTTP on a non-loopback address with no auth token
    #[arg(long, env = "EMAILULATOR_ALLOW_ANONYMOUS_HTTP")]
    allow_anonymous_http: bool,

    /// On a non-loopback address, accept SMTP from clients with no inbox key
    #[arg(long, env = "EMAILULATOR_ALLOW_ANONYMOUS_SMTP")]
    allow_anonymous_smtp: bool,

    /// PEM certificate chain; with --tls-key, enables HTTPS and SMTP STARTTLS
    #[arg(
        long,
        env = "EMAILULATOR_TLS_CERT",
        value_name = "FILE",
        requires = "tls_key"
    )]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert
    #[arg(
        long,
        env = "EMAILULATOR_TLS_KEY",
        value_name = "FILE",
        requires = "tls_cert"
    )]
    tls_key: Option<PathBuf>,

    /// Largest message accepted, e.g. 25MB
    #[arg(long, env = "EMAILULATOR_MAX_MESSAGE_SIZE", default_value = "25MB", value_parser = parse_size, value_name = "SIZE")]
    max_message_size: u64,

    /// Messages kept before the oldest are dropped; 0 keeps all
    #[arg(
        long,
        env = "EMAILULATOR_MAX_MESSAGES",
        default_value_t = 1000,
        value_name = "N"
    )]
    max_messages: usize,

    /// Total message bytes kept before the oldest are dropped, e.g. 1GB; 0 for no cap
    #[arg(long, env = "EMAILULATOR_MAX_STORAGE", default_value = "1GB", value_parser = parse_size, value_name = "SIZE")]
    max_storage: u64,

    /// Do not serve the web UI; the API and MCP endpoint stay available
    #[arg(long, env = "EMAILULATOR_NO_UI")]
    no_ui: bool,

    /// Log verbosity: error, warn, info, debug or trace
    #[arg(
        long,
        env = "EMAILULATOR_LOG_LEVEL",
        default_value = "info",
        value_name = "LEVEL"
    )]
    log_level: tracing::Level,
}

fn parse_provision(value: &str) -> Result<(String, String), String> {
    match value.trim().split_once('=') {
        Some((inbox, key)) if !inbox.trim().is_empty() && !key.trim().is_empty() => {
            Ok((inbox.trim().to_string(), key.trim().to_string()))
        }
        _ => Err(format!("`{value}` is not an inbox=key pair")),
    }
}

/// Parse a byte count with an optional KB, MB or GB suffix.
fn parse_size(value: &str) -> Result<u64, String> {
    let lower = value.trim().to_ascii_lowercase();
    let (digits, multiplier) = [
        ("kb", 1u64 << 10),
        ("mb", 1 << 20),
        ("gb", 1 << 30),
        ("k", 1 << 10),
        ("m", 1 << 20),
        ("g", 1 << 30),
        ("b", 1),
    ]
    .iter()
    .find_map(|(suffix, multiplier)| lower.strip_suffix(suffix).map(|d| (d.trim(), *multiplier)))
    .unwrap_or((lower.as_str(), 1));
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or_else(|| {
            format!("`{value}` is not a size; use a number of bytes or a suffix such as 25MB")
        })
}

fn format_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.0} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / (1u64 << 10) as f64),
        b => format!("{b} bytes"),
    }
}

/// A secret given directly or in a file; surrounding whitespace is dropped.
fn secret(direct: Option<String>, file: Option<PathBuf>, what: &str) -> Result<Option<String>> {
    let value = match (direct, file) {
        (Some(value), _) => value,
        (None, Some(path)) => std::fs::read_to_string(&path)
            .with_context(|| format!("reading the {what} from {}", path.display()))?,
        (None, None) => return Ok(None),
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("the {what} is empty");
    }
    Ok(Some(value))
}

impl RunArgs {
    fn into_config(self) -> Result<Config> {
        let data_dir = if self.memory {
            None
        } else {
            Some(self.store.data_dir.unwrap_or_else(default_data_dir))
        };
        Ok(Config {
            smtp_addr: self.smtp_addr,
            http_addr: self.http_addr,
            data_dir,
            limits: Limits {
                max_messages: self.max_messages,
                max_storage_bytes: self.max_storage,
            },
            max_message_size: usize::try_from(self.max_message_size)
                .map_err(|_| anyhow!("--max-message-size is too large for this platform"))?,
            auth_token: secret(self.auth_token, self.auth_token_file, "auth token")?,
            provision: self.provision,
            allow_anonymous_http: self.allow_anonymous_http,
            allow_anonymous_smtp: self.allow_anonymous_smtp,
            tls: self
                .tls_cert
                .zip(self.tls_key)
                .map(|(cert, key)| TlsFiles { cert, key }),
            ui: !self.no_ui,
        })
    }
}

fn init_logging(level: tracing::Level) {
    // Logs go to stderr so stdout stays clean for the stdio MCP transport.
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = interrupt => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = interrupt.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

async fn serve(args: RunArgs) -> Result<()> {
    init_logging(args.log_level);
    let config = args.into_config()?;
    let data = match &config.data_dir {
        Some(dir) => dir.join(emailulator::DB_FILE).display().to_string(),
        None => "in memory, lost on exit".to_string(),
    };
    let limits = config.limits;
    let ui = config.ui;

    let server = Emailulator::bind(config).await?;
    let info = server.info().clone();
    let scheme = if info.http_tls { "https" } else { "http" };
    let http = server.http_addr();

    let describe = |on: bool, yes: &'static str, no: &'static str| if on { yes } else { no };
    println!("emailulator {VERSION}");
    println!(
        "  SMTP   {}  ({}, {})",
        server.smtp_addr(),
        describe(
            info.smtp_auth_required,
            "inbox id and API key required",
            "no auth; unauthenticated mail goes to the default inbox"
        ),
        describe(info.smtp_starttls, "STARTTLS", "no TLS"),
    );
    println!(
        "  HTTP   {scheme}://{http}  ({})",
        describe(
            info.auth_required,
            "admin token or inbox API key required",
            "no auth"
        ),
    );
    if ui {
        println!("         web UI   {scheme}://{http}/");
    }
    println!("         API      {scheme}://{http}/api/v1");
    println!("         MCP      {scheme}://{http}/mcp");
    let keep = |n: u64, what: String| {
        if n == 0 {
            "unlimited".to_string()
        } else {
            what
        }
    };
    println!(
        "  Data   {data}  (keeps {}, {})",
        keep(
            limits.max_messages as u64,
            format!("{} messages", limits.max_messages)
        ),
        keep(
            limits.max_storage_bytes,
            format_size(limits.max_storage_bytes)
        ),
    );
    for warning in server.warnings() {
        tracing::warn!("{warning}");
    }

    tokio::select! {
        result = server.serve() => result,
        _ = shutdown_signal() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}

fn local_store(args: &StoreArgs) -> Result<emailulator::store::Store> {
    let dir = args.data_dir.clone().unwrap_or_else(default_data_dir);
    open_store(Some(&dir), Limits::default())
}

async fn mcp_stdio(args: McpArgs) -> Result<()> {
    init_logging(tracing::Level::WARN);
    let store = local_store(&args.store)?;
    let access = match args.inbox {
        Some(inbox) => Access::Inbox(find_inbox(&store, &inbox)?),
        None => Access::Admin,
    };
    mcp::serve_stdio(
        Mcp::new(std::sync::Arc::new(store), 25 * 1024 * 1024),
        access,
    )
    .await
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// What an application needs to deliver into an inbox, shown with a new key.
fn print_key(inbox: &str, key: &str) {
    println!("API key, shown this once:\n\n  {key}\n");
    println!("SMTP   username  {inbox}");
    println!("       password  the key");
    println!("API    Authorization: Bearer <the key>");
}

/// The id of the inbox a person named by id or by name.
fn find_inbox(store: &emailulator::store::Store, text: &str) -> Result<String> {
    store.resolve_inbox(text)?.ok_or_else(|| {
        anyhow!("there is no inbox with the id or name `{text}`; see `emailulator inbox list`")
    })
}

fn inbox_command(command: InboxCommand) -> Result<()> {
    match command {
        InboxCommand::List(output) => {
            let inboxes = local_store(&output.store)?.inboxes()?;
            if output.json {
                return print_json(&inboxes);
            }
            let ids = inboxes.iter().map(|i| i.id.len()).max().unwrap_or(2).max(2);
            let names = inboxes
                .iter()
                .map(|i| i.name.chars().count())
                .max()
                .unwrap_or(4)
                .max(4);
            println!(
                "{:<ids$}  {:<names$}  {:>8}  {:>6}  {:>4}",
                "ID", "NAME", "MESSAGES", "UNREAD", "KEYS"
            );
            for inbox in &inboxes {
                println!(
                    "{:<ids$}  {:<names$}  {:>8}  {:>6}  {:>4}",
                    inbox.id, inbox.name, inbox.total, inbox.unread, inbox.keys
                );
            }
            println!(
                "\nCreate one with `emailulator inbox create <name>`. For scripts: add --json."
            );
            Ok(())
        }
        InboxCommand::Create {
            name,
            description,
            output,
        } => {
            let (inbox, key) =
                local_store(&output.store)?.create_inbox_named(emailulator::store::NewInbox {
                    name,
                    description,
                    ..Default::default()
                })?;
            if output.json {
                let mut value = serde_json::to_value(&inbox)?;
                value["key"] = serde_json::json!(key);
                return print_json(&value);
            }
            println!(
                "Created inbox \"{}\" with the id {}.\n",
                inbox.name, inbox.id
            );
            print_key(&inbox.id, &key);
            Ok(())
        }
        InboxCommand::Delete { inbox, store } => {
            let store = local_store(&store)?;
            let id = find_inbox(&store, &inbox)?;
            store.delete_inbox(&id)?;
            println!("Deleted inbox {id} with its messages and keys.");
            Ok(())
        }
    }
}

fn key_command(command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::List { inbox, output } => {
            let store = local_store(&output.store)?;
            let inbox = inbox.map(|text| find_inbox(&store, &text)).transpose()?;
            let keys = store.keys(inbox.as_deref())?;
            if output.json {
                return print_json(&keys);
            }
            if keys.is_empty() {
                println!("No keys yet. Create one with `emailulator key create <inbox>`.");
                return Ok(());
            }
            let width = keys.iter().map(|k| k.inbox.len()).max().unwrap_or(5).max(5);
            println!(
                "{:>4}  {:<width$}  {:<12}  {:<9}  LABEL",
                "ID", "INBOX", "KEY", "LAST USED"
            );
            for key in &keys {
                let used = if key.last_used_at.is_some() {
                    "yes"
                } else {
                    "never"
                };
                println!(
                    "{:>4}  {:<width$}  {:<12}  {:<9}  {}",
                    key.id,
                    key.inbox,
                    format!("{}…", key.prefix),
                    used,
                    key.label
                );
            }
            for key in &keys {
                if let Some(value) = &key.key {
                    println!(
                        "\nThe {} inbox's starter key: {value}\n\
                         It is kept readable so it can be shown here. Before an application \
                         outside this machine uses it, replace it with one that is kept only \
                         as a hash: `emailulator key regenerate {}`.",
                        key.inbox, key.id
                    );
                }
            }
            println!("\nRevoke one with `emailulator key revoke <id>`. For scripts: add --json.");
            Ok(())
        }
        KeyCommand::Create {
            inbox,
            label,
            output,
        } => {
            let store = local_store(&output.store)?;
            let inbox = find_inbox(&store, &inbox)?;
            let (record, key) = store.create_key(&inbox, &label)?;
            if output.json {
                let mut value = serde_json::to_value(&record)?;
                value["key"] = serde_json::json!(key);
                return print_json(&value);
            }
            print_key(&inbox, &key);
            Ok(())
        }
        KeyCommand::Regenerate { id, output } => {
            let Some((record, key)) = local_store(&output.store)?.regenerate_key(id, None)? else {
                bail!("there is no key with id {id}; see `emailulator key list`");
            };
            if output.json {
                let mut value = serde_json::to_value(&record)?;
                value["key"] = serde_json::json!(key);
                return print_json(&value);
            }
            println!("Key {id} regenerated. Its old value is now refused.\n");
            print_key(&record.inbox, &key);
            Ok(())
        }
        KeyCommand::Revoke { id, store } => {
            if !local_store(&store)?.revoke_key(id, None)? {
                bail!("there is no key with id {id}; see `emailulator key list`");
            }
            println!("Revoked key {id}. Anything still using it is now refused.");
            Ok(())
        }
    }
}

/// Open the desktop app, which is compiled into this binary when it is built
/// with the `desktop` feature on macOS or Windows.
#[cfg(all(feature = "desktop", any(target_os = "macos", target_os = "windows")))]
fn open_app(args: AppArgs) -> Result<()> {
    if args.foreground {
        desktop::run(desktop::Options {
            smtp_addr: args.smtp_addr,
            http_addr: args.http_addr,
            data_dir: args.store.data_dir,
        });
        return Ok(());
    }

    // Start the app as its own process and hand the terminal back, the way
    // opening any other application does.
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("finding this program in order to open the app")?;
    let mut command = Command::new(&exe);
    command.args(["app", "--foreground"]);
    if let Some(addr) = args.smtp_addr {
        command.arg("--smtp-addr").arg(addr.to_string());
    }
    if let Some(addr) = args.http_addr {
        command.arg("--http-addr").arg(addr.to_string());
    }
    if let Some(dir) = &args.store.data_dir {
        command.arg("--data-dir").arg(dir);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        // Its own process group, so closing this terminal does not take the
        // app down with it.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    Ok(())
}

#[cfg(not(all(feature = "desktop", any(target_os = "macos", target_os = "windows"))))]
fn open_app(_args: AppArgs) -> Result<()> {
    bail!(
        "this build of emailulator has no desktop app: it is the server-only build, which is \
         what runs on Linux and in containers.\nUse the web UI from `emailulator run`, or build \
         with the app from a checkout: cargo build --release --features desktop"
    )
}

/// A wildcard listen address is not one a client can connect to.
fn reachable(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

async fn healthcheck(args: HealthArgs) -> Result<()> {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let check = async {
        let smtp = reachable(args.smtp_addr);
        let mut stream = TcpStream::connect(smtp)
            .await
            .with_context(|| format!("SMTP is not answering on {smtp}"))?;
        let mut greeting = [0u8; 3];
        stream
            .read_exact(&mut greeting)
            .await
            .context("SMTP sent no greeting")?;
        if &greeting != b"220" {
            bail!("SMTP on {smtp} greeted with something other than 220");
        }
        let http = reachable(args.http_addr);
        TcpStream::connect(http)
            .await
            .with_context(|| format!("HTTP is not answering on {http}"))?;
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), check)
        .await
        .map_err(|_| anyhow!("the server did not answer within 5 seconds"))?
}

async fn run(command: Command) -> Result<()> {
    match command {
        Command::Run(args) => serve(*args).await,
        Command::App(args) => open_app(args),
        Command::Inbox(command) => inbox_command(command),
        Command::Key(command) => key_command(command),
        Command::Mcp(args) => mcp_stdio(args).await,
        Command::Token => {
            println!("{}", security::generate_token());
            Ok(())
        }
        Command::Healthcheck(args) => healthcheck(args).await,
        Command::Version => {
            println!("emailulator {VERSION}");
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        // The app needs the main thread for its window, and runs the servers
        // on a runtime of its own.
        Command::App(args) => open_app(args),
        command => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("starting the async runtime")
            .and_then(|runtime| runtime.block_on(run(command))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_with_and_without_suffixes() {
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("25MB"), Ok(25 << 20));
        assert_eq!(parse_size("1gb"), Ok(1 << 30));
        assert_eq!(parse_size("64 k"), Ok(64 << 10));
        assert_eq!(parse_size("0"), Ok(0));
        assert!(parse_size("lots").is_err());
        assert!(parse_size("-1").is_err());
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
