//! `emailulator service`: `emailulator run` as a macOS LaunchAgent, so the
//! servers are up from login onwards with nothing left open, and come back
//! whenever they stop. That includes `self-update --restart`, which stops the
//! server for its supervisor to start the new binary.
//!
//! While the agent runs it is the one server on this Mac: `emailulator app`
//! opens its window on the agent's web UI instead of starting servers of its
//! own, and `emailulator run` refuses to start a second one.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;

/// The agent's launchd label, the identifier the release is signed with.
pub const LABEL: &str = "com.webteractive.emailulator";

/// Set in the agent's environment, so that the `run` it starts knows it is
/// the agent and does not refuse to start because the agent is running.
const MARKER: &str = "EMAILULATOR_SERVICE";

const DEFAULT_SMTP: &str = "127.0.0.1:1025";
const DEFAULT_HTTP: &str = "127.0.0.1:8025";

/// How long `install` waits for a new agent to answer.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// Exit codes of `service status`, for scripts.
const STATUS_NOT_RUNNING: u8 = 3;
const STATUS_NOT_INSTALLED: u8 = 4;

/// `run` options `install` will not write into the agent: their values are
/// secrets, and an argument is visible to every user of the machine in the
/// process list.
const SECRET_OPTIONS: &[(&str, &str)] = &[
    (
        "--auth-token",
        "use --auth-token-file with a file only you can read",
    ),
    (
        "--provision",
        "keys made with `emailulator key create` are kept in the message store, so the agent needs none",
    ),
];

/// A wildcard listen address is not one a client can connect to.
pub fn reachable(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

/// Whether this process was started by the agent.
pub fn is_the_agent() -> bool {
    std::env::var(MARKER).is_ok_and(|label| label == LABEL)
}

/// The installed agent, as launchd reports it and as its plist starts it.
#[derive(Debug, Clone, Serialize)]
pub struct Agent {
    pub plist: PathBuf,
    pub log: PathBuf,
    /// What launchd runs: this binary, `run` and its options.
    pub program: Vec<String>,
    pub smtp_addr: SocketAddr,
    pub http_addr: SocketAddr,
    /// Whether the agent serves HTTPS, given a certificate.
    pub tls: bool,
    /// Whether launchd has the agent loaded at all.
    pub loaded: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub last_exit_code: Option<String>,
}

impl Agent {
    /// The address of its web UI.
    pub fn origin(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}/", reachable(self.http_addr))
    }

    /// Whether both of its servers answer, within `wait`.
    pub fn answers(&self, wait: Duration) -> bool {
        answering(self.smtp_addr, self.http_addr, wait)
    }
}

/// The agent, if one is installed. Never anything off macOS.
pub fn installed() -> Result<Option<Agent>> {
    if !cfg!(target_os = "macos") {
        return Ok(None);
    }
    let paths = paths()?;
    if !paths.plist.exists() {
        return Ok(None);
    }
    let program = read_program(&paths.plist)?;
    let args = program.get(2..).unwrap_or_default();
    let (smtp_addr, http_addr) = addresses(args)?;
    let launchd = launchctl_print()?;
    Ok(Some(Agent {
        plist: paths.plist,
        log: paths.log,
        tls: flag_value(args, "--tls-cert").is_some(),
        program,
        smtp_addr,
        http_addr,
        loaded: launchd.is_some(),
        running: launchd.as_ref().is_some_and(|l| l.state == "running"),
        pid: launchd.as_ref().and_then(|l| l.pid),
        last_exit_code: launchd.and_then(|l| l.last_exit_code),
    }))
}

/// The agent, if launchd has it running. A failure to ask counts as no:
/// `run` and the app then behave as they would with no agent at all.
pub fn running() -> Option<Agent> {
    installed().ok().flatten().filter(|agent| agent.running)
}

/// The running agent, once it answers within `wait`: what the app opens its
/// window on instead of starting servers of its own.
#[cfg(all(feature = "desktop", any(target_os = "macos", target_os = "windows")))]
pub fn serving(wait: Duration) -> Option<Agent> {
    running().filter(|agent| agent.answers(wait))
}

/// Refuse to start a server while the agent runs one, unless this is it.
pub fn refuse_a_second_server() -> Result<()> {
    if is_the_agent() {
        return Ok(());
    }
    let Some(agent) = running() else {
        return Ok(());
    };
    let pid = agent
        .pid
        .map(|pid| format!(" (pid {pid})"))
        .unwrap_or_default();
    bail!(
        "emailulator is already running as a LaunchAgent{pid}, SMTP {}, HTTP {}\n\
         Stop it with `emailulator service uninstall`, or see `emailulator service status`.",
        agent.smtp_addr,
        agent.origin().trim_end_matches('/'),
    )
}

/// Install the agent and start it. `run` holds the options for
/// `emailulator run`, already checked by the caller to parse as they would
/// there.
pub fn install(run: &[String]) -> Result<()> {
    macos_only()?;
    refuse_secrets(run)?;
    let (smtp_addr, http_addr) = addresses(run)?;
    let exe = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .context("finding this program for the agent to run")?;
    let paths = paths()?;

    // A reinstall replaces the agent, so take the old one down first, and
    // wait for its ports to be free before checking whether anything else
    // holds them.
    if launchctl_print()?.is_some() {
        bootout()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while listening(smtp_addr).or(listening(http_addr)).is_some() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    if let Some(addr) = listening(smtp_addr).or(listening(http_addr)) {
        bail!(
            "something is already listening on {addr}: the desktop app, an `emailulator run` or \
             another mail catcher. Quit it and install again, or give the agent other ports: \
             emailulator service install -- --smtp-addr 127.0.0.1:2525 --http-addr 127.0.0.1:8525"
        );
    }

    let program = program_arguments(&exe, run);
    let plist = render_plist(&program, &paths.log);
    for dir in [paths.plist.parent(), paths.log.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    write_private(&paths.plist, &plist)?;
    launchctl(&["bootstrap", &domain()?, &paths.plist.display().to_string()])?;

    println!("Installed the LaunchAgent {LABEL}.");
    println!("  Runs     {}", program.join(" "));
    println!("  Plist    {}", paths.plist.display());
    println!("  Log      {}", paths.log.display());
    if exe.components().any(|part| part.as_os_str() == "target") {
        println!(
            "\nThis is a build from a checkout, and the agent runs it from there. Install a \
             release to have it run that instead."
        );
    }
    let carried_over: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("EMAILULATOR_") && name != MARKER)
        .collect();
    if !carried_over.is_empty() {
        println!(
            "\nNot carried over: {}. launchd does not see this shell's environment, so pass \
             what the agent needs as options after `--`.",
            carried_over.join(", ")
        );
    }

    let agent = Agent {
        plist: paths.plist,
        log: paths.log.clone(),
        tls: flag_value(run, "--tls-cert").is_some(),
        program,
        smtp_addr,
        http_addr,
        loaded: true,
        running: true,
        pid: None,
        last_exit_code: None,
    };
    if !agent.answers(START_TIMEOUT) {
        let tail = log_tail(&paths.log, 20);
        bail!(
            "the agent did not answer within {} seconds. The end of its log:\n\n{tail}\n\
             See `emailulator service status`; remove it with `emailulator service uninstall`.",
            START_TIMEOUT.as_secs()
        );
    }
    println!(
        "\nRunning: SMTP {}, web UI {}",
        agent.smtp_addr,
        agent.origin()
    );
    if other_apps_open() {
        println!(
            "An emailulator app is open. If it started servers of its own, quit it and open it \
             again, and it will show this agent's mail."
        );
    }
    Ok(())
}

/// Stop the agent and remove it. Messages and logs stay.
pub fn uninstall() -> Result<()> {
    macos_only()?;
    let paths = paths()?;
    let loaded = launchctl_print()?.is_some();
    if !loaded && !paths.plist.exists() {
        println!("The LaunchAgent {LABEL} is not installed.");
        return Ok(());
    }
    if loaded {
        bootout()?;
    }
    if paths.plist.exists() {
        std::fs::remove_file(&paths.plist)
            .with_context(|| format!("removing {}", paths.plist.display()))?;
    }
    println!("Stopped and removed the LaunchAgent {LABEL}.");
    println!(
        "Messages stay in the message store, and the log in {}.",
        paths.log.display()
    );
    Ok(())
}

#[derive(Serialize)]
struct Status {
    label: &'static str,
    installed: bool,
    answering: bool,
    #[serde(flatten)]
    agent: Option<Agent>,
}

/// Report the agent. Exits 0 when it is running and answering, 3 when it is
/// installed but is not, and 4 when it is not installed.
pub fn status(json: bool) -> Result<ExitCode> {
    macos_only()?;
    let agent = installed()?;
    let answering = agent
        .as_ref()
        .is_some_and(|agent| agent.running && agent.answers(Duration::ZERO));
    let code = match &agent {
        None => STATUS_NOT_INSTALLED,
        Some(_) if !answering => STATUS_NOT_RUNNING,
        Some(_) => 0,
    };
    if json {
        let status = Status {
            label: LABEL,
            installed: agent.is_some(),
            answering,
            agent,
        };
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(ExitCode::from(code));
    }

    let Some(agent) = agent else {
        println!("The LaunchAgent {LABEL} is not installed.");
        println!("Install it with `emailulator service install`. For scripts: add --json.");
        return Ok(ExitCode::from(code));
    };
    let state = match (agent.loaded, agent.running, agent.pid) {
        (false, _, _) => "installed, but not loaded by launchd".to_string(),
        (true, true, Some(pid)) => format!("running, pid {pid}"),
        (true, true, None) => "running".to_string(),
        (true, false, _) => match &agent.last_exit_code {
            Some(code) => format!("not running; last exit code {code}"),
            None => "not running".to_string(),
        },
    };
    let answer = if answering {
        "answering"
    } else {
        "not answering"
    };
    println!("LaunchAgent  {LABEL}");
    println!("  State      {state}");
    println!("  SMTP       {}  ({answer})", agent.smtp_addr);
    println!("  Web UI     {}", agent.origin());
    println!("  Runs       {}", agent.program.join(" "));
    println!("  Plist      {}", agent.plist.display());
    println!("  Log        {}", agent.log.display());
    if !answering {
        println!("\nThe end of its log:\n\n{}", log_tail(&agent.log, 10));
    }
    println!("\nFor scripts: emailulator service status --json");
    Ok(ExitCode::from(code))
}

// ---------------------------------------------------------------------------
// The plist
// ---------------------------------------------------------------------------

struct Paths {
    plist: PathBuf,
    log: PathBuf,
}

fn paths() -> Result<Paths> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("finding your home directory"))?;
    Ok(Paths {
        plist: home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")),
        log: home.join("Library/Logs/emailulator/server.log"),
    })
}

fn macos_only() -> Result<()> {
    if cfg!(target_os = "macos") {
        return Ok(());
    }
    bail!(
        "`emailulator service` installs a macOS LaunchAgent. Elsewhere, run `emailulator run` \
         under your service manager, such as systemd or a Forge daemon."
    )
}

/// Refuse options whose values are secrets.
fn refuse_secrets(args: &[String]) -> Result<()> {
    for (option, instead) in SECRET_OPTIONS {
        if flag_value(args, option).is_some() {
            bail!(
                "the agent's options are visible to every user of this Mac in the process \
                 list, so it will not be given {option}: {instead}"
            );
        }
    }
    Ok(())
}

/// The value given for an option, as `--option value` or `--option=value`.
fn flag_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == option {
            return Some(args.next().map_or("", String::as_str));
        }
        if let Some(value) = arg
            .strip_prefix(option)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}

/// The SMTP and HTTP addresses `run` would listen on with these options.
fn addresses(args: &[String]) -> Result<(SocketAddr, SocketAddr)> {
    let addr = |option: &str, default: &str| -> Result<SocketAddr> {
        let value = flag_value(args, option).unwrap_or(default);
        value
            .parse()
            .map_err(|_| anyhow!("{option} `{value}` is not an address such as {default}"))
    };
    Ok((
        addr("--smtp-addr", DEFAULT_SMTP)?,
        addr("--http-addr", DEFAULT_HTTP)?,
    ))
}

/// What launchd runs: this binary's `run`, with both addresses spelled out so
/// that the app and `status` read them from the plist rather than guess.
fn program_arguments(exe: &Path, run: &[String]) -> Vec<String> {
    let mut program = vec![exe.display().to_string(), "run".to_string()];
    for (option, default) in [("--smtp-addr", DEFAULT_SMTP), ("--http-addr", DEFAULT_HTTP)] {
        if flag_value(run, option).is_none() {
            program.extend([option.to_string(), default.to_string()]);
        }
    }
    program.extend(run.iter().cloned());
    program
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_plist(program: &[String], log: &Path) -> String {
    let string = |value: &str| format!("<string>{}</string>", xml_escape(value));
    let arguments: String = program
        .iter()
        .map(|arg| format!("\n\t\t{}", string(arg)))
        .collect();
    let log = string(&log.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	{label}
	<key>ProgramArguments</key>
	<array>{arguments}
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>{MARKER}</key>
		{label}
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	{log}
	<key>StandardErrorPath</key>
	{log}
</dict>
</plist>
"#,
        label = string(LABEL),
    )
}

/// Write a file only its owner can read.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        // An existing file keeps its mode through `open`, so set it as well.
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("setting the mode of {}", path.display()))?;
        }
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))
}

/// The installed plist's ProgramArguments.
fn read_program(plist: &Path) -> Result<Vec<String>> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", "ProgramArguments", "json", "-o", "-"])
        .arg(plist)
        .output()
        .context("running plutil")?;
    if !output.status.success() {
        bail!(
            "reading {}: {}",
            plist.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("reading the program {} runs", plist.display()))
}

fn log_tail(log: &Path, lines: usize) -> String {
    match std::fs::read_to_string(log) {
        Ok(text) if !text.trim().is_empty() => {
            let all: Vec<&str> = text.lines().collect();
            all[all.len().saturating_sub(lines)..].join("\n")
        }
        Ok(_) => "(the log is empty)".to_string(),
        Err(_) => format!("(no log at {})", log.display()),
    }
}

// ---------------------------------------------------------------------------
// launchd
// ---------------------------------------------------------------------------

/// The user's GUI domain, where LaunchAgents run.
fn domain() -> Result<String> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .context("running id")?;
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid.is_empty() {
        bail!("finding your user id");
    }
    Ok(format!("gui/{uid}"))
}

fn launchctl(args: &[&str]) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("running launchctl")?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stderr);
        let said = if said.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout)
        } else {
            said
        };
        bail!("launchctl {} failed: {}", args.join(" "), said.trim());
    }
    Ok(())
}

fn bootout() -> Result<()> {
    launchctl(&["bootout", &format!("{}/{LABEL}", domain()?)])
}

/// What `launchctl print` says of the agent.
#[derive(Debug, PartialEq, Eq)]
struct Launchd {
    state: String,
    pid: Option<u32>,
    last_exit_code: Option<String>,
}

/// The agent as launchd has it, or `None` when it is not loaded.
fn launchctl_print() -> Result<Option<Launchd>> {
    let output = Command::new("/bin/launchctl")
        .args(["print", &format!("{}/{LABEL}", domain()?)])
        .output()
        .context("running launchctl")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(parse_print(&String::from_utf8_lossy(&output.stdout))))
}

/// Read the service's own fields: those one tab in. Deeper ones, such as the
/// resource coalition's `state`, are about something else.
fn parse_print(output: &str) -> Launchd {
    let mut launchd = Launchd {
        state: String::new(),
        pid: None,
        last_exit_code: None,
    };
    for line in output.lines() {
        let Some(field) = line.strip_prefix('\t') else {
            continue;
        };
        if field.starts_with('\t') {
            continue;
        }
        let Some((name, value)) = field.split_once(" = ") else {
            continue;
        };
        let value = value.trim();
        match name {
            "state" => launchd.state = value.to_string(),
            "pid" => launchd.pid = value.parse().ok(),
            "last exit code" => launchd.last_exit_code = Some(value.to_string()),
            _ => {}
        }
    }
    launchd
}

/// Another `emailulator app` window this user has open.
fn other_apps_open() -> bool {
    Command::new("/usr/bin/pgrep")
        .args(["-f", "(^|/)emailulator app --foreground"])
        .output()
        .is_ok_and(|output| output.status.success())
}

// ---------------------------------------------------------------------------
// Answering
// ---------------------------------------------------------------------------

/// The address, if something accepts connections on it.
fn listening(addr: SocketAddr) -> Option<SocketAddr> {
    TcpStream::connect_timeout(&reachable(addr), Duration::from_millis(300))
        .ok()
        .map(|_| addr)
}

/// Whether SMTP greets and HTTP accepts, trying until `wait` is up.
fn answering(smtp: SocketAddr, http: SocketAddr, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if greets(reachable(smtp)) && listening(http).is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn greets(smtp: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&smtp, Duration::from_millis(500)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).is_ok() && &greeting == b"220"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn options_are_found_in_both_spellings() {
        let given = args(&[
            "--http-addr",
            "127.0.0.1:9000",
            "--smtp-addr=127.0.0.1:2525",
        ]);
        assert_eq!(flag_value(&given, "--http-addr"), Some("127.0.0.1:9000"));
        assert_eq!(flag_value(&given, "--smtp-addr"), Some("127.0.0.1:2525"));
        assert_eq!(flag_value(&given, "--tls-cert"), None);
        // A longer option that starts the same way is another option.
        assert_eq!(flag_value(&args(&["--http-addrs=x"]), "--http-addr"), None);
    }

    #[test]
    fn secrets_are_refused_in_both_spellings() {
        assert!(refuse_secrets(&args(&["--auth-token", "s3cret"])).is_err());
        assert!(refuse_secrets(&args(&["--auth-token=s3cret"])).is_err());
        assert!(refuse_secrets(&args(&["--provision", "app=key"])).is_err());
        assert!(refuse_secrets(&args(&["--auth-token-file", "/tmp/token"])).is_ok());
        assert!(refuse_secrets(&args(&["--max-messages", "5000"])).is_ok());
    }

    #[test]
    fn addresses_default_to_those_of_run() {
        let (smtp, http) = addresses(&[]).unwrap();
        assert_eq!(smtp, DEFAULT_SMTP.parse().unwrap());
        assert_eq!(http, DEFAULT_HTTP.parse().unwrap());
        let (smtp, http) = addresses(&args(&["--smtp-addr", "0.0.0.0:2525"])).unwrap();
        assert_eq!(smtp, "0.0.0.0:2525".parse().unwrap());
        assert_eq!(http, DEFAULT_HTTP.parse().unwrap());
        assert!(addresses(&args(&["--http-addr", "nowhere"])).is_err());
    }

    #[test]
    fn the_program_spells_out_both_addresses_once() {
        let exe = Path::new("/Users/me/.local/bin/emailulator");
        assert_eq!(
            program_arguments(exe, &args(&["--max-messages", "5000"])),
            args(&[
                "/Users/me/.local/bin/emailulator",
                "run",
                "--smtp-addr",
                DEFAULT_SMTP,
                "--http-addr",
                DEFAULT_HTTP,
                "--max-messages",
                "5000",
            ])
        );
        assert_eq!(
            program_arguments(exe, &args(&["--http-addr=127.0.0.1:9000"])),
            args(&[
                "/Users/me/.local/bin/emailulator",
                "run",
                "--smtp-addr",
                DEFAULT_SMTP,
                "--http-addr=127.0.0.1:9000",
            ])
        );
    }

    #[test]
    fn the_plist_escapes_what_it_holds() {
        let plist = render_plist(
            &args(&["/Apps/A&B <x>/emailulator", "run"]),
            Path::new("/Users/me/Library/Logs/emailulator/server.log"),
        );
        assert!(plist.contains("<string>/Apps/A&amp;B &lt;x&gt;/emailulator</string>"));
        assert!(!plist.contains("A&B"));
        assert!(plist.contains(&format!("<key>{MARKER}</key>")));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_plist_is_one_launchd_reads() {
        let dir = std::env::temp_dir().join(format!("emailulator-plist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.plist");
        let program = args(&[
            "/Apps/A&B/emailulator",
            "run",
            "--http-addr",
            "127.0.0.1:9000",
        ]);
        write_private(&path, &render_plist(&program, &dir.join("server.log"))).unwrap();
        let lint = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            lint.status.success(),
            "{}",
            String::from_utf8_lossy(&lint.stdout)
        );
        assert_eq!(read_program(&path).unwrap(), program);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn launchctl_print_is_read_at_the_service_level() {
        let output = "gui/502/com.webteractive.emailulator = {\n\
            \tactive count = 1\n\
            \tstate = running\n\
            \n\
            \tprogram = /Users/me/.local/bin/emailulator\n\
            \targuments = {\n\
            \t\t/Users/me/.local/bin/emailulator\n\
            \t}\n\
            \tpid = 4821\n\
            \tlast exit code = (never exited)\n\
            \tresource coalition = {\n\
            \t\tstate = active\n\
            \t}\n\
            }\n";
        assert_eq!(
            parse_print(output),
            Launchd {
                state: "running".to_string(),
                pid: Some(4821),
                last_exit_code: Some("(never exited)".to_string()),
            }
        );
    }

    #[test]
    fn the_origin_reaches_a_wildcard_address() {
        let agent = Agent {
            plist: PathBuf::new(),
            log: PathBuf::new(),
            program: Vec::new(),
            smtp_addr: "0.0.0.0:1025".parse().unwrap(),
            http_addr: "0.0.0.0:8025".parse().unwrap(),
            tls: false,
            loaded: true,
            running: true,
            pid: None,
            last_exit_code: None,
        };
        assert_eq!(agent.origin(), "http://127.0.0.1:8025/");
        assert_eq!(
            Agent { tls: true, ..agent }.origin(),
            "https://127.0.0.1:8025/"
        );
    }
}
