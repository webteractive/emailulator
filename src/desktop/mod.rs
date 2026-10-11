//! The desktop app behind `emailulator app`: the web UI in a window of its
//! own. It runs the same SMTP and HTTP servers as `emailulator run` inside the
//! app, bound to this machine only, and shows what the HTTP server serves in
//! the system webview, so the app and the browser are one interface.
//!
//! Compiled in with the `desktop` feature, for macOS and Windows. It is left
//! out of the Linux server build because the webview links the windowing
//! system, and a binary that does so cannot start on a headless host that
//! lacks those libraries.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use emailulator::{Config, Emailulator, default_data_dir};
use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::WindowBuilder;
use wry::{NewWindowResponse, PageLoadEvent, WebView, WebViewBuilder};

/// Where the app's own servers listen and keep their mail. Anything left
/// unset takes the same default as `emailulator run`.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub smtp_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub data_dir: Option<PathBuf>,
}

/// Ports to fall back to, in order, when the usual pair is taken: by another
/// mail catcher, most often. They are fixed rather than picked by the system,
/// so that an application configured for one of them still finds the app there
/// the next time it starts.
const FALLBACK_PORTS: &[(u16, u16)] = &[(1026, 8026), (2525, 8525), (2526, 8526)];

/// How long the self-test waits for the web UI to show a message.
const SELFTEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The configurations to try, first to last. Addresses the user asked for are
/// used as given or not at all; only the defaults fall back.
fn candidates(options: Options) -> Vec<Config> {
    let defaults = Config::default();
    let base = Config {
        data_dir: Some(options.data_dir.unwrap_or_else(default_data_dir)),
        ..defaults.clone()
    };
    let chosen = options.smtp_addr.is_some() || options.http_addr.is_some();
    let mut configs = vec![Config {
        smtp_addr: options.smtp_addr.unwrap_or(defaults.smtp_addr),
        http_addr: options.http_addr.unwrap_or(defaults.http_addr),
        ..base.clone()
    }];
    if !chosen {
        configs.extend(FALLBACK_PORTS.iter().map(|(smtp, http)| Config {
            smtp_addr: SocketAddr::new(defaults.smtp_addr.ip(), *smtp),
            http_addr: SocketAddr::new(defaults.http_addr.ip(), *http),
            ..base.clone()
        }));
    }
    configs
}

/// Start the servers on their own thread and runtime; the window owns the main
/// one. Returns the address the HTTP server answers on.
fn start(options: Options) -> anyhow::Result<SocketAddr> {
    let candidates = candidates(options);
    let (ready, started) = mpsc::channel();
    std::thread::Builder::new()
        .name("emailulator-server".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(anyhow::Error::from(error)));
                    return;
                }
            };
            runtime.block_on(async move {
                // The first failure is the one worth reporting: it is about the
                // ports the user expects.
                let mut first_error = None;
                for config in candidates {
                    match Emailulator::bind(config).await {
                        Ok(server) => {
                            let _ = ready.send(Ok(server.http_addr()));
                            if let Err(error) = server.serve().await {
                                eprintln!("emailulator: the server stopped: {error:#}");
                            }
                            return;
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                let error = first_error.unwrap_or_else(|| anyhow::anyhow!("nothing to bind"));
                let _ = ready.send(Err(error));
            });
        })?;
    started
        .recv()
        .unwrap_or_else(|_| Err(anyhow::anyhow!("the server thread exited")))
}

/// Whether a link may be handed to the system to open.
fn openable(url: &str) -> bool {
    // `get`, not indexing: a link is untrusted, and slicing through a
    // multi-byte character would panic.
    ["http://", "https://", "mailto:"].iter().any(|scheme| {
        url.len() > scheme.len()
            && url
                .get(..scheme.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
    })
}

/// Open a link in the user's browser or mail client.
fn open_externally(url: &str) {
    if !openable(url) {
        return;
    }
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(url).spawn();
    // Through the URL protocol handler rather than `cmd /c start`, which would
    // read the URL's `&` as a command separator.
    #[cfg(target_os = "windows")]
    let spawned = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    if let Err(error) = spawned {
        eprintln!("emailulator: could not open {url}: {error}");
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The page shown when the servers could not start, so there is no web UI to
/// load. It names the reason and the way out.
fn failure_page(reason: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <style>\
         :root{{color-scheme:light dark}}\
         body{{margin:0;display:grid;place-items:center;min-height:100vh;\
         font:14px/1.5 system-ui,-apple-system,sans-serif}}\
         main{{max-width:520px;padding:24px}}\
         h1{{font-size:17px;margin:0 0 8px}}\
         code{{font:12.5px ui-monospace,Menlo,monospace}}\
         </style>\
         <main><h1>emailulator could not start its mail servers</h1>\
         <p>{}</p>\
         <p>Another emailulator may already be using every port it tries. Quit it, \
         or open this one with <code>--smtp-addr</code> and <code>--http-addr</code>.</p></main>",
        escape(reason)
    )
}

/// Run in the page once it has loaded, with `EMAILULATOR_APP_SELFTEST` set:
/// deliver a message through the API and wait for the web UI to show it.
const SELFTEST_SCRIPT: &str = r#"(async () => {
  const wait = async (test, what) => {
    for (let i = 0; i < 200; i++) {
      const found = test();
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`timed out waiting for ${what}`);
  };
  try {
    await wait(() => document.querySelector('.brand'), 'the web UI');
    const response = await fetch('/api/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'selftest@example.test',
        to: ['you@example.test'],
        subject: 'Self-test',
        text: 'Plain body',
        html: '<p>HTML body</p>',
      }),
    });
    if (!response.ok) throw new Error(`delivering a message: HTTP ${response.status}`);
    const { id } = await response.json();
    location.hash = `#/all/${id}`;
    await wait(() => document.querySelector(`iframe[src$="/messages/${id}/html"]`), 'the message view');
    window.ipc.postMessage('ok');
  } catch (error) {
    window.ipc.postMessage(`failed: ${error.message}`);
  }
})();"#;

/// Give the Dock the app's icon. The app is one bare binary, with no bundle to
/// carry an icon, so the image is compiled in and handed to AppKit at launch.
#[cfg(target_os = "macos")]
fn set_dock_icon() {
    use objc2::rc::{Allocated, Retained};
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};

    const ICON: &[u8] = include_bytes!("../../assets/app-icon.png");

    // SAFETY: called on the main thread, once the event loop has created
    // NSApplication. Each message is sent to the class that declares it, with
    // the argument and return types its signature gives, and
    // `dataWithBytes:length:` copies the bytes before it returns.
    unsafe {
        let data: Retained<AnyObject> = msg_send![
            class!(NSData),
            dataWithBytes: ICON.as_ptr().cast::<std::ffi::c_void>(),
            length: ICON.len(),
        ];
        let image: Allocated<AnyObject> = msg_send![class!(NSImage), alloc];
        let image: Option<Retained<AnyObject>> = msg_send![image, initWithData: &*data];
        let Some(image) = image else { return };
        let app: Retained<AnyObject> = msg_send![class!(NSApplication), sharedApplication];
        let _: () = msg_send![&*app, setApplicationIconImage: &*image];
    }
}

enum UserEvent {
    Menu(MenuEvent),
    OpenUrl(String),
    PageLoaded,
    SelfTest(String),
}

/// The menu bar, and the ids of the items the app handles itself. The Edit
/// items are the system's own: they are what makes copy and paste reach the
/// webview, which has no shortcuts of its own.
struct Menus {
    bar: Menu,
    open_in_browser: MenuItem,
    reload: MenuItem,
    quit: MenuItem,
}

fn menus() -> anyhow::Result<Menus> {
    let accelerator = |keys: &str| keys.parse().ok();
    let open_in_browser = MenuItem::new("Open in Browser", true, accelerator("CmdOrCtrl+Shift+O"));
    let reload = MenuItem::new("Reload", true, accelerator("CmdOrCtrl+R"));
    let quit = MenuItem::new("Quit emailulator", true, accelerator("CmdOrCtrl+Q"));

    let bar = Menu::new();
    #[cfg(target_os = "macos")]
    bar.append(&Submenu::with_items(
        "emailulator",
        true,
        &[
            &open_in_browser,
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::hide(None),
            &PredefinedMenuItem::hide_others(None),
            &PredefinedMenuItem::show_all(None),
            &PredefinedMenuItem::separator(),
            &quit,
        ],
    )?)?;
    #[cfg(not(target_os = "macos"))]
    bar.append(&Submenu::with_items(
        "File",
        true,
        &[&open_in_browser, &PredefinedMenuItem::separator(), &quit],
    )?)?;
    bar.append(&Submenu::with_items(
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(None),
            &PredefinedMenuItem::redo(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::select_all(None),
        ],
    )?)?;
    bar.append(&Submenu::with_items("View", true, &[&reload])?)?;
    #[cfg(target_os = "macos")]
    bar.append(&Submenu::with_items(
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(None),
            &PredefinedMenuItem::fullscreen(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::close_window(None),
        ],
    )?)?;
    Ok(Menus {
        bar,
        open_in_browser,
        reload,
        quit,
    })
}

fn webview(
    window: &tao::window::Window,
    started: &anyhow::Result<SocketAddr>,
    proxy: &EventLoopProxy<UserEvent>,
    selftest: bool,
) -> anyhow::Result<WebView> {
    let mut builder = WebViewBuilder::new()
        .with_devtools(cfg!(debug_assertions))
        // Saving an attachment or a message is a download: it lands in
        // Downloads, under a name that never overwrites a file.
        .with_download_started_handler(|_url, _destination| true);

    let addr = match started {
        Ok(addr) => *addr,
        Err(error) => {
            return Ok(builder
                .with_html(failure_page(&format!("{error:#}")))
                .build(window)?);
        }
    };
    let origin = format!("http://{addr}/");

    // The web UI may load only its own pages. That holds for the frame an
    // email is shown in too, so a meta refresh in an email goes nowhere.
    let allowed = origin.clone();
    builder = builder
        .with_url(&origin)
        .with_navigation_handler(move |url| url.starts_with(&allowed) || url == "about:blank")
        // Links in an email carry target=_blank, as do the web UI's links out.
        // A new window is never opened here; the link goes to the browser.
        .with_new_window_req_handler({
            let proxy = proxy.clone();
            move |url, _features| {
                let _ = proxy.send_event(UserEvent::OpenUrl(url));
                NewWindowResponse::Deny
            }
        });

    if selftest {
        let loaded = proxy.clone();
        let reported = proxy.clone();
        builder = builder
            .with_on_page_load_handler(move |event, _url| {
                if matches!(event, PageLoadEvent::Finished) {
                    let _ = loaded.send_event(UserEvent::PageLoaded);
                }
            })
            .with_ipc_handler(move |request| {
                if request.uri().to_string().starts_with(&origin) {
                    let _ = reported.send_event(UserEvent::SelfTest(request.into_body()));
                }
            });
    }
    Ok(builder.build(window)?)
}

/// Run the app. Must be called on the main thread, which it keeps until the
/// window closes.
pub fn run(options: Options) {
    let started = start(options);
    let selftest = std::env::var_os("EMAILULATOR_APP_SELFTEST").is_some();

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some({
        let proxy = proxy.clone();
        move |event| {
            let _ = proxy.send_event(UserEvent::Menu(event));
        }
    }));

    let window = match WindowBuilder::new()
        .with_title("emailulator")
        .with_inner_size(LogicalSize::new(1240.0, 780.0))
        .with_min_inner_size(LogicalSize::new(900.0, 520.0))
        .build(&event_loop)
    {
        Ok(window) => window,
        Err(error) => {
            eprintln!("emailulator: could not open the window: {error}");
            std::process::exit(1);
        }
    };
    let webview = match webview(&window, &started, &proxy, selftest) {
        Ok(webview) => webview,
        Err(error) => {
            eprintln!("emailulator: could not create the webview: {error:#}");
            std::process::exit(1);
        }
    };
    let menus = match menus() {
        Ok(menus) => Some(menus),
        Err(error) => {
            eprintln!("emailulator: could not build the menu bar: {error:#}");
            None
        }
    };
    #[cfg(target_os = "windows")]
    if let Some(menus) = &menus {
        use tao::platform::windows::WindowExtWindows;
        // SAFETY: the handle is this live window's, and the menu bar is kept
        // for as long as the window by the event loop closure below.
        if let Err(error) = unsafe { menus.bar.init_for_hwnd(window.hwnd() as isize) } {
            eprintln!("emailulator: could not attach the menu bar: {error}");
        }
    }
    let web_ui = started.as_ref().ok().map(|addr| format!("http://{addr}/"));
    let deadline = Instant::now() + SELFTEST_TIMEOUT;
    if selftest && let Err(error) = &started {
        eprintln!("emailulator: self-test failed: {error:#}");
        std::process::exit(1);
    }

    event_loop.run(move |event, _, control_flow| {
        // Kept alive by the closure, which lives as long as the app.
        let _ = &window;
        *control_flow = if selftest {
            ControlFlow::WaitUntil(deadline)
        } else {
            ControlFlow::Wait
        };

        match event {
            Event::NewEvents(StartCause::Init) => {
                #[cfg(target_os = "macos")]
                {
                    set_dock_icon();
                    if let Some(menus) = &menus {
                        menus.bar.init_for_nsapp();
                    }
                }
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) if selftest => {
                eprintln!("emailulator: self-test failed: no answer within {SELFTEST_TIMEOUT:?}");
                std::process::exit(1);
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            Event::UserEvent(UserEvent::OpenUrl(url)) => open_externally(&url),
            Event::UserEvent(UserEvent::PageLoaded) => {
                if let Err(error) = webview.evaluate_script(SELFTEST_SCRIPT) {
                    eprintln!("emailulator: self-test failed: {error}");
                    std::process::exit(1);
                }
            }
            Event::UserEvent(UserEvent::SelfTest(outcome)) => {
                if outcome == "ok" {
                    println!("emailulator: self-test passed");
                    std::process::exit(0);
                }
                eprintln!("emailulator: self-test {outcome}");
                std::process::exit(1);
            }
            Event::UserEvent(UserEvent::Menu(event)) => {
                let Some(menus) = &menus else { return };
                if event.id() == menus.quit.id() {
                    *control_flow = ControlFlow::Exit;
                } else if event.id() == menus.reload.id() {
                    let _ = webview.reload();
                } else if event.id() == menus.open_in_browser.id()
                    && let Some(url) = &web_ui
                {
                    open_externally(url);
                }
            }
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_and_mail_links_open() {
        assert!(openable("https://example.test/"));
        assert!(openable("HTTP://example.test/"));
        assert!(openable("mailto:a@example.test"));
        assert!(!openable("https://"));
        assert!(!openable("file:///etc/passwd"));
        assert!(!openable("javascript:alert(1)"));
        assert!(!openable("-a Calculator"));
        // A multi-byte character across the scheme's length is not a panic.
        assert!(!openable("ht€ps://example.test/"));
    }

    #[test]
    fn the_failure_page_escapes_the_reason() {
        let page = failure_page("<script>alert(1)</script> & more");
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more"));
        assert!(!page.contains("<script>"));
    }

    #[test]
    fn only_default_addresses_fall_back() {
        assert_eq!(
            candidates(Options::default()).len(),
            1 + FALLBACK_PORTS.len()
        );
        let chosen = Options {
            http_addr: Some("127.0.0.1:9000".parse().unwrap()),
            ..Options::default()
        };
        assert_eq!(candidates(chosen).len(), 1);
    }
}
