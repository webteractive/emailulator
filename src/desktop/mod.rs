//! The desktop app behind `emailulator app`: a native mail client for the mail
//! your app sends in development. It runs the same SMTP and HTTP servers as
//! `emailulator run` inside the app, bound to this machine only, and reads the
//! message store directly.
//!
//! Compiled in with the `desktop` feature. It is left out of the Linux server
//! build because gpui links against the windowing system, and a binary that
//! does so cannot start on a headless host that lacks those libraries.

mod body;
mod input;
mod mail;
mod theme;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;

use emailulator::store::{Limits, Store};
use emailulator::{Config, Emailulator, default_data_dir, open_store};
use gpui::{
    App, AppContext, Application, Bounds, Menu, MenuItem, OsAction, TitlebarOptions, WindowBounds,
    WindowOptions, px, size,
};

use self::mail::{Mail, ServerStatus};

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

/// Start the servers on their own thread and runtime; gpui owns the main one.
/// When they cannot start on any port, fall back to showing the store read-only.
fn start(options: Options) -> (Arc<Store>, ServerStatus) {
    let candidates = candidates(options);
    let data_dir = candidates[0]
        .data_dir
        .clone()
        .unwrap_or_else(default_data_dir);

    let (ready, started) = mpsc::channel();
    let spawned = std::thread::Builder::new()
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
                            let _ = ready.send(Ok((
                                server.store(),
                                server.smtp_addr(),
                                server.http_addr(),
                            )));
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
        });

    let outcome = match spawned {
        Ok(_) => started
            .recv()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the server thread exited"))),
        Err(error) => Err(anyhow::Error::from(error)),
    };
    match outcome {
        Ok((store, smtp, http)) => (store, ServerStatus::Running { smtp, http }),
        Err(error) => viewer_only(data_dir, format!("{error:#}")),
    }
}

fn viewer_only(data_dir: PathBuf, reason: String) -> (Arc<Store>, ServerStatus) {
    let (store, reason) = match open_store(Some(&data_dir), Limits::default()) {
        Ok(store) => (store, reason),
        // Nothing on disk is readable either; show an empty window that says why.
        Err(error) => (
            Store::in_memory().expect("an in-memory store needs nothing from the system"),
            format!("{reason}. The mail store could not be opened either: {error:#}"),
        ),
    };
    (Arc::new(store), ServerStatus::ViewerOnly { reason })
}

/// Give the Dock the app's icon. The app is one bare binary, with no bundle to
/// carry an icon, so the image is compiled in and handed to AppKit at launch.
#[cfg(target_os = "macos")]
fn set_dock_icon() {
    use objc2::rc::{Allocated, Retained};
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};

    const ICON: &[u8] = include_bytes!("../../assets/app-icon.png");

    // SAFETY: called on the main thread, from the closure gpui runs once
    // NSApplication exists. Each message is sent to the class that declares
    // it, with the argument and return types its signature gives, and
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

/// Run the app. Must be called on the main thread, which it keeps until the
/// window closes.
pub fn run(options: Options) {
    let (store, status) = start(options);

    Application::new()
        .with_assets(theme::Assets)
        .run(move |cx: &mut App| {
            #[cfg(target_os = "macos")]
            set_dock_icon();
            input::bind_keys(cx);
            mail::bind_keys(cx);
            cx.on_action(|_: &mail::Quit, cx| cx.quit());
            cx.set_menus(vec![
                Menu {
                    name: "emailulator".into(),
                    items: vec![
                        MenuItem::action("Open Web UI", mail::OpenWebUi),
                        MenuItem::separator(),
                        MenuItem::action("Quit emailulator", mail::Quit),
                    ],
                },
                // The system routes these to whichever native view has focus,
                // which is what makes copying out of a message body work.
                Menu {
                    name: "Edit".into(),
                    items: vec![
                        MenuItem::os_action("Cut", input::Cut, OsAction::Cut),
                        MenuItem::os_action("Copy", input::Copy, OsAction::Copy),
                        MenuItem::os_action("Paste", input::Paste, OsAction::Paste),
                        MenuItem::os_action("Select All", input::SelectAll, OsAction::SelectAll),
                        MenuItem::separator(),
                        MenuItem::action("Find", mail::FocusSearch),
                    ],
                },
                Menu {
                    name: "Message".into(),
                    items: vec![
                        MenuItem::action("Next", mail::NextMessage),
                        MenuItem::action("Previous", mail::PreviousMessage),
                        MenuItem::separator(),
                        MenuItem::action("Star", mail::ToggleStar),
                        MenuItem::action("Mark Read or Unread", mail::ToggleRead),
                        MenuItem::action("Delete", mail::DeleteMessage),
                        MenuItem::separator(),
                        MenuItem::action("Refresh", mail::Refresh),
                    ],
                },
            ]);

            let bounds = Bounds::centered(None, size(px(1240.), px(780.)), cx);
            let opened = cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    window_min_size: Some(size(px(900.), px(520.))),
                    titlebar: Some(TitlebarOptions {
                        title: Some("emailulator".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| cx.new(|cx| Mail::new(store, status, window, cx)),
            );
            let window = match opened {
                Ok(window) => window,
                Err(error) => {
                    eprintln!("emailulator: could not open the window: {error:#}");
                    cx.quit();
                    return;
                }
            };
            if std::env::var_os("EMAILULATOR_APP_SELFTEST").is_some() {
                let _ = window.update(cx, |mail, window, cx| mail.selftest(window, cx));
            }
            // One window is the whole app; closing it ends the servers too.
            cx.on_window_closed(|cx| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            cx.activate(true);
        });
}
