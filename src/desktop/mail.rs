//! The mail client window: inboxes, message list and reading pane.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use emailulator::check::Report;
use emailulator::model::{
    ApiKey, AttachmentMeta, Inbox, Link, ListFilter, MessageDetail, MessageSummary, Page, Stats,
};
use emailulator::store::Store;
use futures::StreamExt;
use futures::channel::mpsc;
use gpui::{
    App, ClipboardItem, Context, Div, Entity, FocusHandle, Focusable, FontWeight, KeyBinding,
    ScrollStrategy, SharedString, Stateful, UniformListScrollHandle, Window, actions, div,
    prelude::*, px, svg, uniform_list,
};
use tokio::sync::broadcast::error::RecvError;

use super::body::{Body, BodyPane};
use super::input::{InputEvent, TextInput};
use super::theme::Theme;

actions!(
    mail,
    [
        Quit,
        NextMessage,
        PreviousMessage,
        ToggleStar,
        ToggleRead,
        DeleteMessage,
        FocusSearch,
        Refresh,
        OpenWebUi,
    ]
);

const NAV_CONTEXT: &str = "MailNav";
const PAGE_SIZE: usize = 100;
/// Height of each of a row's three text lines. Fixed, because gpui's default
/// line height is 1.618 times the font size and three of those do not fit.
const ROW_LINE_HEIGHT: f32 = 18.;
const ROW_PADDING: f32 = 8.;
/// Three lines, the padding around them, and the 1px rule under the row. A
/// uniform list gives every row this height, so the content must fit exactly.
const ROW_HEIGHT: f32 = 3. * ROW_LINE_HEIGHT + 2. * ROW_PADDING + 1.;
/// Raw source beyond this is cut for display; the saved file is complete.
const MAX_RAW_CHARS: usize = 2_000_000;

pub fn bind_keys(cx: &mut App) {
    // The search field sits inside the list pane, so these single-key
    // shortcuts must stand down while it has focus or they would eat letters.
    let nav = Some("MailNav && !TextInput");
    cx.bind_keys([
        KeyBinding::new("cmd-q", Quit, None),
        KeyBinding::new("cmd-f", FocusSearch, None),
        KeyBinding::new("ctrl-f", FocusSearch, None),
        KeyBinding::new("cmd-r", Refresh, None),
        KeyBinding::new("j", NextMessage, nav),
        KeyBinding::new("down", NextMessage, nav),
        KeyBinding::new("k", PreviousMessage, nav),
        KeyBinding::new("up", PreviousMessage, nav),
        KeyBinding::new("s", ToggleStar, nav),
        KeyBinding::new("u", ToggleRead, nav),
        KeyBinding::new("backspace", DeleteMessage, nav),
        KeyBinding::new("delete", DeleteMessage, nav),
        KeyBinding::new("#", DeleteMessage, nav),
        KeyBinding::new("/", FocusSearch, nav),
    ]);
}

/// Whether this app is receiving mail itself or only showing the store.
#[derive(Clone)]
pub enum ServerStatus {
    Running {
        smtp: SocketAddr,
        http: SocketAddr,
    },
    /// The listeners could not start, typically because another emailulator
    /// already holds the ports. The store is still readable.
    ViewerOnly {
        reason: String,
    },
}

#[derive(Clone, PartialEq)]
enum View {
    All,
    Starred,
    Inbox(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Html,
    Text,
    Headers,
    Raw,
    Links,
    /// Which email clients support what the message uses.
    Check,
}

impl Tab {
    const ALL: [Tab; 6] = [
        Tab::Html,
        Tab::Text,
        Tab::Headers,
        Tab::Raw,
        Tab::Links,
        Tab::Check,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Html => "HTML",
            Tab::Text => "Text",
            Tab::Headers => "Headers",
            Tab::Raw => "Raw",
            Tab::Links => "Links",
            Tab::Check => "Check",
        }
    }
}

/// The width an HTML body is previewed at, as the device it might be read on.
/// The widths match the web UI's, so the two previews agree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Device {
    /// As wide as the reading pane.
    Desktop,
    Tablet,
    Mobile,
}

impl Device {
    const ALL: [Device; 3] = [Device::Desktop, Device::Tablet, Device::Mobile];

    fn label(self) -> &'static str {
        match self {
            Device::Desktop => "Desktop",
            Device::Tablet => "Tablet",
            Device::Mobile => "Mobile",
        }
    }

    /// The preview width in pixels, or `None` to fill the pane.
    fn width(self) -> Option<f32> {
        match self {
            Device::Desktop => None,
            Device::Tablet => Some(768.),
            Device::Mobile => Some(375.),
        }
    }
}

/// Width of the rule drawn down each side of a device preview.
const DEVICE_FRAME_RULE: f32 = 1.;

/// Everything read from the store for the open message.
struct Loaded {
    detail: MessageDetail,
    links: Vec<Link>,
    html: Option<String>,
    raw: String,
    /// How the main email clients cope with what the message uses.
    report: Report,
}

/// The clients the Check tab reports on: the ones most mail is read in.
const CHECKED_CLIENTS: [&str; 5] = ["gmail", "outlook", "apple-mail", "yahoo", "samsung-email"];

/// What the New inbox dialog is showing besides its two fields: the id and
/// key the inbox will be created with, so they can be copied before it exists.
struct InboxDraft {
    /// Made from the name as it is typed; empty until there is a name.
    id: String,
    key: SharedString,
    error: Option<SharedString>,
}

pub struct Mail {
    store: Arc<Store>,
    status: ServerStatus,
    view: View,
    inboxes: Vec<Inbox>,
    stats: Stats,
    page: Page,
    limit: usize,
    selected: Option<i64>,
    selected_summary: Option<MessageSummary>,
    loaded: Option<Loaded>,
    tab: Tab,
    /// The device width HTML bodies are previewed at. Kept from one message to
    /// the next: someone checking mobile layouts checks them for every message.
    device: Device,
    confirm_clear: bool,
    /// Showing how to connect to the open inbox, and its keys, in place of
    /// the reading pane.
    connecting: bool,
    /// A key created a moment ago: its inbox and the key, shown this once.
    new_key: Option<(String, SharedString)>,
    confirm_delete_inbox: bool,
    /// The keys of the inbox being connected to.
    keys: Vec<ApiKey>,
    /// A key whose regeneration is waiting to be confirmed.
    confirm_regenerate: Option<i64>,
    /// The New inbox dialog, while it is open.
    draft: Option<InboxDraft>,
    notice: Option<SharedString>,
    error: Option<SharedString>,
    /// What the store looked like at the last reload, to notice changes made
    /// by another process.
    fingerprint: (i64, Stats, i64),
    search: Entity<TextInput>,
    new_inbox: Entity<TextInput>,
    new_description: Entity<TextInput>,
    nav_focus: FocusHandle,
    list_scroll: UniformListScrollHandle,
    body: BodyPane,
}

fn format_size(bytes: usize) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / f64::from(1 << 20)),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / f64::from(1 << 10)),
        b => format!("{b} B"),
    }
}

fn local_time(ms: i64) -> Option<chrono::DateTime<chrono::Local>> {
    chrono::DateTime::from_timestamp_millis(ms).map(|utc| utc.with_timezone(&chrono::Local))
}

/// A compact timestamp for a list row: the time today, the date otherwise.
fn short_time(ms: i64) -> String {
    use chrono::Datelike;
    let Some(when) = local_time(ms) else {
        return String::new();
    };
    let now = chrono::Local::now();
    if when.date_naive() == now.date_naive() {
        when.format("%H:%M").to_string()
    } else if when.year() == now.year() {
        when.format("%b %-d").to_string()
    } else {
        when.format("%Y-%m-%d").to_string()
    }
}

fn long_time(ms: i64) -> String {
    local_time(ms)
        .map(|when| when.format("%a %-d %b %Y, %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// A filename safe to create inside the downloads folder. Attachment names
/// come from the email, so they are treated as hostile: no directories, no
/// leading dots, no control characters.
fn safe_filename(name: &str, fallback: &str) -> String {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = leaf
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, ':' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned.chars().take(120).collect()
    }
}

/// `dir/name`, or `dir/name (2).ext` and so on if that is taken.
fn unused_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (name, String::new()),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){extension}")))
        .find(|path| !path.exists())
        .expect("an unbounded range always yields an unused name")
}

fn icon(name: &'static str, color: gpui::Rgba) -> gpui::Svg {
    svg()
        .path(format!("icons/{name}.svg"))
        .size(px(15.))
        .flex_none()
        .text_color(color)
}

fn button(id: impl Into<gpui::ElementId>, theme: Theme) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .gap_1()
        .px_2()
        .h(px(26.))
        .rounded_md()
        .text_size(px(12.))
        .text_color(theme.muted)
        .cursor_pointer()
        .hover(|style| style.bg(theme.hover))
}

/// The one action a dialog is there for. Built on its own rather than on
/// `button`, which already sets a hover style: gpui allows only one.
fn primary_button(id: impl Into<gpui::ElementId>, theme: Theme) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .h(px(30.))
        .px_3()
        .rounded_md()
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .bg(theme.accent)
        .text_color(theme.on_accent)
        .cursor_pointer()
        .hover(|style| style.opacity(0.88))
}

/// A box holding something to read or type: the dialog's fields and values.
fn value_box(theme: Theme) -> Div {
    div()
        .flex()
        .items_center()
        .px_2()
        .h(px(32.))
        .rounded_md()
        .border_1()
        .border_color(theme.border)
        .text_size(px(13.))
        .text_color(theme.text)
}

fn field_label(label: &'static str, hint: &'static str, theme: Theme) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .h(px(22.))
        .child(
            div()
                .flex_none()
                .text_size(px(12.))
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme.text)
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .truncate()
                .text_size(px(12.))
                .text_color(theme.faint)
                .child(hint),
        )
}

impl Mail {
    pub fn new(
        store: Arc<Store>,
        status: ServerStatus,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.set_global(Theme::for_appearance(window.appearance()));
        cx.observe_window_appearance(window, |_, window, cx| {
            cx.set_global(Theme::for_appearance(window.appearance()));
            cx.notify();
        })
        .detach();

        let new_inbox = cx.new(|cx| TextInput::new("Billing app", cx));
        let new_description = cx.new(|cx| TextInput::new("What sends mail here (optional)", cx));
        cx.subscribe_in(
            &new_inbox,
            window,
            |this, _, event, window, cx| match event {
                InputEvent::Changed => this.name_changed(cx),
                InputEvent::Submitted => this.create_inbox(window, cx),
                InputEvent::Cancelled => this.cancel_new_inbox(window, cx),
                InputEvent::Next | InputEvent::Previous => {
                    window.focus(&this.new_description.focus_handle(cx))
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &new_description,
            window,
            |this, _, event, window, cx| match event {
                InputEvent::Changed => {}
                InputEvent::Submitted => this.create_inbox(window, cx),
                InputEvent::Cancelled => this.cancel_new_inbox(window, cx),
                InputEvent::Next | InputEvent::Previous => {
                    window.focus(&this.new_inbox.focus_handle(cx))
                }
            },
        )
        .detach();

        let search = cx.new(|cx| TextInput::new("Search mail", cx));
        cx.subscribe_in(&search, window, |this, _, event, window, cx| match event {
            InputEvent::Changed => {
                this.limit = PAGE_SIZE;
                this.reload(cx);
            }
            InputEvent::Submitted => window.focus(&this.nav_focus),
            InputEvent::Cancelled => {
                this.search.update(cx, |search, cx| search.clear(cx));
                window.focus(&this.nav_focus);
            }
            InputEvent::Next | InputEvent::Previous => {}
        })
        .detach();

        // Changes made through this process's own server arrive as events.
        let mut events = store.subscribe();
        cx.spawn(async move |this, cx| {
            // Falling behind only means some events were missed; reload anyway.
            while let Ok(_) | Err(RecvError::Lagged(_)) = events.recv().await {
                if this.update(cx, |this, cx| this.reload(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();

        // Changes made by another process on the same database do not, so the
        // store is also checked once a second.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |this, cx| this.poll(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();

        let (open_url, mut clicked) = mpsc::unbounded::<String>();
        cx.spawn(async move |_, cx| {
            while let Some(url) = clicked.next().await {
                if cx.update(|cx| cx.open_url(&url)).is_err() {
                    break;
                }
            }
        })
        .detach();

        let mut this = Self {
            store,
            status,
            view: View::All,
            inboxes: Vec::new(),
            stats: Stats::default(),
            page: Page {
                messages: Vec::new(),
                total: 0,
                unread: 0,
            },
            limit: PAGE_SIZE,
            selected: None,
            selected_summary: None,
            loaded: None,
            tab: Tab::Html,
            device: Device::Desktop,
            confirm_clear: false,
            connecting: false,
            new_key: None,
            confirm_delete_inbox: false,
            keys: Vec::new(),
            confirm_regenerate: None,
            draft: None,
            notice: None,
            error: None,
            fingerprint: (0, Stats::default(), 0),
            search,
            new_inbox,
            new_description,
            nav_focus: cx.focus_handle(),
            list_scroll: UniformListScrollHandle::new(),
            body: BodyPane::new(open_url),
        };
        this.reload(cx);
        window.focus(&this.nav_focus);
        this
    }

    /// Self-test, run by setting `EMAILULATOR_APP_SELFTEST`: open a message,
    /// visit every tab, report whether the system webview came up, and exit
    /// non-zero if it did not. `scripts/package.sh` runs it against the signed
    /// binary, because the webview can only be exercised on a real window and
    /// the hardened runtime is exactly what could stop it loading.
    ///
    /// It delivers a message of its own when the store is empty, so point it at
    /// a scratch `--data-dir`.
    pub fn selftest(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.page.messages.is_empty() {
            let seeded = self.store.insert(emailulator::store::Incoming {
                raw: b"From: Self-test <selftest@emailulator.test>\r\nTo: you@emailulator.test\r\n\
                       Subject: Self-test\r\nContent-Type: text/html\r\n\r\n\
                       <h1>Self-test</h1><p><a href=\"https://example.test/\">A link</a></p>\r\n"
                    .to_vec(),
                inbox: emailulator::store::DEFAULT_INBOX.into(),
                envelope_from: None,
                envelope_to: vec!["you@emailulator.test".into()],
                source: emailulator::model::Source::Api,
            });
            if let Err(error) = seeded {
                eprintln!("selftest: could not seed a message: {error:#}");
                std::process::exit(1);
            }
            self.reload(cx);
        }

        cx.spawn_in(window, async move |this, cx| {
            let pause = Duration::from_millis(700);
            let mut passed = true;
            cx.background_executor().timer(pause).await;
            this.update(cx, |this, cx| this.step(true, cx))?;
            cx.background_executor().timer(pause).await;
            for tab in Tab::ALL {
                this.update(cx, |this, cx| {
                    this.tab = tab;
                    cx.notify();
                })?;
                cx.background_executor().timer(pause).await;
                let (live, selected) =
                    this.update(cx, |this, _| (this.body.is_live(), this.selected))?;
                println!(
                    "selftest: tab={} webview_live={live} selected={selected:?}",
                    tab.label()
                );
                passed &= selected.is_some();
                // Where there is no embeddable webview the app draws text itself.
                if cfg!(any(target_os = "macos", target_os = "windows")) {
                    passed &= live;
                }
            }
            // The New inbox dialog is drawn by gpui, and the webview is a
            // native view above anything gpui draws: with a message open, the
            // dialog is only visible if the webview has stepped aside.
            this.update(cx, |this, cx| {
                this.tab = Tab::Html;
                cx.notify();
            })?;
            cx.background_executor().timer(pause).await;

            // A device preview narrows the holder; the webview has to follow,
            // and come back to the pane's full width afterwards.
            let full = this.update(cx, |this, _| this.body.width())?;
            for device in [Device::Mobile, Device::Desktop] {
                this.update(cx, |this, cx| {
                    this.device = device;
                    cx.notify();
                })?;
                cx.background_executor().timer(pause).await;
                let width = this.update(cx, |this, _| this.body.width())?;
                println!(
                    "selftest: device={} webview_width={width:?}",
                    device.label()
                );
                if cfg!(any(target_os = "macos", target_os = "windows")) {
                    passed &= match (device.width(), width) {
                        (Some(wanted), Some(width)) => width == wanted,
                        (None, width) => width.is_some() && width == full,
                        _ => false,
                    };
                }
            }

            this.update_in(cx, |this, window, cx| this.open_new_inbox(window, cx))?;
            cx.background_executor().timer(pause).await;
            let (open, covered) =
                this.update(cx, |this, _| (this.draft.is_some(), this.body.is_visible()))?;
            println!("selftest: dialog_open={open} webview_over_it={covered}");
            passed &= open && !covered;
            this.update_in(cx, |this, window, cx| this.cancel_new_inbox(window, cx))?;
            cx.background_executor().timer(pause).await;

            let error = this.update(cx, |this, _| this.error.clone())?;
            passed &= error.is_none();
            println!(
                "selftest: {} error={error:?}",
                if passed { "passed" } else { "FAILED" }
            );
            if !passed {
                std::process::exit(1);
            }
            cx.update(|_, cx| cx.quit())
        })
        .detach_and_log_err(cx);
    }

    /// The width the body is previewed at, or `None` to fill the pane. A
    /// device width only means something for a rendered HTML body, so the
    /// other tabs always fill the pane, and the control is offered with the
    /// HTML tab alone.
    fn preview_width(&self) -> Option<f32> {
        (self.tab == Tab::Html)
            .then(|| self.device.width())
            .flatten()
    }

    /// The inbox being shown, when the view is one inbox.
    fn open_inbox(&self) -> Option<&str> {
        match &self.view {
            View::Inbox(id) => Some(id),
            _ => None,
        }
    }

    fn filter(&self, cx: &App) -> ListFilter {
        let query = self.search.read(cx).text().trim().to_string();
        ListFilter {
            inbox: self.open_inbox().map(str::to_string),
            starred: (self.view == View::Starred).then_some(true),
            query: (!query.is_empty()).then_some(query),
            limit: Some(self.limit),
            ..Default::default()
        }
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        let filter = self.filter(cx);
        let open = self.open_inbox().map(str::to_string);
        let result = (|| -> anyhow::Result<_> {
            Ok((
                self.store.list(&filter)?,
                self.store.inboxes()?,
                self.store.stats(None)?,
                self.store.latest_id()?,
                self.store.inbox_revision()?,
                match &open {
                    Some(inbox) => self.store.keys(Some(inbox))?,
                    None => Vec::new(),
                },
            ))
        })();
        match result {
            Ok((page, inboxes, stats, latest, revision, keys)) => {
                self.page = page;
                self.inboxes = inboxes;
                self.stats = stats;
                self.keys = keys;
                self.fingerprint = (latest, stats, revision);
            }
            Err(error) => {
                self.error = Some(format!("Could not read the mail store: {error:#}").into())
            }
        }

        // The inbox being shown was deleted, here or by another process.
        if let View::Inbox(id) = &self.view
            && !self.inboxes.iter().any(|inbox| &inbox.id == id)
        {
            self.view = View::All;
            self.connecting = false;
            return self.reload(cx);
        }

        if let Some(id) = self.selected {
            self.selected_summary = self.store.summary(id).ok().flatten();
            if self.selected_summary.is_none() {
                self.selected = None;
                self.loaded = None;
            }
        }
        if self.page.total == 0 {
            self.confirm_clear = false;
        }
        cx.notify();
    }

    fn poll(&mut self, cx: &mut Context<Self>) {
        let current = (|| -> anyhow::Result<_> {
            Ok((
                self.store.latest_id()?,
                self.store.stats(None)?,
                self.store.inbox_revision()?,
            ))
        })();
        if current.is_ok_and(|current| current != self.fingerprint) {
            self.reload(cx);
        }
    }

    fn set_view(&mut self, view: View, cx: &mut Context<Self>) {
        if self.view != view {
            // A key is shown once, for the inbox it was made in.
            self.new_key = None;
            self.connecting = false;
        }
        self.view = view;
        self.limit = PAGE_SIZE;
        self.confirm_clear = false;
        self.confirm_delete_inbox = false;
        self.confirm_regenerate = None;
        self.error = None;
        self.list_scroll.scroll_to_item(0, ScrollStrategy::Top);
        self.reload(cx);
    }

    fn select(&mut self, id: i64, cx: &mut Context<Self>) {
        if self.selected == Some(id) {
            return;
        }
        self.selected = Some(id);
        self.loaded = None;
        self.notice = None;
        self.error = None;
        self.connecting = false;
        if let Err(error) = self.store.set_flags(id, Some(true), None) {
            self.error = Some(format!("Could not mark the message read: {error:#}").into());
        }
        self.reload(cx);

        // Parsing a large message takes long enough to keep off the UI thread.
        let store = self.store.clone();
        cx.spawn(async move |this, cx| {
            let loaded = cx
                .background_executor()
                .spawn(async move {
                    let detail = store.get(id)?;
                    let raw = store.raw(id)?.unwrap_or_default();
                    let mut raw = String::from_utf8_lossy(&raw).into_owned();
                    if let Some((cut, _)) = raw.char_indices().nth(MAX_RAW_CHARS) {
                        raw.truncate(cut);
                        raw.push_str(
                            "\n\n[truncated for display; save the message for the full source]",
                        );
                    }
                    anyhow::Ok(detail.map(|detail| {
                        let clients = CHECKED_CLIENTS.map(String::from);
                        let report = emailulator::check::check(&detail, Some(&clients));
                        (
                            detail,
                            store.links(id).ok().flatten().unwrap_or_default(),
                            store.rendered_html(id).ok().flatten(),
                            raw,
                            report,
                        )
                    }))
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.selected != Some(id) {
                    return;
                }
                match loaded {
                    Ok(Some((detail, links, html, raw, report))) => {
                        // Stay on Headers, Raw or Links while paging through
                        // mail; otherwise show the richest body there is.
                        if matches!(this.tab, Tab::Html | Tab::Text) {
                            this.tab = if detail.html.is_some() {
                                Tab::Html
                            } else {
                                Tab::Text
                            };
                        }
                        this.loaded = Some(Loaded {
                            detail,
                            links,
                            html,
                            raw,
                            report,
                        });
                    }
                    Ok(None) => this.selected = None,
                    Err(error) => {
                        this.error = Some(format!("Could not open the message: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn selected_index(&self) -> Option<usize> {
        let id = self.selected?;
        self.page.messages.iter().position(|m| m.id == id)
    }

    fn step(&mut self, forward: bool, cx: &mut Context<Self>) {
        if self.page.messages.is_empty() {
            return;
        }
        let last = self.page.messages.len() - 1;
        let index = match (self.selected_index(), forward) {
            (None, _) => 0,
            (Some(index), true) => (index + 1).min(last),
            (Some(index), false) => index.saturating_sub(1),
        };
        self.list_scroll
            .scroll_to_item(index, ScrollStrategy::Center);
        self.select(self.page.messages[index].id, cx);
    }

    fn toggle_star(&mut self, cx: &mut Context<Self>) {
        if let Some(summary) = &self.selected_summary {
            let _ = self
                .store
                .set_flags(summary.id, None, Some(!summary.starred));
            self.reload(cx);
        }
    }

    fn toggle_read(&mut self, cx: &mut Context<Self>) {
        if let Some(summary) = &self.selected_summary {
            let _ = self.store.set_flags(summary.id, Some(!summary.read), None);
            self.reload(cx);
        }
    }

    fn delete_selected(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected else { return };
        // Move to the neighbouring message, as a mail client does.
        let next = self.selected_index().and_then(|index| {
            self.page
                .messages
                .get(index + 1)
                .or_else(|| index.checked_sub(1).and_then(|i| self.page.messages.get(i)))
                .map(|m| m.id)
        });
        if let Err(error) = self.store.delete(id) {
            self.error = Some(format!("Could not delete the message: {error:#}").into());
        }
        self.selected = None;
        self.loaded = None;
        match next {
            Some(next) => self.select(next, cx),
            None => self.reload(cx),
        }
    }

    /// Everything the list is showing, not just the page of it that is loaded.
    fn whole_view(&self, cx: &App) -> ListFilter {
        ListFilter {
            limit: None,
            ..self.filter(cx)
        }
    }

    /// Delete exactly what is listed: an inbox, a search within one, the
    /// starred messages, or everything.
    fn clear_view(&mut self, cx: &mut Context<Self>) {
        let result = self.store.clear(&self.whole_view(cx));
        self.confirm_clear = false;
        self.selected = None;
        self.loaded = None;
        self.reload(cx);
        if let Err(error) = result {
            self.error = Some(format!("Could not delete the messages: {error:#}").into());
        }
    }

    fn mark_view_read(&mut self, cx: &mut Context<Self>) {
        let result = self.store.mark_all_read(&self.whole_view(cx));
        self.reload(cx);
        if let Err(error) = result {
            self.error = Some(format!("Could not mark the messages read: {error:#}").into());
        }
    }

    /// What people call an inbox, for showing in place of its id.
    fn inbox_name(&self, id: &str) -> SharedString {
        self.inboxes
            .iter()
            .find(|inbox| inbox.id == id)
            .map(|inbox| inbox.name.clone())
            .unwrap_or_else(|| id.to_string())
            .into()
    }

    /// Open the New inbox dialog with a key already made, so that everything
    /// the app will need can be copied from one place.
    fn open_new_inbox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.new_inbox.update(cx, |input, cx| input.clear(cx));
        self.new_description.update(cx, |input, cx| input.clear(cx));
        self.draft = Some(InboxDraft {
            id: String::new(),
            key: emailulator::security::generate_api_key().into(),
            error: None,
        });
        self.error = None;
        window.focus(&self.new_inbox.focus_handle(cx));
        cx.notify();
    }

    /// The id follows the name: it is the name as a slug, numbered if taken.
    fn name_changed(&mut self, cx: &mut Context<Self>) {
        let name = self.new_inbox.read(cx).text().trim().to_string();
        let id = if name.is_empty() {
            String::new()
        } else {
            self.store.suggest_inbox_id(&name).unwrap_or_default()
        };
        if let Some(draft) = &mut self.draft {
            draft.id = id;
            draft.error = None;
        }
        cx.notify();
    }

    fn regenerate_draft_key(&mut self, cx: &mut Context<Self>) {
        if let Some(draft) = &mut self.draft {
            draft.key = emailulator::security::generate_api_key().into();
        }
        cx.notify();
    }

    /// Create the inbox with exactly the id and key the dialog showed.
    fn create_inbox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = self.new_inbox.read(cx).text().trim().to_string();
        let description = self.new_description.read(cx).text().trim().to_string();
        let Some(draft) = &mut self.draft else {
            return;
        };
        if name.is_empty() {
            draft.error = Some("Give the inbox a name.".into());
            window.focus(&self.new_inbox.focus_handle(cx));
            return cx.notify();
        }
        let created = self.store.create_inbox_named(emailulator::store::NewInbox {
            name,
            description,
            id: (!draft.id.is_empty()).then(|| draft.id.clone()),
            key: Some(draft.key.to_string()),
        });
        match created {
            Ok((inbox, key)) => {
                self.draft = None;
                self.new_inbox.update(cx, |input, cx| input.clear(cx));
                self.new_description.update(cx, |input, cx| input.clear(cx));
                window.focus(&self.nav_focus);
                self.set_view(View::Inbox(inbox.id.clone()), cx);
                // A new inbox is no use until an app can deliver into it, and
                // this is the last place its key can be read.
                self.connecting = true;
                self.new_key = Some((inbox.id, key.into()));
                cx.notify();
            }
            // Keep the dialog as it is, so the name can be corrected.
            Err(error) => {
                draft.error = Some(format!("{error:#}").into());
                // The id may have been the problem; show the one a retry gets.
                self.name_changed(cx);
                if let Some(draft) = &mut self.draft {
                    draft.error = Some(format!("{error:#}").into());
                }
                cx.notify();
            }
        }
    }

    fn cancel_new_inbox(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.draft = None;
        self.new_inbox.update(cx, |input, cx| input.clear(cx));
        self.new_description.update(cx, |input, cx| input.clear(cx));
        window.focus(&self.nav_focus);
        cx.notify();
    }

    /// Mint a key for the open inbox. It goes to the clipboard and is shown
    /// until the view changes; after that only its first characters remain.
    fn create_key(&mut self, cx: &mut Context<Self>) {
        let Some(inbox) = self.open_inbox().map(str::to_string) else {
            return;
        };
        match self.store.create_key(&inbox, "desktop") {
            Ok((_, key)) => {
                cx.write_to_clipboard(ClipboardItem::new_string(key.clone()));
                self.new_key = Some((inbox, key.into()));
                self.reload(cx);
            }
            Err(error) => {
                self.error = Some(format!("Could not create a key: {error:#}").into());
                cx.notify();
            }
        }
    }

    /// Replace a key's value. The old one stops working at once, so this is
    /// only reached through a confirmation; the new one is shown like a new key.
    fn regenerate_key(&mut self, id: i64, cx: &mut Context<Self>) {
        let Some(inbox) = self.open_inbox().map(str::to_string) else {
            return;
        };
        self.confirm_regenerate = None;
        match self.store.regenerate_key(id, Some(&inbox)) {
            Ok(Some((_, key))) => {
                cx.write_to_clipboard(ClipboardItem::new_string(key.clone()));
                self.new_key = Some((inbox, key.into()));
                self.reload(cx);
            }
            Ok(None) => self.reload(cx),
            Err(error) => {
                self.error = Some(format!("Could not regenerate the key: {error:#}").into());
                cx.notify();
            }
        }
    }

    fn revoke_key(&mut self, id: i64, cx: &mut Context<Self>) {
        let result = self.store.revoke_key(id, self.open_inbox());
        self.confirm_regenerate = None;
        self.new_key = None;
        self.reload(cx);
        if let Err(error) = result {
            self.error = Some(format!("Could not revoke the key: {error:#}").into());
        }
    }

    fn delete_open_inbox(&mut self, cx: &mut Context<Self>) {
        let Some(inbox) = self.open_inbox().map(str::to_string) else {
            return;
        };
        let result = self.store.delete_inbox(&inbox);
        self.confirm_delete_inbox = false;
        self.selected = None;
        self.loaded = None;
        match result {
            Ok(()) => self.set_view(View::All, cx),
            Err(error) => {
                self.reload(cx);
                self.error = Some(format!("{error:#}").into());
            }
        }
    }

    fn copy(&mut self, text: String, what: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.notice = Some(format!("{what} copied").into());
        cx.notify();
    }

    fn save(&mut self, name: &str, bytes: &[u8], cx: &mut Context<Self>) {
        let Some(dir) = dirs::download_dir() else {
            self.error = Some("Could not find the Downloads folder".into());
            return cx.notify();
        };
        let path = unused_path(&dir, name);
        match std::fs::write(&path, bytes) {
            Ok(()) => {
                self.notice = Some(format!("Saved to {}", path.display()).into());
                cx.reveal_path(&path);
            }
            Err(error) => {
                self.error = Some(format!("Could not save {}: {error}", path.display()).into())
            }
        }
        cx.notify();
    }

    fn save_message(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected else { return };
        match self.store.raw(id) {
            Ok(Some(raw)) => self.save(&format!("message-{id}.eml"), &raw, cx),
            Ok(None) => {}
            Err(error) => {
                self.error = Some(format!("Could not read the message: {error:#}").into())
            }
        }
    }

    fn save_attachment(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(id) = self.selected else { return };
        match self.store.attachment(id, index) {
            Ok(Some((meta, bytes))) => {
                let fallback = format!("attachment-{index}");
                let name = safe_filename(meta.filename.as_deref().unwrap_or_default(), &fallback);
                self.save(&name, &bytes, cx);
            }
            Ok(None) => {}
            Err(error) => {
                self.error = Some(format!("Could not read the attachment: {error:#}").into())
            }
        }
    }

    fn open_web_ui(&mut self, cx: &mut Context<Self>) {
        if let ServerStatus::Running { http, .. } = &self.status {
            cx.open_url(&format!("http://{http}/"));
        }
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    fn nav_item(
        &self,
        id: gpui::ElementId,
        icon_name: &'static str,
        label: SharedString,
        unread: usize,
        view: View,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let theme = *cx.global::<Theme>();
        let active = self.view == view;
        div()
            .id(id)
            .flex()
            .items_center()
            .gap_2()
            .mx_2()
            .px_2()
            .h(px(28.))
            .rounded_md()
            .text_size(px(13.))
            .cursor_pointer()
            .text_color(if active { theme.text } else { theme.muted })
            .when(active, |el| {
                el.bg(theme.selected).font_weight(FontWeight::MEDIUM)
            })
            .when(!active, |el| el.hover(|style| style.bg(theme.hover)))
            .on_click(cx.listener(move |this, _, window, cx| {
                window.focus(&this.nav_focus);
                this.set_view(view.clone(), cx);
            }))
            .child(icon(
                icon_name,
                if active { theme.accent } else { theme.faint },
            ))
            .child(div().flex_1().min_w_0().truncate().child(label))
            .when(unread > 0, |el| {
                el.child(
                    div()
                        .flex_none()
                        .text_size(px(11.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme.accent)
                        .child(unread.to_string()),
                )
            })
    }

    fn render_sidebar(&self, theme: Theme, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let inboxes: Vec<_> = self
            .inboxes
            .iter()
            .enumerate()
            .map(|(index, inbox)| {
                self.nav_item(
                    ("inbox", index).into(),
                    "inbox",
                    inbox.name.clone().into(),
                    inbox.unread,
                    View::Inbox(inbox.id.clone()),
                    cx,
                )
                .into_any_element()
            })
            .collect();

        let status = match &self.status {
            ServerStatus::Running { smtp, http } => div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(div().w(px(36.)).text_color(theme.faint).child("SMTP"))
                        .child(div().text_color(theme.muted).child(smtp.to_string())),
                )
                .child(
                    div()
                        .id("open-web-ui")
                        .flex()
                        .items_center()
                        .gap_2()
                        .cursor_pointer()
                        .on_click(cx.listener(|this, _, _, cx| this.open_web_ui(cx)))
                        .child(div().w(px(36.)).text_color(theme.faint).child("HTTP"))
                        .child(div().text_color(theme.accent).child(http.to_string()))
                        .child(icon("external", theme.accent).size(px(11.))),
                ),
            ServerStatus::ViewerOnly { reason } => div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme.warning)
                        .child("Viewing only"),
                )
                .child(
                    div()
                        .text_color(theme.muted)
                        .child(SharedString::from(reason.clone())),
                ),
        };

        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(232.))
            .h_full()
            .bg(theme.sidebar)
            .border_r_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .pt_3()
                    .child(self.nav_item(
                        "all-mail".into(),
                        "unread",
                        "All mail".into(),
                        self.stats.unread,
                        View::All,
                        cx,
                    ))
                    .child(self.nav_item(
                        "starred".into(),
                        "star",
                        "Starred".into(),
                        0,
                        View::Starred,
                        cx,
                    )),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .pl_4()
                    .pr_2()
                    .pt_4()
                    .pb_1()
                    .child(
                        div()
                            .flex_1()
                            .text_size(px(11.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme.faint)
                            .child("INBOXES"),
                    )
                    .child(
                        button("new-inbox", theme)
                            .h(px(20.))
                            .on_click(
                                cx.listener(|this, _, window, cx| this.open_new_inbox(window, cx)),
                            )
                            .child("New"),
                    ),
            )
            .child(
                div()
                    .id("inboxes")
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(inboxes),
            )
            .child(
                div()
                    .p_3()
                    .border_t_1()
                    .border_color(theme.border)
                    .text_size(px(11.5))
                    .child(status),
            )
    }

    fn render_row(
        &self,
        index: usize,
        theme: Theme,
        focused: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let message = &self.page.messages[index];
        let id = message.id;
        let selected = self.selected == Some(id);
        let sender: SharedString = message
            .from
            .as_ref()
            .map(|from| from.label().to_string())
            .unwrap_or_else(|| "(no sender)".to_string())
            .into();
        let subject: SharedString = if message.subject.is_empty() {
            "(no subject)".into()
        } else {
            message.subject.clone().into()
        };
        let weight = if message.read {
            FontWeight::NORMAL
        } else {
            FontWeight::SEMIBOLD
        };
        // Worth saying only where the list spans inboxes.
        let inbox_tag = self
            .open_inbox()
            .is_none()
            .then(|| SharedString::from(message.inbox_name.clone()));

        div()
            .id(("message", id as u64))
            .debug_selector(move || format!("row-{index}"))
            // Without a width a list item sizes to its own text: narrower than
            // the pane for a short message, wider than it for a long one.
            .w_full()
            .h(px(ROW_HEIGHT))
            .flex()
            .gap_2()
            .pl_2()
            .pr_3()
            .py(px(ROW_PADDING))
            .overflow_hidden()
            .border_b_1()
            .border_color(theme.border)
            .cursor_pointer()
            .when(selected, |el| {
                el.bg(if focused {
                    theme.selected
                } else {
                    theme.selected_inactive
                })
            })
            .when(!selected, |el| el.hover(|style| style.bg(theme.hover)))
            .on_click(cx.listener(move |this, _, window, cx| {
                window.focus(&this.nav_focus);
                this.select(id, cx);
            }))
            .child(
                // The unread marker has its own column so text stays aligned.
                div().flex_none().w(px(8.)).pt(px(5.)).child(
                    div()
                        .size(px(8.))
                        .rounded_full()
                        .when(!message.read, |el| el.bg(theme.accent)),
                ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .debug_selector(move || format!("row-{index}-top"))
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_2()
                            .h(px(ROW_LINE_HEIGHT))
                            .line_height(px(ROW_LINE_HEIGHT))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .text_size(px(13.))
                                    .font_weight(weight)
                                    .text_color(theme.text)
                                    .child(sender),
                            )
                            .when_some(inbox_tag, |el, inbox| {
                                el.child(
                                    div()
                                        .flex_none()
                                        .max_w(px(96.))
                                        .truncate()
                                        .px(px(5.))
                                        .rounded_sm()
                                        .bg(theme.hover)
                                        .text_size(px(10.5))
                                        .line_height(px(15.))
                                        .text_color(theme.muted)
                                        .child(inbox),
                                )
                            })
                            .when(message.starred, |el| {
                                el.child(icon("star-filled", theme.star).size(px(12.)))
                            })
                            .when(message.attachment_count > 0, |el| {
                                el.child(icon("paperclip", theme.faint).size(px(12.)))
                            })
                            .child(
                                div()
                                    .debug_selector(move || format!("row-{index}-time"))
                                    .flex_none()
                                    .text_size(px(11.))
                                    .text_color(theme.faint)
                                    .child(short_time(message.received_at)),
                            ),
                    )
                    .child(
                        div()
                            .debug_selector(move || format!("row-{index}-subject"))
                            .flex_none()
                            .h(px(ROW_LINE_HEIGHT))
                            .line_height(px(ROW_LINE_HEIGHT))
                            .truncate()
                            .text_size(px(12.5))
                            .font_weight(weight)
                            .text_color(if message.read {
                                theme.muted
                            } else {
                                theme.text
                            })
                            .child(subject),
                    )
                    .child(
                        div()
                            .debug_selector(move || format!("row-{index}-snippet"))
                            .flex_none()
                            .h(px(ROW_LINE_HEIGHT))
                            .line_height(px(ROW_LINE_HEIGHT))
                            .truncate()
                            .text_size(px(12.))
                            .text_color(theme.faint)
                            .child(SharedString::from(message.snippet.clone())),
                    ),
            )
    }

    fn render_list(&self, theme: Theme, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let count = self.page.messages.len();
        let searching = !self.search.read(cx).text().trim().is_empty();
        let summary: SharedString = match (self.page.total, self.page.unread) {
            (0, _) => "No messages".into(),
            (total, 0) => format!("{total} messages").into(),
            (total, unread) => format!("{total} messages, {unread} unread").into(),
        };

        let title: SharedString = match &self.view {
            View::All => "All mail".into(),
            View::Starred => "Starred".into(),
            View::Inbox(id) => self.inbox_name(id),
        };

        let toolbar = if self.confirm_clear {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .text_size(px(12.))
                        .text_color(theme.danger)
                        .child(SharedString::from(format!(
                            "Delete {} messages?",
                            self.page.total
                        ))),
                )
                .child(
                    button("confirm-clear", theme)
                        .text_color(theme.danger)
                        .font_weight(FontWeight::SEMIBOLD)
                        .on_click(cx.listener(|this, _, _, cx| this.clear_view(cx)))
                        .child("Delete"),
                )
                .child(
                    button("cancel-clear", theme)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.confirm_clear = false;
                            cx.notify();
                        }))
                        .child("Cancel"),
                )
        } else {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .text_size(px(12.))
                        .text_color(theme.faint)
                        .child(summary),
                )
                .when(self.page.unread > 0, |el| {
                    el.child(
                        button("mark-all-read", theme)
                            .on_click(cx.listener(|this, _, _, cx| this.mark_view_read(cx)))
                            .child(icon("check", theme.muted).size(px(13.)))
                            .child("Mark read"),
                    )
                })
                .when(self.page.total > 0, |el| {
                    el.child(
                        button("clear", theme)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.confirm_clear = true;
                                cx.notify();
                            }))
                            .child(icon("trash", theme.muted).size(px(13.)))
                            .child("Delete all"),
                    )
                })
        };

        div()
            .debug_selector(|| "list-pane".into())
            .flex()
            .flex_col()
            .flex_none()
            .w(px(348.))
            .h_full()
            .bg(theme.list)
            .border_r_1()
            .border_color(theme.border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pl_3()
                    .pr_2()
                    .pt_2()
                    .h(px(34.))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_size(px(14.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme.text)
                            .child(title),
                    )
                    .when(self.open_inbox().is_some(), |el| {
                        el.child(
                            button("connect", theme)
                                .when(self.connecting, |el| {
                                    el.bg(theme.selected).text_color(theme.text)
                                })
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.connecting = !this.connecting;
                                    this.confirm_delete_inbox = false;
                                    cx.notify();
                                }))
                                .child(icon("external", theme.muted).size(px(13.)))
                                .child("Connect"),
                        )
                    }),
            )
            .child(
                div().p_2().child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_2()
                        .h(px(30.))
                        .rounded_md()
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.field)
                        .text_size(px(13.))
                        .text_color(theme.text)
                        .child(icon("search", theme.faint).size(px(13.)))
                        .child(self.search.clone()),
                ),
            )
            .child(
                div()
                    .px_3()
                    .pb_2()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(toolbar),
            )
            .child(if count == 0 {
                self.render_empty_list(theme, searching).into_any_element()
            } else {
                uniform_list(
                    "messages",
                    count,
                    cx.processor(move |this, range: std::ops::Range<usize>, window, cx| {
                        let theme = *cx.global::<Theme>();
                        let focused = this.nav_focus.is_focused(window);
                        range
                            .filter(|index| *index < this.page.messages.len())
                            .map(|index| {
                                this.render_row(index, theme, focused, cx)
                                    .into_any_element()
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(self.list_scroll.clone())
                .flex_1()
                .min_h_0()
                .into_any_element()
            })
            .when(self.page.total > count && count > 0, |el| {
                el.child(
                    div().p_2().border_t_1().border_color(theme.border).child(
                        button("load-more", theme)
                            .justify_center()
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.limit += PAGE_SIZE;
                                this.reload(cx);
                            }))
                            .child(SharedString::from(format!(
                                "Show more ({} of {})",
                                count, self.page.total
                            ))),
                    ),
                )
            })
    }

    fn render_empty_list(&self, theme: Theme, searching: bool) -> impl IntoElement + use<> {
        let (title, hint): (&str, SharedString) = if searching {
            (
                "Nothing matches",
                "Try fewer words, or from: to: subject: is:unread has:attachment".into(),
            )
        } else if let Some(inbox) = self
            .open_inbox()
            .filter(|id| *id != emailulator::store::DEFAULT_INBOX)
            .map(|id| self.inbox_name(id))
        {
            (
                "No mail yet",
                format!("Nothing has been delivered to {inbox}. Connect shows the username and key an app needs.").into(),
            )
        } else if self.view == View::Starred {
            (
                "No starred mail",
                "Star a message with S to keep it here.".into(),
            )
        } else {
            match &self.status {
                ServerStatus::Running { smtp, .. } => (
                    "No mail yet",
                    format!(
                        "Point your app's SMTP settings at {} port {} and send something.",
                        smtp.ip(),
                        smtp.port()
                    )
                    .into(),
                ),
                ServerStatus::ViewerOnly { .. } => (
                    "No mail yet",
                    "Mail caught by the running emailulator server appears here.".into(),
                ),
            }
        };
        div()
            .flex()
            .flex_col()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_1()
            .p_6()
            .child(
                div()
                    .text_size(px(14.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme.muted)
                    .child(title),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_center()
                    .text_color(theme.faint)
                    .child(hint),
            )
    }

    fn field(label: &'static str, value: String, theme: Theme) -> impl IntoElement + use<> {
        div()
            .flex()
            .gap_2()
            .text_size(px(12.))
            .child(
                div()
                    .flex_none()
                    .w(px(84.))
                    .text_color(theme.faint)
                    .child(label),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_color(theme.muted)
                    .child(SharedString::from(value)),
            )
    }

    fn render_attachment(
        &self,
        attachment: &AttachmentMeta,
        theme: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let index = attachment.index;
        let name = attachment
            .filename
            .clone()
            .unwrap_or_else(|| format!("attachment-{index}"));
        div()
            .id(("attachment", index))
            .flex()
            .items_center()
            .gap_2()
            .px_2()
            .h(px(28.))
            .max_w(px(280.))
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .text_size(px(12.))
            .cursor_pointer()
            .hover(|style| style.bg(theme.hover))
            .on_click(cx.listener(move |this, _, _, cx| this.save_attachment(index, cx)))
            .child(
                icon(
                    if attachment.inline {
                        "paperclip"
                    } else {
                        "download"
                    },
                    theme.muted,
                )
                .size(px(13.)),
            )
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_color(theme.text)
                    .child(SharedString::from(name)),
            )
            .child(
                div()
                    .flex_none()
                    .text_color(theme.faint)
                    .child(format_size(attachment.size)),
            )
    }

    /// Which of the main email clients support what the message uses.
    fn render_check(
        &self,
        report: &Report,
        theme: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let scores: Vec<_> = report
            .clients
            .iter()
            .map(|client| {
                let total = client.supported + client.partial + client.unsupported + client.unknown;
                let (edge, detail): (gpui::Rgba, String) = if client.unsupported > 0 {
                    (theme.danger, format!("{} unsupported", client.unsupported))
                } else if client.partial > 0 {
                    (theme.warning, format!("{} partial", client.partial))
                } else {
                    (theme.ok, "all supported".to_string())
                };
                div()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .w(px(138.))
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_1()
                    .border_l_4()
                    .border_color(theme.border)
                    .child(
                        div()
                            .text_size(px(13.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme.text)
                            .child(SharedString::from(client.name.clone())),
                    )
                    .child(div().text_size(px(13.)).text_color(theme.text).child(
                        SharedString::from(format!("{} of {total}", client.supported)),
                    ))
                    .child(
                        div()
                            .text_size(px(11.5))
                            .text_color(edge)
                            .child(SharedString::from(detail)),
                    )
                    .into_any_element()
            })
            .collect();

        let notices: Vec<_> = report
            .notices
            .iter()
            .map(|notice| {
                div()
                    .mt_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_l_4()
                    .border_color(theme.warning)
                    .bg(theme.hover)
                    .text_size(px(12.5))
                    .text_color(theme.text)
                    .child(SharedString::from(notice.message.clone()))
                    .into_any_element()
            })
            .collect();

        let issue = |index: usize, item: &emailulator::check::Issue, cx: &mut Context<Self>| {
            let url = item.url.clone();
            let broken = item.severity == "unsupported";
            let clients: Vec<_> = item
                .clients
                .iter()
                .map(|client| {
                    let mut parts = Vec::new();
                    if !client.unsupported.is_empty() {
                        parts.push(format!(
                            "not supported on {}",
                            client.unsupported.join(", ")
                        ));
                    }
                    if !client.partial.is_empty() {
                        parts.push(format!("partly on {}", client.partial.join(", ")));
                    }
                    div()
                        .flex()
                        .gap_3()
                        .pt_1()
                        .text_size(px(12.5))
                        .child(
                            div()
                                .flex_none()
                                .w(px(112.))
                                .text_color(theme.text)
                                .child(SharedString::from(client.name.clone())),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w_0()
                                .text_color(theme.muted)
                                .child(SharedString::from(parts.join("; ")))
                                .children(client.notes.iter().map(|note| {
                                    div()
                                        .text_size(px(12.))
                                        .text_color(theme.faint)
                                        .child(SharedString::from(format!("– {note}")))
                                })),
                        )
                        .into_any_element()
                })
                .collect();
            div()
                .flex()
                .flex_col()
                .py_2()
                .border_t_1()
                .border_color(theme.border)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            // The feature's page on caniemail.com.
                            div()
                                .id(("check-issue", index))
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(if broken { theme.danger } else { theme.accent })
                                .cursor_pointer()
                                .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&url)))
                                .child(SharedString::from(item.title.clone())),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(theme.faint)
                                .child(SharedString::from(format!("used {}×", item.count))),
                        ),
                )
                .children(clients)
                .into_any_element()
        };

        let heading = |title: String, blurb: &'static str| {
            div()
                .pt_5()
                .pb_1()
                .child(
                    div()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(theme.text)
                        .child(SharedString::from(title)),
                )
                .child(
                    div()
                        .text_size(px(12.))
                        .text_color(theme.faint)
                        .child(blurb),
                )
        };

        let (broken, partial): (Vec<_>, Vec<_>) = report
            .issues
            .iter()
            .enumerate()
            .partition(|(_, item)| item.severity == "unsupported");
        let broken_rows: Vec<_> = broken.iter().map(|(i, item)| issue(*i, item, cx)).collect();
        let partial_rows: Vec<_> = partial
            .iter()
            .map(|(i, item)| issue(*i, item, cx))
            .collect();

        let intro: SharedString = if report.features_found == 0 {
            "This message has no HTML to check.".into()
        } else {
            format!(
                "This message uses {} HTML and CSS features. This is how many of them each client supports, from caniemail.com data of {}. It reads the markup; it is not a rendering.",
                report.features_found, report.data_updated
            )
            .into()
        };

        div()
            .id("check")
            .debug_selector(|| "check".into())
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .px_5()
            .pt_4()
            .pb_5()
            .child(
                div()
                    .text_size(px(13.))
                    .text_color(theme.muted)
                    .child(intro),
            )
            .when(report.features_found > 0, |el| {
                el.child(div().flex().flex_wrap().gap_2().pt_3().children(scores))
            })
            .children(notices)
            .when(!broken_rows.is_empty(), |el| {
                el.child(heading(
                    format!("Not supported ({})", broken_rows.len()),
                    "These do nothing at all in at least one of the main clients.",
                ))
                .children(broken_rows)
            })
            .when(!partial_rows.is_empty(), |el| {
                el.child(heading(
                    format!("Partly supported ({})", partial_rows.len()),
                    "These work, with the caveats noted.",
                ))
                .children(partial_rows)
            })
            .when(
                report.features_found > 0 && report.issues.is_empty(),
                |el| {
                    el.child(
                        div()
                            .pt_4()
                            .text_size(px(13.))
                            .text_color(theme.faint)
                            .child(
                                "Every feature this message uses is supported by these clients.",
                            ),
                    )
                },
            )
    }

    fn render_links(
        &self,
        links: &[Link],
        theme: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let rows: Vec<_> = links
            .iter()
            .enumerate()
            .map(|(index, link)| {
                let url = link.url.clone();
                let copy = link.url.clone();
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_5()
                    .py_2()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .when_some(link.text.clone(), |el, text| {
                                el.child(
                                    div()
                                        .truncate()
                                        .text_size(px(13.))
                                        .text_color(theme.text)
                                        .child(SharedString::from(text)),
                                )
                            })
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(12.))
                                    .text_color(theme.accent)
                                    .child(SharedString::from(link.url.clone())),
                            ),
                    )
                    .child(
                        button(("copy-link", index), theme)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()));
                                this.notice = Some("Link copied".into());
                                cx.notify();
                            }))
                            .child("Copy"),
                    )
                    .child(
                        button(("open-link", index), theme)
                            .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&url)))
                            .child(icon("external", theme.muted).size(px(13.)))
                            .child("Open"),
                    )
                    .into_any_element()
            })
            .collect();

        div()
            .id("links")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .children(rows)
            .when(links.is_empty(), |el| {
                el.child(
                    div()
                        .p_5()
                        .text_size(px(13.))
                        .text_color(theme.faint)
                        .child("This message has no links."),
                )
            })
    }

    /// The New inbox dialog: two things to type, and the two credentials the
    /// inbox will have, shown before it exists so they can be copied from here.
    fn render_new_inbox(
        &self,
        draft: &InboxDraft,
        theme: Theme,
        window: &Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let ring = |input: &Entity<TextInput>| {
            if input.focus_handle(cx).is_focused(window) {
                theme.accent
            } else {
                theme.border
            }
        };
        let name_ring = ring(&self.new_inbox);
        let description_ring = ring(&self.new_description);
        let id = draft.id.clone();
        let key = draft.key.to_string();
        let has_id = !id.is_empty();

        // Never taller than the window: past that it scrolls instead of
        // running off the top and bottom, where its buttons would be lost.
        let tallest = window.viewport_size().height - px(24.);
        let card = div()
            .id("new-inbox-dialog")
            .debug_selector(|| "new-inbox-dialog".into())
            .flex()
            .flex_col()
            .w(px(540.))
            .max_h(tallest)
            .overflow_y_scroll()
            .px_5()
            .py_4()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.reader)
            .shadow_lg()
            .child(
                div()
                    .text_size(px(17.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme.text)
                    .child("New inbox"),
            )
            .child(
                div()
                    .pt_1()
                    .pb_3()
                    .text_size(px(13.))
                    .text_color(theme.muted)
                    .child("One inbox per app. The app signs in with the inbox's ID and key."),
            )
            .child(field_label("Name", "", theme))
            .child(
                value_box(theme)
                    .bg(theme.field)
                    .border_color(name_ring)
                    .child(self.new_inbox.clone()),
            )
            .child(
                div()
                    .pt_3()
                    .child(field_label("Description", "optional", theme)),
            )
            .child(
                value_box(theme)
                    .bg(theme.field)
                    .border_color(description_ring)
                    .child(self.new_description.clone()),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .pt_4()
                    .child(div().flex_1().min_w_0().child(field_label(
                        "Inbox ID",
                        "the SMTP username",
                        theme,
                    )))
                    .when(has_id, |el| {
                        let copied = id.clone();
                        el.child(
                            button("copy-draft-id", theme)
                                .h(px(22.))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.copy(copied.clone(), "Inbox ID", cx)
                                }))
                                .child("Copy"),
                        )
                    }),
            )
            .child(
                value_box(theme)
                    .debug_selector(|| "new-inbox-id".into())
                    .bg(theme.sidebar)
                    .font_family("Menlo")
                    .text_size(px(12.5))
                    .child(if has_id {
                        div().truncate().child(SharedString::from(id))
                    } else {
                        div()
                            .truncate()
                            .text_color(theme.faint)
                            .child("made from the name")
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .pt_3()
                    .child(div().flex_1().min_w_0().child(field_label(
                        "API key",
                        "the SMTP password, and the API token",
                        theme,
                    )))
                    .child(
                        button("regenerate-draft-key", theme)
                            .h(px(22.))
                            .on_click(cx.listener(|this, _, _, cx| this.regenerate_draft_key(cx)))
                            .child("Regenerate"),
                    )
                    .child(
                        button("copy-draft-key", theme)
                            .h(px(22.))
                            .on_click(cx.listener({
                                let key = key.clone();
                                move |this, _, _, cx| this.copy(key.clone(), "API key", cx)
                            }))
                            .child("Copy"),
                    ),
            )
            .child(
                value_box(theme)
                    .debug_selector(|| "new-inbox-key".into())
                    .bg(theme.sidebar)
                    .font_family("Menlo")
                    .text_size(px(12.))
                    .child(div().truncate().child(SharedString::from(key))),
            )
            .child(
                div()
                    .pt_2()
                    .text_size(px(12.))
                    .text_color(theme.muted)
                    .child("Copy the key now: later only its first characters can be shown."),
            )
            .when_some(draft.error.clone(), |el, error| {
                el.child(
                    div()
                        .debug_selector(|| "new-inbox-error".into())
                        .mt_3()
                        .px_3()
                        .py_2()
                        .rounded_md()
                        .text_size(px(12.5))
                        .text_color(theme.danger)
                        .border_1()
                        .border_color(theme.danger)
                        .child(error),
                )
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pt_4()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_size(px(12.))
                            .text_color(theme.faint)
                            .when_some(self.notice.clone(), |el, notice| el.child(notice)),
                    )
                    .child(
                        button("new-inbox-cancel", theme)
                            .debug_selector(|| "new-inbox-cancel".into())
                            .h(px(30.))
                            .px_3()
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.cancel_new_inbox(window, cx)
                                }),
                            )
                            .child("Cancel"),
                    )
                    .child(
                        primary_button("new-inbox-create", theme)
                            .debug_selector(|| "new-inbox-create".into())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.create_inbox(window, cx)),
                            )
                            .child("Create inbox"),
                    ),
            );

        // The scrim takes every click, so nothing under the dialog can be
        // operated while it is open.
        div()
            .debug_selector(|| "new-inbox-scrim".into())
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .occlude()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui::rgba(0x00000073))
            .child(card)
    }

    /// One line of connection details, with a button to copy its value.
    fn setting(
        index: usize,
        label: &'static str,
        value: String,
        theme: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let copied = value.clone();
        div()
            .flex()
            .items_center()
            .gap_2()
            .h(px(26.))
            .text_size(px(13.))
            .child(
                div()
                    .flex_none()
                    .w(px(84.))
                    .text_color(theme.faint)
                    .child(label),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .text_color(theme.text)
                    .child(SharedString::from(value)),
            )
            .child(
                button(("copy-setting", index), theme)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.copy(copied.clone(), label, cx)),
                    )
                    .child("Copy"),
            )
    }

    fn section(title: &'static str, theme: Theme) -> gpui::Div {
        div()
            .pt_4()
            .pb_1()
            .text_size(px(11.))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(theme.faint)
            .child(title)
    }

    /// How an application connects to an inbox, and the inbox's keys.
    fn render_connect(
        &self,
        inbox: String,
        theme: Theme,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let is_default = inbox == emailulator::store::DEFAULT_INBOX;
        let name = self.inbox_name(&inbox);
        let description = self
            .inboxes
            .iter()
            .find(|candidate| candidate.id == inbox)
            .map(|found| found.description.clone())
            .filter(|description| !description.is_empty());
        let new_key = self
            .new_key
            .as_ref()
            .filter(|(owner, _)| *owner == inbox)
            .map(|(_, key)| key.clone());

        let servers = match &self.status {
            ServerStatus::Running { smtp, http } => Some((*smtp, *http)),
            ServerStatus::ViewerOnly { .. } => None,
        };
        // What goes in an application's configuration. The key is filled in
        // only while a new one is on screen; it is not recoverable later.
        let password = new_key
            .as_ref()
            .map(|key| key.to_string())
            .unwrap_or_else(|| "<an API key>".to_string());
        let env = servers.map(|(smtp, _)| {
            format!(
                "MAIL_MAILER=smtp\nMAIL_HOST={}\nMAIL_PORT={}\nMAIL_USERNAME={inbox}\nMAIL_PASSWORD={password}\n",
                smtp.ip(),
                smtp.port()
            )
        });

        let keys: Vec<_> = self
            .keys
            .iter()
            .map(|key| {
                let id = key.id;
                let used: SharedString = match key.last_used_at {
                    Some(at) => format!("last used {}", short_time(at)).into(),
                    None => "never used".into(),
                };
                let row = div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h(px(32.))
                    .border_b_1()
                    .border_color(theme.border)
                    .text_size(px(13.));
                if self.confirm_regenerate == Some(id) {
                    // Regenerating cuts off whatever is using the key now.
                    return row
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_color(theme.danger)
                                .child(SharedString::from(format!(
                                    "Replace {}…? Its current value stops working at once.",
                                    key.prefix
                                ))),
                        )
                        .child(
                            button(("confirm-regenerate", id as u64), theme)
                                .text_color(theme.danger)
                                .font_weight(FontWeight::SEMIBOLD)
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.regenerate_key(id, cx)),
                                )
                                .child("Regenerate"),
                        )
                        .child(
                            button(("cancel-regenerate", id as u64), theme)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.confirm_regenerate = None;
                                    cx.notify();
                                }))
                                .child("Cancel"),
                        )
                        .into_any_element();
                }
                row.child(
                    div()
                        .flex_none()
                        .w(px(104.))
                        .font_family("Menlo")
                        .text_size(px(12.))
                        .text_color(theme.text)
                        .child(SharedString::from(format!("{}…", key.prefix))),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .text_color(theme.muted)
                        .child(SharedString::from(key.label.clone())),
                )
                .child(
                    div()
                        .flex_none()
                        .text_size(px(12.))
                        .text_color(theme.faint)
                        .child(used),
                )
                .child(
                    button(("regenerate-key", id as u64), theme)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.confirm_regenerate = Some(id);
                            cx.notify();
                        }))
                        .child("Regenerate"),
                )
                .child(
                    button(("revoke-key", id as u64), theme)
                        .text_color(theme.danger)
                        .on_click(cx.listener(move |this, _, _, cx| this.revoke_key(id, cx)))
                        .child("Revoke"),
                )
                .into_any_element()
            })
            .collect();

        div()
            .id("connect")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .px_5()
            .pt_4()
            .pb_5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_size(px(18.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme.text)
                            .child(SharedString::from(format!("Connect to {name}"))),
                    )
                    .child(
                        button("connect-done", theme)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.connecting = false;
                                cx.notify();
                            }))
                            .child("Done"),
                    ),
            )
            .when_some(description, |el, description| {
                el.child(
                    div()
                        .pt_1()
                        .text_size(px(13.))
                        .text_color(theme.text)
                        .child(SharedString::from(description)),
                )
            })
            .child(
                div()
                    .pt_1()
                    .text_size(px(13.))
                    .text_color(theme.muted)
                    .child(if is_default {
                        "Mail sent without a key lands in this inbox. With one of its keys, an app can also deliver here from another machine."
                    } else {
                        "An app delivers into this inbox by signing in to SMTP with the inbox ID as its username and one of the keys below as its password."
                    }),
            )
            .child(Self::section("SMTP", theme))
            .map(|el| match servers {
                Some((smtp, _)) => el
                    .child(Self::setting(0, "Host", smtp.ip().to_string(), theme, cx))
                    .child(Self::setting(1, "Port", smtp.port().to_string(), theme, cx)),
                None => el.child(
                    div()
                        .text_size(px(13.))
                        .text_color(theme.muted)
                        .child("Host and port are those of the emailulator server that is running."),
                ),
            })
            .child(Self::setting(2, "Username", inbox.clone(), theme, cx))
            .child(Self::setting(3, "Password", password.clone(), theme, cx))
            .when_some(env, |el, env| {
                el.child(
                    div().flex().pt_1().child(
                        button("copy-env", theme)
                            .border_1()
                            .border_color(theme.border)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.copy(env.clone(), "Laravel .env lines", cx)
                            }))
                            .child("Copy as Laravel .env"),
                    ),
                )
            })
            .when_some(servers, |el, (_, http)| {
                el.child(Self::section("API AND MCP", theme))
                    .child(Self::setting(4, "API", format!("http://{http}/api/v1"), theme, cx))
                    .child(Self::setting(5, "MCP", format!("http://{http}/mcp"), theme, cx))
                    .child(Self::setting(
                        6,
                        "Header",
                        format!("Authorization: Bearer {password}"),
                        theme,
                        cx,
                    ))
            })
            .child(
                div()
                    .flex()
                    .items_end()
                    .child(div().flex_1().child(Self::section("API KEYS", theme)))
                    .child(
                        button("create-key", theme)
                            .text_color(theme.accent)
                            .on_click(cx.listener(|this, _, _, cx| this.create_key(cx)))
                            .child("Create key"),
                    ),
            )
            .when_some(new_key, |el, key| {
                let copied = key.to_string();
                el.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .my_2()
                        .p_3()
                        .rounded_md()
                        .border_1()
                        .border_color(theme.accent)
                        .bg(theme.selected)
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme.text)
                                .child("Copy this key now. It is shown only until you leave this inbox."),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .truncate()
                                        .text_size(px(13.))
                                        .text_color(theme.text)
                                        .child(key),
                                )
                                .child(
                                    button("copy-new-key", theme)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.copy(copied.clone(), "Key", cx)
                                        }))
                                        .child("Copy"),
                                ),
                        ),
                )
            })
            .children(keys)
            .when(self.keys.is_empty(), |el| {
                el.child(
                    div()
                        .py_2()
                        .text_size(px(13.))
                        .text_color(theme.faint)
                        .child("No keys yet. Create one to let an app deliver into this inbox."),
                )
            })
            .when(!is_default, |el| {
                el.child(Self::section("DANGER", theme)).child(if self.confirm_delete_inbox {
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .text_size(px(13.))
                                .text_color(theme.danger)
                                .child(SharedString::from(format!(
                                    "Delete {name} with its messages and keys?"
                                ))),
                        )
                        .child(
                            button("confirm-delete-inbox", theme)
                                .text_color(theme.danger)
                                .font_weight(FontWeight::SEMIBOLD)
                                .on_click(cx.listener(|this, _, _, cx| this.delete_open_inbox(cx)))
                                .child("Delete"),
                        )
                        .child(
                            button("cancel-delete-inbox", theme)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.confirm_delete_inbox = false;
                                    cx.notify();
                                }))
                                .child("Cancel"),
                        )
                } else {
                    div().flex().child(
                        button("delete-inbox", theme)
                            .text_color(theme.danger)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.confirm_delete_inbox = true;
                                cx.notify();
                            }))
                            .child(icon("trash", theme.danger).size(px(13.)))
                            .child("Delete inbox"),
                    )
                })
            })
            .when_some(self.notice.clone(), |el, notice| {
                el.child(div().pt_3().text_size(px(12.)).text_color(theme.faint).child(notice))
            })
    }

    fn render_reader(
        &mut self,
        theme: Theme,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let base = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .h_full()
            .bg(theme.reader);

        if self.connecting
            && let Some(inbox) = self.open_inbox().map(str::to_string)
        {
            self.body.hide();
            return base.child(self.render_connect(inbox, theme, cx));
        }

        let (Some(summary), Some(loaded)) = (self.selected_summary.clone(), self.loaded.as_ref())
        else {
            self.body.hide();
            let hint = if self.selected.is_some() {
                "Opening…"
            } else if self.page.messages.is_empty() {
                ""
            } else {
                "Select a message to read it"
            };
            return base
                .items_center()
                .justify_center()
                .child(div().text_size(px(13.)).text_color(theme.faint).child(hint));
        };
        let detail = &loaded.detail;

        let addresses = |list: &[emailulator::model::Address]| {
            list.iter()
                .map(|a| a.display())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let subject: SharedString = if summary.subject.is_empty() {
            "(no subject)".into()
        } else {
            summary.subject.clone().into()
        };
        // Recipients that are in the envelope but in no header were Bcc'd.
        let visible: Vec<String> = detail
            .summary
            .to
            .iter()
            .chain(&detail.summary.cc)
            .map(|a| a.address.to_ascii_lowercase())
            .collect();
        let hidden: Vec<String> = summary
            .recipients
            .iter()
            .filter(|m| !visible.contains(m))
            .cloned()
            .collect();

        let header = div()
            .flex()
            .flex_col()
            .gap_2()
            .px_5()
            .pt_4()
            .pb_3()
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_size(px(18.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme.text)
                            .child(subject),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .child(
                                button("star", theme)
                                    .on_click(cx.listener(|this, _, _, cx| this.toggle_star(cx)))
                                    .child(if summary.starred {
                                        icon("star-filled", theme.star)
                                    } else {
                                        icon("star", theme.muted)
                                    }),
                            )
                            .child(
                                button("unread", theme)
                                    .on_click(cx.listener(|this, _, _, cx| this.toggle_read(cx)))
                                    .child(icon("unread", theme.muted))
                                    .child(if summary.read {
                                        "Mark unread"
                                    } else {
                                        "Mark read"
                                    }),
                            )
                            .child(
                                button("save", theme)
                                    .on_click(cx.listener(|this, _, _, cx| this.save_message(cx)))
                                    .child(icon("download", theme.muted))
                                    .child("Save .eml"),
                            )
                            .child(
                                button("delete", theme)
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.delete_selected(cx)),
                                    )
                                    .child(icon("trash", theme.danger)),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.))
                    .child(Self::field(
                        "From",
                        summary
                            .from
                            .as_ref()
                            .map(|a| a.display())
                            .unwrap_or_else(|| "(none)".into()),
                        theme,
                    ))
                    .when(!detail.summary.to.is_empty(), |el| {
                        el.child(Self::field("To", addresses(&detail.summary.to), theme))
                    })
                    .when(!detail.summary.cc.is_empty(), |el| {
                        el.child(Self::field("Cc", addresses(&detail.summary.cc), theme))
                    })
                    .when(!hidden.is_empty(), |el| {
                        el.child(Self::field("Bcc", hidden.join(", "), theme))
                    })
                    .when(!detail.reply_to.is_empty(), |el| {
                        el.child(Self::field("Reply-To", addresses(&detail.reply_to), theme))
                    })
                    .child(Self::field(
                        "Received",
                        long_time(summary.received_at),
                        theme,
                    )),
            )
            .when(!detail.attachments.is_empty(), |el| {
                el.child(
                    div().flex().flex_wrap().gap_2().pt_1().children(
                        detail
                            .attachments
                            .iter()
                            .map(|a| self.render_attachment(a, theme, cx).into_any_element())
                            .collect::<Vec<_>>(),
                    ),
                )
            });

        let tabs = div()
            .flex()
            .items_center()
            .gap_1()
            .px_4()
            .border_b_1()
            .border_color(theme.border)
            .children(Tab::ALL.iter().map(|tab| {
                let tab = *tab;
                let active = self.tab == tab;
                let label: SharedString = match tab {
                    Tab::Links if !loaded.links.is_empty() => {
                        format!("Links {}", loaded.links.len()).into()
                    }
                    // The number of things that will not work somewhere.
                    Tab::Check
                        if loaded
                            .report
                            .issues
                            .iter()
                            .any(|i| i.severity == "unsupported") =>
                    {
                        let broken = loaded
                            .report
                            .issues
                            .iter()
                            .filter(|i| i.severity == "unsupported")
                            .count();
                        format!("Check {broken}").into()
                    }
                    _ => tab.label().into(),
                };
                div()
                    .id(tab.label())
                    .px_2()
                    .py_2()
                    .text_size(px(12.5))
                    .cursor_pointer()
                    .border_b_2()
                    .border_color(if active {
                        theme.accent
                    } else {
                        gpui::transparent_black().into()
                    })
                    .text_color(if active { theme.text } else { theme.muted })
                    .when(active, |el| el.font_weight(FontWeight::MEDIUM))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.tab = tab;
                        cx.notify();
                    }))
                    .child(label)
            }))
            .child(div().flex_1())
            .when_some(self.notice.clone(), |el, notice| {
                el.child(
                    div()
                        .truncate()
                        .text_size(px(11.5))
                        .text_color(theme.faint)
                        .child(notice),
                )
            })
            // A device width only means something for a rendered HTML body.
            .when(self.tab == Tab::Html, |el| {
                el.child(
                    div()
                        .debug_selector(|| "device-toggle".into())
                        .flex()
                        .flex_none()
                        .items_center()
                        .ml_2()
                        .p(px(2.))
                        .gap(px(2.))
                        .rounded_md()
                        .bg(theme.hover)
                        .children(Device::ALL.iter().map(|device| {
                            let device = *device;
                            let active = self.device == device;
                            div()
                                .id(device.label())
                                .px_2()
                                .h(px(22.))
                                .flex()
                                .items_center()
                                .rounded_sm()
                                .text_size(px(12.))
                                .cursor_pointer()
                                .text_color(if active { theme.text } else { theme.muted })
                                .when(active, |el| {
                                    el.bg(theme.reader).font_weight(FontWeight::MEDIUM)
                                })
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.device = device;
                                    cx.notify();
                                }))
                                .child(device.label())
                        })),
                )
            });

        let body = match self.tab {
            Tab::Links | Tab::Check => None,
            Tab::Html => Some(match &loaded.html {
                Some(html) => Body::Html(html.clone()),
                None => Body::Plain(detail.text.clone().unwrap_or_default()),
            }),
            Tab::Text => {
                Some(Body::Plain(detail.text.clone().unwrap_or_else(|| {
                    "This message has no plain-text part.".into()
                })))
            }
            Tab::Headers => Some(Body::Headers(detail.headers.clone())),
            Tab::Raw => Some(Body::Plain(loaded.raw.clone())),
        };

        let content = match body {
            None => {
                self.body.hide();
                if self.tab == Tab::Check {
                    self.render_check(&loaded.report, theme, cx)
                        .into_any_element()
                } else {
                    self.render_links(&loaded.links, theme, cx)
                        .into_any_element()
                }
            }
            // The webview is a native view above everything drawn here, the
            // dialog included, so it steps aside while the dialog is open.
            Some(_) if self.draft.is_some() => {
                self.body.hide();
                div().flex_1().min_h_0().into_any_element()
            }
            Some(body) => {
                // An HTML body is laid out at the chosen device width and
                // centred, with the pane showing either side of it. Everything
                // else, and Desktop, fills the pane. The webview follows the
                // bounds of whatever holds it, so sizing the holder is enough.
                let preview = self.preview_width();
                let frame = |inner: gpui::AnyElement| {
                    div()
                        .debug_selector(|| "body-area".into())
                        .flex()
                        .flex_1()
                        .min_h_0()
                        .justify_center()
                        .when(preview.is_some(), |el| el.bg(theme.sidebar))
                        .child(
                            div()
                                .debug_selector(|| "body-frame".into())
                                .flex()
                                .flex_col()
                                .h_full()
                                .map(|el| match preview {
                                    // The rules either side are outside the
                                    // device width, so the body gets all of
                                    // it. Never wider than the pane, though.
                                    Some(width) => el
                                        .w(px(width + 2. * DEVICE_FRAME_RULE))
                                        .max_w_full()
                                        .flex_none(),
                                    None => el.w_full(),
                                })
                                .when(preview.is_some(), |el| {
                                    el.bg(theme.reader)
                                        .border_l_1()
                                        .border_r_1()
                                        .border_color(theme.border)
                                })
                                .child(inner),
                        )
                        .into_any_element()
                };
                match self.body.show(&body, theme.dark, window) {
                    Some(webview) => {
                        frame(div().flex_1().min_h_0().child(webview).into_any_element())
                    }
                    // No webview on this platform: draw the text ourselves.
                    None => {
                        let text = match &body {
                            Body::Html(_) => detail.text.clone().unwrap_or_else(|| {
                                "HTML preview needs the web UI on this platform.".into()
                            }),
                            Body::Plain(text) => text.clone(),
                            Body::Headers(headers) => headers
                                .iter()
                                .map(|h| format!("{}: {}", h.name, h.value))
                                .collect::<Vec<_>>()
                                .join("\n"),
                        };
                        frame(
                            div()
                                .id("body-text")
                                .flex_1()
                                .min_h_0()
                                .overflow_y_scroll()
                                .p_5()
                                .text_size(px(13.))
                                .text_color(theme.text)
                                .child(SharedString::from(text))
                                .into_any_element(),
                        )
                    }
                }
            }
        };

        base.child(header).child(tabs).child(content)
    }
}

impl Focusable for Mail {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.nav_focus.clone()
    }
}

impl Render for Mail {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = *cx.global::<Theme>();
        let sidebar = self.render_sidebar(theme, cx).into_any_element();
        let list = self.render_list(theme, cx).into_any_element();
        let reader = self.render_reader(theme, window, cx).into_any_element();
        let dialog = self.draft.as_ref().map(|draft| {
            self.render_new_inbox(draft, theme, window, cx)
                .into_any_element()
        });

        div()
            .debug_selector(|| "window".into())
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.window)
            .text_color(theme.text)
            .on_action(cx.listener(|_, _: &Quit, _, cx| cx.quit()))
            .on_action(cx.listener(|this, _: &Refresh, _, cx| this.reload(cx)))
            .on_action(cx.listener(|this, _: &OpenWebUi, _, cx| this.open_web_ui(cx)))
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                // Not out from under an open dialog.
                if this.draft.is_none() {
                    window.focus(&this.search.focus_handle(cx));
                }
            }))
            .when_some(self.error.clone(), |el, error| {
                el.child(
                    div()
                        .px_4()
                        .py_2()
                        .text_size(px(12.))
                        .text_color(theme.on_accent)
                        .bg(theme.danger)
                        .child(error),
                )
            })
            .child(
                div().flex().flex_1().min_h_0().child(sidebar).child(
                    div()
                        .flex()
                        .flex_1()
                        .min_w_0()
                        .key_context(NAV_CONTEXT)
                        .track_focus(&self.nav_focus)
                        .on_action(cx.listener(|this, _: &NextMessage, _, cx| this.step(true, cx)))
                        .on_action(
                            cx.listener(|this, _: &PreviousMessage, _, cx| this.step(false, cx)),
                        )
                        .on_action(cx.listener(|this, _: &ToggleStar, _, cx| this.toggle_star(cx)))
                        .on_action(cx.listener(|this, _: &ToggleRead, _, cx| this.toggle_read(cx)))
                        .on_action(
                            cx.listener(|this, _: &DeleteMessage, _, cx| this.delete_selected(cx)),
                        )
                        .child(list)
                        .child(reader),
                ),
            )
            .children(dialog)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_attachment_names_stay_in_the_downloads_folder() {
        assert_eq!(
            safe_filename("../../.ssh/authorized_keys", "x"),
            "authorized_keys"
        );
        assert_eq!(safe_filename("C:\\Windows\\evil.exe", "x"), "evil.exe");
        assert_eq!(safe_filename("/etc/passwd", "x"), "passwd");
        assert_eq!(safe_filename("..", "fallback"), "fallback");
        assert_eq!(safe_filename(".bashrc", "x"), "bashrc");
        assert_eq!(safe_filename("a\nb\0c.txt", "x"), "a_b_c.txt");
        assert_eq!(safe_filename("", "attachment-0"), "attachment-0");
        assert_eq!(safe_filename("report.pdf", "x"), "report.pdf");
    }

    #[test]
    fn saving_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("emailulator-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unused_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"1").unwrap();
        assert_eq!(unused_path(&dir, "a.txt"), dir.join("a (2).txt"));
        std::fs::write(dir.join("a (2).txt"), b"2").unwrap();
        assert_eq!(unused_path(&dir, "a.txt"), dir.join("a (3).txt"));
        std::fs::write(dir.join("noext"), b"3").unwrap();
        assert_eq!(unused_path(&dir, "noext"), dir.join("noext (2)"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2 KB");
        assert_eq!(format_size(3 * 1024 * 1024 + 512 * 1024), "3.5 MB");
    }
}

/// Drives the real view through gpui's headless test window. Needs gpui's test
/// support: `cargo test --features desktop-test`.
#[cfg(all(test, feature = "desktop-test"))]
mod interaction_tests {
    use super::*;
    use emailulator::model::Source;
    use emailulator::store::Incoming;
    use gpui::{TestAppContext, VisualTestContext};

    fn deliver_in(store: &Store, inbox: &str, to: &str, subject: &str, html: bool) -> i64 {
        let body = if html {
            "Content-Type: text/html\r\n\r\n<p>Hello <a href=\"https://app.test/go\">go</a></p>\r\n"
        } else {
            "\r\nplain body\r\n"
        };
        store
            .insert(Incoming {
                raw: format!("From: App <app@x.test>\r\nTo: {to}\r\nSubject: {subject}\r\n{body}")
                    .into_bytes(),
                inbox: inbox.into(),
                envelope_from: None,
                envelope_to: vec![to.into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id
    }

    fn deliver(store: &Store, to: &str, subject: &str, html: bool) -> i64 {
        deliver_in(store, emailulator::store::DEFAULT_INBOX, to, subject, html)
    }

    fn open<'a>(
        cx: &'a mut TestAppContext,
        store: &Arc<Store>,
    ) -> (Entity<Mail>, &'a mut VisualTestContext) {
        cx.update(|cx| {
            crate::desktop::input::bind_keys(cx);
            bind_keys(cx);
        });
        let status = ServerStatus::Running {
            smtp: "127.0.0.1:1025".parse().unwrap(),
            http: "127.0.0.1:8025".parse().unwrap(),
        };
        let store = store.clone();
        let (view, cx) = cx.add_window_view(|window, cx| Mail::new(store, status, window, cx));
        cx.run_until_parked();
        (view, cx)
    }

    #[gpui::test]
    fn keys_walk_the_list_and_opening_marks_read(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let first = deliver(&store, "bob@x.test", "First", false);
        let second = deliver(&store, "bob@x.test", "Second", true);
        let (view, cx) = open(cx, &store);

        view.read_with(cx, |mail, _| {
            assert_eq!(mail.page.total, 2);
            assert_eq!(mail.selected, None);
            assert_eq!(mail.inboxes.len(), 1);
        });

        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.selected, Some(second), "newest is first in the list");
            let loaded = mail.loaded.as_ref().expect("the message body loads");
            assert_eq!(loaded.links[0].url, "https://app.test/go");
            assert!(
                mail.tab == Tab::Html,
                "an HTML message opens on the HTML tab"
            );
        });
        assert!(store.get(second).unwrap().unwrap().summary.read);
        assert!(!store.get(first).unwrap().unwrap().summary.read);

        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.selected, Some(first));
            assert!(
                mail.tab == Tab::Text,
                "a text-only message opens on the Text tab"
            );
        });
        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.selected, Some(first), "stops at the end")
        });
        cx.simulate_keystrokes("k");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert_eq!(mail.selected, Some(second)));
    }

    #[gpui::test]
    fn keys_star_unread_and_delete(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let first = deliver(&store, "bob@x.test", "First", false);
        let second = deliver(&store, "bob@x.test", "Second", false);
        let (view, cx) = open(cx, &store);

        cx.simulate_keystrokes("j s");
        cx.run_until_parked();
        assert!(store.get(second).unwrap().unwrap().summary.starred);
        cx.simulate_keystrokes("u");
        cx.run_until_parked();
        assert!(!store.get(second).unwrap().unwrap().summary.read);

        cx.simulate_keystrokes("#");
        cx.run_until_parked();
        assert!(store.get(second).unwrap().is_none());
        view.read_with(cx, |mail, _| {
            assert_eq!(
                mail.selected,
                Some(first),
                "selection moves to the neighbour"
            );
            assert_eq!(mail.page.total, 1);
        });
        cx.simulate_keystrokes("backspace");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.selected, None);
            assert_eq!(mail.page.total, 0);
            assert_eq!(mail.inboxes[0].total, 0);
        });
    }

    #[gpui::test]
    fn typing_in_search_filters_instead_of_running_shortcuts(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        deliver(&store, "bob@x.test", "Invoice", false);
        let reset = deliver(&store, "carol@x.test", "Reset link", false);
        let (view, cx) = open(cx, &store);

        cx.simulate_keystrokes("/");
        cx.simulate_input("subject:reset");
        cx.run_until_parked();
        view.read_with(cx, |mail, cx| {
            assert_eq!(mail.search.read(cx).text(), "subject:reset");
            assert_eq!(mail.page.total, 1);
            assert_eq!(mail.page.messages[0].id, reset);
            assert_eq!(
                mail.selected, None,
                "the letters j, s and u were typed, not run"
            );
        });
        assert_eq!(
            store.stats(None).unwrap().total,
            2,
            "and nothing was deleted"
        );

        cx.simulate_keystrokes("escape");
        cx.run_until_parked();
        view.read_with(cx, |mail, cx| {
            assert_eq!(mail.search.read(cx).text(), "");
            assert_eq!(mail.page.total, 2);
        });
        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert!(mail.selected.is_some(), "focus is back on the list")
        });
    }

    #[gpui::test]
    fn inboxes_filter_and_bulk_actions_touch_only_what_is_listed(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        store.create_inbox("billing").unwrap();
        deliver_in(&store, "billing", "bob@x.test", "Invoice", false);
        deliver_in(&store, "billing", "bob@x.test", "Receipt", false);
        let other = deliver(&store, "carol@x.test", "Elsewhere", false);
        let (view, cx) = open(cx, &store);

        view.read_with(cx, |mail, _| {
            let listed: Vec<_> = mail
                .inboxes
                .iter()
                .map(|i| (i.id.as_str(), i.unread))
                .collect();
            assert_eq!(listed, vec![("default", 1), ("billing", 2)]);
        });
        view.update(cx, |mail, cx| {
            mail.set_view(View::Inbox("billing".into()), cx)
        });
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert_eq!(mail.page.total, 2));

        view.update(cx, |mail, cx| mail.mark_view_read(cx));
        assert_eq!(
            store.stats(None).unwrap().unread,
            1,
            "the other inbox stays unread"
        );

        view.update(cx, |mail, cx| mail.clear_view(cx));
        cx.run_until_parked();
        assert_eq!(store.stats(None).unwrap().total, 1);
        assert!(store.get(other).unwrap().is_some());
        view.read_with(cx, |mail, _| {
            assert!(
                mail.view == View::Inbox("billing".into()),
                "an emptied inbox is still an inbox"
            );
            assert_eq!(mail.page.total, 0);
        });

        // Starred is a subset of all mail: clearing it must not clear the store.
        deliver(&store, "dave@x.test", "Keep me", false);
        store.set_flags(other, None, Some(true)).unwrap();
        view.update(cx, |mail, cx| mail.set_view(View::Starred, cx));
        view.update(cx, |mail, cx| mail.clear_view(cx));
        assert_eq!(store.stats(None).unwrap().total, 1);
        assert!(store.get(other).unwrap().is_none());
    }

    /// Open the New inbox dialog the way the sidebar's button does.
    fn open_dialog(view: &Entity<Mail>, cx: &mut VisualTestContext) {
        view.update_in(cx, |mail, window, cx| mail.open_new_inbox(window, cx));
        cx.run_until_parked();
    }

    #[gpui::test]
    fn the_new_inbox_dialog_creates_exactly_what_it_shows(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        deliver(&store, "bob@x.test", "Already here", false);
        let (view, cx) = open(cx, &store);

        open_dialog(&view, cx);
        let first_key = view.read_with(cx, |mail, _| {
            let draft = mail.draft.as_ref().expect("the dialog is open");
            assert_eq!(draft.id, "", "no id until there is a name");
            assert!(
                draft.key.starts_with("emu_"),
                "a key is ready before anything is typed"
            );
            draft.key.to_string()
        });

        // The id follows the name. The name has j, s and u in it, which are
        // list shortcuts everywhere but in a text field.
        cx.simulate_input("Just Sales (US)");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.draft.as_ref().unwrap().id, "just-sales-us");
            assert_eq!(mail.selected, None, "typing a name opened no message");
        });
        assert!(!store.get(1).unwrap().unwrap().summary.starred);

        // The key can be swapped for another before the inbox exists.
        view.update(cx, |mail, cx| mail.regenerate_draft_key(cx));
        let key = view.read_with(cx, |mail, _| mail.draft.as_ref().unwrap().key.to_string());
        assert_ne!(key, first_key);

        // Tab reaches the description, and Enter there creates the inbox.
        cx.simulate_keystrokes("tab");
        cx.simulate_input("Invoices and receipts");
        cx.simulate_keystrokes("enter");
        cx.run_until_parked();

        let inbox = store
            .inbox("just-sales-us")
            .unwrap()
            .expect("created with the id shown");
        assert_eq!(inbox.name, "Just Sales (US)");
        assert_eq!(inbox.description, "Invoices and receipts");
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some("just-sales-us"),
            "and with the key shown"
        );
        assert!(
            store.inbox_for_key(&first_key).unwrap().is_none(),
            "not the one it replaced"
        );
        view.read_with(cx, |mail, _| {
            assert!(mail.draft.is_none(), "the dialog closed");
            assert!(mail.view == View::Inbox("just-sales-us".into()));
            assert!(mail.connecting, "showing how to connect to the new inbox");
            assert_eq!(
                mail.new_key.as_ref().map(|(_, k)| k.to_string()),
                Some(key.clone())
            );
            assert_eq!(mail.inbox_name("just-sales-us"), "Just Sales (US)");
        });

        // A second name that makes the same slug is offered a numbered id.
        open_dialog(&view, cx);
        cx.simulate_input("just sales us");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.draft.as_ref().unwrap().id, "just-sales-us-2");
        });
    }

    #[gpui::test]
    fn a_refused_name_keeps_the_dialog_open_with_the_reason(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        store.create_inbox("billing").unwrap();
        let (view, cx) = open(cx, &store);

        // No name at all.
        open_dialog(&view, cx);
        cx.simulate_keystrokes("enter");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            let draft = mail.draft.as_ref().expect("still open");
            assert_eq!(
                draft
                    .error
                    .as_ref()
                    .map(|error| error.to_string())
                    .as_deref(),
                Some("Give the inbox a name.")
            );
        });

        // A name another inbox has, whatever its case.
        cx.simulate_input("Billing");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            let draft = mail.draft.as_ref().unwrap();
            assert_eq!(draft.error, None, "typing clears the last error");
            assert_eq!(draft.id, "billing-2");
        });
        cx.simulate_keystrokes("enter");
        cx.run_until_parked();
        view.read_with(cx, |mail, cx| {
            let draft = mail.draft.as_ref().expect("still open");
            assert!(
                draft.error.as_ref().unwrap().contains("already exists"),
                "{:?}",
                draft.error
            );
            assert_eq!(
                mail.new_inbox.read(cx).text(),
                "Billing",
                "the name is left as typed"
            );
            assert!(mail.view == View::All);
        });
        assert_eq!(store.inboxes().unwrap().len(), 2, "nothing was created");

        // Escape closes it, and creates nothing.
        cx.simulate_keystrokes("escape");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert!(mail.draft.is_none()));
        assert_eq!(store.inboxes().unwrap().len(), 2);
        // Focus is back on the list: j opens a message again.
        deliver(&store, "bob@x.test", "Hello", false);
        cx.run_until_parked();
        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert!(mail.selected.is_some()));
    }

    #[gpui::test]
    fn keys_are_created_regenerated_and_revoked_from_connect(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        store.create_inbox("billing-app").unwrap();
        let (view, cx) = open(cx, &store);
        view.update(cx, |mail, cx| {
            mail.set_view(View::Inbox("billing-app".into()), cx)
        });

        view.update(cx, |mail, cx| mail.create_key(cx));
        cx.run_until_parked();
        let key = view.read_with(cx, |mail, _| {
            let (inbox, key) = mail.new_key.clone().expect("the new key is on screen");
            assert_eq!(inbox, "billing-app");
            assert_eq!(mail.keys.len(), 1);
            key.to_string()
        });
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some("billing-app")
        );
        assert_eq!(
            cx.read_from_clipboard().and_then(|item| item.text()),
            Some(key.clone())
        );

        // Regenerating swaps the value under the same key, and shows the new one.
        let key_id = view.read_with(cx, |mail, _| mail.keys[0].id);
        view.update(cx, |mail, cx| {
            mail.confirm_regenerate = Some(key_id);
            mail.regenerate_key(key_id, cx);
        });
        cx.run_until_parked();
        let renewed = view.read_with(cx, |mail, _| {
            assert_eq!(mail.confirm_regenerate, None);
            assert_eq!(mail.keys.len(), 1, "replaced, not added");
            assert_eq!(mail.keys[0].id, key_id);
            mail.new_key
                .clone()
                .expect("the new value is on screen")
                .1
                .to_string()
        });
        assert_ne!(renewed, key);
        assert!(
            store.inbox_for_key(&key).unwrap().is_none(),
            "the old value is dead"
        );
        assert_eq!(
            store.inbox_for_key(&renewed).unwrap().as_deref(),
            Some("billing-app")
        );
        assert_eq!(
            cx.read_from_clipboard().and_then(|item| item.text()),
            Some(renewed.clone())
        );

        // Leaving the inbox takes the key off screen for good.
        view.update(cx, |mail, cx| mail.set_view(View::All, cx));
        view.read_with(cx, |mail, _| assert!(mail.new_key.is_none()));

        view.update(cx, |mail, cx| {
            mail.set_view(View::Inbox("billing-app".into()), cx)
        });
        view.update(cx, |mail, cx| mail.revoke_key(key_id, cx));
        assert!(store.inbox_for_key(&renewed).unwrap().is_none());

        view.update(cx, |mail, cx| mail.delete_open_inbox(cx));
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert!(mail.view == View::All));
        assert_eq!(
            store.inboxes().unwrap().len(),
            1,
            "only the default is left"
        );
    }

    /// The HTML tab previews a body at a device's width. The body's holder is
    /// what is measured here: the webview follows its bounds.
    #[gpui::test]
    fn the_html_tab_previews_at_device_widths(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        deliver(&store, "bob@x.test", "Plain", false);
        deliver(&store, "bob@x.test", "Rich", true);
        let (view, cx) = open(cx, &store);
        cx.simulate_resize(gpui::size(px(1600.), px(900.)));
        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert!(mail.tab == Tab::Html && mail.device == Device::Desktop)
        });

        let bounds = |cx: &mut VisualTestContext, name: &'static str| {
            cx.debug_bounds(name)
                .unwrap_or_else(|| panic!("{name} was not drawn"))
        };
        let choose = |cx: &mut VisualTestContext, device: Device| {
            view.update(cx, |mail, cx| {
                mail.device = device;
                cx.notify();
            });
            cx.run_until_parked();
        };
        let centre = |b: gpui::Bounds<gpui::Pixels>| b.left() + b.size.width / 2.;

        // Desktop fills the pane.
        assert!(
            cx.debug_bounds("device-toggle").is_some(),
            "the control comes with the HTML tab"
        );
        let area = bounds(cx, "body-area");
        assert_eq!(bounds(cx, "body-frame").size.width, area.size.width);
        assert!(
            area.size.width > px(768.),
            "the pane is wide enough to tell the widths apart"
        );

        for (device, width) in [(Device::Tablet, 768.), (Device::Mobile, 375.)] {
            choose(cx, device);
            let frame = bounds(cx, "body-frame");
            // The frame is the device width plus the rule down each side, so
            // that what is inside it is exactly the device width.
            assert_eq!(
                frame.size.width,
                px(width + 2. * DEVICE_FRAME_RULE),
                "{device:?}"
            );
            assert_eq!(
                centre(frame),
                centre(area),
                "{device:?} is centred in the pane"
            );
            assert_eq!(
                frame.size.height, area.size.height,
                "{device:?} uses the full height"
            );
        }

        // The choice is kept from one message to the next, but a width only
        // applies to a rendered HTML body: text fills the pane, with no control.
        cx.simulate_keystrokes("j");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert!(
                mail.tab == Tab::Text,
                "the plain message has no HTML to preview"
            );
            assert_eq!(mail.device, Device::Mobile);
        });
        // gpui keeps the bounds of elements it has stopped drawing, so that the
        // control is gone cannot be read from them. That it is offered with the
        // HTML tab alone is the `tab` check above, and the same test the
        // render makes.
        view.read_with(cx, |mail, _| assert_eq!(mail.preview_width(), None));
        assert_eq!(
            bounds(cx, "body-frame").size.width,
            bounds(cx, "body-area").size.width
        );
        cx.simulate_keystrokes("k");
        cx.run_until_parked();
        assert_eq!(
            bounds(cx, "body-frame").size.width,
            px(375. + 2. * DEVICE_FRAME_RULE),
            "still Mobile on the way back"
        );

        // Back to Desktop restores the full width.
        choose(cx, Device::Desktop);
        assert_eq!(
            bounds(cx, "body-frame").size.width,
            bounds(cx, "body-area").size.width
        );

        // In a pane narrower than the device, the pane's width is the limit.
        choose(cx, Device::Tablet);
        cx.simulate_resize(gpui::size(px(1000.), px(700.)));
        cx.run_until_parked();
        let (area, frame) = (bounds(cx, "body-area"), bounds(cx, "body-frame"));
        assert!(area.size.width < px(768.));
        assert_eq!(
            frame.size.width, area.size.width,
            "never wider than the pane"
        );
    }

    /// The dialog is drawn over the window, so it has to fit the smallest one
    /// the app allows, at its tallest: with an error showing.
    #[gpui::test]
    fn the_new_inbox_dialog_fits_the_smallest_window(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let (view, cx) = open(cx, &store);
        cx.simulate_resize(gpui::size(px(900.), px(520.)));
        open_dialog(&view, cx);
        cx.simulate_input("A name long enough to matter for the layout of the dialog");
        view.update(cx, |mail, cx| {
            mail.draft.as_mut().unwrap().error = Some(
                "an inbox needs a name of 1 to 80 characters, and a description of at most 300"
                    .into(),
            );
            cx.notify();
        });
        cx.run_until_parked();

        let bounds = |cx: &mut VisualTestContext, name: &'static str| {
            cx.debug_bounds(name)
                .unwrap_or_else(|| panic!("{name} was not drawn"))
        };
        let window = bounds(cx, "window");
        let scrim = bounds(cx, "new-inbox-scrim");
        let dialog = bounds(cx, "new-inbox-dialog");
        assert_eq!(
            scrim, window,
            "the scrim covers everything under the dialog"
        );
        assert!(
            dialog.top() >= window.top() && dialog.bottom() <= window.bottom(),
            "{dialog:?} in {window:?}"
        );
        assert!(dialog.left() >= window.left() && dialog.right() <= window.right());

        for part in [
            "new-inbox-id",
            "new-inbox-key",
            "new-inbox-error",
            "new-inbox-cancel",
            "new-inbox-create",
        ] {
            let inner = bounds(cx, part);
            assert!(
                inner.size.width > px(0.) && inner.size.height > px(0.),
                "{part} has no room"
            );
            assert!(
                inner.left() >= dialog.left() && inner.right() <= dialog.right(),
                "{part} runs out of the dialog sideways: {inner:?} in {dialog:?}"
            );
            assert!(
                inner.top() >= dialog.top() && inner.bottom() <= dialog.bottom(),
                "{part} runs out of the dialog: {inner:?} in {dialog:?}"
            );
        }
        let cancel = bounds(cx, "new-inbox-cancel");
        let create = bounds(cx, "new-inbox-create");
        assert!(
            cancel.right() <= create.left(),
            "the buttons do not overlap"
        );
    }

    #[gpui::test]
    fn the_default_inbox_cannot_be_deleted_from_the_app(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let (view, cx) = open(cx, &store);
        view.update(cx, |mail, cx| {
            mail.set_view(View::Inbox("default".into()), cx);
            mail.delete_open_inbox(cx);
        });
        view.read_with(cx, |mail, _| {
            assert!(mail.error.as_ref().unwrap().contains("cannot be deleted"))
        });
        assert_eq!(store.inboxes().unwrap().len(), 1);
    }

    /// A row has to fill the list and fit its three lines whatever they say.
    /// Left to size itself it shrank to a short message's text and let a long
    /// one run off the edge, and lines at the default line height did not fit
    /// the row, so they were squeezed and clipped.
    #[gpui::test]
    fn rows_fill_the_list_and_fit_their_text(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let long = "word ".repeat(60);
        let message = |subject: &str, body: &str| {
            Incoming {
            raw: format!("From: A Sender With Quite A Long Display Name <a@x.test>\r\nTo: b@x.test\r\nSubject: {subject}\r\n\r\n{body}\r\n")
                .into_bytes(),
            inbox: emailulator::store::DEFAULT_INBOX.into(),
            envelope_from: None,
            envelope_to: vec!["b@x.test".into()],
            source: Source::Smtp,
        }
        };
        store
            .insert(message(&format!("A long subject {long}"), &long))
            .unwrap();
        store.insert(message("Short", "ok")).unwrap();
        let (_view, cx) = open(cx, &store);

        let bounds = |cx: &mut VisualTestContext, name: String| {
            let name: &'static str = Box::leak(name.into_boxed_str());
            cx.debug_bounds(name)
                .unwrap_or_else(|| panic!("{name} was not drawn"))
        };
        let pane = bounds(cx, "list-pane".into());

        // Row 0 is the short message, row 1 the long one.
        for row in 0..2 {
            let whole = bounds(cx, format!("row-{row}"));
            let top = bounds(cx, format!("row-{row}-top"));
            let time = bounds(cx, format!("row-{row}-time"));
            let subject = bounds(cx, format!("row-{row}-subject"));
            let snippet = bounds(cx, format!("row-{row}-snippet"));

            // The pane draws a 1px rule down its right side; rows stop at it.
            assert_eq!(
                whole.left(),
                pane.left(),
                "row {row} starts at the pane's edge"
            );
            assert_eq!(
                whole.right(),
                pane.right() - px(1.),
                "row {row} ends at the pane's edge"
            );
            assert_eq!(whole.size.height, px(ROW_HEIGHT));

            for (name, line) in [("top", top), ("subject", subject), ("snippet", snippet)] {
                assert!(
                    line.size.height >= px(ROW_LINE_HEIGHT),
                    "row {row} {name} line is squeezed to {:?}",
                    line.size.height
                );
                assert!(
                    line.right() <= whole.right(),
                    "row {row} {name} runs past the row"
                );
            }
            assert!(
                top.bottom() <= subject.top(),
                "row {row}: sender overlaps subject"
            );
            assert!(
                subject.bottom() <= snippet.top(),
                "row {row}: subject overlaps snippet"
            );
            assert!(
                snippet.bottom() <= whole.bottom(),
                "row {row}: snippet spills out of the row"
            );
            assert!(
                time.right() <= whole.right(),
                "row {row}: the time is pushed out of view"
            );
            assert!(time.size.width > px(0.), "row {row}: the time has no room");
        }
    }

    #[gpui::test]
    fn the_check_tab_reports_what_clients_will_not_render(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let id = store
            .insert(Incoming {
                raw: b"From: a@x.test\r\nTo: b@x.test\r\nSubject: Styled\r\nContent-Type: text/html\r\n\r\n\
                       <div style=\"display:flex\"><p style=\"border-radius:4px\">Hi</p></div>\r\n"
                    .to_vec(),
                inbox: emailulator::store::DEFAULT_INBOX.into(),
                envelope_from: None,
                envelope_to: vec!["b@x.test".into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id;
        let (view, cx) = open(cx, &store);
        cx.simulate_keystrokes("j");
        cx.run_until_parked();

        view.read_with(cx, |mail, _| {
            assert_eq!(mail.selected, Some(id));
            let report = &mail.loaded.as_ref().expect("the message loads").report;
            assert_eq!(
                report.clients.len(),
                CHECKED_CLIENTS.len(),
                "the main clients"
            );
            let flex = report
                .issues
                .iter()
                .find(|issue| issue.slug == "css-display-flex")
                .expect("flexbox is reported");
            assert_eq!(flex.severity, "unsupported");
            assert!(flex.clients.iter().any(|c| c.family == "outlook"));
        });

        // The tab draws without the webview, and stays put on the next message.
        view.update(cx, |mail, cx| {
            mail.tab = Tab::Check;
            cx.notify();
        });
        cx.run_until_parked();
        let pane = cx.debug_bounds("check").expect("the report is drawn");
        assert!(
            pane.size.height > px(100.) && pane.size.width > px(300.),
            "{pane:?}"
        );
        view.read_with(cx, |mail, _| {
            assert!(!mail.body.is_visible(), "no webview over it")
        });

        deliver(&store, "c@x.test", "Plain", false);
        cx.run_until_parked();
        cx.simulate_keystrokes("k");
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert!(mail.tab == Tab::Check, "checking one message after another");
            let report = &mail.loaded.as_ref().unwrap().report;
            assert_eq!(
                report.features_found, 0,
                "a plain-text message has nothing to check"
            );
        });
    }

    #[gpui::test]
    fn mail_arriving_later_shows_up(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        let (view, cx) = open(cx, &store);
        view.read_with(cx, |mail, _| assert_eq!(mail.page.total, 0));

        deliver(&store, "bob@x.test", "Fresh", false);
        cx.run_until_parked();
        view.read_with(cx, |mail, _| {
            assert_eq!(mail.page.total, 1);
            assert_eq!(mail.stats.unread, 1);
            assert_eq!(mail.inboxes[0].unread, 1);
        });
    }
}
