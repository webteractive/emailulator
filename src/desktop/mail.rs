//! The mail client window: mailboxes, message list and reading pane.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use emailulator::model::{
    AttachmentMeta, Link, ListFilter, Mailbox, MessageDetail, MessageSummary, Page, Stats,
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
const ROW_HEIGHT: f32 = 66.;
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
    Mailbox(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Html,
    Text,
    Headers,
    Raw,
    Links,
}

impl Tab {
    const ALL: [Tab; 5] = [Tab::Html, Tab::Text, Tab::Headers, Tab::Raw, Tab::Links];

    fn label(self) -> &'static str {
        match self {
            Tab::Html => "HTML",
            Tab::Text => "Text",
            Tab::Headers => "Headers",
            Tab::Raw => "Raw",
            Tab::Links => "Links",
        }
    }
}

/// Everything read from the store for the open message.
struct Loaded {
    detail: MessageDetail,
    links: Vec<Link>,
    html: Option<String>,
    raw: String,
}

pub struct Mail {
    store: Arc<Store>,
    status: ServerStatus,
    view: View,
    mailboxes: Vec<Mailbox>,
    stats: Stats,
    page: Page,
    limit: usize,
    selected: Option<i64>,
    selected_summary: Option<MessageSummary>,
    loaded: Option<Loaded>,
    tab: Tab,
    confirm_clear: bool,
    notice: Option<SharedString>,
    error: Option<SharedString>,
    /// What the store looked like at the last reload, to notice changes made
    /// by another process.
    fingerprint: (i64, Stats),
    search: Entity<TextInput>,
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
            mailboxes: Vec::new(),
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
            confirm_clear: false,
            notice: None,
            error: None,
            fingerprint: (0, Stats::default()),
            search,
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
    pub fn selftest(&mut self, cx: &mut Context<Self>) {
        if self.page.messages.is_empty() {
            let seeded = self.store.insert(emailulator::store::Incoming {
                raw: b"From: Self-test <selftest@emailulator.test>\r\nTo: you@emailulator.test\r\n\
                       Subject: Self-test\r\nContent-Type: text/html\r\n\r\n\
                       <h1>Self-test</h1><p><a href=\"https://example.test/\">A link</a></p>\r\n"
                    .to_vec(),
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

        cx.spawn(async move |this, cx| {
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
            let error = this.update(cx, |this, _| this.error.clone())?;
            passed &= error.is_none();
            println!(
                "selftest: {} error={error:?}",
                if passed { "passed" } else { "FAILED" }
            );
            if !passed {
                std::process::exit(1);
            }
            cx.update(|cx| cx.quit())
        })
        .detach_and_log_err(cx);
    }

    fn filter(&self, cx: &App) -> ListFilter {
        let query = self.search.read(cx).text().trim().to_string();
        ListFilter {
            mailbox: match &self.view {
                View::Mailbox(address) => Some(address.clone()),
                _ => None,
            },
            starred: (self.view == View::Starred).then_some(true),
            query: (!query.is_empty()).then_some(query),
            limit: Some(self.limit),
            ..Default::default()
        }
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        let filter = self.filter(cx);
        let result = (|| -> anyhow::Result<_> {
            Ok((
                self.store.list(&filter)?,
                self.store.mailboxes()?,
                self.store.stats()?,
                self.store.latest_id()?,
            ))
        })();
        match result {
            Ok((page, mailboxes, stats, latest)) => {
                self.page = page;
                self.mailboxes = mailboxes;
                self.stats = stats;
                self.fingerprint = (latest, stats);
                self.error = None;
            }
            Err(error) => {
                self.error = Some(format!("Could not read the mail store: {error:#}").into())
            }
        }

        // A mailbox disappears with its last message.
        if let View::Mailbox(address) = &self.view
            && !self.mailboxes.iter().any(|m| &m.address == address)
        {
            self.view = View::All;
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
        let current =
            (|| -> anyhow::Result<_> { Ok((self.store.latest_id()?, self.store.stats()?)) })();
        if current.is_ok_and(|current| current != self.fingerprint) {
            self.reload(cx);
        }
    }

    fn set_view(&mut self, view: View, cx: &mut Context<Self>) {
        self.view = view;
        self.limit = PAGE_SIZE;
        self.confirm_clear = false;
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
                        (
                            detail,
                            store.links(id).ok().flatten().unwrap_or_default(),
                            store.rendered_html(id).ok().flatten(),
                            raw,
                        )
                    }))
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.selected != Some(id) {
                    return;
                }
                match loaded {
                    Ok(Some((detail, links, html, raw))) => {
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

    /// The mailbox to act on when the list shows a whole mailbox or all mail,
    /// or `Err` when it shows a subset that has to be handled message by message.
    fn whole_view(&self, cx: &App) -> Result<Option<String>, ListFilter> {
        let filter = self.filter(cx);
        match (&self.view, &filter.query) {
            (View::All, None) => Ok(None),
            (View::Mailbox(address), None) => Ok(Some(address.clone())),
            _ => Err(ListFilter {
                limit: Some(usize::MAX),
                ..filter
            }),
        }
    }

    fn clear_view(&mut self, cx: &mut Context<Self>) {
        let result = match self.whole_view(cx) {
            Ok(mailbox) => self.store.clear(mailbox.as_deref()).map(|_| ()),
            // A search or the starred view: delete exactly what is listed.
            Err(filter) => self.store.list(&filter).and_then(|page| {
                page.messages
                    .iter()
                    .try_for_each(|m| self.store.delete(m.id).map(|_| ()))
            }),
        };
        if let Err(error) = result {
            self.error = Some(format!("Could not delete the messages: {error:#}").into());
        }
        self.confirm_clear = false;
        self.selected = None;
        self.loaded = None;
        self.reload(cx);
    }

    fn mark_view_read(&mut self, cx: &mut Context<Self>) {
        let result = match self.whole_view(cx) {
            Ok(mailbox) => self.store.mark_all_read(mailbox.as_deref()).map(|_| ()),
            Err(filter) => {
                let unread = ListFilter {
                    unread: Some(true),
                    ..filter
                };
                self.store.list(&unread).and_then(|page| {
                    page.messages
                        .iter()
                        .try_for_each(|m| self.store.set_flags(m.id, Some(true), None).map(|_| ()))
                })
            }
        };
        if let Err(error) = result {
            self.error = Some(format!("Could not mark the messages read: {error:#}").into());
        }
        self.reload(cx);
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
        let mailboxes: Vec<_> = self
            .mailboxes
            .iter()
            .enumerate()
            .map(|(index, mailbox)| {
                self.nav_item(
                    ("mailbox", index).into(),
                    "at",
                    mailbox.address.clone().into(),
                    mailbox.unread,
                    View::Mailbox(mailbox.address.clone()),
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
                        "inbox",
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
                    .px_4()
                    .pt_4()
                    .pb_1()
                    .text_size(px(11.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme.faint)
                    .child("MAILBOXES"),
            )
            .child(
                div()
                    .id("mailboxes")
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .children(mailboxes)
                    .when(self.mailboxes.is_empty(), |el| {
                        el.child(
                            div()
                                .px_4()
                                .text_size(px(12.))
                                .text_color(theme.faint)
                                .child("Each address that receives mail gets a mailbox here."),
                        )
                    }),
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

        div()
            .id(("message", id as u64))
            .h(px(ROW_HEIGHT))
            .flex()
            .gap_2()
            .pl_2()
            .pr_3()
            .py_2()
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
                    .gap(px(1.))
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
                                    .font_weight(weight)
                                    .text_color(theme.text)
                                    .child(sender),
                            )
                            .when(message.starred, |el| {
                                el.child(icon("star-filled", theme.star).size(px(12.)))
                            })
                            .when(message.attachment_count > 0, |el| {
                                el.child(icon("paperclip", theme.faint).size(px(12.)))
                            })
                            .child(
                                div()
                                    .flex_none()
                                    .text_size(px(11.))
                                    .text_color(theme.faint)
                                    .child(short_time(message.received_at)),
                            ),
                    )
                    .child(
                        div()
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
            .flex()
            .flex_col()
            .flex_none()
            .w(px(348.))
            .h_full()
            .bg(theme.list)
            .border_r_1()
            .border_color(theme.border)
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
            .mailboxes
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
            });

        let body = match self.tab {
            Tab::Links => None,
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
                self.render_links(&loaded.links, theme, cx)
                    .into_any_element()
            }
            Some(body) => match self.body.show(&body, theme.dark, window) {
                Some(webview) => div().flex_1().min_h_0().child(webview).into_any_element(),
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
                    div()
                        .id("body-text")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .p_5()
                        .text_size(px(13.))
                        .text_color(theme.text)
                        .child(SharedString::from(text))
                        .into_any_element()
                }
            },
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

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.window)
            .text_color(theme.text)
            .on_action(cx.listener(|_, _: &Quit, _, cx| cx.quit()))
            .on_action(cx.listener(|this, _: &Refresh, _, cx| this.reload(cx)))
            .on_action(cx.listener(|this, _: &OpenWebUi, _, cx| this.open_web_ui(cx)))
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                window.focus(&this.search.focus_handle(cx));
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

    fn deliver(store: &Store, to: &str, subject: &str, html: bool) -> i64 {
        let body = if html {
            "Content-Type: text/html\r\n\r\n<p>Hello <a href=\"https://app.test/go\">go</a></p>\r\n"
        } else {
            "\r\nplain body\r\n"
        };
        store
            .insert(Incoming {
                raw: format!("From: App <app@x.test>\r\nTo: {to}\r\nSubject: {subject}\r\n{body}")
                    .into_bytes(),
                envelope_from: None,
                envelope_to: vec![to.into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id
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
            assert_eq!(mail.mailboxes.len(), 1);
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
            assert!(mail.mailboxes.is_empty());
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
        assert_eq!(store.stats().unwrap().total, 2, "and nothing was deleted");

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
    fn views_filter_and_bulk_actions_touch_only_what_is_listed(cx: &mut TestAppContext) {
        let store = Arc::new(Store::in_memory().unwrap());
        deliver(&store, "bob@x.test", "For Bob", false);
        deliver(&store, "bob@x.test", "Also Bob", false);
        let carol = deliver(&store, "carol@x.test", "For Carol", false);
        let (view, cx) = open(cx, &store);

        view.update(cx, |mail, cx| {
            mail.set_view(View::Mailbox("bob@x.test".into()), cx)
        });
        cx.run_until_parked();
        view.read_with(cx, |mail, _| assert_eq!(mail.page.total, 2));

        view.update(cx, |mail, cx| mail.mark_view_read(cx));
        assert_eq!(store.stats().unwrap().unread, 1, "Carol's stays unread");

        view.update(cx, |mail, cx| mail.clear_view(cx));
        cx.run_until_parked();
        assert_eq!(store.stats().unwrap().total, 1);
        assert!(store.get(carol).unwrap().is_some());
        view.read_with(cx, |mail, _| {
            assert!(
                mail.view == View::All,
                "an emptied mailbox falls back to all mail"
            );
            assert_eq!(mail.page.total, 1);
        });

        // Starred is a subset of all mail: clearing it must not clear the store.
        deliver(&store, "dave@x.test", "Keep me", false);
        store.set_flags(carol, None, Some(true)).unwrap();
        view.update(cx, |mail, cx| mail.set_view(View::Starred, cx));
        view.update(cx, |mail, cx| mail.clear_view(cx));
        assert_eq!(store.stats().unwrap().total, 1);
        assert!(store.get(carol).unwrap().is_none());
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
            assert_eq!(mail.mailboxes[0].address, "bob@x.test");
        });
    }
}
