//! The message body pane.
//!
//! gpui draws text but has no HTML engine, so bodies are shown in the system
//! webview, attached to the window as a child view and positioned by a gpui
//! element. Email is untrusted content, and the webview is locked down to
//! match: JavaScript is switched off in the engine, a restrictive
//! Content-Security-Policy is injected ahead of the content, the webview may
//! navigate nowhere, and a link opens in the user's browser only when clicked.

use emailulator::model::Header;

/// What the pane should show.
#[derive(Clone, PartialEq)]
pub enum Body {
    /// An HTML body as prepared by `emailulator::parse::render_html`.
    Html(String),
    /// Text shown verbatim in a monospace face.
    Plain(String),
    Headers(Vec<Header>),
}

/// Forbids everything but passive content. Scripts are also disabled in the
/// webview itself; this covers frames, forms, objects and outbound requests
/// other than images, styles, fonts and media.
const EMAIL_CSP: &str = "default-src 'none'; img-src data: http: https:; \
    media-src data: http: https:; font-src data: http: https:; \
    style-src 'unsafe-inline' http: https:; form-action 'none'";

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// The complete HTML document for a body.
pub fn document(body: &Body, dark: bool) -> String {
    match body {
        // The policy goes first so it is in force before any of the email's own
        // markup is parsed. No doctype: emails are written for quirks mode.
        Body::Html(html) => format!(
            "<meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"{EMAIL_CSP}\">{html}"
        ),
        Body::Plain(text) => page(&format!("<pre>{}</pre>", escape(text)), dark),
        Body::Headers(headers) => {
            let mut rows = String::new();
            for header in headers {
                rows.push_str(&format!(
                    "<tr><th>{}</th><td>{}</td></tr>",
                    escape(&header.name),
                    escape(&header.value)
                ));
            }
            page(&format!("<table>{rows}</table>"), dark)
        }
    }
}

fn page(content: &str, dark: bool) -> String {
    let (text, muted, background) = if dark {
        ("#e7e9ee", "#a1a7b3", "#1f2126")
    } else {
        ("#1c1e23", "#5f6673", "#ffffff")
    };
    format!(
        "<!doctype html><meta charset=\"utf-8\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <style>\
         html{{color-scheme:{scheme}}}\
         body{{margin:14px 20px;color:{text};background:{background};\
         font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}\
         pre{{margin:0;white-space:pre-wrap;word-break:break-word;font:inherit}}\
         table{{border-collapse:collapse}}\
         th{{text-align:left;vertical-align:top;padding:2px 18px 2px 0;color:{muted};\
         font-weight:600;white-space:nowrap}}\
         td{{padding:2px 0;word-break:break-word}}\
         </style>{content}",
        scheme = if dark { "dark" } else { "light" },
    )
}

// The headless test window has no native view to attach a webview to.
#[cfg(all(not(test), any(target_os = "macos", target_os = "windows")))]
mod pane {
    use std::cell::Cell;
    use std::rc::Rc;

    use futures::channel::mpsc::UnboundedSender;
    use gpui::{
        App, Bounds, Element, ElementId, GlobalElementId, InspectorElementId, IntoElement,
        LayoutId, Pixels, Style, Window, relative,
    };
    use wry::dpi::{LogicalPosition, LogicalSize};
    use wry::{NewWindowResponse, Rect, WebView, WebViewBuilder};

    use super::{Body, document};

    fn openable(url: &str) -> bool {
        ["http://", "https://", "mailto:"].iter().any(|scheme| {
            url.len() > scheme.len() && url[..scheme.len()].eq_ignore_ascii_case(scheme)
        })
    }

    pub struct BodyPane {
        webview: Option<Rc<WebView>>,
        failed: bool,
        shown: Option<(Body, bool)>,
        bounds: Rc<Cell<Option<Bounds<Pixels>>>>,
        visible: bool,
        open_url: UnboundedSender<String>,
    }

    impl BodyPane {
        /// `open_url` receives the links the user clicks.
        pub fn new(open_url: UnboundedSender<String>) -> Self {
            Self {
                webview: None,
                failed: false,
                shown: None,
                bounds: Rc::new(Cell::new(None)),
                visible: false,
                open_url,
            }
        }

        fn webview(&mut self, window: &Window) -> Option<Rc<WebView>> {
            if self.webview.is_none() && !self.failed {
                let open_url = self.open_url.clone();
                let built = WebViewBuilder::new()
                    .with_javascript_disabled()
                    .with_visible(false)
                    .with_focused(false)
                    .with_accept_first_mouse(true)
                    // `load_html` lands on about:blank. Nothing else may load in
                    // this view, including whatever a meta refresh points at.
                    .with_navigation_handler(|url| url.starts_with("about:"))
                    // Links carry target=_blank, so a click asks for a new
                    // window. Hand it to the browser instead of opening one.
                    .with_new_window_req_handler(move |url, _features| {
                        if openable(&url) {
                            let _ = open_url.unbounded_send(url);
                        }
                        NewWindowResponse::Deny
                    })
                    .build_as_child(window);
                match built {
                    Ok(webview) => self.webview = Some(Rc::new(webview)),
                    Err(error) => {
                        eprintln!("emailulator: could not create the message view: {error}");
                        self.failed = true;
                    }
                }
            }
            self.webview.clone()
        }

        /// Show `body`, loading it only when it differs from what is shown.
        /// Returns the element that keeps the webview where gpui lays it out,
        /// or `None` when the platform webview is unavailable.
        pub fn show(
            &mut self,
            body: &Body,
            dark: bool,
            window: &Window,
        ) -> Option<impl IntoElement + use<>> {
            let webview = self.webview(window)?;
            if self
                .shown
                .as_ref()
                .is_none_or(|(shown, was_dark)| shown != body || *was_dark != dark)
            {
                if let Err(error) = webview.load_html(&document(body, dark)) {
                    eprintln!("emailulator: could not load the message: {error}");
                }
                self.shown = Some((body.clone(), dark));
            }
            if !self.visible {
                let _ = webview.set_visible(true);
                self.visible = true;
            }
            Some(WebViewElement {
                webview,
                last: self.bounds.clone(),
            })
        }

        /// Whether the system webview was created and is showing a body.
        pub fn is_live(&self) -> bool {
            self.webview.is_some() && !self.failed && self.shown.is_some()
        }

        /// The width the webview was last placed at.
        pub fn width(&self) -> Option<f32> {
            self.bounds.get().map(|bounds| f32::from(bounds.size.width))
        }

        /// Whether the webview is on screen, over whatever gpui has drawn.
        pub fn is_visible(&self) -> bool {
            self.visible
        }

        /// Take the webview off screen: it is a native view above everything
        /// gpui paints, so it has to be hidden explicitly.
        pub fn hide(&mut self) {
            if self.visible
                && let Some(webview) = &self.webview
            {
                let _ = webview.set_visible(false);
                self.visible = false;
            }
        }
    }

    struct WebViewElement {
        webview: Rc<WebView>,
        last: Rc<Cell<Option<Bounds<Pixels>>>>,
    }

    impl IntoElement for WebViewElement {
        type Element = Self;

        fn into_element(self) -> Self::Element {
            self
        }
    }

    impl Element for WebViewElement {
        type RequestLayoutState = ();
        type PrepaintState = ();

        fn id(&self) -> Option<ElementId> {
            None
        }

        fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
            None
        }

        fn request_layout(
            &mut self,
            _id: Option<&GlobalElementId>,
            _inspector_id: Option<&InspectorElementId>,
            window: &mut Window,
            cx: &mut App,
        ) -> (LayoutId, Self::RequestLayoutState) {
            let mut style = Style::default();
            style.size.width = relative(1.).into();
            style.size.height = relative(1.).into();
            (window.request_layout(style, [], cx), ())
        }

        fn prepaint(
            &mut self,
            _id: Option<&GlobalElementId>,
            _inspector_id: Option<&InspectorElementId>,
            _bounds: Bounds<Pixels>,
            _request_layout: &mut Self::RequestLayoutState,
            _window: &mut Window,
            _cx: &mut App,
        ) -> Self::PrepaintState {
        }

        fn paint(
            &mut self,
            _id: Option<&GlobalElementId>,
            _inspector_id: Option<&InspectorElementId>,
            bounds: Bounds<Pixels>,
            _request_layout: &mut Self::RequestLayoutState,
            _prepaint: &mut Self::PrepaintState,
            _window: &mut Window,
            _cx: &mut App,
        ) {
            if self.last.get() == Some(bounds) {
                return;
            }
            self.last.set(Some(bounds));
            let _ = self.webview.set_bounds(Rect {
                position: LogicalPosition::new(
                    f64::from(f32::from(bounds.origin.x)),
                    f64::from(f32::from(bounds.origin.y)),
                )
                .into(),
                size: LogicalSize::new(
                    f64::from(f32::from(bounds.size.width)),
                    f64::from(f32::from(bounds.size.height)),
                )
                .into(),
            });
        }
    }
}

#[cfg(not(all(not(test), any(target_os = "macos", target_os = "windows"))))]
mod pane {
    use futures::channel::mpsc::UnboundedSender;
    use gpui::{Empty, Window};

    use super::Body;

    /// No embeddable webview on this platform; the caller falls back to
    /// drawing text itself.
    pub struct BodyPane;

    impl BodyPane {
        pub fn new(_open_url: UnboundedSender<String>) -> Self {
            Self
        }

        pub fn show(&mut self, _body: &Body, _dark: bool, _window: &Window) -> Option<Empty> {
            None
        }

        pub fn hide(&mut self) {}

        pub fn is_live(&self) -> bool {
            false
        }

        pub fn is_visible(&self) -> bool {
            false
        }

        pub fn width(&self) -> Option<f32> {
            None
        }
    }
}

pub use pane::BodyPane;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_documents_lead_with_the_policy() {
        let doc = document(
            &Body::Html("<html><body><script>x()</script></body></html>".into()),
            false,
        );
        let policy = doc.find("Content-Security-Policy").unwrap();
        let content = doc.find("<html>").unwrap();
        assert!(
            policy < content,
            "the policy must precede the email's markup"
        );
        assert!(doc.contains("default-src 'none'"));
        assert!(
            !doc.contains("script-src"),
            "no directive re-enables scripts"
        );
    }

    #[test]
    fn text_and_headers_are_escaped() {
        let doc = document(
            &Body::Plain("<img src=x onerror=alert(1)> & more".into()),
            true,
        );
        assert!(doc.contains("&lt;img src=x onerror=alert(1)&gt; &amp; more"));
        assert!(!doc.contains("<img"));

        let doc = document(
            &Body::Headers(vec![Header {
                name: "X-<b>".into(),
                value: "\"</td><script>".into(),
            }]),
            false,
        );
        assert!(doc.contains("<th>X-&lt;b&gt;</th>"));
        assert!(doc.contains("&quot;&lt;/td&gt;&lt;script&gt;"));
        assert!(!doc.contains("<script>"));
    }
}
