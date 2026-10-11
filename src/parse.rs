//! Turning raw RFC 5322 bytes into the fields the catcher stores and serves.

use base64::Engine;
use mail_parser::{MessageParser, MessagePart, MimeHeaders, PartType};

use crate::model::{Address, AttachmentMeta, Header, Link};

const SNIPPET_CHARS: usize = 200;

/// Everything read out of one message. Fields are empty rather than absent when
/// the bytes are not parseable mail: the catcher stores whatever it is handed.
#[derive(Debug, Default, Clone)]
pub struct Parsed {
    pub from: Option<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub reply_to: Vec<Address>,
    pub subject: String,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub headers: Vec<Header>,
    pub attachments: Vec<AttachmentMeta>,
}

impl Parsed {
    pub fn snippet(&self) -> String {
        let source = match (&self.text, &self.html) {
            (Some(text), _) => text.clone(),
            (None, Some(html)) => html_to_text(html),
            (None, None) => String::new(),
        };
        let mut snippet = String::new();
        for word in source.split_whitespace() {
            if !snippet.is_empty() {
                snippet.push(' ');
            }
            snippet.push_str(word);
            if snippet.chars().count() >= SNIPPET_CHARS {
                break;
            }
        }
        if snippet.chars().count() > SNIPPET_CHARS {
            snippet = snippet.chars().take(SNIPPET_CHARS).collect();
        }
        snippet
    }

    /// The text searched by free-text queries: the plain body, or the HTML body
    /// reduced to text when that is all there is.
    pub fn search_text(&self) -> String {
        match (&self.text, &self.html) {
            (Some(text), _) => text.clone(),
            (None, Some(html)) => html_to_text(html),
            (None, None) => String::new(),
        }
    }
}

/// Elements that end a line of text. Their boundaries must read as a space.
const BLOCK_TAGS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];

/// An HTML body as plain text, for snippets, search and agents.
///
/// The converter this wraps drops tags without leaving anything behind, so a
/// heading followed by a paragraph came out as `Build passedAll tests green`.
/// A space goes in ahead of every block-level tag first; inline tags are left
/// alone so a word with emphasis inside it stays one word.
pub fn html_to_text(html: &str) -> String {
    let mut spaced = String::with_capacity(html.len() + 64);
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        spaced.push_str(&rest[..at]);
        let tag = &rest[at + 1..];
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if BLOCK_TAGS.contains(&name.as_str()) {
            spaced.push(' ');
        }
        spaced.push('<');
        rest = tag;
    }
    spaced.push_str(rest);
    mail_parser::decoders::html::html_to_text(&spaced)
}

fn addresses(value: Option<&mail_parser::Address<'_>>) -> Vec<Address> {
    let Some(value) = value else {
        return Vec::new();
    };
    value
        .iter()
        .filter_map(|addr| {
            let address = addr.address()?.trim().to_string();
            if address.is_empty() {
                return None;
            }
            Some(Address {
                name: addr
                    .name()
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty()),
                address,
            })
        })
        .collect()
}

fn attachment_meta(index: usize, part: &MessagePart<'_>) -> AttachmentMeta {
    let content_type = match part.content_type() {
        Some(ct) => match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        },
        None => "application/octet-stream".to_string(),
    };
    let inline = part.content_disposition().is_some_and(|d| d.is_inline())
        || matches!(part.body, PartType::InlineBinary(_));
    AttachmentMeta {
        index,
        filename: part.attachment_name().map(str::to_string),
        content_type,
        size: part.contents().len(),
        content_id: part
            .content_id()
            .map(|id| id.trim_matches(['<', '>', ' ']).to_string())
            .filter(|id| !id.is_empty()),
        inline,
    }
}

pub fn parse(raw: &[u8]) -> Parsed {
    let Some(message) = MessageParser::default().parse(raw) else {
        return Parsed {
            text: Some(String::from_utf8_lossy(raw).into_owned()),
            ..Parsed::default()
        };
    };

    // `body_text` and `body_html` convert between the two when one is missing,
    // so check the part itself to report only what the sender actually wrote.
    let text = message.text_bodies().find_map(|part| match &part.body {
        PartType::Text(text) => Some(text.to_string()),
        _ => None,
    });
    let html = message.html_bodies().find_map(|part| match &part.body {
        PartType::Html(html) => Some(html.to_string()),
        _ => None,
    });

    Parsed {
        from: addresses(message.from()).into_iter().next(),
        to: addresses(message.to()),
        cc: addresses(message.cc()),
        bcc: addresses(message.bcc()),
        reply_to: addresses(message.reply_to()),
        subject: message.subject().unwrap_or_default().trim().to_string(),
        date: message.date().map(|d| d.to_rfc3339()),
        message_id: message.message_id().map(str::to_string),
        text,
        html,
        headers: message
            .headers_raw()
            .map(|(name, value)| Header {
                name: name.to_string(),
                value: unfold(value),
            })
            .collect(),
        attachments: message
            .attachments()
            .enumerate()
            .map(|(index, part)| attachment_meta(index, part))
            .collect(),
    }
}

/// Collapse a folded header value onto one line.
fn unfold(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The decoded bytes of one attachment.
pub fn attachment(raw: &[u8], index: usize) -> Option<(AttachmentMeta, Vec<u8>)> {
    let message = MessageParser::default().parse(raw)?;
    let part = message.attachments().nth(index)?;
    Some((attachment_meta(index, part), part.contents().to_vec()))
}

/// The HTML body made self-contained and safe to hand to a sandboxed frame:
/// `cid:` references become `data:` URIs so inline images need no further
/// request, and links open outside the frame.
///
/// This does not sanitize. Whatever serves the result must also forbid script
/// execution, which the HTTP layer does with a `Content-Security-Policy`.
pub fn render_html(raw: &[u8]) -> Option<String> {
    let message = MessageParser::default().parse(raw)?;
    let mut html = message.html_bodies().find_map(|part| match &part.body {
        PartType::Html(html) => Some(html.to_string()),
        _ => None,
    })?;

    for part in message.attachments() {
        let Some(cid) = part.content_id() else {
            continue;
        };
        let cid = cid.trim_matches(['<', '>', ' ']);
        if cid.is_empty() {
            continue;
        }
        let needle = format!("cid:{cid}");
        if !html.contains(&needle) {
            continue;
        }
        let meta = attachment_meta(0, part);
        let data = base64::engine::general_purpose::STANDARD.encode(part.contents());
        html = html.replace(
            &needle,
            &format!("data:{};base64,{data}", meta.content_type),
        );
    }

    Some(format!("<base target=\"_blank\">{html}"))
}

/// Links in a message, HTML anchors first, then bare URLs from the text body
/// that the HTML did not already yield.
pub fn links(parsed: &Parsed) -> Vec<Link> {
    let mut links: Vec<Link> = Vec::new();
    if let Some(html) = &parsed.html {
        links.extend(html_links(html));
    }
    if let Some(text) = &parsed.text {
        for url in text_urls(text) {
            if !links.iter().any(|l| l.url == url) {
                links.push(Link { url, text: None });
            }
        }
    }
    links
}

fn html_links(html: &str) -> Vec<Link> {
    let lower = html.to_ascii_lowercase();
    let mut links = Vec::new();
    let mut at = 0;
    while let Some(found) = lower[at..].find("<a") {
        let start = at + found;
        let Some(tag_end) = lower[start..].find('>').map(|i| start + i) else {
            break;
        };
        at = tag_end + 1;
        // `<a` must be the whole tag name, not the start of `<abbr` or `<area`.
        match lower.as_bytes().get(start + 2) {
            Some(b) if b.is_ascii_whitespace() => {}
            _ => continue,
        }
        let Some(url) = attribute(&html[start..tag_end], "href") else {
            continue;
        };
        let url = decode_entities(url.trim());
        if !(url.starts_with("http://")
            || url.starts_with("https://")
            || url.starts_with("mailto:"))
        {
            continue;
        }
        let close = lower[at..].find("</a").map(|i| at + i).unwrap_or(at);
        let text = strip_tags(&html[at..close]);
        if !links.iter().any(|l: &Link| l.url == url) {
            links.push(Link {
                url,
                text: (!text.is_empty()).then_some(text),
            });
        }
    }
    links
}

/// The value of `name` inside one opening tag.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut at = 0;
    while let Some(found) = lower[at..].find(name) {
        let start = at + found;
        at = start + name.len();
        let preceded = lower[..start].ends_with(|c: char| c.is_ascii_whitespace());
        let rest = tag[at..].trim_start();
        if !preceded || !rest.starts_with('=') {
            continue;
        }
        let rest = rest[1..].trim_start();
        return match rest.chars().next()? {
            quote @ ('"' | '\'') => rest[1..].split(quote).next(),
            _ => rest
                .split(|c: char| c.is_ascii_whitespace() || c == '>')
                .next(),
        };
    }
    None
}

fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    decode_entities(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

fn text_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("http") {
        let candidate = &rest[start..];
        if !(candidate.starts_with("http://") || candidate.starts_with("https://")) {
            rest = &candidate[4..];
            continue;
        }
        let end = candidate
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '`' | '|'))
            .unwrap_or(candidate.len());
        // Sentence punctuation after a URL belongs to the sentence.
        let url = candidate[..end].trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']']);
        if url.len() > "https://".len() && !urls.iter().any(|u| u == url) {
            urls.push(url.to_string());
        }
        rest = &candidate[end..];
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTIPART: &str = concat!(
        "From: Ada Lovelace <ada@example.com>\r\n",
        "To: bob@example.com, \"Carol C\" <carol@example.com>\r\n",
        "Subject: =?utf-8?q?Caf=C3=A9?= menu\r\n",
        "Message-ID: <abc@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: multipart/related; boundary=\"rel\"\r\n",
        "\r\n",
        "--rel\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>Hi <a href=\"https://example.com/reset?token=1&amp;u=2\">Reset <b>now</b></a>",
        "<img src=\"cid:logo@x\"></p>\r\n",
        "--rel\r\n",
        "Content-Type: image/png\r\n",
        "Content-ID: <logo@x>\r\n",
        "Content-Disposition: inline; filename=\"logo.png\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "iVBORw0KGgo=\r\n",
        "--rel--\r\n",
        "--outer\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"menu.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "JVBERi0=\r\n",
        "--outer--\r\n",
    );

    #[test]
    fn parses_headers_bodies_and_attachments() {
        let parsed = parse(MULTIPART.as_bytes());
        assert_eq!(parsed.from.as_ref().unwrap().address, "ada@example.com");
        assert_eq!(
            parsed.from.as_ref().unwrap().name.as_deref(),
            Some("Ada Lovelace")
        );
        assert_eq!(parsed.to.len(), 2);
        assert_eq!(parsed.subject, "Café menu");
        assert!(
            parsed.text.is_none(),
            "an HTML-only message reports no text part"
        );
        assert!(parsed.html.as_ref().unwrap().contains("Reset"));
        assert_eq!(parsed.attachments.len(), 2);
        assert_eq!(parsed.attachments[0].content_id.as_deref(), Some("logo@x"));
        assert!(parsed.attachments[0].inline);
        assert_eq!(parsed.attachments[1].filename.as_deref(), Some("menu.pdf"));
        assert_eq!(parsed.attachments[1].content_type, "application/pdf");
        assert!(parsed.snippet().contains("Reset"));
    }

    #[test]
    fn fetches_attachment_bytes_by_index() {
        let (meta, bytes) = attachment(MULTIPART.as_bytes(), 1).unwrap();
        assert_eq!(meta.filename.as_deref(), Some("menu.pdf"));
        assert_eq!(bytes, b"%PDF-");
        assert!(attachment(MULTIPART.as_bytes(), 9).is_none());
    }

    #[test]
    fn rendered_html_inlines_cid_images() {
        let html = render_html(MULTIPART.as_bytes()).unwrap();
        assert!(html.contains("data:image/png;base64,iVBORw0KGgo="));
        assert!(!html.contains("cid:logo@x"));
        assert!(html.starts_with("<base target=\"_blank\">"));
    }

    #[test]
    fn extracts_links_from_html_and_text() {
        let mut parsed = parse(MULTIPART.as_bytes());
        parsed.text =
            Some("Verify at https://example.com/verify/abc. Thanks (https://example.com/x)".into());
        let found = links(&parsed);
        assert_eq!(found[0].url, "https://example.com/reset?token=1&u=2");
        assert_eq!(found[0].text.as_deref(), Some("Reset now"));
        assert_eq!(found[1].url, "https://example.com/verify/abc");
        assert_eq!(found[2].url, "https://example.com/x");
    }

    #[test]
    fn html_blocks_read_as_separate_words() {
        let text = html_to_text(
            "<h2>Build passed</h2><p>All 412 tests green.<br>See <a href=x>the build</a></p>",
        );
        let words: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(
            words.join(" "),
            "Build passed All 412 tests green. See the build"
        );

        let text = html_to_text("<p>un<b>believ</b>able</p>");
        assert_eq!(
            text.trim(),
            "unbelievable",
            "inline tags do not split a word"
        );

        let html_only = parse(b"From: a@x.test\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n<h1>Hi</h1><p>there</p>\r\n");
        assert_eq!(html_only.snippet(), "Hi there");
    }

    #[test]
    fn unparseable_bytes_are_kept_as_text() {
        let parsed = parse(b"");
        assert_eq!(parsed.subject, "");
        assert!(parsed.attachments.is_empty());
    }
}
