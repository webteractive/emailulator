//! Which email clients will render a message as written.
//!
//! No client can be emulated exactly: Outlook for Windows lays mail out with
//! Word's engine, and Gmail rewrites markup on its servers. What can be known
//! locally is which HTML and CSS features a message uses and which clients
//! support them, and that is what this reports, from the caniemail.com
//! dataset (MIT licensed; see `data/caniemail.LICENSE`).
//!
//! To refresh the dataset:
//! `curl -o data/caniemail.json https://www.caniemail.com/api/data.json`

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::model::MessageDetail;

/// Gmail cuts a message off behind "View entire message" past this size.
const GMAIL_CLIP_BYTES: usize = 102 * 1024;

/// File types Gmail refuses to deliver as attachments; Outlook blocks these
/// and more. Mail carrying one bounces or arrives with the file removed.
const BLOCKED_EXTENSIONS: &[&str] = &[
    "ade",
    "adp",
    "apk",
    "appx",
    "appxbundle",
    "bat",
    "cab",
    "chm",
    "cmd",
    "com",
    "cpl",
    "diagcab",
    "diagcfg",
    "diagpkg",
    "dll",
    "dmg",
    "ex",
    "ex_",
    "exe",
    "hta",
    "img",
    "ins",
    "iso",
    "isp",
    "jar",
    "jnlp",
    "js",
    "jse",
    "lib",
    "lnk",
    "mde",
    "msc",
    "msi",
    "msix",
    "msixbundle",
    "msp",
    "mst",
    "nsh",
    "pif",
    "ps1",
    "scr",
    "sct",
    "shb",
    "sys",
    "vb",
    "vbe",
    "vbs",
    "vhd",
    "vxd",
    "wsc",
    "wsf",
    "wsh",
    "xll",
];

/// The size, as sent, past which the main providers refuse a message.
const SIZE_LIMITS: &[(usize, &str)] = &[
    (20 * 1024 * 1024, "Outlook.com and iCloud Mail (20 MB)"),
    (25 * 1024 * 1024, "Gmail and Yahoo Mail (25 MB)"),
];

/// The clients most mail is read in, in the order to report them. The rest of
/// the dataset's clients follow, by name.
const MAJOR_CLIENTS: &[&str] = &["gmail", "outlook", "apple-mail", "yahoo", "samsung-email"];

// ---------------------------------------------------------------------------
// The dataset
// ---------------------------------------------------------------------------

/// A JSON object read in the order it was written. The dataset lists a
/// client's versions oldest first under keys that do not sort that way
/// (`2019-02` before `16.80`), so the order is the only record of which is
/// the newest.
struct Ordered<V>(Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Ordered<V> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<V> {
            type Value = Ordered<V>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Ordered(entries))
            }
        }
        deserializer.deserialize_map(Visitor(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
struct RawData {
    last_update_date: String,
    nicenames: RawNames,
    data: Vec<RawFeature>,
}

#[derive(Deserialize)]
struct RawNames {
    family: BTreeMap<String, String>,
    platform: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawFeature {
    slug: String,
    title: String,
    category: String,
    url: String,
    /// family -> platform -> version -> support
    stats: BTreeMap<String, BTreeMap<String, Ordered<String>>>,
    #[serde(default)]
    notes_by_num: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Support {
    Yes,
    Partial,
    No,
    Unknown,
}

struct Feature {
    slug: String,
    title: String,
    category: String,
    url: String,
    /// One entry per client platform: its current support and any notes.
    support: Vec<PlatformSupport>,
}

struct PlatformSupport {
    family: String,
    platform: String,
    support: Support,
    notes: Vec<String>,
}

struct Dataset {
    updated: String,
    features: Vec<Feature>,
    by_slug: HashMap<String, usize>,
    /// Client families in reporting order, with their display names.
    families: Vec<(String, String)>,
    platforms: BTreeMap<String, String>,
}

/// A note from the dataset as plain text: its Markdown links become
/// `label (address)` and its code ticks are dropped.
fn plain(note: &str) -> String {
    let mut out = String::with_capacity(note.len());
    let mut rest = note;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        let link = after.find("](").and_then(|mid| {
            let label = &after[..mid];
            let address = &after[mid + 2..];
            let close = address.find(')')?;
            // Brackets that are part of the prose, not the start of a link.
            (!label.contains('[')).then(|| (label, &address[..close], &address[close + 1..]))
        });
        match link {
            Some((label, address, tail)) => {
                out.push_str(&rest[..open]);
                out.push_str(label);
                out.push_str(" (");
                out.push_str(address);
                out.push(')');
                rest = tail;
            }
            None => {
                out.push_str(&rest[..=open]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out.replace('`', "")
}

fn dataset() -> &'static Dataset {
    static DATASET: OnceLock<Dataset> = OnceLock::new();
    DATASET.get_or_init(|| {
        let raw: RawData = serde_json::from_slice(include_bytes!("../data/caniemail.json"))
            .expect("the bundled caniemail dataset is valid; a unit test parses it");
        let mut features = Vec::with_capacity(raw.data.len());
        for feature in raw.data {
            let notes = feature.notes_by_num.unwrap_or_default();
            let mut support = Vec::new();
            for (family, platforms) in feature.stats {
                for (platform, versions) in platforms {
                    // The last version listed is the client as it is today.
                    let Some((_, value)) = versions.0.last() else {
                        continue;
                    };
                    let mut words = value.split_whitespace();
                    let kind = match words.next() {
                        Some("y") => Support::Yes,
                        Some("a") => Support::Partial,
                        Some("n") => Support::No,
                        _ => Support::Unknown,
                    };
                    let notes = words
                        .filter_map(|word| notes.get(word.trim_start_matches('#')))
                        .map(|note| plain(note))
                        .collect();
                    support.push(PlatformSupport {
                        family: family.clone(),
                        platform,
                        support: kind,
                        notes,
                    });
                }
            }
            features.push(Feature {
                slug: feature.slug,
                title: feature.title,
                category: feature.category,
                url: feature.url,
                support,
            });
        }
        let by_slug = features
            .iter()
            .enumerate()
            .map(|(i, f)| (f.slug.clone(), i))
            .collect();

        let mut families: Vec<(String, String)> = Vec::new();
        for major in MAJOR_CLIENTS {
            if let Some(name) = raw.nicenames.family.get(*major) {
                families.push((major.to_string(), name.clone()));
            }
        }
        let mut rest: Vec<_> = raw
            .nicenames
            .family
            .iter()
            .filter(|(id, _)| !MAJOR_CLIENTS.contains(&id.as_str()))
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect();
        rest.sort_by_cached_key(|(_, name)| name.to_lowercase());
        families.extend(rest);

        Dataset {
            updated: raw.last_update_date.chars().take(10).collect(),
            features,
            by_slug,
            families,
            platforms: raw.nicenames.platform,
        }
    })
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The date of the compatibility data this was checked against.
    pub data_updated: String,
    /// How many distinct features the message was found to use.
    pub features_found: usize,
    /// One score per client, most-used clients first.
    pub clients: Vec<ClientScore>,
    /// Features some client does not fully support, most widely broken first.
    pub issues: Vec<Issue>,
    /// Things worth knowing that are not about one feature.
    pub notices: Vec<Notice>,
}

/// How much of what a message uses one client supports. Each feature found is
/// counted once: `supported` on every platform of the client, `unsupported` if
/// it fails on any of them, `partial` if the worst is a caveat, and `unknown`
/// where the dataset has no result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientScore {
    pub family: String,
    pub name: String,
    pub supported: usize,
    pub partial: usize,
    pub unsupported: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub slug: String,
    pub title: String,
    pub category: String,
    /// The caniemail.com page for the feature.
    pub url: String,
    /// How many times the message uses it.
    pub count: usize,
    /// `unsupported` when it does not work at all somewhere in a major client;
    /// `partial` when the worst that happens is a caveat.
    pub severity: &'static str,
    pub clients: Vec<ClientIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientIssue {
    pub family: String,
    pub name: String,
    /// Platforms of this client where the feature does not work.
    pub unsupported: Vec<String>,
    /// Platforms where it works with caveats, which `notes` explain.
    pub partial: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    pub code: &'static str,
    pub message: String,
}

/// How much of a message's HTML the check reads. Email content is hostile,
/// and this runs on the server, so the work is bounded by the input as well as
/// by the scanners being linear. Gmail clips at 102 KB, so a message this long
/// has bigger problems than its CSS.
const MAX_SCANNED: usize = 512 * 1024;

/// How deeply at-rules may nest before the scanner stops descending.
const MAX_CSS_DEPTH: usize = 16;

/// Check a message against every client, or only the named families.
pub fn check(detail: &MessageDetail, only: Option<&[String]>) -> Report {
    let data = dataset();
    let mut found = Found::default();
    if let Some(html) = &detail.html {
        let mut cut = html.len().min(MAX_SCANNED);
        while !html.is_char_boundary(cut) {
            cut -= 1;
        }
        found.truncated = cut < html.len();
        scan_html(&html[..cut], &mut found);
    }
    for attachment in &detail.attachments {
        if attachment.content_type.starts_with("image/") {
            found.image(&attachment.content_type["image/".len()..]);
        }
    }

    let families: Vec<&(String, String)> = data
        .families
        .iter()
        .filter(|(id, _)| only.is_none_or(|only| only.iter().any(|o| o == id)))
        .collect();

    // Keep only what the dataset knows about, in a stable order.
    let mut used: Vec<(&Feature, usize)> = found
        .counts
        .iter()
        .filter_map(|(slug, count)| Some((&data.features[*data.by_slug.get(slug)?], *count)))
        .collect();
    used.sort_by(|a, b| a.0.slug.cmp(&b.0.slug));

    let mut clients: Vec<ClientScore> = families
        .iter()
        .map(|(family, name)| ClientScore {
            family: family.clone(),
            name: name.clone(),
            supported: 0,
            partial: 0,
            unsupported: 0,
            unknown: 0,
        })
        .collect();

    let mut issues = Vec::new();
    for (feature, count) in &used {
        let mut affected = Vec::new();
        for (index, (family, name)) in families.iter().enumerate() {
            let platforms: Vec<&PlatformSupport> = feature
                .support
                .iter()
                .filter(|p| &p.family == family)
                .collect();
            let all = |kind: Support| {
                !platforms.is_empty() && platforms.iter().all(|p| p.support == kind)
            };
            let score = &mut clients[index];
            if platforms.is_empty() || all(Support::Unknown) {
                score.unknown += 1;
                continue;
            }
            if all(Support::Yes) {
                score.supported += 1;
                continue;
            }
            // Broken on any one of a client's platforms is broken for
            // someone reading in that client; caveats alone are partial.
            if platforms.iter().any(|p| p.support == Support::No) {
                score.unsupported += 1;
            } else {
                score.partial += 1;
            }
            let nice = |p: &&PlatformSupport| {
                data.platforms
                    .get(&p.platform)
                    .cloned()
                    .unwrap_or_else(|| p.platform.clone())
            };
            let mut notes: Vec<String> = Vec::new();
            for platform in platforms.iter().filter(|p| p.support != Support::Yes) {
                for note in &platform.notes {
                    if !notes.contains(note) {
                        notes.push(note.clone());
                    }
                }
            }
            affected.push(ClientIssue {
                family: family.clone(),
                name: name.clone(),
                unsupported: platforms
                    .iter()
                    .filter(|p| p.support == Support::No)
                    .map(nice)
                    .collect(),
                partial: platforms
                    .iter()
                    .filter(|p| p.support == Support::Partial)
                    .map(nice)
                    .collect(),
                notes,
            });
        }
        if !affected.is_empty() {
            let broken = affected
                .iter()
                .any(|c| MAJOR_CLIENTS.contains(&c.family.as_str()) && !c.unsupported.is_empty());
            issues.push(Issue {
                slug: feature.slug.clone(),
                title: feature.title.clone(),
                category: feature.category.clone(),
                url: feature.url.clone(),
                count: *count,
                severity: if broken { "unsupported" } else { "partial" },
                clients: affected,
            });
        }
    }
    // What does not work at all in a major client comes first, the more
    // places the higher; caveats follow, ordered the same way.
    let rank = |issue: &Issue| -> (usize, usize, usize) {
        let platforms = |major: bool, pick: fn(&ClientIssue) -> usize| -> usize {
            issue
                .clients
                .iter()
                .filter(|c| MAJOR_CLIENTS.contains(&c.family.as_str()) == major)
                .map(pick)
                .sum()
        };
        (
            platforms(true, |c| c.unsupported.len()),
            platforms(true, |c| c.partial.len()),
            platforms(false, |c| c.unsupported.len() + c.partial.len()),
        )
    };
    issues.sort_by(|a, b| rank(b).cmp(&rank(a)).then_with(|| a.slug.cmp(&b.slug)));

    Report {
        data_updated: data.updated.clone(),
        features_found: used.len(),
        clients,
        issues,
        notices: notices(detail, &found),
    }
}

fn notices(detail: &MessageDetail, found: &Found) -> Vec<Notice> {
    let mut notices = Vec::new();

    // Attachments: what would bounce, and what is too big to send at all.
    let blocked: Vec<&str> = detail
        .attachments
        .iter()
        .filter_map(|attachment| attachment.filename.as_deref())
        .filter(|name| {
            name.rsplit_once('.').is_some_and(|(_, ext)| {
                BLOCKED_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
            })
        })
        .collect();
    if !blocked.is_empty() {
        notices.push(Notice {
            code: "attachment-blocked-type",
            message: format!(
                "{} is a file type Gmail and Outlook refuse to deliver. The message would bounce or arrive without it; send a link instead.",
                blocked.join(", ")
            ),
        });
    }
    let over: Vec<&str> = SIZE_LIMITS
        .iter()
        .filter(|(limit, _)| detail.summary.size > *limit)
        .map(|(_, who)| *who)
        .collect();
    if !over.is_empty() {
        notices.push(Notice {
            code: "message-too-large",
            message: format!(
                "At {:.1} MB as sent, this is over the size limit of {}. Attachments grow by about a third when encoded for mail.",
                detail.summary.size as f64 / (1024.0 * 1024.0),
                over.join(" and ")
            ),
        });
    }
    let unnamed = detail
        .attachments
        .iter()
        .filter(|attachment| !attachment.inline && attachment.filename.is_none())
        .count();
    if unnamed > 0 {
        notices.push(Notice {
            code: "attachment-without-name",
            message: format!(
                "{unnamed} attachment(s) have no filename. Clients will invent one, usually without an extension, and the file will not open on a double-click."
            ),
        });
    }
    if let Some(html) = &detail.html {
        if html.len() > GMAIL_CLIP_BYTES {
            notices.push(Notice {
                code: "gmail-clipping",
                message: format!(
                    "The HTML is {} KB. Gmail clips messages over 102 KB behind a \"View entire message\" link, and anything after the cut, such as an unsubscribe link, is hidden.",
                    html.len() / 1024
                ),
            });
        }
        if detail.text.is_none() {
            notices.push(Notice {
                code: "no-text-part",
                message: "There is no plain-text alternative. Some clients and most spam filters expect one alongside the HTML.".into(),
            });
        }
        if found.images_without_alt > 0 {
            notices.push(Notice {
                code: "images-without-alt",
                message: format!(
                    "{} image(s) have no alt text. Clients that block images until the reader allows them, Outlook among them, will show nothing in their place.",
                    found.images_without_alt
                ),
            });
        }
        if found.truncated {
            notices.push(Notice {
                code: "check-truncated",
                message: format!(
                    "Only the first {} KB of the HTML was checked.",
                    MAX_SCANNED / 1024
                ),
            });
        }
        if found.css_too_deep {
            notices.push(Notice {
                code: "check-css-too-deep",
                message: format!(
                    "Some CSS is nested more than {MAX_CSS_DEPTH} at-rules deep, and what is inside was not checked."
                ),
            });
        }
        if found.conditional_comments > 0 {
            notices.push(Notice {
                code: "outlook-conditional-comments",
                message: format!(
                    "{} Outlook conditional comment(s) were found. Their contents are read by Outlook for Windows only and were not checked.",
                    found.conditional_comments
                ),
            });
        }
    }
    notices
}

// ---------------------------------------------------------------------------
// Finding what a message uses
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Found {
    /// Feature slug -> times used.
    counts: BTreeMap<String, usize>,
    images_without_alt: usize,
    conditional_comments: usize,
    /// The HTML was longer than the check reads.
    truncated: bool,
    /// Some CSS was nested deeper than the check reads.
    css_too_deep: bool,
}

impl Found {
    fn add(&mut self, slug: &str) {
        // Only what the dataset has a page for is worth recording.
        if dataset().by_slug.contains_key(slug) {
            *self.counts.entry(slug.to_string()).or_default() += 1;
        }
    }

    fn image(&mut self, format: &str) {
        let slug = match format {
            "jpeg" | "jpg" | "pjpeg" => "image-jpg",
            "svg+xml" | "svg" => "image-svg",
            "x-icon" | "vnd.microsoft.icon" | "ico" => "image-ico",
            "heic" | "heif" => "image-heif",
            "tif" | "tiff" => "image-tiff",
            other => return self.add(&format!("image-{other}")),
        };
        self.add(slug);
    }

    fn image_url(&mut self, url: &str) {
        let url = url.trim();
        if let Some(rest) = url.strip_prefix("data:") {
            self.add("image-base64");
            if let Some(format) = rest.strip_prefix("image/") {
                let format: String = format
                    .chars()
                    .take_while(|c| !matches!(c, ';' | ','))
                    .collect();
                self.image(&format);
            }
            return;
        }
        let path = url.split(['?', '#']).next().unwrap_or_default();
        if let Some((_, tail)) = path.rsplit_once('.') {
            // Up to whatever follows the extension, such as `;v=1`.
            let extension: String = tail
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase();
            if (2..=5).contains(&extension.len()) {
                self.image(&extension);
            }
        }
    }
}

const SEMANTIC_ELEMENTS: &[&str] = &[
    "article",
    "aside",
    "details",
    "figcaption",
    "figure",
    "footer",
    "header",
    "main",
    "mark",
    "nav",
    "section",
    "summary",
    "time",
];

fn scan_html(html: &str, found: &mut Found) {
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut at = 0;
    while let Some(offset) = lower[at..].find('<') {
        let start = at + offset;
        let rest = &lower[start..];
        if rest.starts_with("<!--") {
            // Conditional comments are markup only Outlook reads.
            if rest.starts_with("<!--[if") {
                found.conditional_comments += 1;
            } else {
                found.add("html-comments");
            }
            at = rest.find("-->").map_or(lower.len(), |end| start + end + 3);
            continue;
        }
        if rest.starts_with("<!doctype") {
            found.add("html-doctype");
        }
        let Some(end) = tag_end(bytes, start) else {
            break;
        };
        let tag = &html[start + 1..end];
        at = end + 1;
        if tag.starts_with(['/', '!', '?']) {
            continue;
        }
        let name: String = tag
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let attributes = attributes(&tag[name.len()..]);
        element(&name, &attributes, found);

        // The contents of these are not markup.
        if name == "style" || name == "script" {
            let close = format!("</{name}");
            let body_end = lower[at..].find(&close).map_or(lower.len(), |i| at + i);
            if name == "style" {
                scan_css(&html[at..body_end], found);
            }
            at = body_end;
        }
    }
}

/// The index of the `>` that closes the tag opening at `start`, skipping any
/// inside a quoted attribute value.
fn tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (i, byte) in bytes.iter().enumerate().skip(start + 1) {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(*byte),
            (Some(open), close) if open == *close => quote = None,
            (None, b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

/// The attributes of a tag, names lowercased, as written after the tag name.
fn attributes(text: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let mut rest = text.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
    while !rest.is_empty() {
        let before = rest.len();
        let name_end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '=' | '/' | '>'))
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            match after.chars().next() {
                Some(quote @ ('"' | '\'')) => {
                    let inner = &after[1..];
                    let close = inner.find(quote).unwrap_or(inner.len());
                    value = inner[..close].to_string();
                    rest = inner.get(close + 1..).unwrap_or_default();
                }
                _ => {
                    let close = after.find(char::is_whitespace).unwrap_or(after.len());
                    value = after[..close].trim_end_matches('/').to_string();
                    rest = &after[close..];
                }
            }
        }
        if !name.is_empty() {
            attributes.push((name, value));
        }
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        // A quote or `>` where a name should be, such as in `<a '>'>`, is not
        // an attribute. Step over it rather than stand still.
        if rest.len() == before {
            rest = &rest[rest.chars().next().map_or(0, char::len_utf8)..];
        }
    }
    attributes
}

fn element(name: &str, attributes: &[(String, String)], found: &mut Found) {
    let get = |wanted: &str| {
        attributes
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_str())
    };

    match name {
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => found.add("html-h1-h6"),
        "ul" | "ol" | "li" | "dl" | "dt" | "dd" => found.add("html-lists"),
        "map" | "area" => found.add("html-image-maps"),
        "button" => match get("type").map(str::to_ascii_lowercase).as_deref() {
            Some("reset") => found.add("html-button-reset"),
            _ => found.add("html-button-submit"),
        },
        "input" => {
            let kind = get("type")
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| "text".into());
            found.add(&format!("html-input-{kind}"));
        }
        "meta" if get("name").is_some_and(|n| n.eq_ignore_ascii_case("color-scheme")) => {
            found.add("html-meta-color-scheme")
        }
        "a" => {
            if let Some(href) = get("href") {
                let href = href.trim().to_ascii_lowercase();
                if href.starts_with('#') {
                    found.add("html-anchor-links");
                } else if href.starts_with("mailto:") {
                    found.add("html-mailto-links");
                }
            }
        }
        "img" => {
            found.add("html-img");
            if get("alt").is_none() {
                found.images_without_alt += 1;
            }
            if let Some(src) = get("src") {
                found.image_url(src);
            }
        }
        "source" => {
            if let Some(kind) = get("type").and_then(|t| t.strip_prefix("image/")) {
                found.image(&kind.to_ascii_lowercase());
            }
        }
        name if SEMANTIC_ELEMENTS.contains(&name) => found.add("html-semantics"),
        "html"
            if attributes
                .iter()
                .any(|(a, _)| a == "amp4email" || a == "⚡4email") =>
        {
            found.add("amp")
        }
        name => found.add(&format!("html-{name}")),
    }

    for (attribute, value) in attributes {
        match attribute.as_str() {
            "style" => declarations(value, found),
            "srcset" | "sizes" => found.add("html-srcset"),
            "loading" => found.add("html-loading-attribute"),
            "command" | "commandfor" => found.add("html-command-attribute"),
            "inert" => found.add("css-inert-attribute"),
            "background" => {
                found.add("html-background");
                found.image_url(value);
            }
            "align" | "valign" | "cellpadding" | "cellspacing" | "width" | "height" | "dir"
            | "lang" | "role" | "hidden" | "required" | "target" | "popover" => {
                found.add(&format!("html-{attribute}"))
            }
            aria if aria.starts_with("aria-") => found.add(&format!("html-{aria}")),
            _ => {}
        }
    }
}

/// A stylesheet: rules, and at-rules that may hold more rules.
fn scan_css(css: &str, found: &mut Found) {
    let css = strip_comments(css, found);
    scan_rules(&css, 0, found);
}

/// Rules at one level of nesting. Deeper than `MAX_CSS_DEPTH` is not read: a
/// stylesheet of nothing but `@media{` would otherwise exhaust the stack.
fn scan_rules(css: &str, depth: usize, found: &mut Found) {
    let mut rest = css;
    loop {
        rest = rest.trim_start();
        let Some(stop) = rest.find(['{', ';']) else {
            break;
        };
        let prelude = rest[..stop].trim();
        if rest.as_bytes()[stop] == b';' {
            // A statement with no block, such as @import, or a stray semicolon.
            if prelude.starts_with('@') {
                at_rule(prelude, found);
            }
            rest = &rest[stop + 1..];
            continue;
        }
        let body_start = stop + 1;
        let body_end = block_end(rest, body_start);
        let body = &rest[body_start..body_end];
        if prelude.starts_with('@') {
            // Rules nest inside these; the others hold declarations or frames.
            match at_rule(prelude, found) {
                "media" | "supports" | "layer" | "container" => {
                    if depth < MAX_CSS_DEPTH {
                        scan_rules(body, depth + 1, found);
                    } else {
                        found.css_too_deep = true;
                    }
                }
                "font-face" | "page" => declarations(body, found),
                _ => {}
            }
        } else {
            selectors(prelude, found);
            declarations(body, found);
        }
        rest = rest.get(body_end + 1..).unwrap_or_default();
    }
}

fn strip_comments(css: &str, found: &mut Found) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        found.add("css-comments");
        rest = rest[start + 2..]
            .find("*/")
            .map_or("", |end| &rest[start + 2 + end + 2..]);
    }
    out.push_str(rest);
    out
}

/// Where the block opened just before `start` closes.
fn block_end(text: &str, start: usize) -> usize {
    let mut depth = 1;
    for (i, c) in text[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return start + i;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// Record an at-rule and return its name.
fn at_rule<'a>(prelude: &'a str, found: &mut Found) -> &'a str {
    let Some(after) = prelude.strip_prefix('@') else {
        return "";
    };
    let name_end = after
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(after.len());
    let name = &after[..name_end];
    let condition = after[name_end..].to_ascii_lowercase();
    match name.to_ascii_lowercase().as_str() {
        "media" => {
            found.add("css-at-media");
            for (needle, slug) in [
                ("prefers-color-scheme", "css-at-media-prefers-color-scheme"),
                (
                    "prefers-reduced-motion",
                    "css-at-media-prefers-reduced-motion",
                ),
                ("orientation", "css-at-media-orientation"),
                ("device-pixel-ratio", "css-at-media-device-pixel-ratio"),
                ("resolution", "css-at-media-device-pixel-ratio"),
                ("hover", "css-at-media-hover"),
            ] {
                if condition.contains(needle) {
                    found.add(slug);
                }
            }
        }
        other => found.add(&format!("css-at-{other}")),
    }
    name
}

fn selectors(list: &str, found: &mut Found) {
    let lower = list.to_ascii_lowercase();
    if lower.contains(',') {
        found.add("css-selector-grouping");
    }
    for selector in lower.split(',') {
        let selector = selector.trim();
        let mut previous = ' ';
        let mut in_compound = 0;
        let mut chars = selector.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '[' => {
                    found.add("css-selector-attribute");
                    in_compound += 1;
                    // Whatever is quoted in the brackets is not selector syntax.
                    for (_, inner) in chars.by_ref() {
                        if inner == ']' {
                            break;
                        }
                    }
                }
                '*' => found.add("css-selector-universal"),
                '>' => found.add("css-selector-child"),
                '+' => found.add("css-selector-adjacent-sibling"),
                '~' => found.add("css-selector-general-sibling"),
                '.' => {
                    found.add("css-selector-class");
                    in_compound += 1;
                }
                '#' => {
                    found.add("css-selector-id");
                    in_compound += 1;
                }
                ':' => {
                    let element = chars.peek().is_some_and(|(_, next)| *next == ':');
                    if element {
                        chars.next();
                    }
                    let from = i + if element { 2 } else { 1 };
                    let name: String = selector[from..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                        .collect();
                    // The four that predate the double colon are still written with one.
                    let kind = if element
                        || matches!(
                            name.as_str(),
                            "after" | "before" | "first-letter" | "first-line"
                        ) {
                        "element"
                    } else {
                        "class"
                    };
                    found.add(&format!("css-pseudo-{kind}-{name}"));
                }
                c if c.is_whitespace() => {
                    if in_compound > 1 {
                        found.add("css-selector-chaining");
                    }
                    in_compound = 0;
                    // A space between two compounds, not around a combinator.
                    // Looked ahead from the first space of a run only, so a
                    // long run is crossed once rather than once per space.
                    if !matches!(previous, '>' | '+' | '~' | ' ')
                        && selector[i..]
                            .trim_start()
                            .chars()
                            .next()
                            .is_some_and(|n| !matches!(n, '>' | '+' | '~'))
                    {
                        found.add("css-selector-descendant");
                    }
                }
                c if c.is_ascii_alphabetic() && matches!(previous, ' ' | '>' | '+' | '~') => {
                    found.add("css-selector-type");
                    in_compound += 1;
                }
                _ => {}
            }
            previous = if c.is_whitespace() { ' ' } else { c };
        }
        if in_compound > 1 {
            found.add("css-selector-chaining");
        }
    }
}

/// A block of `property: value` pairs, as in a rule or a style attribute.
fn declarations(block: &str, found: &mut Found) {
    let mut depth = 0;
    let mut start = 0;
    let mut pieces = Vec::new();
    for (i, c) in block.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            // A semicolon inside url(...) belongs to the value.
            ';' if depth <= 0 => {
                pieces.push(&block[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&block[start..]);

    for piece in pieces {
        let Some((property, value)) = piece.split_once(':') else {
            continue;
        };
        let property = property.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        if property.is_empty() || value.is_empty() {
            continue;
        }
        if property.starts_with("--") {
            found.add("css-variables");
        } else {
            self::property(&property, &value, found);
        }
        self::value(&value, found);
        if property.contains("background")
            || property == "list-style-image"
            || property == "mask-image"
        {
            for url in urls(&value) {
                found.image_url(url);
            }
        }
    }
}

fn property(property: &str, value: &str, found: &mut Found) {
    let slug: String = match property {
        "display" => {
            if value.contains("flex") {
                "css-display-flex".into()
            } else if value.contains("grid") {
                "css-display-grid".into()
            } else if value.starts_with("none") {
                "css-display-none".into()
            } else {
                "css-display".into()
            }
        }
        "top" | "right" | "bottom" | "left" => "css-left-right-top-bottom".into(),
        "word-wrap" => "css-word-wrap".into(),
        "inline-size" => "css-inline-size".into(),
        "block-size" => "css-block-inline-size".into(),
        "font-family" | "font-style" | "font-variant" => "css-font".into(),
        "color" => return,
        p if p.starts_with("border-") && p.ends_with("-radius") => {
            if p.contains("start") || p.contains("end") {
                "css-border-radius-logical".into()
            } else {
                "css-border-radius".into()
            }
        }
        p if p.starts_with("border-inline") || p.starts_with("border-block") => {
            "css-border-inline-block".into()
        }
        "border-collapse" | "border-spacing" | "border-image" | "border-radius" => {
            format!("css-{property}")
        }
        p if p.starts_with("border") => "css-border".into(),
        p if p.starts_with("margin-inline-") => "css-margin-inline-start-end".into(),
        p if p.starts_with("margin-block-") => "css-margin-block-start-end".into(),
        "margin-inline" | "margin-block" => "css-margin-inline-block".into(),
        p if p.starts_with("margin") => "css-margin".into(),
        p if p.starts_with("padding-inline-") => "css-padding-inline-start-end".into(),
        p if p.starts_with("padding-block-") => "css-padding-block-start-end".into(),
        "padding-inline" | "padding-block" => "css-padding-inline-block".into(),
        p if p.starts_with("padding") => "css-padding".into(),
        p if p.starts_with("overflow-") && p != "overflow-wrap" => "css-overflow".into(),
        p if p.starts_with("grid-template") => "css-grid-template".into(),
        p if p.starts_with("animation") => "css-animation".into(),
        p if p.starts_with("transition") => "css-transition".into(),
        p if p.starts_with("scroll-snap") => "css-scroll-snap".into(),
        p if p.starts_with("outline-") && p != "outline-offset" => "css-outline".into(),
        "columns" | "column-gap" | "column-width" | "column-rule" | "column-span"
        | "column-fill" => "css-column-layout-properties".into(),
        "row-gap" => "css-gap".into(),
        other => format!("css-{other}"),
    };
    found.add(&slug);
}

/// Things a value can use whatever property it is on.
fn value(value: &str, found: &mut Found) {
    if value.contains("!important") {
        found.add("css-important");
    }
    for (needle, slug) in [
        ("var(", "css-variables"),
        ("calc(", "css-unit-calc"),
        ("clamp(", "css-function-clamp"),
        ("light-dark(", "css-function-light-dark"),
        ("linear-gradient(", "css-linear-gradient"),
        ("radial-gradient(", "css-radial-gradient"),
        ("conic-gradient(", "css-conic-gradient"),
        ("rgba(", "css-rgba"),
        ("rgb(", "css-rgb"),
        ("system-ui", "css-sytem-ui"),
    ] {
        if value.contains(needle) {
            found.add(slug);
        }
    }
    if ["lch(", "lab(", "oklch(", "oklab(", "hwb(", "color("]
        .iter()
        .any(|f| value.contains(f))
    {
        found.add("css-modern-color");
    }
    // `min(` and `max(` as functions, not as the tail of `minmax(` or `vmin`.
    for (function, slug) in [("min(", "css-function-min"), ("max(", "css-function-max")] {
        let standalone = value
            .match_indices(function)
            .any(|(i, _)| !value[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '-'));
        if standalone {
            found.add(slug);
        }
    }
    if value.split_whitespace().any(|word| word == "initial") {
        found.add("css-unit-initial");
    }

    // Units: letters, or a percent sign, directly after a number. Each run of
    // digits and dots is read once.
    let bytes = value.as_bytes();
    let mut seen: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
            continue;
        }
        let number_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        // Skip digits inside a name or a hex colour, and a dot with no digits.
        if !bytes[number_start..i].iter().any(u8::is_ascii_digit)
            || bytes[i - 1] == b'.'
            || (number_start > 0 && matches!(bytes[number_start - 1], b'#' | b'a'..=b'z' | b'_'))
        {
            continue;
        }
        let after = &value[i..];
        // No unit is longer than four letters; read no further than that.
        let unit: &str = if after.starts_with('%') {
            "percent"
        } else {
            let end = after
                .bytes()
                .take(5)
                .take_while(u8::is_ascii_alphabetic)
                .count();
            &after[..end]
        };
        if matches!(
            unit,
            "px" | "em"
                | "rem"
                | "pt"
                | "pc"
                | "in"
                | "cm"
                | "mm"
                | "ex"
                | "ch"
                | "vw"
                | "vh"
                | "vmin"
                | "vmax"
                | "percent"
        ) && !seen.contains(&unit)
        {
            seen.push(unit);
            found.add(&format!("css-unit-{unit}"));
        }
    }
}

/// The addresses inside each `url(...)` of a value, read in one pass: each
/// search starts after the last address found.
fn urls(value: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = value;
    while let Some(at) = rest.find("url(") {
        let inner = &rest[at + 4..];
        let Some(end) = inner.find(')') else {
            break;
        };
        found.push(inner[..end].trim().trim_matches(['"', '\'']));
        rest = &inner[end + 1..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MessageSummary, Source};

    fn message(html: Option<&str>, text: Option<&str>) -> MessageDetail {
        MessageDetail {
            summary: MessageSummary {
                id: 1,
                received_at: 0,
                from: None,
                to: Vec::new(),
                cc: Vec::new(),
                subject: String::new(),
                snippet: String::new(),
                size: 0,
                read: false,
                starred: false,
                attachment_count: 0,
                inbox: "default".into(),
                inbox_name: "Default".into(),
                recipients: Vec::new(),
                source: Source::Smtp,
            },
            envelope_from: None,
            bcc: Vec::new(),
            reply_to: Vec::new(),
            date: None,
            message_id: None,
            text: text.map(str::to_string),
            html: html.map(str::to_string),
            headers: Vec::new(),
            attachments: Vec::new(),
        }
    }

    fn found(html: &str) -> Vec<String> {
        let mut found = Found::default();
        scan_html(html, &mut found);
        found.counts.into_keys().collect()
    }

    fn uses(html: &str, slug: &str) -> bool {
        found(html).iter().any(|s| s == slug)
    }

    #[test]
    fn the_bundled_dataset_loads() {
        let data = dataset();
        assert!(
            data.features.len() > 250,
            "{} features",
            data.features.len()
        );
        assert_eq!(data.updated.len(), 10, "a date: {}", data.updated);
        let families: Vec<_> = data
            .families
            .iter()
            .take(5)
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(families, MAJOR_CLIENTS, "the major clients lead");
        assert!(data.families.len() > 15);

        // Outlook for Windows still cannot do flexbox; Apple Mail can.
        let flex = &data.features[data.by_slug["css-display-flex"]];
        let on = |family: &str, platform: &str| {
            flex.support
                .iter()
                .find(|p| p.family == family && p.platform == platform)
                .map(|p| p.support)
        };
        assert_eq!(on("outlook", "windows"), Some(Support::No));
        assert_eq!(on("apple-mail", "macos"), Some(Support::Yes));
        // The newest version is the last one listed, not the one that sorts last.
        assert_eq!(
            on("outlook", "ios"),
            Some(Support::Yes),
            "partial in 2019, supported since"
        );
    }

    #[test]
    fn notes_lose_their_markdown() {
        assert_eq!(
            plain(
                "Use `RoundRect`. See [buttons.cm](https://buttons.cm/) and [docs](https://x.test/a)."
            ),
            "Use RoundRect. See buttons.cm (https://buttons.cm/) and docs (https://x.test/a)."
        );
        assert_eq!(
            plain("Not with `a[href]` selectors."),
            "Not with a[href] selectors."
        );
        assert_eq!(plain("plain"), "plain");
    }

    #[test]
    fn finds_what_inline_styles_use() {
        let html = r#"<div style="display:flex; border-radius: 4px; padding-left:2rem; background:url('a.webp;v=1') no-repeat; color: #fff; width: calc(100% - 10px) !important">x</div>"#;
        let found = found(html);
        for slug in [
            "html-div",
            "css-display-flex",
            "css-border-radius",
            "css-padding",
            "css-background",
            "image-webp",
            "css-width",
            "css-unit-calc",
            "css-unit-rem",
            "css-unit-px",
            "css-unit-percent",
            "css-important",
        ] {
            assert!(found.iter().any(|s| s == slug), "{slug} in {found:?}");
        }
        assert!(
            !found.iter().any(|s| s == "css-display"),
            "flex is not plain display"
        );
    }

    #[test]
    fn finds_what_a_stylesheet_uses() {
        let html = r#"<html><head><style>
            /* layout */
            @import url("more.css");
            @media (prefers-color-scheme: dark) and (max-width: 600px) {
              .card > p:hover, #main a::after { color: rgba(0,0,0,.5); gap: 8px }
            }
            @font-face { font-family: X; src: url(x.woff2) }
            td.a.b + td[lang] ~ * { display: grid; margin-inline-start: 1em }
            p:first-child { text-decoration: underline }
        </style></head><body><p>x</p></body></html>"#;
        let found = found(html);
        for slug in [
            "html-style",
            "css-comments",
            "css-at-import",
            "css-at-media",
            "css-at-media-prefers-color-scheme",
            "css-at-font-face",
            "css-selector-class",
            "css-selector-child",
            "css-selector-id",
            "css-selector-type",
            "css-selector-descendant",
            "css-selector-grouping",
            "css-selector-chaining",
            "css-selector-adjacent-sibling",
            "css-selector-general-sibling",
            "css-selector-attribute",
            "css-selector-universal",
            "css-pseudo-class-hover",
            "css-pseudo-element-after",
            "css-pseudo-class-first-child",
            "css-rgba",
            "css-gap",
            "css-display-grid",
            "css-margin-inline-start-end",
            "css-text-decoration",
            "css-unit-em",
        ] {
            assert!(found.iter().any(|s| s == slug), "{slug} in {found:?}");
        }
    }

    #[test]
    fn finds_elements_attributes_and_images() {
        let html = r##"<!DOCTYPE html><!-- note --><table align="center" cellpadding="0" role="presentation">
            <tr><td valign="top" background="bg.gif"><h2>Hi</h2>
            <img src="logo.svg?v=2" alt="Logo"><img src="data:image/png;base64,AAAA">
            <picture><source type="image/avif" srcset="a.avif"></picture>
            <a href="#top" target="_blank">up</a><a href="mailto:a@b.c">mail</a>
            <video src="v.mp4"></video><button type="reset">r</button><input type="checkbox">
            <section aria-label="x"><ul><li>one</li></ul></section></td></tr></table>"##;
        let found = found(html);
        for slug in [
            "html-doctype",
            "html-comments",
            "html-table",
            "html-align",
            "html-cellpadding",
            "html-role",
            "html-valign",
            "html-background",
            "image-gif",
            "html-h1-h6",
            "html-img",
            "image-svg",
            "image-base64",
            "image-png",
            "html-picture",
            "image-avif",
            "html-srcset",
            "html-anchor-links",
            "html-target",
            "html-mailto-links",
            "html-video",
            "html-button-reset",
            "html-input-checkbox",
            "html-semantics",
            "html-aria-label",
            "html-lists",
        ] {
            assert!(found.iter().any(|s| s == slug), "{slug} in {found:?}");
        }
    }

    #[test]
    fn markup_inside_strings_comments_and_scripts_is_not_mistaken_for_features() {
        assert!(!uses(r#"<p title="<video>">x</p>"#, "html-video"));
        assert!(!uses("<!-- <video></video> -->", "html-video"));
        assert!(!uses("<script>var a = '<video>';</script>", "html-video"));
        assert!(
            !uses(r#"<p style="color:#123456">x</p>"#, "css-unit-px"),
            "a hex colour has no unit"
        );
        assert!(!uses(
            r#"<p style="grid-template-columns: minmax(1px, 2px)">x</p>"#,
            "css-function-max"
        ));
        assert!(uses(
            r#"<p style="width: max(1px, 2px)">x</p>"#,
            "css-function-max"
        ));
        // Conditional comments are counted apart, and their contents left alone.
        let mut found = Found::default();
        scan_html(
            "<!--[if mso]><table><tr><td><![endif]--><p>x</p>",
            &mut found,
        );
        assert_eq!(found.conditional_comments, 1);
        assert!(!found.counts.contains_key("html-table"));
    }

    #[test]
    fn reports_who_cannot_render_what() {
        let html = r#"<div style="display:flex"><p style="border-radius:4px">Hi</p></div>"#;
        let report = check(&message(Some(html), Some("Hi")), None);
        assert!(report.features_found >= 4, "{}", report.features_found);
        assert_eq!(report.clients[0].family, "gmail");
        assert_eq!(report.clients[1].family, "outlook");

        let flex = report
            .issues
            .iter()
            .find(|i| i.slug == "css-display-flex")
            .expect("flex is an issue");
        assert_eq!(flex.severity, "unsupported");
        // What is broken outright is listed before what merely has caveats.
        let first_partial = report.issues.iter().position(|i| i.severity == "partial");
        let last_broken = report
            .issues
            .iter()
            .rposition(|i| i.severity == "unsupported");
        if let (Some(partial), Some(broken)) = (first_partial, last_broken) {
            assert!(broken < partial, "unsupported issues lead the list");
        }
        assert_eq!(flex.title, "display:flex");
        assert!(flex.url.starts_with("https://www.caniemail.com/features/"));
        let outlook = flex
            .clients
            .iter()
            .find(|c| c.family == "outlook")
            .expect("Outlook has trouble with it");
        assert!(
            outlook.unsupported.iter().any(|p| p == "Windows"),
            "{outlook:?}"
        );
        assert!(
            !flex.clients.iter().any(|c| c.family == "apple-mail"),
            "Apple Mail supports it fully"
        );

        // The scores account for every feature found, for every client.
        for client in &report.clients {
            let total = client.supported + client.partial + client.unsupported + client.unknown;
            assert_eq!(total, report.features_found, "{}", client.name);
        }
        let outlook = report
            .clients
            .iter()
            .find(|c| c.family == "outlook")
            .unwrap();
        assert!(
            outlook.unsupported >= 2,
            "flexbox and round corners fail on Windows: {outlook:?}"
        );
        assert!(report.notices.is_empty(), "{:?}", report.notices);
    }

    #[test]
    fn can_be_limited_to_named_clients() {
        let html = r#"<div style="display:flex">x</div>"#;
        let only = vec!["outlook".to_string()];
        let report = check(&message(Some(html), Some("x")), Some(&only));
        assert_eq!(report.clients.len(), 1);
        assert!(
            report
                .issues
                .iter()
                .all(|i| i.clients.iter().all(|c| c.family == "outlook"))
        );
    }

    #[test]
    fn hostile_markup_is_read_in_bounded_time_and_without_panicking() {
        let style = |css: &str| format!("<style>{css}</style>");
        let cases = [
            // Once an endless loop in the attribute reader.
            "<a '>'>".to_string(),
            "<img src=a.png \"b>\">".to_string(),
            // Once a stack overflow, nesting without end.
            style(&"@media{".repeat(50_000)),
            // Once quadratic: a long number, a long run of spaces in a
            // selector, and url( inside url( inside url(.
            format!("<p style=\"width:{}\">", "1".repeat(400_000)),
            style(&format!("a{}b{{}}", " ".repeat(400_000))),
            format!("<p style=\"background:{}\">", "url(".repeat(100_000)),
            // Once panics: a statement that is not an at-rule.
            style(";"),
            style("é;"),
            style("a{};"),
        ];
        for html in cases {
            let started = std::time::Instant::now();
            check(&message(Some(&html), Some("x")), None);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "took {:?} on input starting {:?}",
                started.elapsed(),
                &html[..html.len().min(40)]
            );
        }
    }

    #[test]
    fn css_nested_past_the_limit_is_noted_not_read() {
        let html = format!(
            "<style>{}a{{display:grid}}{}</style>",
            "@media screen{".repeat(MAX_CSS_DEPTH + 1),
            "}".repeat(MAX_CSS_DEPTH + 1)
        );
        let report = check(&message(Some(&html), Some("x")), None);
        let codes: Vec<_> = report.notices.iter().map(|n| n.code).collect();
        assert!(codes.contains(&"check-css-too-deep"), "{codes:?}");
    }

    #[test]
    fn only_the_start_of_a_long_message_is_read() {
        let html = format!("<p>{}</p><video></video>", "x".repeat(MAX_SCANNED));
        let report = check(&message(Some(&html), Some("x")), None);
        let codes: Vec<_> = report.notices.iter().map(|n| n.code).collect();
        assert!(codes.contains(&"check-truncated"), "{codes:?}");
        assert!(
            report.issues.iter().all(|issue| issue.slug != "html-video"),
            "nothing past the cut is reported"
        );
    }

    #[test]
    fn notices_what_is_not_about_one_feature() {
        let big = format!(
            "<p>{}</p><img src=\"a.png\"><!--[if mso]>x<![endif]-->",
            "x".repeat(110 * 1024)
        );
        let report = check(&message(Some(&big), None), None);
        let codes: Vec<_> = report.notices.iter().map(|n| n.code).collect();
        assert_eq!(
            codes,
            vec![
                "gmail-clipping",
                "no-text-part",
                "images-without-alt",
                "outlook-conditional-comments"
            ]
        );

        // Attachments are checked whether or not there is HTML.
        let mut carrying = message(None, Some("see attached"));
        let attachment = |filename: Option<&str>, inline: bool| crate::model::AttachmentMeta {
            index: 0,
            filename: filename.map(str::to_string),
            content_type: "application/octet-stream".into(),
            size: 10,
            content_id: None,
            inline,
        };
        carrying.attachments = vec![
            attachment(Some("report.pdf"), false),
            attachment(Some("Setup.EXE"), false),
            attachment(Some("run.js"), false),
            attachment(None, false),
            attachment(None, true),
        ];
        carrying.summary.size = 22 * 1024 * 1024;
        let report = check(&carrying, None);
        let codes: Vec<_> = report.notices.iter().map(|n| n.code).collect();
        assert_eq!(
            codes,
            vec![
                "attachment-blocked-type",
                "message-too-large",
                "attachment-without-name"
            ]
        );
        assert!(
            report.notices[0]
                .message
                .starts_with("Setup.EXE, run.js is"),
            "{}",
            report.notices[0].message
        );
        assert!(
            report.notices[1].message.contains("Outlook.com")
                && !report.notices[1].message.contains("Gmail")
        );
        assert!(
            report.notices[2].message.starts_with("1 attachment"),
            "an unnamed inline image is normal"
        );

        let plain = check(&message(None, Some("just text")), None);
        assert_eq!(plain.features_found, 0);
        assert!(plain.issues.is_empty() && plain.notices.is_empty());
    }
}
