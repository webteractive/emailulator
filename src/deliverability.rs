//! Whether a message is likely to reach the inbox rather than the spam folder.
//!
//! What a receiver decides rests on much it alone can see: the server that
//! delivered the message, the sender's DNS records, its own reputation data.
//! What the message itself shows is checked here: whether its DKIM signatures
//! are well-formed and still match the body, whether its domains line up the
//! way DMARC needs, whether it carries the one-click unsubscribe Gmail and
//! Yahoo require of bulk mail, and the header and content signals spam filters
//! weigh. A spam score comes from SpamAssassin, when one is configured.

use std::cell::OnceCell;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::{Link, MessageDetail};
use crate::parse::{self, Parsed};

/// Worst first, which is also the order findings are reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Receivers will reject or junk it for this.
    Fail,
    /// Likely to count against it.
    Warn,
    /// Worth knowing; whether it matters depends on the mail.
    Info,
    Pass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub status: Status,
    pub title: String,
    pub message: String,
}

impl Finding {
    fn new(code: &'static str, status: Status, title: &str, message: String) -> Self {
        Self {
            code,
            status,
            title: title.to_string(),
            message,
        }
    }
}

/// Check what a message shows of how receivers will treat it.
pub fn check(detail: &MessageDetail, raw: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let signatures: Vec<Signature> = header_values(detail, "dkim-signature")
        .map(Signature::parse)
        .collect();
    authentication(detail, raw, &signatures, &mut findings);
    unsubscribe(detail, &signatures, &mut findings);
    headers(detail, &mut findings);
    content(detail, &mut findings);
    findings.sort_by_key(|finding| finding.status);
    findings
}

fn header_values<'a>(detail: &'a MessageDetail, name: &'a str) -> impl Iterator<Item = &'a str> {
    detail
        .headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn header<'a>(detail: &'a MessageDetail, name: &'a str) -> Option<&'a str> {
    header_values(detail, name).next()
}

fn domain_of(address: &str) -> Option<String> {
    let (_, domain) = address.trim().trim_matches(['<', '>']).rsplit_once('@')?;
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// The registrable part of a domain, as DMARC's relaxed alignment compares
/// them: `mail.example.com` and `example.com` are one organization. Without
/// the Public Suffix List this is an approximation, which knows the common
/// two-level suffixes such as `co.uk`.
fn organization(domain: &str) -> String {
    const SECOND_LEVEL: &[&str] = &["ac", "co", "com", "edu", "gov", "ne", "net", "or", "org"];
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let n = labels.len();
    let keep = if n >= 3 && labels[n - 1].len() == 2 && SECOND_LEVEL.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n.saturating_sub(keep)..].join(".")
}

fn aligned(a: &str, b: &str) -> bool {
    organization(a) == organization(b)
}

// ---------------------------------------------------------------------------
// DKIM and DMARC alignment
// ---------------------------------------------------------------------------

/// One DKIM-Signature header, read into its tags.
struct Signature {
    tags: Vec<(String, String)>,
}

impl Signature {
    fn parse(value: &str) -> Self {
        let tags = value
            .split(';')
            .filter_map(|tag| tag.split_once('='))
            .map(|(name, value)| {
                // Whitespace is allowed inside every tag's value and is not
                // part of it, as in a folded b= or h=.
                let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                (name.trim().to_ascii_lowercase(), value)
            })
            .collect();
        Self { tags }
    }

    fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|(tag, _)| tag == name)
            .map(|(_, value)| value.as_str())
    }

    fn domain(&self) -> &str {
        self.tag("d").unwrap_or("")
    }

    /// The headers it signs, lowercased.
    fn signed_headers(&self) -> Vec<String> {
        self.tag("h")
            .unwrap_or("")
            .split(':')
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect()
    }

    fn signs(&self, header: &str) -> bool {
        self.signed_headers().iter().any(|name| name == header)
    }

    /// What can be checked without the key: the tags, and the body hash.
    /// `received_at` is in milliseconds.
    fn check(&self, bodies: &Bodies<'_>, received_at: i64) -> Finding {
        let domain = self.domain();
        let title = if domain.is_empty() {
            "DKIM signature".to_string()
        } else {
            format!("DKIM signature by {domain}")
        };
        let fail = |message: String| Finding {
            code: "dkim",
            status: Status::Fail,
            title: title.clone(),
            message,
        };

        let missing: Vec<&str> = ["v", "a", "b", "bh", "d", "h", "s"]
            .into_iter()
            .filter(|tag| self.tag(tag).is_none_or(str::is_empty))
            .collect();
        if !missing.is_empty() {
            return fail(format!(
                "The signature has no {} tag, so receivers will ignore it.",
                missing.join(", ")
            ));
        }
        if self.tag("v") != Some("1") {
            return fail(
                "The signature's version (v=) is not 1, so receivers will ignore it.".into(),
            );
        }
        let algorithm = self.tag("a").unwrap_or_default().to_ascii_lowercase();
        let digest = match algorithm.as_str() {
            "rsa-sha256" | "ed25519-sha256" => &ring::digest::SHA256,
            "rsa-sha1" => {
                return fail(
                    "It is signed with rsa-sha1, which receivers no longer accept (RFC 8301). Sign with rsa-sha256."
                        .into(),
                );
            }
            other => {
                return fail(format!(
                    "It is signed with {other}, which receivers do not know."
                ));
            }
        };
        if !self.signs("from") {
            return fail(
                "It does not sign the From header, so it says nothing about who sent the message, and receivers will not count it."
                    .into(),
            );
        }
        let canonicalization = self
            .tag("c")
            .unwrap_or("simple/simple")
            .to_ascii_lowercase();
        let body_canonicalization = canonicalization
            .split_once('/')
            .map_or("simple", |(_, body)| body);
        let canonical = match body_canonicalization {
            "simple" => bodies.simple(),
            "relaxed" => bodies.relaxed(),
            other => {
                return fail(format!(
                    "Its body canonicalization ({other}) is not simple or relaxed."
                ));
            }
        };
        let length = match self.tag("l") {
            None => None,
            Some(l) => match l.parse::<usize>() {
                Ok(l) => Some(l),
                Err(_) => return fail(format!("Its body length (l={l}) is not a number.")),
            },
        };
        let hashed = match length {
            Some(l) if l > canonical.len() => {
                return fail(format!(
                    "It signs the first {l} bytes of the body, but the body is only {} bytes: it was cut short after signing.",
                    canonical.len()
                ));
            }
            Some(l) => &canonical[..l],
            None => canonical,
        };
        let hash = base64::engine::general_purpose::STANDARD
            .encode(ring::digest::digest(digest, hashed).as_ref());
        if Some(hash.as_str()) != self.tag("bh") {
            return fail(
                "The body hash does not match: the body changed after it was signed, often because something rewrote its links or added a footer. Receivers will treat the message as unsigned."
                    .into(),
            );
        }

        let selector = self.tag("s").unwrap_or_default();
        let mut message = format!(
            "Signed with {algorithm} and selector {selector}, and the body hash matches. The signature itself is checked against the key published at {selector}._domainkey.{domain}, which the receiver looks up; this does not."
        );
        let mut status = Status::Pass;
        if let Some(expires) = self.tag("x").and_then(|x| x.parse::<i64>().ok())
            && expires.saturating_mul(1000) < received_at
        {
            status = Status::Warn;
            message.push_str(
                " It had already expired (x=) when it arrived, so receivers will ignore it.",
            );
        }
        if let Some(l) = length {
            status = Status::Warn;
            message.push_str(&format!(
                " It covers only the first {l} bytes of the body (l=), so anyone can append to the message without breaking it, and some receivers distrust it for that."
            ));
        }
        Finding {
            code: "dkim",
            status,
            title,
            message,
        }
    }
}

/// The body canonicalized each way, at most once however many signatures ask
/// for it: a message can carry any number of them.
struct Bodies<'a> {
    raw: &'a [u8],
    simple: OnceCell<Vec<u8>>,
    relaxed: OnceCell<Vec<u8>>,
}

impl<'a> Bodies<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            simple: OnceCell::new(),
            relaxed: OnceCell::new(),
        }
    }

    fn simple(&self) -> &[u8] {
        self.simple.get_or_init(|| simple_body(&body_of(self.raw)))
    }

    fn relaxed(&self) -> &[u8] {
        self.relaxed
            .get_or_init(|| relaxed_body(&body_of(self.raw)))
    }
}

/// The body as it would be transmitted: after the first empty line, with
/// line endings as CRLF.
fn body_of(raw: &[u8]) -> Vec<u8> {
    let crlf = find(raw, b"\r\n\r\n").map(|at| at + 4);
    let lf = find(raw, b"\n\n").map(|at| at + 2);
    let start = match (crlf, lf) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => return Vec::new(),
    };
    let mut body = Vec::with_capacity(raw.len() - start);
    for (i, &byte) in raw[start..].iter().enumerate() {
        if byte == b'\n' && (i == 0 || raw[start + i - 1] != b'\r') {
            body.push(b'\r');
        }
        body.push(byte);
    }
    body
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// RFC 6376 3.4.3: trailing empty lines go, and an empty body is one CRLF.
fn simple_body(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    while out.ends_with(b"\r\n\r\n") {
        out.truncate(out.len() - 2);
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// RFC 6376 3.4.4: runs of whitespace become one space, whitespace at the end
/// of a line goes, then trailing empty lines; an empty body stays empty.
fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut rest = body;
    loop {
        let (line, next) = match find(rest, b"\r\n") {
            Some(at) => (&rest[..at], Some(&rest[at + 2..])),
            None => (rest, None),
        };
        let mut out = Vec::with_capacity(line.len());
        let mut space = false;
        for &byte in line {
            if byte == b' ' || byte == b'\t' {
                space = true;
            } else {
                if space {
                    out.push(b' ');
                    space = false;
                }
                out.push(byte);
            }
        }
        lines.push(out);
        match next {
            Some(next) => rest = next,
            None => break,
        }
    }
    while lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// How many DKIM signatures are checked. Real mail carries one to three; a
/// message with thousands would otherwise have its body hashed for each.
const MAX_SIGNATURES: usize = 5;

fn authentication(
    detail: &MessageDetail,
    raw: &[u8],
    signatures: &[Signature],
    findings: &mut Vec<Finding>,
) {
    if signatures.is_empty() {
        findings.push(Finding::new(
            "dkim-missing",
            Status::Warn,
            "Not DKIM-signed",
            "There is no DKIM signature. Gmail and Yahoo junk or reject unsigned mail from bulk senders, and DMARC needs one. If your mail provider signs as it sends, as SES, Postmark and Mailgun can, that is expected here.".into(),
        ));
    }
    let bodies = Bodies::new(raw);
    let mut valid = Vec::new();
    for signature in signatures.iter().take(MAX_SIGNATURES) {
        let finding = signature.check(&bodies, detail.summary.received_at);
        if finding.status != Status::Fail {
            valid.push(signature.domain().to_ascii_lowercase());
        }
        findings.push(finding);
    }
    if signatures.len() > MAX_SIGNATURES {
        findings.push(Finding::new(
            "dkim-unchecked",
            Status::Warn,
            "Too many DKIM signatures",
            format!(
                "It carries {} DKIM signatures; only the first {MAX_SIGNATURES} were checked. Receivers stop after a few too, so a good signature further down may never be seen.",
                signatures.len()
            ),
        ));
    }

    let Some(from) = detail
        .summary
        .from
        .as_ref()
        .and_then(|from| domain_of(&from.address))
    else {
        return;
    };
    let envelope = detail.envelope_from.as_deref().and_then(domain_of);
    let envelope_aligned = envelope.as_deref().is_some_and(|e| aligned(e, &from));
    if let Some(domain) = valid.iter().find(|d| aligned(d, &from)) {
        findings.push(Finding::new(
            "dmarc-alignment",
            Status::Pass,
            "Aligned for DMARC",
            format!("The DKIM signature by {domain} is for the From address's domain, {from}, which is what DMARC asks for."),
        ));
    } else if !valid.is_empty() {
        findings.push(Finding::new(
            "dmarc-alignment",
            Status::Warn,
            "Not aligned for DMARC",
            format!(
                "The message is signed by {}, not by {from}, the From address's domain. DMARC needs a signature for {from}, or SPF passing for an envelope sender at {from}, or receivers apply {from}'s DMARC policy.",
                valid.join(" and ")
            ),
        ));
    } else if envelope_aligned {
        findings.push(Finding::new(
            "dmarc-alignment",
            Status::Info,
            "Aligned by SPF alone",
            format!(
                "Only the envelope sender lines up with {from}, the From address's domain. That passes DMARC only when SPF passes for the server that sends it, and a forwarded copy fails; a DKIM signature for {from} would hold up."
            ),
        ));
    } else {
        let sender = envelope
            .map(|e| format!("the envelope sender ({e})"))
            .unwrap_or_else(|| "the envelope sender".into());
        findings.push(Finding::new(
            "dmarc-alignment",
            Status::Warn,
            "Not aligned for DMARC",
            format!(
                "Neither a DKIM signature nor {sender} is for {from}, the From address's domain, so it fails DMARC wherever {from} publishes a policy."
            ),
        ));
    }
}

// ---------------------------------------------------------------------------
// Unsubscribe
// ---------------------------------------------------------------------------

fn unsubscribe(detail: &MessageDetail, signatures: &[Signature], findings: &mut Vec<Finding>) {
    let Some(value) = header(detail, "list-unsubscribe") else {
        findings.push(Finding::new(
            "list-unsubscribe",
            Status::Info,
            "No unsubscribe header",
            "There is no List-Unsubscribe header. Gmail and Yahoo require one, with one-click unsubscribe, on marketing and other bulk mail. Mail someone asked for, such as a receipt or a password reset, does not need it.".into(),
        ));
        return;
    };
    let uris: Vec<&str> = value
        .split('<')
        .skip(1)
        .filter_map(|part| part.split_once('>').map(|(uri, _)| uri.trim()))
        .collect();
    if uris.is_empty() {
        findings.push(Finding::new(
            "list-unsubscribe",
            Status::Fail,
            "Unreadable unsubscribe header",
            "List-Unsubscribe holds no address in angle brackets. It must be a list such as <https://example.com/unsubscribe/…>, <mailto:unsubscribe@example.com>.".into(),
        ));
        return;
    }
    let https = uris
        .iter()
        .any(|uri| uri.to_ascii_lowercase().starts_with("https://"));
    let http = uris
        .iter()
        .any(|uri| uri.to_ascii_lowercase().starts_with("http://"));
    let post = header(detail, "list-unsubscribe-post");

    let mut problems = Vec::new();
    if !https {
        problems.push(if http {
            "It links over http:, and one-click unsubscribe needs an https: address."
        } else {
            "It has only a mailto: address, and Gmail and Yahoo need an https: one for one-click unsubscribe."
        });
    }
    match post {
        None if https => problems.push(
            "There is no List-Unsubscribe-Post: List-Unsubscribe=One-Click header, so mail clients cannot unsubscribe in one click (RFC 8058).",
        ),
        Some(post) if !post.trim().eq_ignore_ascii_case("List-Unsubscribe=One-Click") => problems
            .push("List-Unsubscribe-Post should say exactly List-Unsubscribe=One-Click."),
        _ => {}
    }
    let covered = signatures.iter().any(|signature| {
        signature.signs("list-unsubscribe")
            && (post.is_none() || signature.signs("list-unsubscribe-post"))
    });
    if !signatures.is_empty() && !covered {
        problems.push(if post.is_some() {
            "The DKIM signature does not cover List-Unsubscribe and List-Unsubscribe-Post, which RFC 8058 requires for one-click unsubscribe."
        } else {
            "The DKIM signature does not cover List-Unsubscribe."
        });
    }

    if problems.is_empty() {
        findings.push(Finding::new(
            "list-unsubscribe",
            Status::Pass,
            "One-click unsubscribe",
            "List-Unsubscribe has an https: address and List-Unsubscribe-Post asks for one-click, as Gmail and Yahoo require of bulk mail.".into(),
        ));
    } else {
        findings.push(Finding::new(
            "list-unsubscribe",
            Status::Warn,
            "Unsubscribe is not one-click",
            problems.join(" "),
        ));
    }
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

fn headers(detail: &MessageDetail, findings: &mut Vec<Finding>) {
    let before = findings.len();
    let froms = header_values(detail, "from").count();
    match &detail.summary.from {
        None => findings.push(Finding::new(
            "from",
            Status::Fail,
            "No From address",
            "There is no readable From address, and receivers reject mail without one.".into(),
        )),
        Some(_) if froms > 1 => findings.push(Finding::new(
            "from",
            Status::Fail,
            "More than one From header",
            format!("There are {froms} From headers. Gmail rejects such mail outright."),
        )),
        Some(from) => {
            // A display name that is itself an address, and not this one, is
            // the oldest trick in phishing, and filters score it.
            let shown = from.name.as_deref().unwrap_or("").to_ascii_lowercase();
            let shown = shown.trim_matches(['"', '\'', ' ']);
            if shown.contains('@')
                && shown.split_whitespace().any(|word| {
                    word.contains('@')
                        && word.trim_matches(['<', '>', '(', ')'])
                            != from.address.to_ascii_lowercase()
                })
            {
                findings.push(Finding::new(
                    "from-name-address",
                    Status::Warn,
                    "The From name shows another address",
                    format!(
                        "The From name, \"{}\", shows an address that is not the one it is sent from, {}. Spam and phishing filters score that.",
                        from.name.as_deref().unwrap_or(""),
                        from.address
                    ),
                ));
            }
        }
    }
    if detail.message_id.is_none() {
        findings.push(Finding::new(
            "message-id",
            Status::Warn,
            "No Message-ID",
            "There is no Message-ID header. Gmail may reject the message, and spam filters score its absence. Most mail libraries add one; check that nothing strips it.".into(),
        ));
    }
    if header(detail, "date").is_none() {
        findings.push(Finding::new(
            "date",
            Status::Warn,
            "No Date",
            "There is no Date header, which every message must have. Spam filters score its absence.".into(),
        ));
    } else if detail.date.is_none() {
        findings.push(Finding::new(
            "date",
            Status::Warn,
            "Unreadable Date",
            format!(
                "The Date header, \"{}\", is not a date in the form mail uses, such as Tue, 20 Oct 2026 14:03:00 +0800.",
                header(detail, "date").unwrap_or_default()
            ),
        ));
    }
    let subject = detail.summary.subject.trim();
    let letters: Vec<char> = subject.chars().filter(|c| c.is_alphabetic()).collect();
    if subject.is_empty() {
        findings.push(Finding::new(
            "subject",
            Status::Warn,
            "No subject",
            "The subject is empty, which spam filters score and readers skip.".into(),
        ));
    } else if letters.len() >= 8 && letters.iter().all(|c| !c.is_lowercase()) {
        findings.push(Finding::new(
            "subject",
            Status::Warn,
            "Subject in capitals",
            "The subject is all capitals, which spam filters score.".into(),
        ));
    }
    if findings.len() == before {
        findings.push(Finding::new(
            "headers",
            Status::Pass,
            "Headers in order",
            "From, Date, Message-ID and Subject are present and readable.".into(),
        ));
    }
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// Link shorteners spam filters distrust: they hide where a link goes.
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
];

/// How much text an HTML message with images needs before it stops looking
/// like the image-only mail spam filters score.
const MIN_TEXT_WITH_IMAGES: usize = 400;

/// How many examples a finding about links quotes.
const EXAMPLES: usize = 3;

fn content(detail: &MessageDetail, findings: &mut Vec<Finding>) {
    let parsed = Parsed {
        text: detail.text.clone(),
        html: detail.html.clone(),
        ..Parsed::default()
    };
    let links: Vec<Link> = parse::links(&parsed)
        .into_iter()
        .filter(|link| !link.url.to_ascii_lowercase().starts_with("mailto:"))
        .collect();
    let quote = |urls: Vec<&str>| -> String {
        let shown: Vec<&str> = urls.iter().take(EXAMPLES).copied().collect();
        let more = urls.len().saturating_sub(EXAMPLES);
        let mut text = shown.join(", ");
        if more > 0 {
            text.push_str(&format!(" and {more} more"));
        }
        text
    };

    let mut local = Vec::new();
    let mut bare_ip = Vec::new();
    let mut shortened = Vec::new();
    let mut mismatched = Vec::new();
    for link in &links {
        let Some(host) = host_of(&link.url) else {
            continue;
        };
        match reach(&host) {
            Reach::Local => local.push(link.url.as_str()),
            Reach::PublicIp => bare_ip.push(link.url.as_str()),
            Reach::Public => {}
        }
        let site = host.strip_prefix("www.").unwrap_or(&host);
        if SHORTENERS.contains(&site) {
            shortened.push(link.url.as_str());
        }
        if let Some(shown) = link.text.as_deref().and_then(shown_domain)
            && reach(&host) == Reach::Public
            && !aligned(&shown, &host)
        {
            mismatched.push((shown, host.clone()));
        }
    }

    if !local.is_empty() {
        findings.push(Finding::new(
            "local-links",
            Status::Info,
            "Links to this network",
            format!(
                "{} to addresses only this machine or network can reach: {}. That is expected in development; sent from staging or production, it means the app builds links from the wrong base URL (APP_URL in Laravel).",
                links_go(local.len()),
                quote(local)
            ),
        ));
    }
    if !bare_ip.is_empty() {
        findings.push(Finding::new(
            "ip-links",
            Status::Warn,
            "Links to IP addresses",
            format!(
                "{} to an IP address rather than a domain: {}. Spam filters score that.",
                links_go(bare_ip.len()),
                quote(bare_ip)
            ),
        ));
    }
    if !shortened.is_empty() {
        findings.push(Finding::new(
            "shortened-links",
            Status::Warn,
            "Shortened links",
            format!(
                "{} through a link shortener: {}. Spam filters distrust them, because they hide where a link goes; link to the page itself.",
                links_go(shortened.len()),
                quote(shortened)
            ),
        ));
    }
    if !mismatched.is_empty() {
        let pairs: Vec<String> = mismatched
            .iter()
            .map(|(shown, host)| format!("\"{shown}\" goes to {host}"))
            .collect();
        findings.push(Finding::new(
            "link-text-mismatch",
            Status::Warn,
            "Link text names another site",
            format!(
                "{} {} one address and {} to another, which phishing filters flag: {}. Click tracking does this; a tracking domain of your own, under the sender's domain, avoids it.",
                count(mismatched.len(), "link"),
                verb(mismatched.len(), "shows", "show"),
                verb(mismatched.len(), "goes", "go"),
                quote(pairs.iter().map(String::as_str).collect())
            ),
        ));
    }

    if let Some(html) = &detail.html {
        let images = html.to_ascii_lowercase().matches("<img").count();
        let text = parse::html_to_text(html)
            .chars()
            .filter(|c| !c.is_whitespace())
            .count();
        if images > 0 && text < MIN_TEXT_WITH_IMAGES {
            findings.push(Finding::new(
                "image-heavy",
                Status::Warn,
                "Mostly images",
                format!(
                    "The HTML is {} with only {text} characters of text. Spam filters score mail that is mostly images, and readers whose client blocks images see next to nothing.",
                    count(images, "image")
                ),
            ));
        }
    }
}

fn count(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// The form of a verb that agrees with `n`.
fn verb<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// "1 link goes", "3 links go".
fn links_go(n: usize) -> String {
    format!("{} {}", count(n, "link"), verb(n, "goes", "go"))
}

/// The host a URL goes to, lowercased, without credentials or port.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// Only this machine or its network: loopback, private ranges, and names
    /// that do not resolve on the internet.
    Local,
    PublicIp,
    Public,
}

fn reach(host: &str) -> Reach {
    const LOCAL_SUFFIXES: &[&str] = &[
        ".example",
        ".home.arpa",
        ".internal",
        ".invalid",
        ".lan",
        ".local",
        ".localhost",
        ".test",
    ];
    if let Ok(ip) = host.parse::<IpAddr>() {
        let local = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4 == Ipv4Addr::BROADCAST
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        return if local { Reach::Local } else { Reach::PublicIp };
    }
    let dotted = format!(".{host}");
    if host == "localhost"
        || !host.contains('.')
        || LOCAL_SUFFIXES.iter().any(|suffix| dotted.ends_with(suffix))
    {
        return Reach::Local;
    }
    Reach::Public
}

/// The domain a link's text shows, when the text is an address: a URL, or a
/// bare name such as `example.com`.
fn shown_domain(text: &str) -> Option<String> {
    let text = text.trim();
    if text.contains(char::is_whitespace) {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return host_of(&lower);
    }
    let host = lower.split(['/', '?', '#']).next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    let (_, tld) = host.rsplit_once('.')?;
    let looks_like_a_domain = tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.contains("..")
        && !host.starts_with('.');
    looks_like_a_domain.then(|| host.to_string())
}

// ---------------------------------------------------------------------------
// SpamAssassin
// ---------------------------------------------------------------------------

/// A spam score from SpamAssassin, or why there is none.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Spam {
    Scored {
        score: f64,
        /// The score at which SpamAssassin calls a message spam.
        required: f64,
        spam: bool,
        /// The rules that matched, highest scoring first.
        rules: Vec<SpamRule>,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpamRule {
    pub name: String,
    pub points: f64,
    pub description: String,
}

/// The largest message scored. spamc, SpamAssassin's own client, skips
/// anything bigger by default, since the rules get slow on it.
pub const MAX_SPAM_BYTES: usize = 500 * 1024;

const SPAMD_TIMEOUT: Duration = Duration::from_secs(20);

/// Bounds what is read back: a report is a few kilobytes.
const MAX_SPAMD_RESPONSE: u64 = 1024 * 1024;

/// The port spamd listens on unless told otherwise.
pub const SPAMD_PORT: u16 = 783;

/// Score a message with the spamd at `addr`, a `host:port`.
pub async fn spamassassin(addr: &str, raw: &[u8]) -> Spam {
    if raw.len() > MAX_SPAM_BYTES {
        return Spam::Failed {
            error: format!(
                "The message is {} KB, over the {} KB SpamAssassin scores by default.",
                raw.len() / 1024,
                MAX_SPAM_BYTES / 1024
            ),
        };
    }
    match tokio::time::timeout(SPAMD_TIMEOUT, ask_spamd(addr, raw)).await {
        Ok(Ok(spam)) => spam,
        Ok(Err(error)) => Spam::Failed {
            error: format!("SpamAssassin at {addr}: {error:#}"),
        },
        Err(_) => Spam::Failed {
            error: format!(
                "SpamAssassin at {addr} did not answer within {} seconds.",
                SPAMD_TIMEOUT.as_secs()
            ),
        },
    }
}

/// One REPORT request in spamd's protocol, as `spamc -R` makes it.
async fn ask_spamd(addr: &str, raw: &[u8]) -> Result<Spam> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .context("connecting")?;
    let head = format!("REPORT SPAMC/1.5\r\nContent-length: {}\r\n\r\n", raw.len());
    stream.write_all(head.as_bytes()).await.context("sending")?;
    stream.write_all(raw).await.context("sending")?;
    stream.shutdown().await.context("sending")?;
    let mut response = Vec::new();
    stream
        .take(MAX_SPAMD_RESPONSE)
        .read_to_end(&mut response)
        .await
        .context("reading the answer")?;
    parse_spamd(&String::from_utf8_lossy(&response))
}

fn parse_spamd(response: &str) -> Result<Spam> {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    let mut parts = status.splitn(3, ' ');
    if !parts.next().unwrap_or_default().starts_with("SPAMD/") {
        bail!("it did not answer in spamd's protocol");
    }
    let code = parts.next().unwrap_or_default();
    if code != "0" {
        bail!(
            "it refused the message: {}",
            parts.next().unwrap_or(code).trim()
        );
    }
    // Spam: True ; 15.3 / 5.0
    let verdict = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("spam").then_some(value)
        })
        .ok_or_else(|| anyhow!("its answer had no score"))?;
    let (flag, numbers) = verdict
        .split_once(';')
        .ok_or_else(|| anyhow!("its score was unreadable: {}", verdict.trim()))?;
    let (score, required) = numbers
        .split_once('/')
        .ok_or_else(|| anyhow!("its score was unreadable: {}", verdict.trim()))?;
    let number = |text: &str| -> Result<f64> {
        text.trim()
            .parse()
            .map_err(|_| anyhow!("its score was unreadable: {}", verdict.trim()))
    };
    let mut rules = parse_report(body);
    rules.sort_by(|a, b| b.points.total_cmp(&a.points));
    Ok(Spam::Scored {
        score: number(score)?,
        required: number(required)?,
        spam: matches!(flag.trim().to_ascii_lowercase().as_str(), "true" | "yes"),
        rules,
    })
}

/// The rules in a report's table:
///
/// ```text
///  pts rule name              description
/// ---- ---------------------- --------------------------------------------------
///  1.2 MISSING_HEADERS        Missing To: header
///  0.1 MISSING_MID            Missing Message-Id: header
///                             with a description that wraps
/// ```
fn parse_report(body: &str) -> Vec<SpamRule> {
    let mut rules: Vec<SpamRule> = Vec::new();
    let mut in_table = false;
    for line in body.lines() {
        if !in_table {
            in_table = line.starts_with("----");
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        let (first, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        match first.parse::<f64>() {
            Ok(points) => {
                let rest = rest.trim_start();
                let (name, description) =
                    rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                rules.push(SpamRule {
                    name: name.to_string(),
                    points,
                    description: description.trim().to_string(),
                });
            }
            Err(_) => {
                if let Some(rule) = rules.last_mut() {
                    rule.description.push(' ');
                    rule.description.push_str(line);
                }
            }
        }
    }
    rules
}

/// A `host:port` for spamd, with its usual port when none is given.
pub fn spamd_address(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("give SpamAssassin's spamd as host:port, such as 127.0.0.1:{SPAMD_PORT}");
    }
    let has_port = match value.rsplit_once(':') {
        // An IPv6 address without brackets is all colons; with brackets, the
        // port follows the closing one.
        Some((host, port)) => {
            (!host.contains(':') || host.ends_with(']')) && !port.is_empty() && !port.contains(']')
        }
        None => false,
    };
    if has_port {
        let port = value
            .rsplit_once(':')
            .map(|(_, port)| port)
            .unwrap_or_default();
        port.parse::<u16>()
            .map_err(|_| anyhow!("`{value}` has no valid port; give spamd as host:port"))?;
        Ok(value.to_string())
    } else if value.contains(':') && !value.starts_with('[') {
        Ok(format!("[{value}]:{SPAMD_PORT}"))
    } else {
        Ok(format!("{value}:{SPAMD_PORT}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Address, Header, MessageSummary, Source};

    /// A message as the store would hand it over, from raw bytes.
    fn detail(raw: &str) -> MessageDetail {
        let parsed = parse::parse(raw.as_bytes());
        MessageDetail {
            summary: MessageSummary {
                id: 1,
                email_id: "em_test".into(),
                received_at: 1_790_000_000_000,
                from: parsed.from.clone(),
                to: parsed.to.clone(),
                cc: Vec::new(),
                subject: parsed.subject.clone(),
                snippet: String::new(),
                size: raw.len(),
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
            date: parsed.date,
            message_id: parsed.message_id,
            text: parsed.text,
            html: parsed.html,
            headers: parsed.headers,
            attachments: Vec::new(),
            tags: Default::default(),
        }
    }

    fn codes(findings: &[Finding]) -> Vec<(&'static str, Status)> {
        findings.iter().map(|f| (f.code, f.status)).collect()
    }

    fn find_code<'a>(findings: &'a [Finding], code: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.code == code)
            .unwrap_or_else(|| panic!("no {code} in {:?}", codes(findings)))
    }

    const PLAIN: &str = "From: Shop <shop@example.com>\r\n\
        To: bob@example.org\r\n\
        Subject: Your order shipped\r\n\
        Date: Tue, 20 Oct 2026 14:03:00 +0800\r\n\
        Message-ID: <1@example.com>\r\n\
        \r\n\
        It is on its way.\r\n";

    /// Sign `raw`'s body as a sender would, with the hash only: the header
    /// signature is not checked here, so b= can be anything.
    fn signed(raw: &str, domain: &str, canonicalization: &str, extra: &str) -> String {
        let body = body_of(raw.as_bytes());
        let canonical = match canonicalization
            .split_once('/')
            .map_or("simple", |(_, b)| b)
        {
            "relaxed" => relaxed_body(&body),
            _ => simple_body(&body),
        };
        let bh = base64::engine::general_purpose::STANDARD
            .encode(ring::digest::digest(&ring::digest::SHA256, &canonical).as_ref());
        format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c={canonicalization}; d={domain}; s=mail;\r\n\
             \th=from:to:subject:date:message-id{extra}; bh={bh};\r\n\
             \tb=c2lnbmF0dXJl\r\n{raw}"
        )
    }

    #[test]
    fn canonicalization_follows_rfc_6376() {
        // The examples of RFC 6376 3.4.5.
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(simple_body(body), b" C \r\nD \t E\r\n");
        assert_eq!(relaxed_body(body), b" C\r\nD E\r\n");
        assert_eq!(simple_body(b""), b"\r\n");
        assert_eq!(relaxed_body(b""), b"");
        assert_eq!(simple_body(b"no ending"), b"no ending\r\n");
        assert_eq!(relaxed_body(b"no ending  "), b"no ending\r\n");
    }

    #[test]
    fn the_body_is_read_with_crlf_line_endings() {
        assert_eq!(
            body_of(b"A: b\r\n\r\nline\r\nline\r\n"),
            b"line\r\nline\r\n"
        );
        assert_eq!(body_of(b"A: b\n\nline\nline\n"), b"line\r\nline\r\n");
        assert_eq!(body_of(b"A: b\r\n"), b"");
    }

    #[test]
    fn a_signature_whose_body_hash_matches_passes_and_aligns() {
        for c in ["simple/simple", "relaxed/relaxed", "relaxed"] {
            let raw = signed(PLAIN, "example.com", c, "");
            let findings = check(&detail(&raw), raw.as_bytes());
            let dkim = find_code(&findings, "dkim");
            assert_eq!(dkim.status, Status::Pass, "{c}: {}", dkim.message);
            assert_eq!(find_code(&findings, "dmarc-alignment").status, Status::Pass);
            assert!(!findings.iter().any(|f| f.code == "dkim-missing"));
        }
    }

    #[test]
    fn a_body_changed_after_signing_fails() {
        let raw = signed(PLAIN, "example.com", "relaxed/relaxed", "").replace(
            "on its way",
            "on its way. Track it: https://t.example.net/x",
        );
        let findings = check(&detail(&raw), raw.as_bytes());
        let dkim = find_code(&findings, "dkim");
        assert_eq!(dkim.status, Status::Fail);
        assert!(
            dkim.message.contains("body hash does not match"),
            "{}",
            dkim.message
        );
        assert_eq!(findings[0].status, Status::Fail, "failures come first");
        // A failed signature does not count towards alignment.
        assert_eq!(find_code(&findings, "dmarc-alignment").status, Status::Warn);
    }

    #[test]
    fn only_the_first_few_signatures_are_checked() {
        let mut raw = signed(PLAIN, "example.com", "relaxed/relaxed", "");
        for _ in 0..MAX_SIGNATURES {
            raw = signed(&raw, "example.com", "relaxed/relaxed", "");
        }
        let findings = check(&detail(&raw), raw.as_bytes());
        let checked = findings.iter().filter(|f| f.code == "dkim").count();
        assert_eq!(checked, MAX_SIGNATURES);
        let unchecked = find_code(&findings, "dkim-unchecked");
        assert_eq!(unchecked.status, Status::Warn);
        assert!(
            unchecked.message.contains("carries 6"),
            "{}",
            unchecked.message
        );
    }

    #[test]
    fn an_absurd_expiry_does_not_overflow() {
        let raw = signed(
            PLAIN,
            "example.com",
            "relaxed/relaxed",
            "; x=9223372036854775807",
        );
        let finding = find_code(&check(&detail(&raw), raw.as_bytes()), "dkim").clone();
        assert_eq!(finding.status, Status::Pass, "{}", finding.message);
    }

    #[test]
    fn broken_signatures_say_why() {
        let sha1 =
            signed(PLAIN, "example.com", "relaxed/relaxed", "").replace("rsa-sha256", "rsa-sha1");
        let finding = find_code(&check(&detail(&sha1), sha1.as_bytes()), "dkim").clone();
        assert_eq!(finding.status, Status::Fail);
        assert!(finding.message.contains("RFC 8301"), "{}", finding.message);

        let unsigned_from =
            signed(PLAIN, "example.com", "relaxed/relaxed", "").replace("h=from:", "h=");
        let finding = find_code(
            &check(&detail(&unsigned_from), unsigned_from.as_bytes()),
            "dkim",
        )
        .clone();
        assert!(
            finding.message.contains("does not sign the From"),
            "{}",
            finding.message
        );

        let no_selector =
            signed(PLAIN, "example.com", "relaxed/relaxed", "").replace(" s=mail;", "");
        let finding = find_code(
            &check(&detail(&no_selector), no_selector.as_bytes()),
            "dkim",
        )
        .clone();
        assert!(finding.message.contains("no s tag"), "{}", finding.message);
    }

    #[test]
    fn a_length_limited_signature_is_a_warning() {
        let raw = signed(PLAIN, "example.com", "simple/simple", "");
        let length = simple_body(&body_of(raw.as_bytes())).len();
        let raw = raw.replace("s=mail;", &format!("s=mail; l={length};"));
        let dkim = find_code(&check(&detail(&raw), raw.as_bytes()), "dkim").clone();
        assert_eq!(dkim.status, Status::Warn, "{}", dkim.message);
        assert!(dkim.message.contains("(l=)"));
    }

    #[test]
    fn a_signature_for_another_domain_is_not_aligned() {
        let raw = signed(PLAIN, "esp-mailer.net", "relaxed/relaxed", "");
        let findings = check(&detail(&raw), raw.as_bytes());
        assert_eq!(find_code(&findings, "dkim").status, Status::Pass);
        let dmarc = find_code(&findings, "dmarc-alignment");
        assert_eq!(dmarc.status, Status::Warn);
        assert!(
            dmarc.message.contains("esp-mailer.net"),
            "{}",
            dmarc.message
        );

        // A subdomain of the sender's own is the same organization.
        let raw = signed(PLAIN, "mail.example.com", "relaxed/relaxed", "");
        let findings = check(&detail(&raw), raw.as_bytes());
        assert_eq!(find_code(&findings, "dmarc-alignment").status, Status::Pass);
    }

    #[test]
    fn unsigned_mail_relies_on_the_envelope() {
        let mut message = detail(PLAIN);
        let findings = check(&message, PLAIN.as_bytes());
        assert_eq!(find_code(&findings, "dkim-missing").status, Status::Warn);
        assert_eq!(find_code(&findings, "dmarc-alignment").status, Status::Warn);

        message.envelope_from = Some("bounces@example.com".into());
        let findings = check(&message, PLAIN.as_bytes());
        assert_eq!(find_code(&findings, "dmarc-alignment").status, Status::Info);
    }

    #[test]
    fn organizations_are_compared_for_alignment() {
        assert_eq!(organization("mail.example.com"), "example.com");
        assert_eq!(organization("shop.example.co.uk"), "example.co.uk");
        assert_eq!(organization("example.com"), "example.com");
        assert_eq!(organization("a.b.example.io"), "example.io");
        assert!(aligned("bounce.example.com", "example.com"));
        assert!(!aligned("example.com", "example.net"));
    }

    #[test]
    fn one_click_unsubscribe_needs_https_the_post_header_and_a_signature_over_both() {
        let message = |headers: &str| {
            let raw = PLAIN.replacen("Subject:", &format!("{headers}Subject:"), 1);
            let raw = signed(
                &raw,
                "example.com",
                "relaxed/relaxed",
                ":list-unsubscribe:list-unsubscribe-post",
            );
            let findings = check(&detail(&raw), raw.as_bytes());
            find_code(&findings, "list-unsubscribe").clone()
        };

        let good = message(
            "List-Unsubscribe: <https://example.com/u/1>, <mailto:u@example.com>\r\n\
             List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
        );
        assert_eq!(good.status, Status::Pass, "{}", good.message);

        let mailto_only = message("List-Unsubscribe: <mailto:u@example.com>\r\n");
        assert_eq!(mailto_only.status, Status::Warn);
        assert!(
            mailto_only.message.contains("https:"),
            "{}",
            mailto_only.message
        );

        let no_post = message("List-Unsubscribe: <https://example.com/u/1>\r\n");
        assert!(no_post.message.contains("RFC 8058"), "{}", no_post.message);

        let unreadable = message("List-Unsubscribe: https://example.com/u/1\r\n");
        assert_eq!(unreadable.status, Status::Fail);

        let none = find_code(&check(&detail(PLAIN), PLAIN.as_bytes()), "list-unsubscribe").clone();
        assert_eq!(none.status, Status::Info, "transactional mail needs none");

        // Signed, but not over the unsubscribe headers.
        let raw = PLAIN.replacen(
            "Subject:",
            "List-Unsubscribe: <https://example.com/u/1>\r\n\
             List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\nSubject:",
            1,
        );
        let raw = signed(&raw, "example.com", "relaxed/relaxed", "");
        let finding = find_code(&check(&detail(&raw), raw.as_bytes()), "list-unsubscribe").clone();
        assert!(
            finding.message.contains("does not cover"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn missing_and_odd_headers_are_reported() {
        let findings = check(&detail(PLAIN), PLAIN.as_bytes());
        assert_eq!(find_code(&findings, "headers").status, Status::Pass);

        let bare = "From: shop@example.com\r\nSubject: YOUR ORDER HAS SHIPPED\r\n\r\nHi\r\n";
        let findings = check(&detail(bare), bare.as_bytes());
        for code in ["message-id", "date", "subject"] {
            assert_eq!(find_code(&findings, code).status, Status::Warn, "{code}");
        }
        assert!(!findings.iter().any(|f| f.code == "headers"));

        let two = format!("From: other@example.com\r\n{PLAIN}");
        assert_eq!(
            find_code(&check(&detail(&two), two.as_bytes()), "from").status,
            Status::Fail
        );

        let mut spoof = detail(PLAIN);
        spoof.summary.from = Some(Address {
            name: Some("support@bank.example.com".into()),
            address: "shop@example.com".into(),
        });
        let finding = find_code(&check(&spoof, PLAIN.as_bytes()), "from-name-address").clone();
        assert_eq!(finding.status, Status::Warn);

        let mut unreadable = detail(PLAIN);
        unreadable.date = None;
        unreadable.headers.push(Header {
            name: "Date".into(),
            value: "yesterday".into(),
        });
        assert_eq!(
            find_code(&check(&unreadable, PLAIN.as_bytes()), "date").title,
            "Unreadable Date"
        );
    }

    #[test]
    fn links_are_judged_by_where_they_go() {
        let html = "<p>Reset your password: <a href=\"http://localhost:8000/reset/abc\">reset</a>,
            <a href=\"http://192.168.1.20/x\">here</a>, <a href=\"http://203.0.113.9/y\">there</a>,
            <a href=\"https://bit.ly/3abc\">short</a>,
            <a href=\"https://u123.ct.sendgrid.net/ls/click?x\">www.example.com</a>,
            <a href=\"https://example.com/account\">example.com/account</a>,
            <a href=\"https://shop.test/orders\">orders</a>,
            <a href=\"mailto:help@example.com\">help@example.com</a></p>";
        let raw = format!(
            "From: Shop <shop@example.com>\r\nSubject: Reset\r\nContent-Type: text/html\r\n\r\n{html}\r\n"
        );
        let findings = check(&detail(&raw), raw.as_bytes());

        let local = find_code(&findings, "local-links");
        assert!(local.message.starts_with("3 links"), "{}", local.message);
        assert!(local.message.contains("localhost:8000"));
        assert!(
            find_code(&findings, "ip-links")
                .message
                .contains("203.0.113.9")
        );
        assert!(
            find_code(&findings, "shortened-links")
                .message
                .contains("bit.ly")
        );
        let mismatch = find_code(&findings, "link-text-mismatch");
        assert!(
            mismatch.message.starts_with("1 link "),
            "{}",
            mismatch.message
        );
        assert!(
            mismatch
                .message
                .contains("\"example.com\" goes to u123.ct.sendgrid.net")
        );
    }

    #[test]
    fn hosts_and_their_reach() {
        assert_eq!(
            host_of("https://user:pw@Example.COM:8443/x?y").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("http://[::1]:8000/").as_deref(), Some("::1"));
        assert_eq!(reach("::1"), Reach::Local);
        assert_eq!(reach("10.0.0.4"), Reach::Local);
        assert_eq!(reach("myapp"), Reach::Local);
        assert_eq!(reach("app.localhost"), Reach::Local);
        assert_eq!(reach("8.8.8.8"), Reach::PublicIp);
        assert_eq!(reach("example.com"), Reach::Public);
        assert_eq!(
            shown_domain("www.Example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(shown_domain("Click here"), None);
        assert_eq!(shown_domain("v1.2"), None);
    }

    #[test]
    fn image_only_html_is_reported() {
        let raw = "From: shop@example.com\r\nSubject: Sale\r\nContent-Type: text/html\r\n\r\n\
            <a href=\"https://example.com\"><img src=\"https://example.com/sale.png\" alt=\"Sale\"></a>\r\n";
        let findings = check(&detail(raw), raw.as_bytes());
        assert_eq!(find_code(&findings, "image-heavy").status, Status::Warn);
    }

    const SPAMD_ANSWER: &str = "SPAMD/1.1 0 EX_OK\r\n\
        Content-length: 900\r\n\
        Spam: False ; 2.6 / 5.0\r\n\
        \r\n\
        Spam detection software, running on the system \"spamd\",\n\
        has NOT identified this incoming email as spam.\n\
        \n\
        Content analysis details:   (2.6 points, 5.0 required)\n\
        \n\
         pts rule name              description\n\
        ---- ---------------------- --------------------------------------------------\n\
        -0.0 NO_RELAYS              Informational: message was not relayed via SMTP\n\
         1.4 MISSING_DATE           Missing Date: header\n\
         0.1 MISSING_MID            Missing Message-Id: header\n\
         1.1 HTML_IMAGE_ONLY_08     BODY: HTML: images with 400-800 bytes of\n\
                                    words\n\
        \n";

    #[test]
    fn a_spamd_report_is_read() {
        let Spam::Scored {
            score,
            required,
            spam,
            rules,
        } = parse_spamd(SPAMD_ANSWER).unwrap()
        else {
            panic!("not scored");
        };
        assert_eq!((score, required, spam), (2.6, 5.0, false));
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "MISSING_DATE",
                "HTML_IMAGE_ONLY_08",
                "MISSING_MID",
                "NO_RELAYS"
            ]
        );
        assert_eq!(
            rules[1].description,
            "BODY: HTML: images with 400-800 bytes of words"
        );

        let refused = parse_spamd("SPAMD/1.0 76 Bad header line: x\r\n\r\n").unwrap_err();
        assert!(refused.to_string().contains("Bad header line"), "{refused}");
        assert!(parse_spamd("HTTP/1.1 200 OK\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn spamd_is_asked_as_spamc_asks_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(SPAMD_ANSWER.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        let spam = spamassassin(&addr, PLAIN.as_bytes()).await;
        assert!(
            matches!(spam, Spam::Scored { score, .. } if score == 2.6),
            "{spam:?}"
        );
        let request = server.await.unwrap();
        assert!(request.starts_with(&format!(
            "REPORT SPAMC/1.5\r\nContent-length: {}\r\n\r\n",
            PLAIN.len()
        )));
        assert!(request.ends_with(PLAIN));

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let nobody = closed.local_addr().unwrap().to_string();
        drop(closed);
        let Spam::Failed { error } = spamassassin(&nobody, PLAIN.as_bytes()).await else {
            panic!("scored by nobody");
        };
        assert!(error.contains("connecting"), "{error}");

        let big = vec![b'x'; MAX_SPAM_BYTES + 1];
        assert!(matches!(
            spamassassin(&addr, &big).await,
            Spam::Failed { .. }
        ));
    }

    #[test]
    fn spamd_addresses_get_the_usual_port() {
        assert_eq!(spamd_address("127.0.0.1").unwrap(), "127.0.0.1:783");
        assert_eq!(spamd_address("spamd:7830").unwrap(), "spamd:7830");
        assert_eq!(spamd_address("::1").unwrap(), "[::1]:783");
        assert_eq!(spamd_address("[::1]:7830").unwrap(), "[::1]:7830");
        assert!(spamd_address("spamd:port").is_err());
        assert!(spamd_address(" ").is_err());
    }
}
