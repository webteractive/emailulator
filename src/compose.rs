//! Building a message from the JSON send API.
//!
//! The API is the SMTP-free way in: an application posts the fields of an email
//! and the catcher assembles the MIME message it would otherwise have received.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use base64::Engine;
use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address as BuilderAddress;
use mail_builder::headers::raw::Raw;
use serde::Deserialize;

use crate::model::{Address, Source};
use crate::store::Incoming;

/// Headers the builder writes itself; a caller may not supply them.
const RESERVED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "subject",
    "content-type",
    "content-transfer-encoding",
    "mime-version",
];

/// An address as `"a@b"`, `"Name <a@b>"`, or `{"name": …, "address": …}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AddressInput {
    Text(String),
    Object {
        #[serde(default)]
        name: Option<String>,
        #[serde(alias = "email")]
        address: String,
    },
}

/// One address or a list of them.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Recipients {
    One(AddressInput),
    Many(Vec<AddressInput>),
}

impl Default for Recipients {
    fn default() -> Self {
        Recipients::Many(Vec::new())
    }
}

impl Recipients {
    fn resolve(&self, field: &str) -> Result<Vec<Address>> {
        match self {
            Recipients::One(one) => Ok(vec![one.resolve(field)?]),
            Recipients::Many(many) => many.iter().map(|a| a.resolve(field)).collect(),
        }
    }
}

impl AddressInput {
    fn resolve(&self, field: &str) -> Result<Address> {
        let (name, address) = match self {
            AddressInput::Object { name, address } => (name.clone(), address.trim().to_string()),
            AddressInput::Text(text) => match text.rsplit_once('<') {
                Some((name, rest)) => {
                    let name = name.trim().trim_matches('"').trim();
                    (
                        (!name.is_empty()).then(|| name.to_string()),
                        rest.trim().trim_end_matches('>').trim().to_string(),
                    )
                }
                None => (None, text.trim().to_string()),
            },
        };
        if !valid_address(&address) {
            bail!("`{field}` has an invalid address: {address:?}");
        }
        if name.as_deref().is_some_and(has_line_break) {
            bail!("`{field}` has a display name containing a line break");
        }
        Ok(Address { name, address })
    }
}

fn has_line_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

/// Loose on purpose: a catcher should accept the odd addresses tests invent,
/// but nothing that could break out of a header.
pub fn valid_address(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && address.len() <= 320
        && !address
            .contains(|c: char| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ','))
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentInput {
    pub filename: String,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Base64-encoded bytes.
    pub content: String,
    /// Set to embed the attachment inline, referenced from HTML as `cid:<id>`.
    #[serde(default)]
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SendRequest {
    pub from: AddressInput,
    #[serde(default)]
    pub to: Recipients,
    #[serde(default)]
    pub cc: Recipients,
    #[serde(default)]
    pub bcc: Recipients,
    #[serde(default)]
    pub reply_to: Recipients,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
}

fn builder_list(addresses: &[Address]) -> BuilderAddress<'_> {
    BuilderAddress::new_list(
        addresses
            .iter()
            .map(|a| BuilderAddress::new_address(a.name.as_deref(), a.address.as_str()))
            .collect(),
    )
}

impl SendRequest {
    /// Assemble the message for delivery into `inbox`. Bcc recipients are
    /// delivered to but, as with SMTP, appear in no header.
    pub fn build(&self, inbox: &str) -> Result<Incoming> {
        let from = self.from.resolve("from")?;
        let to = self.to.resolve("to")?;
        let cc = self.cc.resolve("cc")?;
        let bcc = self.bcc.resolve("bcc")?;
        let reply_to = self.reply_to.resolve("reply_to")?;
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            bail!("at least one recipient is required in `to`, `cc` or `bcc`");
        }

        let mut builder = MessageBuilder::new().from(BuilderAddress::new_address(
            from.name.as_deref(),
            from.address.as_str(),
        ));
        if !to.is_empty() {
            builder = builder.to(builder_list(&to));
        }
        if !cc.is_empty() {
            builder = builder.cc(builder_list(&cc));
        }
        if !reply_to.is_empty() {
            builder = builder.reply_to(builder_list(&reply_to));
        }

        let subject = self.subject.as_deref().unwrap_or_default();
        if has_line_break(subject) {
            bail!("`subject` contains a line break");
        }
        builder = builder.subject(subject);

        for (name, value) in &self.headers {
            let token = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !token {
                bail!("header name {name:?} is not valid");
            }
            if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                bail!("header `{name}` is set from its own field, not `headers`");
            }
            if has_line_break(value) {
                bail!("header `{name}` contains a line break");
            }
            builder = builder.header(name.as_str(), Raw::new(value.as_str()));
        }

        match (&self.text, &self.html) {
            (None, None) => builder = builder.text_body(""),
            (text, html) => {
                if let Some(text) = text {
                    builder = builder.text_body(text.as_str());
                }
                if let Some(html) = html {
                    builder = builder.html_body(html.as_str());
                }
            }
        }

        for attachment in &self.attachments {
            if attachment.filename.is_empty() || has_line_break(&attachment.filename) {
                bail!("attachment filename {:?} is not valid", attachment.filename);
            }
            let content_type = match &attachment.content_type {
                Some(content_type) if has_line_break(content_type) => {
                    bail!(
                        "attachment `{}` has an invalid content type",
                        attachment.filename
                    )
                }
                Some(content_type) => content_type.clone(),
                None => mime_guess::from_path(&attachment.filename)
                    .first_or_octet_stream()
                    .to_string(),
            };
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(attachment.content.trim())
                .map_err(|_| {
                    anyhow::anyhow!("attachment `{}` is not valid base64", attachment.filename)
                })?;
            builder = match &attachment.content_id {
                Some(cid) if has_line_break(cid) || cid.is_empty() => {
                    bail!(
                        "attachment `{}` has an invalid content_id",
                        attachment.filename
                    )
                }
                Some(cid) => builder.inline(content_type, cid.as_str(), bytes),
                None => builder.attachment(content_type, attachment.filename.as_str(), bytes),
            };
        }

        let raw = builder.write_to_vec()?;
        Ok(Incoming {
            raw,
            inbox: inbox.to_string(),
            envelope_from: Some(from.address),
            envelope_to: to
                .into_iter()
                .chain(cc)
                .chain(bcc)
                .map(|a| a.address)
                .collect(),
            source: Source::Api,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn request(json: serde_json::Value) -> Result<Incoming> {
        serde_json::from_value::<SendRequest>(json)?.build("default")
    }

    #[test]
    fn builds_a_message_the_parser_reads_back() {
        let incoming = request(serde_json::json!({
            "from": "Shop <shop@example.com>",
            "to": ["bob@example.com", {"name": "Carol", "email": "carol@example.com"}],
            "bcc": "audit@example.com",
            "subject": "Order shipped ✈",
            "text": "plain",
            "html": "<p>rich</p>",
            "headers": {"X-Order": "42"},
            "attachments": [{"filename": "a.txt", "content": "aGVsbG8="}],
        }))
        .unwrap();

        assert_eq!(incoming.envelope_from.as_deref(), Some("shop@example.com"));
        assert_eq!(
            incoming.envelope_to,
            vec!["bob@example.com", "carol@example.com", "audit@example.com"]
        );
        let parsed = parse::parse(&incoming.raw);
        assert_eq!(parsed.from.unwrap().name.as_deref(), Some("Shop"));
        assert_eq!(parsed.to[1].name.as_deref(), Some("Carol"));
        assert!(parsed.bcc.is_empty(), "Bcc is delivered to but not written");
        assert_eq!(parsed.subject, "Order shipped ✈");
        assert_eq!(parsed.text.as_deref().map(str::trim), Some("plain"));
        assert!(parsed.html.unwrap().contains("rich"));
        assert!(
            parsed
                .headers
                .iter()
                .any(|h| h.name == "X-Order" && h.value == "42")
        );
        assert_eq!(parsed.attachments[0].filename.as_deref(), Some("a.txt"));
        assert_eq!(parsed.attachments[0].content_type, "text/plain");
    }

    #[test]
    fn rejects_what_could_inject_headers() {
        let base = |extra: serde_json::Value| {
            let mut json = serde_json::json!({"from": "a@x.test", "to": "b@x.test"});
            json.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            request(json)
        };
        assert!(base(serde_json::json!({"subject": "hi\r\nBcc: evil@x.test"})).is_err());
        assert!(base(serde_json::json!({"headers": {"X-A": "1\nX-B: 2"}})).is_err());
        assert!(base(serde_json::json!({"headers": {"X A": "1"}})).is_err());
        assert!(base(serde_json::json!({"headers": {"Subject": "override"}})).is_err());
        assert!(base(serde_json::json!({"to": "b@x.test\r\nBcc: evil@x.test"})).is_err());
        assert!(
            base(serde_json::json!({"to": {"name": "B\nX: y", "address": "b@x.test"}})).is_err()
        );
        assert!(
            base(serde_json::json!({"attachments": [{"filename": "a", "content": "***"}]}))
                .is_err()
        );
        assert!(base(serde_json::json!({})).is_ok());
    }

    #[test]
    fn requires_a_recipient() {
        assert!(request(serde_json::json!({"from": "a@x.test"})).is_err());
        assert!(request(serde_json::json!({"from": "nope", "to": "b@x.test"})).is_err());
    }
}
