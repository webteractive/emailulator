//! Webhooks: events about the mail an inbox catches, posted to an application
//! so it can test the handler that would hear of sends, deliveries, bounces and
//! the rest from a real email provider.
//!
//! Each body is signed as the Standard Webhooks specification describes, with
//! `webhook-id`, `webhook-timestamp` and `webhook-signature` headers, so any
//! library for that specification checks them. Mail never really goes out, so
//! the outcome is decided by test addresses, and any other event can be asked
//! for on demand.

pub mod client;
pub mod worker;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use ring::hmac;
use serde::Serialize;

/// The email events emailulator can send.
pub const EVENT_TYPES: &[&str] = &[
    "email.bounced",
    "email.clicked",
    "email.complained",
    "email.delivered",
    "email.delivery_delayed",
    "email.failed",
    "email.opened",
    "email.scheduled",
    "email.sent",
    "email.suppressed",
];

/// How long to wait after each failed attempt before the next. After the last
/// one fails the delivery is given up as failed.
pub const RETRY_DELAYS: [Duration; 7] = [
    Duration::from_secs(5),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 3600),
    Duration::from_secs(5 * 3600),
    Duration::from_secs(10 * 3600),
    Duration::from_secs(10 * 3600),
];

/// The test domain. Mail to `bounced@emailulator.test`, `complained@…` and
/// `suppressed@…`, with or without a `+label`, has the outcome it names.
pub const TEST_DOMAIN: &str = "emailulator.test";

/// The fields of a caught message that every email event carries.
#[derive(Debug, Clone, Default)]
pub struct Email {
    pub email_id: String,
    /// Unix milliseconds the message was caught at.
    pub created_at: i64,
    /// The Message-ID header, without its angle brackets.
    pub message_id: Option<String>,
    /// The From header as written, `Name <address>` when it has a name.
    pub from: Option<String>,
    /// The To header's addresses.
    pub to: Vec<String>,
    pub subject: String,
    pub tags: BTreeMap<String, String>,
    /// The first link in the message, for a click that names none.
    pub first_link: Option<String>,
}

/// What a simulated event may say beyond the email itself.
#[derive(Debug, Clone, Default)]
pub struct Detail {
    /// The link an `email.clicked` event reports.
    pub link: Option<String>,
}

#[derive(Serialize)]
struct Envelope<'a> {
    #[serde(rename = "type")]
    event: &'a str,
    created_at: String,
    data: Data<'a>,
}

#[derive(Serialize)]
struct Data<'a> {
    created_at: String,
    email_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'a str>,
    to: &'a [String],
    subject: &'a str,
    tags: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bounce: Option<Bounce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    click: Option<Click>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed: Option<Failed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed: Option<Suppressed>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bounce {
    diagnostic_code: Vec<&'static str>,
    message: &'static str,
    sub_type: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Click {
    ip_address: &'static str,
    link: String,
    timestamp: String,
    user_agent: &'static str,
}

#[derive(Serialize)]
struct Failed {
    reason: &'static str,
}

#[derive(Serialize)]
struct Suppressed {
    message: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
}

/// Whether `event` is one emailulator sends.
pub fn is_event_type(event: &str) -> bool {
    EVENT_TYPES.contains(&event)
}

/// Check a list of event types for a webhook. `all`, alone, means every type
/// and is stored as an empty list.
pub fn event_list(events: &[String]) -> Result<Vec<String>> {
    if events.iter().any(|e| e == "all") {
        return Ok(Vec::new());
    }
    let mut list = Vec::new();
    for event in events {
        let event = event.trim();
        if !is_event_type(event) {
            bail!(
                "`{event}` is not an event emailulator sends; use `all` or some of: {}",
                EVENT_TYPES.join(", ")
            );
        }
        if !list.iter().any(|e| e == event) {
            list.push(event.to_string());
        }
    }
    Ok(list)
}

/// Check a webhook's endpoint: an absolute http or https URL with a host.
pub fn check_endpoint(endpoint: &str) -> Result<()> {
    let uri: hyper::Uri = endpoint
        .trim()
        .parse()
        .with_context(|| format!("`{endpoint}` is not a URL"))?;
    match uri.scheme_str() {
        Some("http" | "https") => {}
        _ => bail!("a webhook endpoint must be an http:// or https:// URL"),
    }
    if uri.host().is_none_or(str::is_empty) {
        bail!("`{endpoint}` has no host");
    }
    if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
        bail!("a webhook endpoint cannot carry a user name or password");
    }
    Ok(())
}

/// The events a message causes as it arrives: the outcome a test address
/// names, and a plain delivery for anything else.
pub fn arrival_events(recipients: &[String]) -> &'static [&'static str] {
    let outcome = |name: &str| {
        recipients.iter().any(|address| {
            let address = address.to_ascii_lowercase();
            let Some((local, domain)) = address.rsplit_once('@') else {
                return false;
            };
            let base = local.split_once('+').map_or(local, |(base, _)| base);
            domain == TEST_DOMAIN && base == name
        })
    };
    if outcome("bounced") {
        &["email.sent", "email.bounced"]
    } else if outcome("suppressed") {
        &["email.suppressed"]
    } else if outcome("complained") {
        &["email.sent", "email.delivered", "email.complained"]
    } else {
        &["email.sent", "email.delivered"]
    }
}

/// Unix milliseconds as an ISO 8601 UTC timestamp with milliseconds.
pub fn timestamp(ms: i64) -> String {
    let seconds = crate::mcp::rfc3339(ms);
    format!(
        "{}.{:03}Z",
        seconds.trim_end_matches('Z'),
        ms.rem_euclid(1000)
    )
}

/// The JSON body of one event about one email.
pub fn payload(event: &str, email: &Email, detail: &Detail, now: i64) -> Result<String> {
    if !is_event_type(event) {
        bail!(
            "`{event}` is not an event emailulator sends; use one of: {}",
            EVENT_TYPES.join(", ")
        );
    }
    let click = if event == "email.clicked" {
        let link = detail
            .link
            .clone()
            .or_else(|| email.first_link.clone())
            .context("the message has no links to click; give the link to report")?;
        Some(Click {
            ip_address: "127.0.0.1",
            link,
            timestamp: timestamp(now),
            user_agent: "Mozilla/5.0 (emailulator simulated click)",
        })
    } else {
        None
    };
    let envelope = Envelope {
        event,
        created_at: timestamp(now),
        data: Data {
            created_at: timestamp(email.created_at),
            email_id: &email.email_id,
            message_id: email.message_id.as_ref().map(|id| format!("<{id}>")),
            from: email.from.as_deref(),
            to: &email.to,
            subject: &email.subject,
            tags: &email.tags,
            bounce: (event == "email.bounced").then(|| Bounce {
                diagnostic_code: vec![
                    "smtp; 550 5.1.1 The email account that you tried to reach does not exist.",
                ],
                message: "The recipient's email address does not exist.",
                sub_type: "General",
                kind: "Permanent",
            }),
            click,
            failed: (event == "email.failed").then_some(Failed {
                reason: "simulated_failure",
            }),
            suppressed: (event == "email.suppressed").then_some(Suppressed {
                message: "The recipient's address is on the suppression list because it \
                          has a recent history of producing hard bounces.",
                kind: "OnAccountSuppressionList",
            }),
        },
    };
    Ok(serde_json::to_string(&envelope)?)
}

/// The `webhook-signature` header for a body: HMAC-SHA256 over
/// `{id}.{timestamp}.{body}`, keyed with the secret's base64 part.
pub fn sign(secret: &str, id: &str, timestamp: i64, body: &str) -> Result<String> {
    let encoded = secret.strip_prefix("whsec_").unwrap_or(secret);
    let key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("the webhook's signing secret is not base64")?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let tag = hmac::sign(&key, format!("{id}.{timestamp}.{body}").as_bytes());
    Ok(format!(
        "v1,{}",
        base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
    ))
}

/// When to try again after the `attempts`-th attempt failed, or `None` once
/// the schedule is spent.
pub fn retry_after(attempts: u32) -> Option<Duration> {
    let index = usize::try_from(attempts).ok()?.checked_sub(1)?;
    RETRY_DELAYS.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn signatures_match_a_published_example() {
        // A worked example published for this signing scheme.
        let signature = sign(
            "whsec_plJ3nmyCDGBKInavdOK15jsl",
            "msg_loFOjxBNrRLzqYUf",
            1_731_705_121,
            r#"{"event_type":"ping","data":{"success":true}}"#,
        )
        .unwrap();
        assert_eq!(signature, "v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0=");
    }

    #[test]
    fn test_addresses_decide_the_outcome() {
        let to = |a: &str| vec!["someone@example.test".to_string(), a.to_string()];
        assert_eq!(
            arrival_events(&to("user@example.test")),
            ["email.sent", "email.delivered"]
        );
        assert_eq!(
            arrival_events(&to("Bounced+signup@Emailulator.test")),
            ["email.sent", "email.bounced"]
        );
        assert_eq!(
            arrival_events(&to("complained@emailulator.test")),
            ["email.sent", "email.delivered", "email.complained"]
        );
        assert_eq!(
            arrival_events(&to("suppressed@emailulator.test")),
            ["email.suppressed"]
        );
        assert_eq!(
            arrival_events(&to("bounced@emailulator.test.example")),
            ["email.sent", "email.delivered"]
        );
    }

    fn email() -> Email {
        Email {
            email_id: "em_abc".into(),
            created_at: 1_760_184_000_123,
            message_id: Some("1@x.test".into()),
            from: Some("Acme <a@x.test>".into()),
            to: vec!["b@x.test".into()],
            subject: "Hi".into(),
            tags: BTreeMap::from([("category".into(), "welcome".into())]),
            first_link: Some("https://x.test/verify".into()),
        }
    }

    #[test]
    fn payloads_have_the_documented_shape() {
        let body = payload(
            "email.bounced",
            &email(),
            &Detail::default(),
            1_760_184_001_000,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["type"], "email.bounced");
        assert_eq!(value["created_at"], "2025-10-11T12:00:01.000Z");
        let data = &value["data"];
        assert_eq!(data["created_at"], "2025-10-11T12:00:00.123Z");
        assert_eq!(data["email_id"], "em_abc");
        assert_eq!(data["message_id"], "<1@x.test>");
        assert_eq!(data["from"], "Acme <a@x.test>");
        assert_eq!(data["to"][0], "b@x.test");
        assert_eq!(data["tags"]["category"], "welcome");
        assert_eq!(data["bounce"]["type"], "Permanent");
        assert!(data["bounce"]["subType"].is_string());
        assert!(data.get("click").is_none());
        assert!(body.starts_with(r#"{"type":"email.bounced""#), "{body}");
    }

    #[test]
    fn clicks_report_the_link_given_or_the_first_in_the_message() {
        let first = payload("email.clicked", &email(), &Detail::default(), 0).unwrap();
        assert!(
            first.contains(r#""link":"https://x.test/verify""#),
            "{first}"
        );
        let given = Detail {
            link: Some("https://x.test/other".into()),
        };
        let other = payload("email.clicked", &email(), &given, 0).unwrap();
        assert!(
            other.contains(r#""link":"https://x.test/other""#),
            "{other}"
        );
        let bare = Email {
            first_link: None,
            ..email()
        };
        assert!(payload("email.clicked", &bare, &Detail::default(), 0).is_err());
        assert!(payload("email.nope", &email(), &Detail::default(), 0).is_err());
    }

    #[test]
    fn event_lists_are_checked() {
        assert_eq!(event_list(&["all".into()]).unwrap(), Vec::<String>::new());
        assert_eq!(
            event_list(&["email.sent".into(), "email.sent".into()]).unwrap(),
            ["email.sent"]
        );
        assert!(event_list(&["domain.created".into()]).is_err());
    }

    #[test]
    fn endpoints_must_be_http_urls() {
        assert!(check_endpoint("http://127.0.0.1:8000/webhooks/email").is_ok());
        assert!(check_endpoint("https://app.test/webhooks").is_ok());
        assert!(check_endpoint("ftp://app.test/").is_err());
        assert!(check_endpoint("/webhooks").is_err());
        assert!(check_endpoint("https://user:pw@app.test/").is_err());
    }

    #[test]
    fn retries_follow_the_schedule() {
        assert_eq!(retry_after(0), None);
        assert_eq!(retry_after(1), Some(Duration::from_secs(5)));
        assert_eq!(retry_after(7), Some(Duration::from_secs(36_000)));
        assert_eq!(retry_after(8), None);
    }
}
