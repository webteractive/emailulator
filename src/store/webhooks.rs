//! Webhooks and their deliveries, kept beside the mail they are about.
//!
//! A delivery is queued in the same transaction as the event that causes it,
//! so the queue survives a restart and is filled even by a process that sends
//! nothing itself, such as `emailulator mcp`. A running server's worker claims
//! due deliveries one by one, so two processes never post the same one.

use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::{InboxError, Store, now_ms};
use crate::model::{Delivery, Webhook};
use crate::parse;
use crate::security::{generate_public_id, generate_webhook_secret};
use crate::webhook::{self, Detail, Email};

/// Deliveries kept once they are done; the oldest beyond this are dropped.
const MAX_DELIVERIES: i64 = 1000;
/// Deliveries a webhook may have waiting; beyond this the oldest are given up,
/// so an endpoint that is down cannot grow the queue without end.
const MAX_PENDING: i64 = 1000;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 500;

/// How long a claimed delivery is held before it may be claimed again. Longer
/// than an attempt can take, so it only lapses when the sender died mid-way.
const CLAIM_LEASE_MS: i64 = 60_000;

const WEBHOOK_COLUMNS: &str =
    "id, inbox, endpoint, events_json, enabled, verify_tls, secret, created_at";

const DELIVERY_COLUMNS: &str = "id, webhook, inbox, email_id, type, status, attempts, \
    next_attempt_at, last_attempt_at, last_status, last_error, last_response, created_at, payload";

/// Why a webhook operation was refused, in words for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookError {
    Invalid(String),
    NotFound(String),
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::Invalid(why) | WebhookError::NotFound(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for WebhookError {}

fn invalid(error: anyhow::Error) -> anyhow::Error {
    WebhookError::Invalid(error.to_string()).into()
}

/// A webhook to create.
#[derive(Debug, Clone)]
pub struct NewWebhook {
    pub inbox: String,
    pub endpoint: String,
    /// Event types, or `all`; empty means all.
    pub events: Vec<String>,
    pub verify_tls: bool,
}

/// Changes to a webhook; what is `None` stays as it is.
#[derive(Debug, Clone, Default)]
pub struct WebhookChanges {
    pub endpoint: Option<String>,
    pub events: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub verify_tls: Option<bool>,
}

/// Which deliveries to list.
#[derive(Debug, Clone, Default)]
pub struct DeliveryFilter {
    pub inbox: Option<String>,
    pub webhook: Option<String>,
    pub email_id: Option<String>,
    pub limit: Option<usize>,
}

/// A delivery claimed for sending, with what sending it needs.
#[derive(Debug, Clone)]
pub struct DueDelivery {
    pub id: String,
    pub webhook: String,
    pub endpoint: String,
    pub secret: String,
    pub verify_tls: bool,
    /// The body to post, exactly as it is signed.
    pub payload: String,
}

/// How an attempt went.
#[derive(Debug, Clone)]
pub enum Attempt {
    /// The endpoint answered, with this status and the start of the body.
    Answered { status: u16, body: String },
    /// It could not be reached, or did not answer in time.
    Failed(String),
}

fn webhook_from_row(row: &Row<'_>) -> rusqlite::Result<Webhook> {
    let events: String = row.get(3)?;
    Ok(Webhook {
        id: row.get(0)?,
        inbox: row.get(1)?,
        endpoint: row.get(2)?,
        events: serde_json::from_str(&events).unwrap_or_default(),
        enabled: row.get(4)?,
        verify_tls: row.get(5)?,
        secret: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn delivery_from_row(row: &Row<'_>) -> rusqlite::Result<Delivery> {
    let payload: String = row.get(13)?;
    Ok(Delivery {
        id: row.get(0)?,
        webhook: row.get(1)?,
        inbox: row.get(2)?,
        email_id: row.get(3)?,
        event: row.get(4)?,
        status: row.get(5)?,
        attempts: row.get(6)?,
        next_attempt_at: row.get(7)?,
        last_attempt_at: row.get(8)?,
        last_status: row.get(9)?,
        last_error: row.get(10)?,
        last_response: row.get(11)?,
        created_at: row.get(12)?,
        payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
    })
}

/// Queue `events` about `email` for every enabled webhook of `inbox` that
/// wants them. Returns how many deliveries were queued.
pub(super) fn enqueue(
    conn: &Connection,
    inbox: &str,
    email: &Email,
    events: &[&str],
    detail: &Detail,
) -> Result<usize> {
    let hooks = conn
        .prepare("SELECT id, events_json FROM webhooks WHERE inbox = ? AND enabled = 1")?
        .query_map([inbox], |row| {
            let wanted: String = row.get(1)?;
            let wanted: Vec<String> = serde_json::from_str(&wanted).unwrap_or_default();
            Ok((row.get::<_, String>(0)?, wanted))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if hooks.is_empty() {
        return Ok(0);
    }
    let now = now_ms();
    let mut queued = 0;
    for event in events {
        let body = webhook::payload(event, email, detail, now).map_err(invalid)?;
        for (id, wanted) in &hooks {
            if !wanted.is_empty() && !wanted.iter().any(|w| w == event) {
                continue;
            }
            conn.execute(
                "INSERT INTO webhook_deliveries (id, webhook, inbox, email_id, type, payload, \
                 next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    generate_public_id("msg_"),
                    id,
                    inbox,
                    email.email_id,
                    event,
                    body,
                    now,
                    now
                ],
            )?;
            queued += 1;
        }
    }
    if queued > 0 {
        for (id, _) in &hooks {
            conn.execute(
                "UPDATE webhook_deliveries SET status = 'failed', \
                 last_error = 'given up: too many deliveries were waiting' \
                 WHERE webhook = ?1 AND status = 'pending' AND seq NOT IN \
                 (SELECT seq FROM webhook_deliveries WHERE webhook = ?1 \
                 AND status = 'pending' ORDER BY seq DESC LIMIT ?2)",
                params![id, MAX_PENDING],
            )?;
        }
        conn.execute(
            "DELETE FROM webhook_deliveries WHERE status <> 'pending' AND seq NOT IN \
             (SELECT seq FROM webhook_deliveries ORDER BY seq DESC LIMIT ?)",
            [MAX_DELIVERIES],
        )?;
    }
    Ok(queued)
}

impl Store {
    /// Woken whenever deliveries are queued in this process.
    pub fn deliveries_queued(&self) -> &tokio::sync::Notify {
        &self.deliveries_queued
    }

    pub fn create_webhook(&self, new: NewWebhook) -> Result<Webhook> {
        if !self.inbox_exists(&new.inbox)? {
            return Err(InboxError::NotFound(new.inbox).into());
        }
        let endpoint = new.endpoint.trim().to_string();
        webhook::check_endpoint(&endpoint).map_err(invalid)?;
        let events = webhook::event_list(&new.events).map_err(invalid)?;
        let id = generate_public_id("we_");
        self.conn().execute(
            "INSERT INTO webhooks (id, inbox, endpoint, events_json, secret, verify_tls, \
             created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                new.inbox,
                endpoint,
                serde_json::to_string(&events)?,
                generate_webhook_secret(),
                new.verify_tls,
                now_ms()
            ],
        )?;
        self.webhook(&id)?
            .ok_or_else(|| anyhow::anyhow!("the webhook vanished as it was created"))
    }

    /// Every webhook, or one inbox's, oldest first.
    pub fn webhooks(&self, inbox: Option<&str>) -> Result<Vec<Webhook>> {
        let conn = self.conn();
        let sql = format!(
            "SELECT {WEBHOOK_COLUMNS} FROM webhooks WHERE (?1 IS NULL OR inbox = ?1) \
             ORDER BY created_at, id"
        );
        Ok(conn
            .prepare(&sql)?
            .query_map([inbox], webhook_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn webhook(&self, id: &str) -> Result<Option<Webhook>> {
        let conn = self.conn();
        let sql = format!("SELECT {WEBHOOK_COLUMNS} FROM webhooks WHERE id = ?");
        Ok(conn.query_row(&sql, [id], webhook_from_row).optional()?)
    }

    pub fn update_webhook(&self, id: &str, changes: WebhookChanges) -> Result<Webhook> {
        let Some(mut hook) = self.webhook(id)? else {
            return Err(WebhookError::NotFound(format!("there is no webhook `{id}`")).into());
        };
        if let Some(endpoint) = changes.endpoint {
            let endpoint = endpoint.trim().to_string();
            webhook::check_endpoint(&endpoint).map_err(invalid)?;
            hook.endpoint = endpoint;
        }
        if let Some(events) = changes.events {
            hook.events = webhook::event_list(&events).map_err(invalid)?;
        }
        hook.enabled = changes.enabled.unwrap_or(hook.enabled);
        hook.verify_tls = changes.verify_tls.unwrap_or(hook.verify_tls);
        self.conn().execute(
            "UPDATE webhooks SET endpoint = ?, events_json = ?, enabled = ?, verify_tls = ? \
             WHERE id = ?",
            params![
                hook.endpoint,
                serde_json::to_string(&hook.events)?,
                hook.enabled,
                hook.verify_tls,
                id
            ],
        )?;
        // Deliveries held back while it was off may go now.
        if hook.enabled {
            self.deliveries_queued.notify_one();
        }
        Ok(hook)
    }

    /// Delete a webhook with its deliveries. Returns whether it existed.
    pub fn delete_webhook(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM webhooks WHERE id = ?", [id])?
            > 0)
    }

    /// The fields events carry, for a message already caught.
    fn email_facts(&self, id: i64) -> Result<Option<(String, Email)>> {
        let Some(detail) = self.get(id)? else {
            return Ok(None);
        };
        let first_link = self
            .raw(id)?
            .and_then(|raw| parse::links(&parse::parse(&raw)).into_iter().next())
            .map(|link| link.url);
        let summary = detail.summary;
        let to = if summary.to.is_empty() {
            summary.recipients
        } else {
            summary.to.into_iter().map(|a| a.address).collect()
        };
        Ok(Some((
            summary.inbox,
            Email {
                email_id: summary.email_id,
                created_at: summary.received_at,
                message_id: detail.message_id,
                from: summary.from.as_ref().map(|a| a.display()),
                to,
                subject: summary.subject,
                tags: detail.tags,
                first_link,
            },
        )))
    }

    /// Queue an event about a caught message, such as a bounce or a click
    /// that a real provider would have reported, for every webhook of its inbox that wants it. Returns how many
    /// deliveries were queued: none when the inbox has no such webhook.
    pub fn simulate_event(&self, id: i64, event: &str, detail: &Detail) -> Result<usize> {
        if !webhook::is_event_type(event) {
            return Err(WebhookError::Invalid(format!(
                "`{event}` is not an event emailulator sends; use one of: {}",
                webhook::EVENT_TYPES.join(", ")
            ))
            .into());
        }
        let Some((inbox, email)) = self.email_facts(id)? else {
            return Err(WebhookError::NotFound(format!("message {id} not found")).into());
        };
        let queued = {
            let mut conn = self.conn();
            let tx = conn.transaction()?;
            let queued = enqueue(&tx, &inbox, &email, &[event], detail)?;
            tx.commit()?;
            queued
        };
        if queued > 0 {
            self.deliveries_queued.notify_one();
        }
        Ok(queued)
    }

    /// Deliveries, newest first.
    pub fn deliveries(&self, filter: &DeliveryFilter) -> Result<Vec<Delivery>> {
        let limit = filter.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as i64;
        let conn = self.conn();
        let sql = format!(
            "SELECT {DELIVERY_COLUMNS} FROM webhook_deliveries \
             WHERE (?1 IS NULL OR inbox = ?1) AND (?2 IS NULL OR webhook = ?2) \
             AND (?3 IS NULL OR email_id = ?3) ORDER BY seq DESC LIMIT ?4"
        );
        Ok(conn
            .prepare(&sql)?
            .query_map(
                params![filter.inbox, filter.webhook, filter.email_id, limit],
                delivery_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delivery(&self, id: &str) -> Result<Option<Delivery>> {
        let conn = self.conn();
        let sql = format!("SELECT {DELIVERY_COLUMNS} FROM webhook_deliveries WHERE id = ?");
        Ok(conn.query_row(&sql, [id], delivery_from_row).optional()?)
    }

    /// Send a delivery again now, from the start of the retry schedule, with
    /// the same body and `webhook-id`. Returns whether it exists.
    pub fn replay_delivery(&self, id: &str) -> Result<bool> {
        let replayed = self.conn().execute(
            "UPDATE webhook_deliveries SET status = 'pending', attempts = 0, \
             next_attempt_at = ? WHERE id = ?",
            params![now_ms(), id],
        )? > 0;
        if replayed {
            self.deliveries_queued.notify_one();
        }
        Ok(replayed)
    }

    /// When the next pending delivery of an enabled webhook falls due.
    pub fn next_delivery_at(&self) -> Result<Option<i64>> {
        Ok(self.conn().query_row(
            "SELECT MIN(d.next_attempt_at) FROM webhook_deliveries d \
             JOIN webhooks w ON w.id = d.webhook \
             WHERE d.status = 'pending' AND w.enabled = 1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Claim the deliveries due by `now`, oldest first. Each is held for a
    /// while, so nothing else sends it meanwhile.
    pub fn claim_due_deliveries(&self, now: i64, limit: usize) -> Result<Vec<DueDelivery>> {
        let conn = self.conn();
        let due = conn
            .prepare(
                "SELECT d.id, d.webhook, w.endpoint, w.secret, w.verify_tls, d.payload, \
                 d.next_attempt_at FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook \
                 WHERE d.status = 'pending' AND d.next_attempt_at <= ? AND w.enabled = 1 \
                 ORDER BY d.seq LIMIT ?",
            )?
            .query_map(params![now, limit as i64], |row| {
                Ok((
                    DueDelivery {
                        id: row.get(0)?,
                        webhook: row.get(1)?,
                        endpoint: row.get(2)?,
                        secret: row.get(3)?,
                        verify_tls: row.get(4)?,
                        payload: row.get(5)?,
                    },
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut claimed = Vec::new();
        for (delivery, due_at) in due {
            let won = conn.execute(
                "UPDATE webhook_deliveries SET next_attempt_at = ? \
                 WHERE id = ? AND status = 'pending' AND next_attempt_at = ?",
                params![now + CLAIM_LEASE_MS, delivery.id, due_at],
            )?;
            if won == 1 {
                claimed.push(delivery);
            }
        }
        Ok(claimed)
    }

    /// Record how an attempt went, and when to try again if it failed and the
    /// schedule has room left.
    pub fn record_attempt(&self, id: &str, attempt: &Attempt) -> Result<()> {
        let now = now_ms();
        let conn = self.conn();
        let attempts: Option<u32> = conn
            .query_row(
                "SELECT attempts FROM webhook_deliveries WHERE id = ?",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(attempts) = attempts.map(|a| a + 1) else {
            // Deleted with its webhook while it was being sent.
            return Ok(());
        };
        let (status, error, body) = match attempt {
            Attempt::Answered { status, body } if (200..300).contains(status) => {
                (Some(*status), None, Some(body.as_str()))
            }
            Attempt::Answered { status, body } => (
                Some(*status),
                Some(format!("answered {status}")),
                Some(body.as_str()),
            ),
            Attempt::Failed(why) => (None, Some(why.clone()), None),
        };
        let (state, next) = match &error {
            None => ("succeeded", None),
            Some(_) => match webhook::retry_after(attempts) {
                Some(delay) => ("pending", Some(now + delay.as_millis() as i64)),
                None => ("failed", None),
            },
        };
        conn.execute(
            "UPDATE webhook_deliveries SET status = ?, attempts = ?, next_attempt_at = ?, \
             last_attempt_at = ?, last_status = ?, last_error = ?, last_response = ? WHERE id = ?",
            params![state, attempts, next, now, status, error, body, id],
        )?;
        Ok(())
    }
}

/// Tags as a send request gives them: `[{"name", "value"}]`, or an object.
pub fn tags_from_json(value: &serde_json::Value) -> Result<BTreeMap<String, String>, String> {
    let mut tags = BTreeMap::new();
    let mut add = |name: &str, value: &serde_json::Value| -> Result<(), String> {
        let value = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => return Err(format!("tag `{name}` needs a string value")),
        };
        tags.insert(name.to_string(), value);
        Ok(())
    };
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Array(items) => {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("each tag needs a `name`")?;
                add(name, item.get("value").unwrap_or(&serde_json::Value::Null))?;
            }
        }
        serde_json::Value::Object(map) => {
            for (name, value) in map {
                add(name, value)?;
            }
        }
        _ => return Err("`tags` is a list of {name, value} or an object".into()),
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;
    use crate::store::{DEFAULT_INBOX, EMAIL_ID_PREFIX, Incoming};

    fn hooked() -> (Store, Webhook) {
        let store = Store::in_memory().unwrap();
        let hook = store
            .create_webhook(NewWebhook {
                inbox: DEFAULT_INBOX.into(),
                endpoint: "http://127.0.0.1:9/hook".into(),
                events: vec![],
                verify_tls: true,
            })
            .unwrap();
        (store, hook)
    }

    fn deliver(store: &Store, to: &str) -> i64 {
        store
            .insert(Incoming {
                raw: format!(
                    "From: App <app@x.test>\r\nTo: {to}\r\nMessage-ID: <1@x.test>\r\n\
                     Subject: Hi\r\n\r\nGo to https://x.test/verify\r\n"
                )
                .into_bytes(),
                inbox: DEFAULT_INBOX.into(),
                envelope_from: None,
                envelope_to: vec![],
                source: Source::Api,
                tags: BTreeMap::from([("category".into(), "welcome".into())]),
            })
            .unwrap()
            .id
    }

    #[test]
    fn arriving_mail_queues_sent_then_delivered() {
        let (store, hook) = hooked();
        assert!(hook.id.starts_with("we_") && hook.secret.starts_with("whsec_"));
        deliver(&store, "user@x.test");
        let deliveries = store.deliveries(&DeliveryFilter::default()).unwrap();
        let types: Vec<_> = deliveries.iter().rev().map(|d| d.event.as_str()).collect();
        assert_eq!(types, ["email.sent", "email.delivered"]);
        let payload = &deliveries[0].payload;
        assert_eq!(payload["data"]["tags"]["category"], "welcome");
        assert_eq!(payload["data"]["message_id"], "<1@x.test>");
        assert!(deliveries[0].id.starts_with("msg_"));
        assert_eq!(deliveries[0].status, "pending");
    }

    #[test]
    fn webhooks_get_only_the_events_they_want() {
        let (store, hook) = hooked();
        store
            .update_webhook(
                &hook.id,
                WebhookChanges {
                    events: Some(vec!["email.bounced".into()]),
                    ..Default::default()
                },
            )
            .unwrap();
        deliver(&store, "user@x.test");
        assert!(
            store
                .deliveries(&DeliveryFilter::default())
                .unwrap()
                .is_empty()
        );
        deliver(&store, "bounced+x@emailulator.test");
        let deliveries = store.deliveries(&DeliveryFilter::default()).unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].event, "email.bounced");
    }

    #[test]
    fn no_webhooks_means_nothing_queued() {
        let store = Store::in_memory().unwrap();
        let id = deliver(&store, "user@x.test");
        assert!(
            store
                .deliveries(&DeliveryFilter::default())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .simulate_event(id, "email.opened", &Detail::default())
                .unwrap(),
            0
        );
    }

    #[test]
    fn simulated_events_carry_the_message() {
        let (store, _) = hooked();
        let id = deliver(&store, "user@x.test");
        assert_eq!(
            store
                .simulate_event(id, "email.clicked", &Detail::default())
                .unwrap(),
            1
        );
        let click = &store.deliveries(&DeliveryFilter::default()).unwrap()[0];
        assert_eq!(click.event, "email.clicked");
        assert_eq!(
            click.payload["data"]["click"]["link"],
            "https://x.test/verify"
        );
        assert!(
            store
                .simulate_event(id, "email.nope", &Detail::default())
                .is_err()
        );
    }

    #[test]
    fn a_webhook_holds_only_so_many_waiting_deliveries() {
        let (store, _) = hooked();
        let id = deliver(&store, "user@x.test");
        for _ in 0..MAX_PENDING {
            store
                .simulate_event(id, "email.opened", &Detail::default())
                .unwrap();
        }
        let count = |status: &str| -> i64 {
            store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM webhook_deliveries WHERE status = ?",
                    [status],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(count("pending"), MAX_PENDING);
        // The oldest, the first mail's sent and delivered, were given up and,
        // being done, pruned.
        let waiting: Vec<String> = store
            .conn()
            .prepare("SELECT DISTINCT type FROM webhook_deliveries")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(waiting, ["email.opened"]);
    }

    #[test]
    fn failed_attempts_follow_the_schedule_until_given_up() {
        let (store, _) = hooked();
        deliver(&store, "user@x.test");
        let due = store.claim_due_deliveries(now_ms(), 10).unwrap();
        assert_eq!(due.len(), 2);
        // Claimed ones are not handed out twice.
        assert!(store.claim_due_deliveries(now_ms(), 10).unwrap().is_empty());

        let id = &due[0].id;
        store
            .record_attempt(
                id,
                &Attempt::Answered {
                    status: 500,
                    body: "boom".into(),
                },
            )
            .unwrap();
        let delivery = store.delivery(id).unwrap().unwrap();
        assert_eq!(
            (delivery.status.as_str(), delivery.attempts),
            ("pending", 1)
        );
        assert_eq!(delivery.last_status, Some(500));
        let wait = delivery.next_attempt_at.unwrap() - delivery.last_attempt_at.unwrap();
        assert_eq!(wait, 5_000);

        for _ in 0..7 {
            store
                .record_attempt(id, &Attempt::Failed("refused".into()))
                .unwrap();
        }
        let delivery = store.delivery(id).unwrap().unwrap();
        assert_eq!((delivery.status.as_str(), delivery.attempts), ("failed", 8));
        assert_eq!(delivery.next_attempt_at, None);

        assert!(store.replay_delivery(id).unwrap());
        let delivery = store.delivery(id).unwrap().unwrap();
        assert_eq!(
            (delivery.status.as_str(), delivery.attempts),
            ("pending", 0)
        );

        store
            .record_attempt(
                &due[1].id,
                &Attempt::Answered {
                    status: 204,
                    body: String::new(),
                },
            )
            .unwrap();
        assert_eq!(
            store.delivery(&due[1].id).unwrap().unwrap().status,
            "succeeded"
        );
    }

    #[test]
    fn disabled_webhooks_queue_nothing_and_hold_what_is_pending() {
        let (store, hook) = hooked();
        deliver(&store, "user@x.test");
        store
            .update_webhook(
                &hook.id,
                WebhookChanges {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(store.claim_due_deliveries(now_ms(), 10).unwrap().is_empty());
        assert_eq!(store.next_delivery_at().unwrap(), None);
        deliver(&store, "user@x.test");
        assert_eq!(
            store.deliveries(&DeliveryFilter::default()).unwrap().len(),
            2
        );
    }

    #[test]
    fn webhooks_are_checked_and_go_with_their_inbox() {
        let store = Store::in_memory().unwrap();
        let bad = |endpoint: &str, events: Vec<String>| {
            store
                .create_webhook(NewWebhook {
                    inbox: DEFAULT_INBOX.into(),
                    endpoint: endpoint.into(),
                    events,
                    verify_tls: true,
                })
                .unwrap_err()
                .downcast::<WebhookError>()
                .is_ok()
        };
        assert!(bad("ftp://x.test", vec![]));
        assert!(bad("https://x.test", vec!["contact.created".into()]));

        let (inbox, _) = store
            .create_inbox_named(crate::store::NewInbox {
                name: "Billing".into(),
                ..Default::default()
            })
            .unwrap();
        let hook = store
            .create_webhook(NewWebhook {
                inbox: inbox.id.clone(),
                endpoint: "https://x.test/hook".into(),
                events: vec!["all".into()],
                verify_tls: false,
            })
            .unwrap();
        assert_eq!(store.webhooks(Some(&inbox.id)).unwrap().len(), 1);
        store.delete_inbox(&inbox.id).unwrap();
        assert!(store.webhook(&hook.id).unwrap().is_none());
    }

    #[test]
    fn tags_are_read_in_either_form() {
        let list = serde_json::json!([{"name": "category", "value": "welcome"}]);
        let object = serde_json::json!({"category": "welcome"});
        assert_eq!(
            tags_from_json(&list).unwrap(),
            tags_from_json(&object).unwrap()
        );
        assert!(tags_from_json(&serde_json::json!("x")).is_err());
        assert!(tags_from_json(&serde_json::json!([{"value": "x"}])).is_err());
    }

    #[test]
    fn message_ids_are_public_and_resolve() {
        let store = Store::in_memory().unwrap();
        let id = deliver(&store, "user@x.test");
        let email_id = store.summary(id).unwrap().unwrap().email_id;
        assert!(email_id.starts_with(EMAIL_ID_PREFIX) && email_id.len() == 27);
        assert_eq!(store.message_ref(&email_id).unwrap(), Some(id));
        assert_eq!(store.message_ref(&id.to_string()).unwrap(), Some(id));
        assert_eq!(store.message_ref("em_nope").unwrap(), None);
        assert_eq!(store.message_ref("nope").unwrap(), None);
    }
}
