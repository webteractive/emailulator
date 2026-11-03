//! Sends queued deliveries as they fall due: at once for new events, then on
//! the retry schedule for those that failed.

use std::sync::Arc;
use std::time::Duration;

use super::client::{self, Policy, Post};
use crate::store::{Attempt, DueDelivery, Store, now_ms};

/// How often to look for deliveries even when nothing in this process queued
/// any: another process, such as `emailulator mcp`, may have.
const POLL: Duration = Duration::from_secs(2);

/// How many deliveries to take on at once.
const BATCH: usize = 32;

/// Send deliveries until the process ends.
pub async fn run(store: Arc<Store>, policy: Policy) {
    loop {
        let claimed = {
            let store = store.clone();
            tokio::task::spawn_blocking(move || store.claim_due_deliveries(now_ms(), BATCH))
                .await
                .map_err(anyhow::Error::from)
                .and_then(|claimed| claimed)
        };
        let due = match claimed {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(%error, "could not read the webhook queue");
                tokio::time::sleep(POLL).await;
                continue;
            }
        };
        if !due.is_empty() {
            // One webhook's deliveries go in the order they were queued, so a
            // receiver hears `email.sent` before `email.delivered`; different
            // webhooks do not wait on one another.
            let mut groups: Vec<Vec<DueDelivery>> = Vec::new();
            for delivery in due {
                match groups.iter_mut().find(|g| g[0].webhook == delivery.webhook) {
                    Some(group) => group.push(delivery),
                    None => groups.push(vec![delivery]),
                }
            }
            for group in groups {
                let store = store.clone();
                tokio::spawn(async move {
                    for delivery in group {
                        let attempt = attempt(&delivery, policy).await;
                        let store = store.clone();
                        let id = delivery.id.clone();
                        let recorded = tokio::task::spawn_blocking(move || {
                            store.record_attempt(&id, &attempt)
                        })
                        .await;
                        if !matches!(recorded, Ok(Ok(()))) {
                            tracing::warn!(delivery = %delivery.id, "could not record a webhook attempt");
                        }
                    }
                });
            }
            continue;
        }

        let next = {
            let store = store.clone();
            tokio::task::spawn_blocking(move || store.next_delivery_at())
                .await
                .ok()
                .and_then(Result::ok)
                .flatten()
        };
        let wait = next.map_or(POLL, |at| {
            Duration::from_millis(u64::try_from(at - now_ms()).unwrap_or(0)).min(POLL)
        });
        tokio::select! {
            () = store.deliveries_queued().notified() => {}
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Sign and post one delivery.
async fn attempt(delivery: &DueDelivery, policy: Policy) -> Attempt {
    let timestamp = now_ms() / 1000;
    let signature = match super::sign(&delivery.secret, &delivery.id, timestamp, &delivery.payload)
    {
        Ok(signature) => signature,
        Err(error) => return Attempt::Failed(format!("{error:#}")),
    };
    let headers = [
        ("webhook-id", delivery.id.clone()),
        ("webhook-timestamp", timestamp.to_string()),
        ("webhook-signature", signature),
    ];
    let post = Post {
        endpoint: &delivery.endpoint,
        body: &delivery.payload,
        headers: &headers,
        verify_tls: delivery.verify_tls,
    };
    match client::post(post, policy).await {
        Ok(answer) => {
            if (200..300).contains(&answer.status) {
                tracing::info!(delivery = %delivery.id, status = answer.status, "webhook delivered");
            } else {
                tracing::warn!(delivery = %delivery.id, status = answer.status, endpoint = %delivery.endpoint, "webhook refused");
            }
            Attempt::Answered {
                status: answer.status,
                body: answer.body,
            }
        }
        Err(error) => {
            let error = format!("{error:#}");
            tracing::warn!(delivery = %delivery.id, endpoint = %delivery.endpoint, %error, "webhook not delivered");
            Attempt::Failed(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use tokio::sync::mpsc;

    use super::*;
    use crate::model::Source;
    use crate::store::{DEFAULT_INBOX, DeliveryFilter, Incoming, NewWebhook};

    /// A receiver that answers `status` and hands over what it was sent.
    async fn receiver(status: StatusCode) -> (String, mpsc::UnboundedReceiver<(HeaderMap, Bytes)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/hook",
            post(move |headers: HeaderMap, body: Bytes| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send((headers, body));
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/hook"), rx)
    }

    fn deliver(store: &Store, to: &str) {
        store
            .insert(Incoming {
                raw: format!("From: a@x.test\r\nTo: {to}\r\nSubject: Hi\r\n\r\nbody\r\n")
                    .into_bytes(),
                inbox: DEFAULT_INBOX.into(),
                envelope_from: None,
                envelope_to: vec![],
                source: Source::Api,
                tags: BTreeMap::new(),
            })
            .unwrap();
    }

    fn hook(store: &Store, endpoint: &str) -> String {
        store
            .create_webhook(NewWebhook {
                inbox: DEFAULT_INBOX.into(),
                endpoint: endpoint.into(),
                events: vec![],
                verify_tls: true,
            })
            .unwrap()
            .secret
    }

    const OPEN: Policy = Policy {
        allow_private: true,
    };

    #[tokio::test]
    async fn deliveries_arrive_signed_and_in_order() {
        let (endpoint, mut received) = receiver(StatusCode::OK).await;
        let store = Arc::new(Store::in_memory().unwrap());
        let secret = hook(&store, &endpoint);
        tokio::spawn(run(store.clone(), OPEN));
        deliver(&store, "user@x.test");

        let mut types = Vec::new();
        for _ in 0..2 {
            let (headers, body) = tokio::time::timeout(Duration::from_secs(10), received.recv())
                .await
                .unwrap()
                .unwrap();
            let header = |name: &str| headers.get(name).unwrap().to_str().unwrap().to_string();
            let id = header("webhook-id");
            let timestamp: i64 = header("webhook-timestamp").parse().unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert_eq!(
                header("webhook-signature"),
                super::super::sign(&secret, &id, timestamp, &body).unwrap()
            );
            assert_eq!(header("content-type"), "application/json");
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            types.push(value["type"].as_str().unwrap().to_string());
        }
        assert_eq!(types, ["email.sent", "email.delivered"]);

        // The log catches up once the answers are recorded.
        for _ in 0..50 {
            let log = store.deliveries(&DeliveryFilter::default()).unwrap();
            if log.iter().all(|d| d.status == "succeeded") {
                assert!(log.iter().all(|d| d.last_status == Some(200)));
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("deliveries were not recorded as succeeded");
    }

    #[tokio::test]
    async fn a_refusal_is_kept_for_retry() {
        let (endpoint, mut received) = receiver(StatusCode::INTERNAL_SERVER_ERROR).await;
        let store = Arc::new(Store::in_memory().unwrap());
        hook(&store, &endpoint);
        tokio::spawn(run(store.clone(), OPEN));
        deliver(&store, "user@x.test");
        received.recv().await.unwrap();
        for _ in 0..50 {
            let log = store.deliveries(&DeliveryFilter::default()).unwrap();
            if let Some(failed) = log.iter().find(|d| d.attempts == 1) {
                assert_eq!(failed.status, "pending");
                assert_eq!(failed.last_status, Some(500));
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the refusal was not recorded");
    }
}
