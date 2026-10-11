//! Model Context Protocol server: lets an agent read the mail its own actions
//! caused. Transport-agnostic — the HTTP endpoint and the stdio command both
//! feed JSON-RPC messages to [`Mcp::handle`], along with what the caller may
//! reach: an agent holding an inbox's API key works inside that inbox.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::compose::SendRequest;
use crate::model::ListFilter;
use crate::security::Access;
use crate::store::{DEFAULT_INBOX, InboxError, Store, now_ms};

/// Newest first. A client asking for a version not listed is answered with the
/// first, and decides for itself whether it can speak it.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const DEFAULT_BODY_CHARS: usize = 20_000;
const MAX_WAIT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_INLINE_ATTACHMENT: usize = 256 * 1024;

const INSTRUCTIONS: &str = "emailulator catches the email an application under development sends, \
instead of delivering it. Use these tools to check what was sent: after triggering something \
that emails (a sign-up, a password reset, an invoice), call wait_for_message with the recipient \
address in `to`, then read the body or the links it returns. Mail is kept in inboxes, one per \
application. With an inbox's API key every tool works inside that inbox and the `inbox` argument \
is unnecessary; with admin access, pass `inbox` to work in one or leave it out to span them all. \
Search queries accept bare words and from:, to:, subject:, is:unread, is:starred, has:attachment.";

const INBOX_ARG: &str = "The inbox to work in, by id or name. Needed only with admin access; an inbox API key is already confined to its own.";

pub struct Mcp {
    store: Arc<Store>,
    max_message_size: usize,
}

fn tools() -> Value {
    json!([
        {
            "name": "list_messages",
            "title": "List messages",
            "description": "List caught emails, newest first. Returns summaries: id, inbox, sender, recipients, subject, a snippet and flags. Use get_message for a body.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "inbox": {"type": "string", "description": INBOX_ARG},
                    "to": {"type": "string", "description": "Only messages delivered to exactly this recipient address."},
                    "query": {"type": "string", "description": "Search terms, e.g. `subject:reset is:unread` or a bare word."},
                    "unread_only": {"type": "boolean", "description": "Only unread messages."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "How many to return. Default 20."},
                    "before_id": {"type": "integer", "description": "Paging: only messages older than this id."}
                }
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_message",
            "title": "Read a message",
            "description": "Read one email: headers, the plain-text body, attachments and the links it contains. The HTML source is included only when asked for.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "include_html": {"type": "boolean", "description": "Also return the HTML body source."},
                    "include_headers": {"type": "boolean", "description": "Also return every raw header."},
                    "max_body_chars": {"type": "integer", "minimum": 1, "description": "Truncate bodies beyond this length. Default 20000."},
                    "mark_read": {"type": "boolean", "description": "Mark the message read."}
                },
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}
        },
        {
            "name": "wait_for_message",
            "title": "Wait for a message",
            "description": "Wait until an email matching the filters arrives and return it in full, as get_message does. Matches mail received in the last `since_seconds` too, so it is safe to call after the action that sends the email. Fails if nothing arrives before the timeout.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "inbox": {"type": "string", "description": INBOX_ARG},
                    "to": {"type": "string", "description": "The recipient address to watch for."},
                    "query": {"type": "string", "description": "Search terms the message must match."},
                    "after_id": {"type": "integer", "description": "Only messages newer than this id. Overrides since_seconds."},
                    "since_seconds": {"type": "integer", "minimum": 0, "description": "How far back an already-arrived message may be. Default 60."},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300, "description": "How long to wait. Default 30."}
                }
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_links",
            "title": "Links in a message",
            "description": "The links in one email, with their anchor text: the quick way to find a verification or reset URL.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "check_message",
            "title": "Check email client support",
            "description": "Report which email clients will not render a message as written: each HTML or CSS feature it uses that Gmail, Outlook, Apple Mail, Yahoo or Samsung Email lacks or only partly supports, with the platforms affected and why, plus notices such as Gmail clipping. Use it after changing an email template. It reads the markup; it does not render it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "clients": {"type": "array", "items": {"type": "string"}, "description": "Client families to check, e.g. [\"outlook\"]. Default: gmail, outlook, apple-mail, yahoo, samsung-email. Pass [\"all\"] for every client in the dataset."},
                    "max_issues": {"type": "integer", "minimum": 1, "description": "Report at most this many issues, worst first. Default 25."}
                },
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_attachment",
            "title": "Read an attachment",
            "description": "One attachment of an email. Text comes back as text, anything else as base64. Attachments over 256 KB are described but not returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "index": {"type": "integer", "minimum": 0, "description": "The attachment's index, from get_message."}
                },
                "required": ["id", "index"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "get_raw_message",
            "title": "Raw message source",
            "description": "The email exactly as received: full headers and MIME source. Use it to debug encoding, headers or MIME structure.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "max_chars": {"type": "integer", "minimum": 1, "description": "Truncate beyond this length. Default 20000."}
                },
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "list_inboxes",
            "title": "List inboxes",
            "description": "The inboxes within reach, with total and unread counts: every inbox with admin access, the caller's own with an inbox API key.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "mark_message",
            "title": "Flag a message",
            "description": "Set a message's read or starred flag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "read": {"type": "boolean"},
                    "starred": {"type": "boolean"}
                },
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}
        },
        {
            "name": "send_message",
            "title": "Deliver a test message",
            "description": "Put an email into an inbox as if an application had sent it. Nothing leaves the catcher. Useful for seeding test data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "inbox": {"type": "string", "description": "The inbox to deliver into. Needed only with admin access, where it defaults to `default`."},
                    "from": {"type": "string", "description": "`a@b` or `Name <a@b>`."},
                    "to": {"type": "array", "items": {"type": "string"}},
                    "cc": {"type": "array", "items": {"type": "string"}},
                    "bcc": {"type": "array", "items": {"type": "string"}},
                    "subject": {"type": "string"},
                    "text": {"type": "string"},
                    "html": {"type": "string"}
                },
                "required": ["from", "to"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false}
        },
        {
            "name": "delete_messages",
            "title": "Delete messages",
            "description": "Permanently delete messages: one by `id`, or everything matching `to` and `query`, or with `all: true` everything within reach. Give `id`, or at least one of `to`, `query` and `all`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "inbox": {"type": "string", "description": INBOX_ARG},
                    "to": {"type": "string", "description": "Delete messages delivered to exactly this address."},
                    "query": {"type": "string", "description": "Delete messages matching these search terms."},
                    "all": {"type": "boolean", "description": "Delete every message in the inbox, or with admin access and no inbox, in all of them."}
                }
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true}
        }
    ])
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Unix milliseconds as an RFC 3339 UTC timestamp.
fn rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days, after Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn truncate(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((cut, _)) => (text[..cut].to_string(), true),
        None => (text.to_string(), false),
    }
}

fn arg_i64(args: &Value, name: &str) -> Result<i64> {
    args.get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("`{name}` is required and must be an integer"))
}

fn arg_str<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn arg_bool(args: &Value, name: &str) -> bool {
    args.get(name).and_then(Value::as_bool).unwrap_or(false)
}

impl Mcp {
    pub fn new(store: Arc<Store>, max_message_size: usize) -> Self {
        Self {
            store,
            max_message_size,
        }
    }

    /// Handle one JSON-RPC message or batch on behalf of a caller with the
    /// given access. Returns `None` when nothing is owed back, as for a
    /// notification.
    pub async fn handle(&self, message: Value, access: &Access) -> Option<Value> {
        match message {
            Value::Array(batch) if batch.is_empty() => {
                Some(rpc_error(Value::Null, -32600, "empty batch"))
            }
            Value::Array(batch) => {
                let mut replies = Vec::new();
                for item in batch {
                    if let Some(reply) = self.handle_one(item, access).await {
                        replies.push(reply);
                    }
                }
                (!replies.is_empty()).then_some(Value::Array(replies))
            }
            other => self.handle_one(other, access).await,
        }
    }

    async fn handle_one(&self, message: Value, access: &Access) -> Option<Value> {
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response to a request we never made, or not JSON-RPC at all.
            return message
                .get("id")
                .is_none()
                .then(|| rpc_error(Value::Null, -32600, "not a JSON-RPC request"));
        };
        // No id means a notification: act on it, answer nothing.
        let id = message.get("id").cloned()?;
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        Some(match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = requested
                    .filter(|v| PROTOCOL_VERSIONS.contains(v))
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {
                            "name": "emailulator",
                            "title": "emailulator",
                            "version": env!("CARGO_PKG_VERSION"),
                        },
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, json!({"tools": tools()})),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(rpc_error(id, -32602, "tools/call needs a tool name"));
                };
                let known = tools()
                    .as_array()
                    .is_some_and(|tools| tools.iter().any(|t| t["name"] == name));
                if !known {
                    return Some(rpc_error(id, -32602, format!("unknown tool: {name}")));
                }
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                // A tool that fails is still a successful protocol exchange: the
                // model should see the failure and be able to correct itself.
                let (payload, is_error) = match self.call(name, &args, access).await {
                    Ok(value) => (value, false),
                    Err(error) => (json!({"error": error.to_string()}), true),
                };
                let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
                rpc_result(
                    id,
                    json!({
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": payload,
                        "isError": is_error,
                    }),
                )
            }
            _ => rpc_error(id, -32601, format!("method not found: {method}")),
        })
    }

    /// Run a store operation off the async threads.
    async fn store<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Store) -> Result<T> + Send + 'static,
    {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&store)).await?
    }

    /// The inbox a call is about: the caller's own if it is confined to one,
    /// otherwise the one it names, or all of them when it names none.
    async fn scope(&self, access: &Access, args: &Value) -> Result<Option<String>> {
        // An inbox may be named by its id or by its name.
        let requested = match arg_str(args, "inbox").map(str::to_string) {
            Some(text) => {
                let wanted = text.clone();
                match self.store(move |s| s.resolve_inbox(&wanted)).await? {
                    Some(id) => Some(id),
                    None => return Err(InboxError::NotFound(text).into()),
                }
            }
            None => None,
        };
        match (access, requested) {
            // Said the same way whether the other inbox exists or not.
            (Access::Inbox(own), Some(other)) if *own != other => {
                bail!("this API key reaches one inbox only, and that is not it")
            }
            (Access::Inbox(own), _) => Ok(Some(own.clone())),
            (Access::Admin, requested) => Ok(requested),
        }
    }

    /// Refuse a message outside the caller's inbox in the same words as one
    /// that does not exist.
    async fn authorize(&self, access: &Access, id: i64) -> Result<()> {
        let owner = self.store(move |s| s.message_inbox(id)).await?;
        match (owner, access) {
            (Some(_), Access::Admin) => Ok(()),
            (Some(owner), Access::Inbox(own)) if owner == *own => Ok(()),
            _ => bail!("no message with id {id}"),
        }
    }

    async fn message(&self, id: i64, args: &Value) -> Result<Value> {
        let detail = self
            .store(move |s| s.get(id))
            .await?
            .ok_or_else(|| anyhow!("no message with id {id}"))?;
        let links = self.store(move |s| s.links(id)).await?.unwrap_or_default();
        let max = args
            .get("max_body_chars")
            .and_then(Value::as_u64)
            .map_or(DEFAULT_BODY_CHARS, |n| n as usize);

        let mut out = json!({
            "id": detail.summary.id,
            "inbox": detail.summary.inbox,
            "inbox_name": detail.summary.inbox_name,
            "received_at": rfc3339(detail.summary.received_at),
            "from": detail.summary.from.as_ref().map(|a| a.display()),
            "to": detail.summary.to.iter().map(|a| a.display()).collect::<Vec<_>>(),
            "cc": detail.summary.cc.iter().map(|a| a.display()).collect::<Vec<_>>(),
            "delivered_to": detail.summary.recipients,
            "subject": detail.summary.subject,
            "read": detail.summary.read,
            "starred": detail.summary.starred,
            "has_html": detail.html.is_some(),
            "attachments": detail.attachments,
            "links": links,
        });
        let body = match (&detail.text, &detail.html) {
            (Some(text), _) => Some(text.clone()),
            // No plain part: give the agent the HTML reduced to text rather
            // than nothing.
            (None, Some(html)) => Some(crate::parse::html_to_text(html)),
            (None, None) => None,
        };
        if let Some(body) = body {
            let (text, cut) = truncate(&body, max);
            out["text"] = json!(text);
            if cut {
                out["text_truncated"] = json!(true);
            }
        }
        if arg_bool(args, "include_html")
            && let Some(html) = &detail.html
        {
            let (html, cut) = truncate(html, max);
            out["html"] = json!(html);
            if cut {
                out["html_truncated"] = json!(true);
            }
        }
        if arg_bool(args, "include_headers") {
            out["headers"] = json!(detail.headers);
        }
        Ok(out)
    }

    async fn call(&self, name: &str, args: &Value, access: &Access) -> Result<Value> {
        match name {
            "list_messages" => {
                let filter = ListFilter {
                    inbox: self.scope(access, args).await?,
                    to: arg_str(args, "to").map(str::to_string),
                    query: arg_str(args, "query").map(str::to_string),
                    unread: arg_bool(args, "unread_only").then_some(true),
                    before_id: args.get("before_id").and_then(Value::as_i64),
                    limit: Some(
                        args.get("limit")
                            .and_then(Value::as_u64)
                            .unwrap_or(20)
                            .min(100) as usize,
                    ),
                    ..Default::default()
                };
                let page = self.store(move |s| s.list(&filter)).await?;
                let messages: Vec<Value> = page
                    .messages
                    .iter()
                    .map(|m| {
                        json!({
                            "id": m.id,
                            "inbox": m.inbox,
                            "inbox_name": m.inbox_name,
                            "received_at": rfc3339(m.received_at),
                            "from": m.from.as_ref().map(|a| a.display()),
                            "to": m.to.iter().map(|a| a.display()).collect::<Vec<_>>(),
                            "delivered_to": m.recipients,
                            "subject": m.subject,
                            "snippet": m.snippet,
                            "read": m.read,
                            "starred": m.starred,
                            "attachments": m.attachment_count,
                        })
                    })
                    .collect();
                Ok(json!({"total": page.total, "unread": page.unread, "messages": messages}))
            }
            "get_message" => {
                let id = arg_i64(args, "id")?;
                self.authorize(access, id).await?;
                if arg_bool(args, "mark_read") {
                    self.store(move |s| s.set_flags(id, Some(true), None))
                        .await?;
                }
                self.message(id, args).await
            }
            "wait_for_message" => {
                let timeout = args
                    .get("timeout_seconds")
                    .and_then(Value::as_u64)
                    .map_or(Duration::from_secs(30), Duration::from_secs)
                    .min(MAX_WAIT);
                let after_id = args.get("after_id").and_then(Value::as_i64);
                let since_seconds = args
                    .get("since_seconds")
                    .and_then(Value::as_i64)
                    .unwrap_or(60);
                let filter = ListFilter {
                    inbox: self.scope(access, args).await?,
                    to: arg_str(args, "to").map(str::to_string),
                    query: arg_str(args, "query").map(str::to_string),
                    after_id,
                    since: after_id
                        .is_none()
                        .then(|| now_ms() - since_seconds.max(0) * 1000),
                    limit: Some(1),
                    ..Default::default()
                };
                let deadline = tokio::time::Instant::now() + timeout;
                loop {
                    let wanted = filter.clone();
                    let page = self.store(move |s| s.list(&wanted)).await?;
                    if let Some(found) = page.messages.first() {
                        return self.message(found.id, args).await;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "no matching message arrived within {} seconds",
                            timeout.as_secs()
                        );
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
            "get_links" => {
                let id = arg_i64(args, "id")?;
                self.authorize(access, id).await?;
                let links = self
                    .store(move |s| s.links(id))
                    .await?
                    .ok_or_else(|| anyhow!("no message with id {id}"))?;
                Ok(json!({"id": id, "links": links}))
            }
            "check_message" => {
                let id = arg_i64(args, "id")?;
                self.authorize(access, id).await?;
                let detail = self
                    .store(move |s| s.get(id))
                    .await?
                    .ok_or_else(|| anyhow!("no message with id {id}"))?;
                // An agent wants the clients that matter, not all twenty-two.
                let named: Vec<String> = args
                    .get("clients")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .map(|c| c.trim().to_ascii_lowercase())
                            .collect()
                    })
                    .unwrap_or_default();
                let only: Option<Vec<String>> = if named.iter().any(|c| c == "all") {
                    None
                } else if named.is_empty() {
                    Some(
                        ["gmail", "outlook", "apple-mail", "yahoo", "samsung-email"]
                            .map(String::from)
                            .to_vec(),
                    )
                } else {
                    Some(named)
                };
                let mut report = crate::check::check(&detail, only.as_deref());
                let max = args.get("max_issues").and_then(Value::as_u64).unwrap_or(25) as usize;
                let total = report.issues.len();
                report.issues.truncate(max);
                let mut out = serde_json::to_value(&report)?;
                out["id"] = json!(id);
                out["has_html"] = json!(detail.html.is_some());
                if total > max {
                    out["issues_omitted"] = json!(total - max);
                }
                Ok(out)
            }
            "get_attachment" => {
                let id = arg_i64(args, "id")?;
                let index = arg_i64(args, "index")? as usize;
                self.authorize(access, id).await?;
                let (meta, bytes) = self
                    .store(move |s| s.attachment(id, index))
                    .await?
                    .ok_or_else(|| anyhow!("message {id} has no attachment {index}"))?;
                let mut out = serde_json::to_value(&meta)?;
                if bytes.len() > MAX_INLINE_ATTACHMENT {
                    out["omitted"] = json!("larger than 256 KB; download it over the HTTP API");
                } else if let Ok(text) = String::from_utf8(bytes.clone())
                    && (meta.content_type.starts_with("text/")
                        || meta.content_type.contains("json"))
                {
                    out["text"] = json!(text);
                } else {
                    use base64::Engine;
                    out["base64"] = json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
                }
                Ok(out)
            }
            "get_raw_message" => {
                let id = arg_i64(args, "id")?;
                self.authorize(access, id).await?;
                let raw = self
                    .store(move |s| s.raw(id))
                    .await?
                    .ok_or_else(|| anyhow!("no message with id {id}"))?;
                let max = args
                    .get("max_chars")
                    .and_then(Value::as_u64)
                    .map_or(DEFAULT_BODY_CHARS, |n| n as usize);
                let (source, cut) = truncate(&String::from_utf8_lossy(&raw), max);
                Ok(json!({"id": id, "size": raw.len(), "source": source, "truncated": cut}))
            }
            "list_inboxes" => {
                let own = access.inbox().map(str::to_string);
                let (inboxes, stats) = self
                    .store(move |s| {
                        let mut inboxes = s.inboxes()?;
                        if let Some(own) = &own {
                            inboxes.retain(|inbox| &inbox.id == own);
                        }
                        Ok((inboxes, s.stats(own.as_deref())?))
                    })
                    .await?;
                let inboxes: Vec<Value> = inboxes
                    .iter()
                    .map(|i| {
                        json!({
                            "id": i.id, "name": i.name, "description": i.description,
                            "total": i.total, "unread": i.unread,
                        })
                    })
                    .collect();
                Ok(json!({"total": stats.total, "unread": stats.unread, "inboxes": inboxes}))
            }
            "mark_message" => {
                let id = arg_i64(args, "id")?;
                let read = args.get("read").and_then(Value::as_bool);
                let starred = args.get("starred").and_then(Value::as_bool);
                if read.is_none() && starred.is_none() {
                    bail!("give `read`, `starred`, or both");
                }
                self.authorize(access, id).await?;
                self.store(move |s| s.set_flags(id, read, starred)).await?;
                Ok(json!({"id": id, "read": read, "starred": starred}))
            }
            "send_message" => {
                let inbox = self
                    .scope(access, args)
                    .await?
                    .unwrap_or_else(|| DEFAULT_INBOX.to_string());
                let mut fields = args.clone();
                if let Some(object) = fields.as_object_mut() {
                    object.remove("inbox");
                }
                let request: SendRequest =
                    serde_json::from_value(fields).map_err(|e| anyhow!("invalid message: {e}"))?;
                let incoming = request.build(&inbox)?;
                if incoming.raw.len() > self.max_message_size {
                    bail!(
                        "the message exceeds the {} byte limit",
                        self.max_message_size
                    );
                }
                let summary = self.store(move |s| s.insert(incoming)).await?;
                Ok(
                    json!({"id": summary.id, "inbox": summary.inbox, "delivered_to": summary.recipients}),
                )
            }
            "delete_messages" => {
                if let Some(id) = args.get("id").and_then(Value::as_i64) {
                    self.authorize(access, id).await?;
                    let deleted = self.store(move |s| s.delete(id)).await?;
                    return Ok(json!({"deleted": usize::from(deleted)}));
                }
                let to = arg_str(args, "to").map(str::to_string);
                let query = arg_str(args, "query").map(str::to_string);
                // Deleting a whole inbox, or everything, has to be said outright
                // rather than follow from having left the filters out.
                if to.is_none() && query.is_none() && !arg_bool(args, "all") {
                    bail!(
                        "give `id`, a `to` or `query` to match, or `all: true` to delete everything within reach"
                    );
                }
                let filter = ListFilter {
                    inbox: self.scope(access, args).await?,
                    to,
                    query,
                    ..Default::default()
                };
                let deleted = self.store(move |s| s.clear(&filter)).await?;
                Ok(json!({"deleted": deleted}))
            }
            other => bail!("unknown tool: {other}"),
        }
    }
}

/// Serve MCP over stdio: one JSON-RPC message per line in, one per line out.
pub async fn serve_stdio(mcp: Mcp, access: Access) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => mcp.handle(message, &access).await,
            Err(error) => Some(rpc_error(
                Value::Null,
                -32700,
                format!("parse error: {error}"),
            )),
        };
        if let Some(reply) = reply {
            let mut out = serde_json::to_vec(&reply)?;
            out.push(b'\n');
            stdout.write_all(&out).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;
    use crate::store::Incoming;

    const ADMIN: Access = Access::Admin;

    fn mcp() -> (Mcp, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        (Mcp::new(store.clone(), 1024 * 1024), store)
    }

    fn deliver_in(store: &Store, inbox: &str, to: &str, subject: &str, body: &str) -> i64 {
        store
            .insert(Incoming {
                raw: format!(
                    "From: app@x.test\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n"
                )
                .into_bytes(),
                inbox: inbox.into(),
                envelope_from: None,
                envelope_to: vec![to.into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id
    }

    fn deliver(store: &Store, to: &str, subject: &str, body: &str) -> i64 {
        deliver_in(store, DEFAULT_INBOX, to, subject, body)
    }

    async fn call_as(mcp: &Mcp, access: &Access, name: &str, arguments: Value) -> (Value, bool) {
        let reply = mcp
            .handle(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}),
                access,
            )
            .await
            .unwrap();
        let result = &reply["result"];
        (
            result["structuredContent"].clone(),
            result["isError"].as_bool().unwrap(),
        )
    }

    async fn call(mcp: &Mcp, name: &str, arguments: Value) -> (Value, bool) {
        call_as(mcp, &ADMIN, name, arguments).await
    }

    #[tokio::test]
    async fn negotiates_a_protocol_version() {
        let (mcp, _) = mcp();
        let init = |version: &str| {
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        };
        let reply = mcp.handle(init("2025-03-26"), &ADMIN).await.unwrap();
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(reply["result"]["serverInfo"]["name"], "emailulator");
        let reply = mcp.handle(init("1999-01-01"), &ADMIN).await.unwrap();
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[tokio::test]
    async fn notifications_get_no_reply_and_unknown_methods_an_error() {
        let (mcp, _) = mcp();
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(mcp.handle(note, &ADMIN).await.is_none());
        let reply = mcp
            .handle(json!({"jsonrpc": "2.0", "id": 7, "method": "nope"}), &ADMIN)
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32601);
        assert_eq!(reply["id"], 7);
        let reply = mcp
            .handle(
                json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "nope"}}),
                &ADMIN,
            )
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn every_tool_has_a_schema() {
        let (mcp, _) = mcp();
        let reply = mcp
            .handle(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                &ADMIN,
            )
            .await
            .unwrap();
        let tools = reply["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 11);
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
            assert!(tool["description"].as_str().unwrap().len() > 20);
        }
    }

    #[tokio::test]
    async fn reads_lists_and_extracts_links() {
        let (mcp, store) = mcp();
        let id = deliver(
            &store,
            "bob@x.test",
            "Reset",
            "Go to https://app.test/reset/abc now",
        );

        let (list, error) = call(&mcp, "list_messages", json!({"to": "bob@x.test"})).await;
        assert!(!error);
        assert_eq!(list["total"], 1);
        assert_eq!(list["messages"][0]["subject"], "Reset");
        assert_eq!(list["messages"][0]["inbox"], "default");

        let (message, _) = call(&mcp, "get_message", json!({"id": id, "mark_read": true})).await;
        assert_eq!(message["links"][0]["url"], "https://app.test/reset/abc");
        assert!(message["text"].as_str().unwrap().contains("Go to"));
        assert!(message["received_at"].as_str().unwrap().ends_with('Z'));
        assert!(store.get(id).unwrap().unwrap().summary.read);

        let (missing, error) = call(&mcp, "get_message", json!({"id": 404})).await;
        assert!(error);
        assert!(missing["error"].as_str().unwrap().contains("404"));
    }

    #[tokio::test]
    async fn an_inbox_key_confines_every_tool_to_its_inbox() {
        let (mcp, store) = mcp();
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        let invoice = deliver_in(&store, "billing", "bob@x.test", "Invoice", "x");
        let promo = deliver_in(
            &store,
            "marketing",
            "bob@x.test",
            "Sale",
            "see https://shop.test/sale",
        );
        let billing = Access::Inbox("billing".into());

        let (list, _) = call_as(&mcp, &billing, "list_messages", json!({})).await;
        assert_eq!(list["total"], 1);
        assert_eq!(list["messages"][0]["id"], invoice);
        let (inboxes, _) = call_as(&mcp, &billing, "list_inboxes", json!({})).await;
        assert_eq!(inboxes["inboxes"].as_array().unwrap().len(), 1);
        assert_eq!(inboxes["inboxes"][0]["id"], "billing");

        // Naming another inbox is an error, not a silent switch or an empty list.
        let (refused, error) = call_as(
            &mcp,
            &billing,
            "list_messages",
            json!({"inbox": "marketing"}),
        )
        .await;
        assert!(error, "{refused}");

        // Another inbox's message is out of reach by id, in every tool that takes one.
        for (tool, args) in [
            ("get_message", json!({"id": promo})),
            ("get_links", json!({"id": promo})),
            ("get_raw_message", json!({"id": promo})),
            ("get_attachment", json!({"id": promo, "index": 0})),
            ("mark_message", json!({"id": promo, "read": true})),
            ("delete_messages", json!({"id": promo})),
        ] {
            let (reply, error) = call_as(&mcp, &billing, tool, args).await;
            assert!(error, "{tool}: {reply}");
            assert!(
                reply["error"].as_str().unwrap().contains("no message"),
                "{tool}: {reply}"
            );
        }
        assert!(!store.get(promo).unwrap().unwrap().summary.read);

        // What it sends and deletes stays in its inbox.
        let (sent, error) = call_as(
            &mcp,
            &billing,
            "send_message",
            json!({"from": "a@x.test", "to": ["b@x.test"], "subject": "Seed"}),
        )
        .await;
        assert!(!error, "{sent}");
        assert_eq!(sent["inbox"], "billing");
        let (deleted, _) = call_as(&mcp, &billing, "delete_messages", json!({"all": true})).await;
        assert_eq!(deleted["deleted"], 2);
        assert!(
            store.get(promo).unwrap().is_some(),
            "marketing's mail is untouched"
        );

        // The admin spans inboxes, or names one.
        let (all, _) = call(&mcp, "list_messages", json!({})).await;
        assert_eq!(all["total"], 1);
        let (one, _) = call(&mcp, "list_messages", json!({"inbox": "billing"})).await;
        assert_eq!(one["total"], 0);
        let (unknown, error) = call(&mcp, "list_messages", json!({"inbox": "nowhere"})).await;
        assert!(error, "{unknown}");
    }

    #[tokio::test]
    async fn checks_a_message_against_the_main_clients() {
        let (mcp, store) = mcp();
        let id = store
            .insert(Incoming {
                raw: b"From: a@x.test\r\nTo: b@x.test\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n\
                       <div style=\"display:flex\"><p style=\"border-radius:4px\">Hi</p></div>\r\n"
                    .to_vec(),
                inbox: DEFAULT_INBOX.into(),
                envelope_from: None,
                envelope_to: vec!["b@x.test".into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id;

        let (report, error) = call(&mcp, "check_message", json!({"id": id})).await;
        assert!(!error, "{report}");
        assert_eq!(
            report["clients"].as_array().unwrap().len(),
            5,
            "the main clients by default"
        );
        let flex = report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["slug"] == "css-display-flex")
            .expect("flexbox is reported");
        assert!(
            flex["clients"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["family"] == "outlook")
        );
        assert!(
            report["notices"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["code"] == "no-text-part")
        );

        let (one, _) = call(
            &mcp,
            "check_message",
            json!({"id": id, "clients": ["outlook"], "max_issues": 1}),
        )
        .await;
        assert_eq!(one["clients"].as_array().unwrap().len(), 1);
        assert_eq!(one["issues"].as_array().unwrap().len(), 1);
        assert!(one["issues_omitted"].as_u64().unwrap() >= 1);

        let (everyone, _) =
            call(&mcp, "check_message", json!({"id": id, "clients": ["all"]})).await;
        assert!(everyone["clients"].as_array().unwrap().len() > 15);

        let (_, error) = call(&mcp, "check_message", json!({"id": 404})).await;
        assert!(error);
    }

    #[tokio::test]
    async fn waits_for_mail_that_arrives_later() {
        let (mcp, store) = mcp();
        deliver(
            &store,
            "bob@x.test",
            "Old",
            "not the recipient being waited on",
        );
        let sender = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            deliver(&sender, "carol@x.test", "Welcome", "hello carol");
        });
        let (found, error) = call(
            &mcp,
            "wait_for_message",
            json!({"to": "carol@x.test", "timeout_seconds": 5}),
        )
        .await;
        assert!(!error, "{found}");
        assert_eq!(found["subject"], "Welcome");

        let (timed_out, error) = call(
            &mcp,
            "wait_for_message",
            json!({"to": "nobody@x.test", "timeout_seconds": 1}),
        )
        .await;
        assert!(error);
        assert!(
            timed_out["error"]
                .as_str()
                .unwrap()
                .contains("within 1 seconds")
        );
    }

    #[tokio::test]
    async fn sends_and_deletes() {
        let (mcp, store) = mcp();
        let (sent, error) = call(
            &mcp,
            "send_message",
            json!({"from": "a@x.test", "to": ["b@x.test"], "subject": "Seed", "text": "hi"}),
        )
        .await;
        assert!(!error, "{sent}");
        assert_eq!(sent["inbox"], "default");
        deliver(&store, "c@x.test", "Other", "x");

        let (_, error) = call(&mcp, "delete_messages", json!({})).await;
        assert!(error, "deleting needs an explicit target");
        let (_, error) = call(&mcp, "delete_messages", json!({"inbox": "default"})).await;
        assert!(error, "naming an inbox is not saying to empty it");
        let (deleted, _) = call(&mcp, "delete_messages", json!({"to": "c@x.test"})).await;
        assert_eq!(deleted["deleted"], 1);
        let (deleted, error) = call(&mcp, "delete_messages", json!({"all": true})).await;
        assert!(!error);
        assert_eq!(deleted["deleted"], 1);
    }

    #[test]
    fn formats_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_760_184_000_000), "2025-10-11T12:00:00Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
    }
}
