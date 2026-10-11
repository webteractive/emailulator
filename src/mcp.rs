//! Model Context Protocol server: lets an agent read the mail its own actions
//! caused. Transport-agnostic — the HTTP endpoint and the stdio command both
//! feed JSON-RPC messages to [`Mcp::handle`].

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::compose::SendRequest;
use crate::model::ListFilter;
use crate::store::{Store, now_ms};

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
address, then read the body or the links it returns. Each recipient address is its own mailbox. \
Search queries accept bare words and from:, to:, subject:, is:unread, is:starred, has:attachment.";

pub struct Mcp {
    store: Arc<Store>,
    max_message_size: usize,
}

fn tools() -> Value {
    json!([
        {
            "name": "list_messages",
            "title": "List messages",
            "description": "List caught emails, newest first. Returns summaries: id, sender, recipients, subject, a snippet and flags. Use get_message for a body.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mailbox": {"type": "string", "description": "Only messages delivered to this recipient address."},
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
                    "mailbox": {"type": "string", "description": "The recipient address to watch."},
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
            "name": "list_mailboxes",
            "title": "List mailboxes",
            "description": "Every recipient address that has received mail, with total and unread counts.",
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
            "description": "Put an email into the catcher as if an application had sent it. Nothing leaves the catcher. Useful for seeding a mailbox.",
            "inputSchema": {
                "type": "object",
                "properties": {
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
            "description": "Permanently delete one message by id, every message in one mailbox, or — with all set to true — every message. Exactly one of id, mailbox or all is required.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "mailbox": {"type": "string"},
                    "all": {"type": "boolean"}
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

    /// Handle one JSON-RPC message or batch. Returns `None` when nothing is
    /// owed back, as for a notification.
    pub async fn handle(&self, message: Value) -> Option<Value> {
        match message {
            Value::Array(batch) if batch.is_empty() => {
                Some(rpc_error(Value::Null, -32600, "empty batch"))
            }
            Value::Array(batch) => {
                let mut replies = Vec::new();
                for item in batch {
                    if let Some(reply) = self.handle_one(item).await {
                        replies.push(reply);
                    }
                }
                (!replies.is_empty()).then_some(Value::Array(replies))
            }
            other => self.handle_one(other).await,
        }
    }

    async fn handle_one(&self, message: Value) -> Option<Value> {
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
                let (payload, is_error) = match self.call(name, &args).await {
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
            "received_at": rfc3339(detail.summary.received_at),
            "from": detail.summary.from.as_ref().map(|a| a.display()),
            "to": detail.summary.to.iter().map(|a| a.display()).collect::<Vec<_>>(),
            "cc": detail.summary.cc.iter().map(|a| a.display()).collect::<Vec<_>>(),
            "delivered_to": detail.summary.mailboxes,
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
            (None, Some(html)) => Some(mail_parser::decoders::html::html_to_text(html)),
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

    async fn call(&self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "list_messages" => {
                let filter = ListFilter {
                    mailbox: arg_str(args, "mailbox").map(str::to_string),
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
                            "received_at": rfc3339(m.received_at),
                            "from": m.from.as_ref().map(|a| a.display()),
                            "to": m.to.iter().map(|a| a.display()).collect::<Vec<_>>(),
                            "delivered_to": m.mailboxes,
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
                    mailbox: arg_str(args, "mailbox").map(str::to_string),
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
                let links = self
                    .store(move |s| s.links(id))
                    .await?
                    .ok_or_else(|| anyhow!("no message with id {id}"))?;
                Ok(json!({"id": id, "links": links}))
            }
            "get_attachment" => {
                let id = arg_i64(args, "id")?;
                let index = arg_i64(args, "index")? as usize;
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
            "list_mailboxes" => {
                let mailboxes = self.store(|s| s.mailboxes()).await?;
                let stats = self.store(|s| s.stats()).await?;
                Ok(json!({"total": stats.total, "unread": stats.unread, "mailboxes": mailboxes}))
            }
            "mark_message" => {
                let id = arg_i64(args, "id")?;
                let read = args.get("read").and_then(Value::as_bool);
                let starred = args.get("starred").and_then(Value::as_bool);
                if read.is_none() && starred.is_none() {
                    bail!("give `read`, `starred`, or both");
                }
                if !self.store(move |s| s.set_flags(id, read, starred)).await? {
                    bail!("no message with id {id}");
                }
                Ok(json!({"id": id, "read": read, "starred": starred}))
            }
            "send_message" => {
                let request: SendRequest = serde_json::from_value(args.clone())
                    .map_err(|e| anyhow!("invalid message: {e}"))?;
                let incoming = request.build()?;
                if incoming.raw.len() > self.max_message_size {
                    bail!(
                        "the message exceeds the {} byte limit",
                        self.max_message_size
                    );
                }
                let summary = self.store(move |s| s.insert(incoming)).await?;
                Ok(json!({"id": summary.id, "delivered_to": summary.mailboxes}))
            }
            "delete_messages" => {
                let id = args.get("id").and_then(Value::as_i64);
                let mailbox = arg_str(args, "mailbox").map(str::to_string);
                let all = arg_bool(args, "all");
                let chosen =
                    usize::from(id.is_some()) + usize::from(mailbox.is_some()) + usize::from(all);
                if chosen != 1 {
                    bail!("give exactly one of `id`, `mailbox`, or `all: true`");
                }
                let deleted = match (id, mailbox) {
                    (Some(id), _) => usize::from(self.store(move |s| s.delete(id)).await?),
                    (None, Some(mailbox)) => self.store(move |s| s.clear(Some(&mailbox))).await?,
                    (None, None) => self.store(|s| s.clear(None)).await?,
                };
                Ok(json!({"deleted": deleted}))
            }
            other => bail!("unknown tool: {other}"),
        }
    }
}

/// Serve MCP over stdio: one JSON-RPC message per line in, one per line out.
pub async fn serve_stdio(mcp: Mcp) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => mcp.handle(message).await,
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

    fn mcp() -> (Mcp, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        (Mcp::new(store.clone(), 1024 * 1024), store)
    }

    fn deliver(store: &Store, to: &str, subject: &str, body: &str) -> i64 {
        store
            .insert(Incoming {
                raw: format!(
                    "From: app@x.test\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n"
                )
                .into_bytes(),
                envelope_from: None,
                envelope_to: vec![to.into()],
                source: Source::Smtp,
            })
            .unwrap()
            .id
    }

    async fn call(mcp: &Mcp, name: &str, arguments: Value) -> (Value, bool) {
        let reply = mcp
            .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}}))
            .await
            .unwrap();
        let result = &reply["result"];
        (
            result["structuredContent"].clone(),
            result["isError"].as_bool().unwrap(),
        )
    }

    #[tokio::test]
    async fn negotiates_a_protocol_version() {
        let (mcp, _) = mcp();
        let init = |version: &str| {
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        };
        let reply = mcp.handle(init("2025-03-26")).await.unwrap();
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(reply["result"]["serverInfo"]["name"], "emailulator");
        let reply = mcp.handle(init("1999-01-01")).await.unwrap();
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[tokio::test]
    async fn notifications_get_no_reply_and_unknown_methods_an_error() {
        let (mcp, _) = mcp();
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(mcp.handle(note).await.is_none());
        let reply = mcp
            .handle(json!({"jsonrpc": "2.0", "id": 7, "method": "nope"}))
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32601);
        assert_eq!(reply["id"], 7);
        let reply = mcp
            .handle(json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "nope"}}))
            .await
            .unwrap();
        assert_eq!(reply["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn every_tool_has_a_schema() {
        let (mcp, _) = mcp();
        let reply = mcp
            .handle(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await
            .unwrap();
        let tools = reply["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
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

        let (list, error) = call(&mcp, "list_messages", json!({"mailbox": "bob@x.test"})).await;
        assert!(!error);
        assert_eq!(list["total"], 1);
        assert_eq!(list["messages"][0]["subject"], "Reset");

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
    async fn waits_for_mail_that_arrives_later() {
        let (mcp, store) = mcp();
        deliver(&store, "bob@x.test", "Old", "not this mailbox's concern");
        let sender = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            deliver(&sender, "carol@x.test", "Welcome", "hello carol");
        });
        let (found, error) = call(
            &mcp,
            "wait_for_message",
            json!({"mailbox": "carol@x.test", "timeout_seconds": 5}),
        )
        .await;
        assert!(!error, "{found}");
        assert_eq!(found["subject"], "Welcome");

        let (timed_out, error) = call(
            &mcp,
            "wait_for_message",
            json!({"mailbox": "nobody@x.test", "timeout_seconds": 1}),
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
        assert_eq!(store.stats().unwrap().total, 1);

        let (_, error) = call(&mcp, "delete_messages", json!({})).await;
        assert!(error, "deleting needs an explicit target");
        let (_, error) = call(&mcp, "delete_messages", json!({"id": 1, "all": true})).await;
        assert!(error, "and only one target");
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
