//! SQLite-backed message store.
//!
//! Every method is synchronous and takes a short-lived lock, so async callers
//! run them on a blocking thread and the desktop app calls them directly.
//!
//! # Search syntax
//!
//! A query is whitespace-separated terms, all of which must match. A bare term
//! matches the subject, sender, recipients or body. Prefixed terms narrow it:
//! `from:`, `to:`, `subject:`, `is:unread`, `is:read`, `is:starred` and
//! `has:attachment`. Double quotes keep a phrase together: `subject:"reset link"`.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};
use tokio::sync::broadcast;

use crate::model::{
    Address, AttachmentMeta, Event, Link, ListFilter, Mailbox, MessageDetail, MessageSummary, Page,
    Source, Stats,
};
use crate::parse;

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 500;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at      INTEGER NOT NULL,
    source           TEXT    NOT NULL,
    envelope_from    TEXT,
    from_name        TEXT,
    from_address     TEXT,
    to_json          TEXT    NOT NULL,
    cc_json          TEXT    NOT NULL,
    recipients_text  TEXT    NOT NULL,
    subject          TEXT    NOT NULL,
    snippet          TEXT    NOT NULL,
    search_text      TEXT    NOT NULL,
    size             INTEGER NOT NULL,
    attachment_count INTEGER NOT NULL,
    read             INTEGER NOT NULL DEFAULT 0,
    starred          INTEGER NOT NULL DEFAULT 0,
    raw              BLOB    NOT NULL
);
CREATE TABLE IF NOT EXISTS recipients (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    address    TEXT    NOT NULL,
    PRIMARY KEY (message_id, address)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS recipients_by_address ON recipients(address, message_id);
";

const SUMMARY_COLUMNS: &str = "m.id, m.received_at, m.source, m.from_name, m.from_address, \
    m.to_json, m.cc_json, m.subject, m.snippet, m.size, m.attachment_count, m.read, m.starred, \
    (SELECT group_concat(address, char(10)) FROM recipients WHERE message_id = m.id)";

/// Retention bounds. Zero disables a bound.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_messages: usize,
    pub max_storage_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_messages: 1000,
            max_storage_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// A message on its way into the store.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub raw: Vec<u8>,
    pub envelope_from: Option<String>,
    /// Envelope recipients. When empty they are taken from the To, Cc and Bcc
    /// headers instead.
    pub envelope_to: Vec<String>,
    pub source: Source,
}

pub struct Store {
    conn: Mutex<Connection>,
    events: broadcast::Sender<Event>,
    limits: Limits,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn normalize_address(address: &str) -> String {
    address
        .trim()
        .trim_matches(['<', '>'])
        .trim()
        .to_ascii_lowercase()
}

fn like_pattern(term: &str) -> String {
    let mut pattern = String::with_capacity(term.len() + 2);
    pattern.push('%');
    for c in term.chars() {
        if matches!(c, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('%');
    pattern
}

/// Split a query into terms, keeping double-quoted phrases whole.
fn tokenize(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in query.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    terms.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        terms.push(current);
    }
    terms
}

/// The WHERE clause for a filter. `paged` adds the `before_id` cursor, which
/// counts must leave out.
fn where_clause(filter: &ListFilter, paged: bool) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();

    if let Some(mailbox) = filter
        .mailbox
        .as_deref()
        .map(normalize_address)
        .filter(|m| !m.is_empty())
    {
        clauses.push(
            "EXISTS (SELECT 1 FROM recipients r WHERE r.message_id = m.id AND r.address = ?)"
                .into(),
        );
        values.push(Value::Text(mailbox));
    }
    if let Some(unread) = filter.unread {
        clauses.push(format!("m.read = {}", if unread { 0 } else { 1 }));
    }
    if let Some(starred) = filter.starred {
        clauses.push(format!("m.starred = {}", if starred { 1 } else { 0 }));
    }
    if let Some(after) = filter.after_id {
        clauses.push("m.id > ?".into());
        values.push(Value::Integer(after));
    }
    if let Some(since) = filter.since {
        clauses.push("m.received_at >= ?".into());
        values.push(Value::Integer(since));
    }
    if paged && let Some(before) = filter.before_id {
        clauses.push("m.id < ?".into());
        values.push(Value::Integer(before));
    }

    for term in tokenize(filter.query.as_deref().unwrap_or_default()) {
        let lower = term.to_ascii_lowercase();
        let (field, value) = match lower.split_once(':') {
            Some((field @ ("from" | "to" | "subject" | "is" | "has"), _)) => {
                (field.to_string(), term[field.len() + 1..].to_string())
            }
            _ => (String::new(), term.clone()),
        };
        if value.is_empty() {
            continue;
        }
        match (field.as_str(), value.to_ascii_lowercase().as_str()) {
            ("is", "unread") => clauses.push("m.read = 0".into()),
            ("is", "read") => clauses.push("m.read = 1".into()),
            ("is", "starred") => clauses.push("m.starred = 1".into()),
            ("has", "attachment" | "attachments") => clauses.push("m.attachment_count > 0".into()),
            ("from", _) => {
                clauses.push(
                    "(m.from_address LIKE ? ESCAPE '\\' OR m.from_name LIKE ? ESCAPE '\\')".into(),
                );
                let pattern = like_pattern(&value);
                values.push(Value::Text(pattern.clone()));
                values.push(Value::Text(pattern));
            }
            ("to", _) => {
                clauses.push("m.recipients_text LIKE ? ESCAPE '\\'".into());
                values.push(Value::Text(like_pattern(&value)));
            }
            ("subject", _) => {
                clauses.push("m.subject LIKE ? ESCAPE '\\'".into());
                values.push(Value::Text(like_pattern(&value)));
            }
            _ => {
                // An unknown `is:` or `has:` value is searched as plain text.
                clauses.push(
                    "(m.subject LIKE ? ESCAPE '\\' OR m.from_address LIKE ? ESCAPE '\\' \
                     OR m.from_name LIKE ? ESCAPE '\\' OR m.recipients_text LIKE ? ESCAPE '\\' \
                     OR m.search_text LIKE ? ESCAPE '\\')"
                        .into(),
                );
                let pattern = like_pattern(&term);
                for _ in 0..5 {
                    values.push(Value::Text(pattern.clone()));
                }
            }
        }
    }

    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    (sql, values)
}

fn summary_from_row(row: &Row<'_>) -> rusqlite::Result<MessageSummary> {
    let from_name: Option<String> = row.get(3)?;
    let from_address: Option<String> = row.get(4)?;
    let to_json: String = row.get(5)?;
    let cc_json: String = row.get(6)?;
    let mailboxes: Option<String> = row.get(13)?;
    Ok(MessageSummary {
        id: row.get(0)?,
        received_at: row.get(1)?,
        source: Source::parse(&row.get::<_, String>(2)?),
        from: from_address.map(|address| Address {
            name: from_name,
            address,
        }),
        to: serde_json::from_str(&to_json).unwrap_or_default(),
        cc: serde_json::from_str(&cc_json).unwrap_or_default(),
        subject: row.get(7)?,
        snippet: row.get(8)?,
        size: row.get::<_, i64>(9)? as usize,
        attachment_count: row.get::<_, i64>(10)? as usize,
        read: row.get(11)?,
        starred: row.get(12)?,
        mailboxes: mailboxes
            .map(|m| m.lines().map(str::to_string).collect())
            .unwrap_or_default(),
    })
}

impl Store {
    /// Open the database at `path`, creating it if needed. `None` keeps
    /// everything in memory.
    pub fn open(path: Option<&Path>, limits: Limits) -> Result<Self> {
        let conn = match path {
            Some(path) => {
                create_private(path)?;
                let conn = Connection::open(path)
                    .with_context(|| format!("opening database {}", path.display()))?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.pragma_update(None, "synchronous", "NORMAL")?;
                conn
            }
            None => Connection::open_in_memory()?,
        };
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Keep scratch data out of /tmp, which a hardened container mounts read-only.
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(SCHEMA)?;
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            conn: Mutex::new(conn),
            events,
            limits,
        })
    }

    pub fn in_memory() -> Result<Self> {
        Self::open(None, Limits::default())
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn emit(&self, event: Event) {
        // No receivers is the normal state when nobody is watching.
        let _ = self.events.send(event);
    }

    /// Changes made through this handle. A second process on the same database
    /// file does not see them and has to poll.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn insert(&self, incoming: Incoming) -> Result<MessageSummary> {
        let parsed = parse::parse(&incoming.raw);

        let mut mailboxes: Vec<String> = Vec::new();
        let header_recipients = parsed.to.iter().chain(&parsed.cc).chain(&parsed.bcc);
        let envelope: Vec<String> = if incoming.envelope_to.is_empty() {
            header_recipients
                .clone()
                .map(|a| a.address.clone())
                .collect()
        } else {
            incoming.envelope_to.clone()
        };
        for address in envelope {
            let address = normalize_address(&address);
            if !address.is_empty() && !mailboxes.contains(&address) {
                mailboxes.push(address);
            }
        }

        let mut recipients_text = mailboxes.join(" ");
        for address in header_recipients {
            recipients_text.push(' ');
            recipients_text.push_str(&address.display());
        }

        let received_at = now_ms();
        let size = incoming.raw.len();
        let mut pruned = Vec::new();
        let id = {
            let mut conn = self.conn();
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO messages (received_at, source, envelope_from, from_name, from_address, \
                 to_json, cc_json, recipients_text, subject, snippet, search_text, size, \
                 attachment_count, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    received_at,
                    incoming.source.as_str(),
                    incoming.envelope_from,
                    parsed.from.as_ref().and_then(|f| f.name.clone()),
                    parsed.from.as_ref().map(|f| f.address.clone()),
                    serde_json::to_string(&parsed.to)?,
                    serde_json::to_string(&parsed.cc)?,
                    recipients_text,
                    parsed.subject,
                    parsed.snippet(),
                    parsed.search_text(),
                    size as i64,
                    parsed.attachments.len() as i64,
                    incoming.raw,
                ],
            )?;
            let id = tx.last_insert_rowid();
            for address in &mailboxes {
                tx.execute(
                    "INSERT OR IGNORE INTO recipients (message_id, address) VALUES (?, ?)",
                    params![id, address],
                )?;
            }

            if self.limits.max_messages > 0 {
                let mut stmt =
                    tx.prepare("SELECT id FROM messages ORDER BY id DESC LIMIT -1 OFFSET ?")?;
                let rows = stmt.query_map([self.limits.max_messages as i64], |row| row.get(0))?;
                for row in rows {
                    pruned.push(row?);
                }
            }
            if self.limits.max_storage_bytes > 0 {
                let mut total: i64 =
                    tx.query_row("SELECT COALESCE(SUM(size), 0) FROM messages", [], |r| {
                        r.get(0)
                    })?;
                let mut stmt =
                    tx.prepare("SELECT id, size FROM messages WHERE id <> ? ORDER BY id ASC")?;
                let mut rows = stmt.query([id])?;
                while total as u64 > self.limits.max_storage_bytes {
                    let Some(row) = rows.next()? else { break };
                    let oldest: i64 = row.get(0)?;
                    if !pruned.contains(&oldest) {
                        pruned.push(oldest);
                    }
                    total -= row.get::<_, i64>(1)?;
                }
            }
            for old in &pruned {
                tx.execute("DELETE FROM messages WHERE id = ?", [old])?;
            }
            tx.commit()?;
            id
        };

        let summary = MessageSummary {
            id,
            received_at,
            from: parsed.from.clone(),
            to: parsed.to.clone(),
            cc: parsed.cc.clone(),
            subject: parsed.subject.clone(),
            snippet: parsed.snippet(),
            size,
            read: false,
            starred: false,
            attachment_count: parsed.attachments.len(),
            mailboxes,
            source: incoming.source,
        };
        for old in pruned {
            self.emit(Event::Deleted { id: old });
        }
        self.emit(Event::New {
            message: summary.clone(),
        });
        Ok(summary)
    }

    pub fn list(&self, filter: &ListFilter) -> Result<Page> {
        let conn = self.conn();
        let limit = filter.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);

        let (where_sql, values) = where_clause(filter, true);
        let sql = format!(
            "SELECT {SUMMARY_COLUMNS} FROM messages m {where_sql} ORDER BY m.id DESC LIMIT {limit}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let messages = stmt
            .query_map(params_from_iter(values), summary_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let (where_sql, values) = where_clause(filter, false);
        let sql =
            format!("SELECT COUNT(*), COALESCE(SUM(m.read = 0), 0) FROM messages m {where_sql}");
        let (total, unread): (i64, i64) =
            conn.query_row(&sql, params_from_iter(values), |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;

        Ok(Page {
            messages,
            total: total as usize,
            unread: unread as usize,
        })
    }

    pub fn summary(&self, id: i64) -> Result<Option<MessageSummary>> {
        let conn = self.conn();
        let sql = format!("SELECT {SUMMARY_COLUMNS} FROM messages m WHERE m.id = ?");
        Ok(conn.query_row(&sql, [id], summary_from_row).optional()?)
    }

    pub fn get(&self, id: i64) -> Result<Option<MessageDetail>> {
        let Some(summary) = self.summary(id)? else {
            return Ok(None);
        };
        let (raw, envelope_from): (Vec<u8>, Option<String>) = {
            let conn = self.conn();
            conn.query_row(
                "SELECT raw, envelope_from FROM messages WHERE id = ?",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
        };
        let parsed = parse::parse(&raw);
        Ok(Some(MessageDetail {
            summary,
            envelope_from,
            bcc: parsed.bcc,
            reply_to: parsed.reply_to,
            date: parsed.date,
            message_id: parsed.message_id,
            text: parsed.text,
            html: parsed.html,
            headers: parsed.headers,
            attachments: parsed.attachments,
        }))
    }

    pub fn raw(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT raw FROM messages WHERE id = ?", [id], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn attachment(&self, id: i64, index: usize) -> Result<Option<(AttachmentMeta, Vec<u8>)>> {
        Ok(self.raw(id)?.and_then(|raw| parse::attachment(&raw, index)))
    }

    /// The HTML body prepared for a sandboxed frame; see [`parse::render_html`].
    pub fn rendered_html(&self, id: i64) -> Result<Option<String>> {
        Ok(self.raw(id)?.and_then(|raw| parse::render_html(&raw)))
    }

    pub fn links(&self, id: i64) -> Result<Option<Vec<Link>>> {
        Ok(self.raw(id)?.map(|raw| parse::links(&parse::parse(&raw))))
    }

    /// Change the read or starred flag. Returns whether the message exists.
    pub fn set_flags(&self, id: i64, read: Option<bool>, starred: Option<bool>) -> Result<bool> {
        let changed = {
            let conn = self.conn();
            conn.execute(
                "UPDATE messages SET read = COALESCE(?1, read), starred = COALESCE(?2, starred) \
                 WHERE id = ?3",
                params![read, starred, id],
            )?
        };
        if changed > 0 {
            self.emit(Event::Updated { id });
        }
        Ok(changed > 0)
    }

    pub fn mark_all_read(&self, mailbox: Option<&str>) -> Result<usize> {
        let mailbox = mailbox.map(normalize_address).filter(|m| !m.is_empty());
        let changed = {
            let conn = self.conn();
            match &mailbox {
                Some(address) => conn.execute(
                    "UPDATE messages SET read = 1 WHERE read = 0 AND id IN \
                     (SELECT message_id FROM recipients WHERE address = ?)",
                    [address],
                )?,
                None => conn.execute("UPDATE messages SET read = 1 WHERE read = 0", [])?,
            }
        };
        if changed > 0 {
            self.emit(Event::ReadAll { mailbox });
        }
        Ok(changed)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        let changed = self
            .conn()
            .execute("DELETE FROM messages WHERE id = ?", [id])?;
        if changed > 0 {
            self.emit(Event::Deleted { id });
        }
        Ok(changed > 0)
    }

    /// Delete every message, or every message delivered to one mailbox.
    pub fn clear(&self, mailbox: Option<&str>) -> Result<usize> {
        let mailbox = mailbox.map(normalize_address).filter(|m| !m.is_empty());
        let changed = {
            let conn = self.conn();
            match &mailbox {
                Some(address) => conn.execute(
                    "DELETE FROM messages WHERE id IN \
                     (SELECT message_id FROM recipients WHERE address = ?)",
                    [address],
                )?,
                None => conn.execute("DELETE FROM messages", [])?,
            }
        };
        if changed > 0 {
            self.emit(Event::Cleared { mailbox });
        }
        Ok(changed)
    }

    pub fn mailboxes(&self) -> Result<Vec<Mailbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT r.address, COUNT(*), COALESCE(SUM(m.read = 0), 0), MAX(m.received_at) \
             FROM recipients r JOIN messages m ON m.id = r.message_id \
             GROUP BY r.address ORDER BY r.address",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Mailbox {
                address: row.get(0)?,
                total: row.get::<_, i64>(1)? as usize,
                unread: row.get::<_, i64>(2)? as usize,
                latest_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn stats(&self) -> Result<Stats> {
        let conn = self.conn();
        Ok(conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(read = 0), 0), COALESCE(SUM(starred), 0), \
             COALESCE(SUM(size), 0) FROM messages",
            [],
            |row| {
                Ok(Stats {
                    total: row.get::<_, i64>(0)? as usize,
                    unread: row.get::<_, i64>(1)? as usize,
                    starred: row.get::<_, i64>(2)? as usize,
                    bytes: row.get::<_, i64>(3)? as u64,
                })
            },
        )?)
    }

    /// The id of the newest message, or zero when the store is empty.
    pub fn latest_id(&self) -> Result<i64> {
        let conn = self.conn();
        Ok(
            conn.query_row("SELECT COALESCE(MAX(id), 0) FROM messages", [], |row| {
                row.get(0)
            })?,
        )
    }
}

/// Create the database file readable by its owner only. SQLite gives the WAL
/// and shared-memory files the same mode as the main file.
fn create_private(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating data directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Tightening an existing directory is best effort: it may be a
            // mounted volume whose mode is not ours to change.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("creating database {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(from: &str, to: &str, subject: &str, body: &str) -> Incoming {
        Incoming {
            raw: format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n")
                .into_bytes(),
            envelope_from: Some(from.to_string()),
            envelope_to: vec![to.to_string()],
            source: Source::Smtp,
        }
    }

    #[test]
    fn stores_lists_and_reads_back() {
        let store = Store::in_memory().unwrap();
        let first = store
            .insert(mail("a@x.test", "Bob@X.test", "Hello", "first body"))
            .unwrap();
        let second = store
            .insert(mail("a@x.test", "carol@x.test", "Reset", "second body"))
            .unwrap();
        assert!(second.id > first.id);
        assert_eq!(first.mailboxes, vec!["bob@x.test"]);

        let page = store.list(&ListFilter::default()).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.unread, 2);
        assert_eq!(page.messages[0].id, second.id, "newest first");

        let detail = store.get(first.id).unwrap().unwrap();
        assert_eq!(detail.summary.subject, "Hello");
        assert_eq!(detail.text.as_deref().map(str::trim), Some("first body"));
        assert!(store.get(999).unwrap().is_none());
    }

    #[test]
    fn mailboxes_follow_the_envelope_and_include_bcc() {
        let store = Store::in_memory().unwrap();
        let mut incoming = mail("a@x.test", "bob@x.test", "Hi", "body");
        incoming.envelope_to.push("hidden@x.test".into());
        store.insert(incoming).unwrap();

        let boxes = store.mailboxes().unwrap();
        let names: Vec<_> = boxes.iter().map(|m| m.address.as_str()).collect();
        assert_eq!(names, vec!["bob@x.test", "hidden@x.test"]);

        let filter = ListFilter {
            mailbox: Some("HIDDEN@x.test".into()),
            ..Default::default()
        };
        assert_eq!(store.list(&filter).unwrap().total, 1);
    }

    #[test]
    fn recipients_come_from_headers_when_the_envelope_is_empty() {
        let store = Store::in_memory().unwrap();
        let mut incoming = mail("a@x.test", "bob@x.test", "Hi", "body");
        incoming.envelope_to.clear();
        let summary = store.insert(incoming).unwrap();
        assert_eq!(summary.mailboxes, vec!["bob@x.test"]);
    }

    #[test]
    fn search_terms_narrow_results() {
        let store = Store::in_memory().unwrap();
        store
            .insert(mail(
                "billing@shop.test",
                "bob@x.test",
                "Your invoice",
                "total due 100%",
            ))
            .unwrap();
        let reset = store
            .insert(mail(
                "auth@shop.test",
                "bob@x.test",
                "Reset link",
                "click here",
            ))
            .unwrap();
        store.set_flags(reset.id, Some(true), Some(true)).unwrap();

        let count = |query: &str| {
            store
                .list(&ListFilter {
                    query: Some(query.into()),
                    ..Default::default()
                })
                .unwrap()
                .total
        };
        assert_eq!(count("invoice"), 1);
        assert_eq!(count("from:auth"), 1);
        assert_eq!(count("to:bob"), 2);
        assert_eq!(count("subject:\"reset link\""), 1);
        assert_eq!(count("is:unread"), 1);
        assert_eq!(count("is:starred"), 1);
        assert_eq!(count("from:auth invoice"), 0);
        assert_eq!(count("100%"), 1, "LIKE wildcards in a term are literal");
        assert_eq!(count("10_%"), 0);
    }

    #[test]
    fn flags_deletes_and_clears() {
        let store = Store::in_memory().unwrap();
        let a = store
            .insert(mail("a@x.test", "bob@x.test", "A", "a"))
            .unwrap();
        store
            .insert(mail("a@x.test", "carol@x.test", "B", "b"))
            .unwrap();

        assert!(store.set_flags(a.id, Some(true), None).unwrap());
        assert!(!store.set_flags(999, Some(true), None).unwrap());
        assert_eq!(store.stats().unwrap().unread, 1);
        assert_eq!(store.mark_all_read(None).unwrap(), 1);

        assert_eq!(store.clear(Some("carol@x.test")).unwrap(), 1);
        assert!(store.delete(a.id).unwrap());
        assert!(!store.delete(a.id).unwrap());
        assert_eq!(store.stats().unwrap().total, 0);
        assert!(
            store.mailboxes().unwrap().is_empty(),
            "recipients go with their message"
        );
    }

    #[test]
    fn retention_drops_the_oldest_messages() {
        let limits = Limits {
            max_messages: 2,
            max_storage_bytes: 0,
        };
        let store = Store::open(None, limits).unwrap();
        let first = store
            .insert(mail("a@x.test", "b@x.test", "1", "x"))
            .unwrap();
        store
            .insert(mail("a@x.test", "b@x.test", "2", "x"))
            .unwrap();
        store
            .insert(mail("a@x.test", "b@x.test", "3", "x"))
            .unwrap();
        assert_eq!(store.stats().unwrap().total, 2);
        assert!(store.get(first.id).unwrap().is_none());

        let limits = Limits {
            max_messages: 0,
            max_storage_bytes: 150,
        };
        let store = Store::open(None, limits).unwrap();
        store
            .insert(mail("a@x.test", "b@x.test", "1", &"x".repeat(60)))
            .unwrap();
        store
            .insert(mail("a@x.test", "b@x.test", "2", &"x".repeat(60)))
            .unwrap();
        assert_eq!(
            store.stats().unwrap().total,
            1,
            "the byte cap evicts the older message"
        );
        let big = store
            .insert(mail("a@x.test", "b@x.test", "3", &"x".repeat(500)))
            .unwrap();
        assert!(
            store.get(big.id).unwrap().is_some(),
            "the newest message is never evicted"
        );
    }

    #[test]
    fn events_announce_changes() {
        let store = Store::in_memory().unwrap();
        let mut events = store.subscribe();
        let message = store
            .insert(mail("a@x.test", "b@x.test", "1", "x"))
            .unwrap();
        assert!(
            matches!(events.try_recv().unwrap(), Event::New { message: m } if m.id == message.id)
        );
        store.delete(message.id).unwrap();
        assert_eq!(
            events.try_recv().unwrap(),
            Event::Deleted { id: message.id }
        );
    }
}
