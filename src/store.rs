//! SQLite-backed message store.
//!
//! Every method is synchronous and takes a short-lived lock, so async callers
//! run them on a blocking thread and the desktop app calls them directly.
//!
//! Mail is organized into inboxes, one per application. An inbox has its own
//! API keys: a key is what lets an application deliver into the inbox and what
//! limits a reader to it.
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
    Address, ApiKey, AttachmentMeta, Event, Inbox, Link, ListFilter, MessageDetail, MessageSummary,
    Page, Source, Stats,
};
use crate::parse;
use crate::security::{API_KEY_PREFIX, generate_api_key, generate_inbox_id, hash_api_key};

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 500;

/// The inbox that always exists. Mail that arrives without an API key lands
/// here, which is what keeps a local setup working with no configuration.
pub const DEFAULT_INBOX: &str = "default";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS inboxes (
    id          TEXT    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    name        TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT ''
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    inbox        TEXT    NOT NULL REFERENCES inboxes(id) ON DELETE CASCADE,
    label        TEXT    NOT NULL,
    prefix       TEXT    NOT NULL,
    hash         TEXT    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    -- The key itself, kept only for the default inbox's starter key.
    secret       TEXT
);
-- One-off facts about the store, such as setup steps already taken.
CREATE TABLE IF NOT EXISTS meta (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS messages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    inbox            TEXT    NOT NULL DEFAULT 'default',
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
    (SELECT group_concat(address, char(10)) FROM recipients WHERE message_id = m.id), m.inbox, \
    (SELECT name FROM inboxes WHERE id = m.inbox)";

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

/// Why an inbox or key operation was refused. Callers turn these into the
/// right kind of answer for their surface, such as an HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxError {
    InvalidId(String),
    Exists(String),
    NotFound(String),
    InvalidName,
    /// The default inbox cannot be deleted.
    Protected,
    WeakKey,
}

impl std::fmt::Display for InboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboxError::InvalidId(id) => write!(
                f,
                "`{id}` is not a valid inbox id: use 1 to 63 lowercase letters, digits, - or _, \
                 starting with a letter or digit"
            ),
            InboxError::InvalidName => write!(
                f,
                "an inbox needs a name of 1 to {MAX_NAME} characters, and a description of at \
                 most {MAX_DESCRIPTION}"
            ),
            InboxError::Exists(id) => write!(f, "an inbox named `{id}` already exists"),
            InboxError::NotFound(id) => write!(f, "there is no inbox named `{id}`"),
            InboxError::Protected => write!(
                f,
                "the `{DEFAULT_INBOX}` inbox cannot be deleted: it is where mail without a key goes"
            ),
            InboxError::WeakKey => write!(f, "an API key must be at least 16 characters"),
        }
    }
}

impl std::error::Error for InboxError {}

const MAX_NAME: usize = 80;
const MAX_DESCRIPTION: usize = 300;

/// Text a person typed, tidied: trimmed, on one line, and `None` if nothing
/// is left or it runs past `max` characters.
fn clean_text(text: &str, max: usize) -> Option<String> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty() && text.chars().count() <= max && !text.chars().any(char::is_control))
        .then_some(text)
}

/// A name reduced to what an inbox id may contain: lowercase letters and
/// digits, with runs of anything else becoming a single hyphen.
pub fn slug(name: &str) -> String {
    let mut slug = String::new();
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug: String = slug.chars().take(63).collect();
    slug.trim_end_matches('-').to_string()
}

/// What a person supplies to create an inbox.
#[derive(Debug, Clone, Default)]
pub struct NewInbox {
    pub name: String,
    pub description: String,
    /// An id and key already shown to the user, to be made real as shown.
    /// Left out, they are generated.
    pub id: Option<String>,
    pub key: Option<String>,
}

/// A message on its way into the store.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub raw: Vec<u8>,
    /// The inbox to deliver into. It must exist.
    pub inbox: String,
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

/// An inbox id is also an SMTP username and a URL path segment, so it is kept
/// to what is safe in both.
pub fn valid_inbox_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
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
/// counts and bulk changes must leave out.
fn where_clause(filter: &ListFilter, paged: bool) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();

    if let Some(inbox) = filter.inbox.as_deref() {
        clauses.push("m.inbox = ?".into());
        values.push(Value::Text(inbox.to_string()));
    }
    if let Some(to) = filter
        .to
        .as_deref()
        .map(normalize_address)
        .filter(|m| !m.is_empty())
    {
        clauses.push(
            "EXISTS (SELECT 1 FROM recipients r WHERE r.message_id = m.id AND r.address = ?)"
                .into(),
        );
        values.push(Value::Text(to));
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
    let recipients: Option<String> = row.get(13)?;
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
        inbox: row.get(14)?,
        inbox_name: row.get::<_, Option<String>>(15)?.unwrap_or_default(),
        recipients: recipients
            .map(|m| m.lines().map(str::to_string).collect())
            .unwrap_or_default(),
    })
}

fn key_from_row(row: &Row<'_>) -> rusqlite::Result<ApiKey> {
    Ok(ApiKey {
        id: row.get(0)?,
        inbox: row.get(1)?,
        label: row.get(2)?,
        prefix: row.get(3)?,
        created_at: row.get(4)?,
        last_used_at: row.get(5)?,
        key: row.get(6)?,
    })
}

const KEY_COLUMNS: &str = "id, inbox, label, prefix, created_at, last_used_at, secret";

/// The label of the default inbox's starter key.
pub const STARTER_KEY_LABEL: &str = "starter key";

/// Give the default inbox a key of its own the first time a store is opened,
/// so there is one to hand an application without making one first. Unlike
/// every other key it is kept readable, so the UI and `emailulator key list`
/// can show it again; regenerating it replaces it with an ordinary key, kept
/// only as a hash. It is made once per store: a store whose starter key was
/// revoked does not get another.
fn create_starter_key(conn: &Connection) -> Result<()> {
    const DONE: &str = "starter_key_created";
    let done: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE name = ?)",
        [DONE],
        |row| row.get(0),
    )?;
    if done {
        return Ok(());
    }
    let has_key: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE inbox = ?)",
        [DEFAULT_INBOX],
        |row| row.get(0),
    )?;
    // A default inbox that already has keys was set up by hand; leave it be.
    if !has_key {
        let key = generate_api_key();
        conn.execute(
            "INSERT INTO api_keys (inbox, label, prefix, hash, created_at, secret) \
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                DEFAULT_INBOX,
                STARTER_KEY_LABEL,
                key_prefix(&key),
                hash_api_key(&key),
                now_ms(),
                key
            ],
        )?;
    }
    conn.execute(
        "INSERT INTO meta (name, value) VALUES (?, ?)",
        params![DONE, now_ms().to_string()],
    )?;
    Ok(())
}

/// Enough of a key to recognize it by, and nothing that helps guess the rest.
fn key_prefix(key: &str) -> String {
    key.chars().take(API_KEY_PREFIX.len() + 6).collect()
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

        // A store made before inboxes existed has messages with no inbox column.
        // Everything in it belongs to the default inbox.
        let has_inbox: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'inbox'",
            [],
            |row| row.get(0),
        )?;
        if has_inbox == 0 {
            conn.execute_batch(
                "ALTER TABLE messages ADD COLUMN inbox TEXT NOT NULL DEFAULT 'default'",
            )?;
        }
        conn.execute_batch("CREATE INDEX IF NOT EXISTS messages_by_inbox ON messages(inbox, id)")?;

        // Inboxes were once known only by an id their creator typed. Those keep
        // that id, which applications are already configured with, and take it
        // as their name.
        for column in ["name", "description"] {
            let present: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('inboxes') WHERE name = ?",
                [column],
                |row| row.get(0),
            )?;
            if present == 0 {
                conn.execute_batch(&format!(
                    "ALTER TABLE inboxes ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
                ))?;
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO inboxes (id, created_at, name, description) VALUES (?, ?, ?, ?)",
            params![
                DEFAULT_INBOX,
                now_ms(),
                "Default",
                "Mail sent without an API key lands here."
            ],
        )?;
        conn.execute(
            "UPDATE inboxes SET name = 'Default', \
             description = 'Mail sent without an API key lands here.' \
             WHERE id = 'default' AND name = ''",
            [],
        )?;
        conn.execute("UPDATE inboxes SET name = id WHERE name = ''", [])?;

        // Keys were once kept only as hashes.
        let has_secret: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'secret'",
            [],
            |row| row.get(0),
        )?;
        if has_secret == 0 {
            conn.execute_batch("ALTER TABLE api_keys ADD COLUMN secret TEXT")?;
        }
        create_starter_key(&conn)?;

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

    // -----------------------------------------------------------------------
    // Inboxes and keys
    // -----------------------------------------------------------------------

    pub fn inbox_exists(&self, id: &str) -> Result<bool> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT 1 FROM inboxes WHERE id = ?", [id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn inboxes(&self) -> Result<Vec<Inbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT i.id, i.created_at, \
                    (SELECT COUNT(*) FROM messages m WHERE m.inbox = i.id), \
                    (SELECT COUNT(*) FROM messages m WHERE m.inbox = i.id AND m.read = 0), \
                    (SELECT MAX(m.received_at) FROM messages m WHERE m.inbox = i.id), \
                    (SELECT COUNT(*) FROM api_keys k WHERE k.inbox = i.id), \
                    i.name, i.description \
             FROM inboxes i ORDER BY (i.id <> 'default'), i.name COLLATE NOCASE, i.id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Inbox {
                id: row.get(0)?,
                created_at: row.get(1)?,
                total: row.get::<_, i64>(2)? as usize,
                unread: row.get::<_, i64>(3)? as usize,
                latest_at: row.get(4)?,
                keys: row.get::<_, i64>(5)? as usize,
                name: row.get(6)?,
                description: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn inbox(&self, id: &str) -> Result<Option<Inbox>> {
        Ok(self.inboxes()?.into_iter().find(|inbox| inbox.id == id))
    }

    /// The id of the inbox someone means by `text`: an id as it is, otherwise
    /// a name, whatever its case. For people typing at a command line.
    pub fn resolve_inbox(&self, text: &str) -> Result<Option<String>> {
        let text = text.trim();
        let inboxes = self.inboxes()?;
        Ok(inboxes
            .iter()
            .find(|inbox| inbox.id == text)
            .or_else(|| {
                inboxes
                    .iter()
                    .find(|inbox| inbox.name.eq_ignore_ascii_case(text))
            })
            .map(|inbox| inbox.id.clone()))
    }

    /// The id an inbox with this name would be given: the name as a slug, so
    /// that it reads well as an SMTP username, with a number added if another
    /// inbox already has it. A name with nothing to make a slug from gets a
    /// random id instead.
    pub fn suggest_inbox_id(&self, name: &str) -> Result<String> {
        let slug = slug(name);
        if slug.is_empty() {
            return Ok(generate_inbox_id());
        }
        if !self.inbox_exists(&slug)? {
            return Ok(slug);
        }
        for n in 2.. {
            let suffix = format!("-{n}");
            let stem: String = slug.chars().take(63 - suffix.len()).collect();
            let candidate = format!("{}{suffix}", stem.trim_end_matches(['-', '_']));
            if !self.inbox_exists(&candidate)? {
                return Ok(candidate);
            }
        }
        unreachable!("an unbounded range always yields a free id")
    }

    fn name_taken(&self, name: &str, except: Option<&str>) -> Result<bool> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT 1 FROM inboxes WHERE name = ?1 COLLATE NOCASE AND (?2 IS NULL OR id <> ?2)",
                params![name, except],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Create an inbox whose id is given rather than generated, named after
    /// it and with no key. For ids chosen outside this program.
    pub fn create_inbox(&self, id: &str) -> Result<Inbox> {
        if !valid_inbox_id(id) {
            return Err(InboxError::InvalidId(id.to_string()).into());
        }
        if self.name_taken(id, None)? {
            return Err(InboxError::Exists(id.to_string()).into());
        }
        let created = self.conn().execute(
            "INSERT OR IGNORE INTO inboxes (id, created_at, name) VALUES (?, ?, ?)",
            params![id, now_ms(), id],
        )?;
        if created == 0 {
            return Err(InboxError::Exists(id.to_string()).into());
        }
        self.emit(Event::Inboxes);
        self.inbox(id)?
            .context("the inbox vanished as it was created")
    }

    /// Create an inbox the way a person does: they give it a name and perhaps
    /// a description, and it comes with an id made from the name and a first
    /// API key. Both are generated unless the draft carries ones already shown
    /// to the user.
    /// Returns the inbox and the key, which is not recoverable afterwards.
    pub fn create_inbox_named(&self, draft: NewInbox) -> Result<(Inbox, String)> {
        let name = clean_text(&draft.name, MAX_NAME).ok_or(InboxError::InvalidName)?;
        let description = clean_text(&draft.description, MAX_DESCRIPTION).unwrap_or_default();
        if draft.description.chars().count() > MAX_DESCRIPTION {
            return Err(InboxError::InvalidName.into());
        }
        if self.name_taken(&name, None)? {
            return Err(InboxError::Exists(name).into());
        }
        let id = match draft.id {
            Some(id) => id,
            None => self.suggest_inbox_id(&name)?,
        };
        if !valid_inbox_id(&id) {
            return Err(InboxError::InvalidId(id).into());
        }
        let key = draft.key.unwrap_or_else(generate_api_key);
        if key.len() < crate::security::MIN_TOKEN_LEN {
            return Err(InboxError::WeakKey.into());
        }
        if self.peek_key(&key)?.is_some() {
            anyhow::bail!("that API key is already in use");
        }
        let created = self.conn().execute(
            "INSERT OR IGNORE INTO inboxes (id, created_at, name, description) VALUES (?, ?, ?, ?)",
            params![id, now_ms(), name, description],
        )?;
        if created == 0 {
            return Err(InboxError::Exists(id).into());
        }
        self.insert_key(&id, "first key", &key)?;
        self.emit(Event::Inboxes);
        let inbox = self
            .inbox(&id)?
            .context("the inbox vanished as it was created")?;
        Ok((inbox, key))
    }

    /// Rename an inbox or change its description. Its id does not change.
    pub fn update_inbox(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<Inbox> {
        if !self.inbox_exists(id)? {
            return Err(InboxError::NotFound(id.to_string()).into());
        }
        if let Some(name) = name {
            let name = clean_text(name, MAX_NAME).ok_or(InboxError::InvalidName)?;
            if self.name_taken(&name, Some(id))? {
                return Err(InboxError::Exists(name).into());
            }
            self.conn().execute(
                "UPDATE inboxes SET name = ? WHERE id = ?",
                params![name, id],
            )?;
        }
        if let Some(description) = description {
            if description.chars().count() > MAX_DESCRIPTION {
                return Err(InboxError::InvalidName.into());
            }
            let description = clean_text(description, MAX_DESCRIPTION).unwrap_or_default();
            self.conn().execute(
                "UPDATE inboxes SET description = ? WHERE id = ?",
                params![description, id],
            )?;
        }
        self.emit(Event::Inboxes);
        self.inbox(id)?
            .context("the inbox vanished as it was updated")
    }

    /// Delete an inbox with its messages and keys.
    pub fn delete_inbox(&self, id: &str) -> Result<()> {
        if id == DEFAULT_INBOX {
            return Err(InboxError::Protected.into());
        }
        {
            let mut conn = self.conn();
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM messages WHERE inbox = ?", [id])?;
            // Its keys go with it, by the foreign key.
            if tx.execute("DELETE FROM inboxes WHERE id = ?", [id])? == 0 {
                return Err(InboxError::NotFound(id.to_string()).into());
            }
            tx.commit()?;
        }
        self.emit(Event::Inboxes);
        self.emit(Event::Cleared {
            inbox: Some(id.to_string()),
        });
        Ok(())
    }

    fn insert_key(&self, inbox: &str, label: &str, key: &str) -> Result<Option<ApiKey>> {
        if !self.inbox_exists(inbox)? {
            return Err(InboxError::NotFound(inbox.to_string()).into());
        }
        let label = label.trim();
        let label = if label.is_empty() { "key" } else { label };
        let conn = self.conn();
        let created = conn.execute(
            "INSERT OR IGNORE INTO api_keys (inbox, label, prefix, hash, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            params![inbox, label, key_prefix(key), hash_api_key(key), now_ms()],
        )?;
        if created == 0 {
            return Ok(None);
        }
        let id = conn.last_insert_rowid();
        Ok(Some(conn.query_row(
            &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = ?"),
            [id],
            key_from_row,
        )?))
    }

    /// Mint a key for an inbox. The key itself is returned once, here, and is
    /// not recoverable afterwards: only its hash is kept.
    pub fn create_key(&self, inbox: &str, label: &str) -> Result<(ApiKey, String)> {
        let key = generate_api_key();
        let record = self
            .insert_key(inbox, label, &key)?
            .context("a freshly generated key collided with an existing one")?;
        self.emit(Event::Inboxes);
        Ok((record, key))
    }

    /// Make `key` valid for `inbox`, creating the inbox if needed. For keys
    /// chosen outside this program, such as one shared with an application
    /// through a deployment's configuration. Doing it twice changes nothing.
    pub fn provision_key(&self, inbox: &str, key: &str) -> Result<()> {
        if !valid_inbox_id(inbox) {
            return Err(InboxError::InvalidId(inbox.to_string()).into());
        }
        if key.len() < crate::security::MIN_TOKEN_LEN {
            return Err(InboxError::WeakKey.into());
        }
        self.conn().execute(
            "INSERT OR IGNORE INTO inboxes (id, created_at, name) VALUES (?, ?, ?)",
            params![inbox, now_ms(), inbox],
        )?;
        if let Some(owner) = self.peek_key(key)?
            && owner != inbox
        {
            anyhow::bail!("that key already belongs to the `{owner}` inbox");
        }
        self.insert_key(inbox, "provisioned", key)?;
        self.emit(Event::Inboxes);
        Ok(())
    }

    /// Keys of one inbox, or of all of them.
    pub fn keys(&self, inbox: Option<&str>) -> Result<Vec<ApiKey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM api_keys WHERE (?1 IS NULL OR inbox = ?1) ORDER BY inbox, id"
        ))?;
        let rows = stmt.query_map([inbox], key_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Replace a key's value, keeping its id and label. The old value stops
    /// working at once; the new one is returned here and only here. `inbox`
    /// limits the reach to that inbox's keys.
    pub fn regenerate_key(&self, id: i64, inbox: Option<&str>) -> Result<Option<(ApiKey, String)>> {
        let key = generate_api_key();
        let record = {
            let conn = self.conn();
            // A regenerated key is an ordinary one, kept only as a hash, even
            // when it replaces the readable starter key.
            let changed = conn.execute(
                "UPDATE api_keys SET hash = ?1, prefix = ?2, created_at = ?3, last_used_at = NULL, \
                 secret = NULL WHERE id = ?4 AND (?5 IS NULL OR inbox = ?5)",
                params![hash_api_key(&key), key_prefix(&key), now_ms(), id, inbox],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            conn.query_row(
                &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = ?"),
                [id],
                key_from_row,
            )?
        };
        self.emit(Event::Inboxes);
        Ok(Some((record, key)))
    }

    /// Revoke a key. `inbox` limits the reach to that inbox's keys.
    pub fn revoke_key(&self, id: i64, inbox: Option<&str>) -> Result<bool> {
        let removed = self.conn().execute(
            "DELETE FROM api_keys WHERE id = ?1 AND (?2 IS NULL OR inbox = ?2)",
            params![id, inbox],
        )?;
        if removed > 0 {
            self.emit(Event::Inboxes);
        }
        Ok(removed > 0)
    }

    fn peek_key(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT inbox FROM api_keys WHERE hash = ?",
                [hash_api_key(key)],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// The inbox a key opens, if the key is valid. Looked up by hash: the key
    /// is too long to guess, and the comparison is of digests, so timing gives
    /// nothing away.
    pub fn inbox_for_key(&self, key: &str) -> Result<Option<String>> {
        let hash = hash_api_key(key);
        let conn = self.conn();
        let found: Option<(i64, String, Option<i64>)> = conn
            .query_row(
                "SELECT id, inbox, last_used_at FROM api_keys WHERE hash = ?",
                [&hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((id, inbox, last_used)) = found else {
            return Ok(None);
        };
        // Recorded to the minute: often enough to spot an unused key, without a
        // write for every message.
        let now = now_ms();
        if last_used.is_none_or(|at| now - at > 60_000) {
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                params![now, id],
            )?;
        }
        Ok(Some(inbox))
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    pub fn insert(&self, incoming: Incoming) -> Result<MessageSummary> {
        if !self.inbox_exists(&incoming.inbox)? {
            return Err(InboxError::NotFound(incoming.inbox).into());
        }
        let parsed = parse::parse(&incoming.raw);

        let mut recipients: Vec<String> = Vec::new();
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
            if !address.is_empty() && !recipients.contains(&address) {
                recipients.push(address);
            }
        }

        let mut recipients_text = recipients.join(" ");
        for address in header_recipients {
            recipients_text.push(' ');
            recipients_text.push_str(&address.display());
        }

        let received_at = now_ms();
        let size = incoming.raw.len();
        let mut pruned: Vec<(i64, String)> = Vec::new();
        let id = {
            let mut conn = self.conn();
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO messages (inbox, received_at, source, envelope_from, from_name, \
                 from_address, to_json, cc_json, recipients_text, subject, snippet, search_text, \
                 size, attachment_count, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    incoming.inbox,
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
            for address in &recipients {
                tx.execute(
                    "INSERT OR IGNORE INTO recipients (message_id, address) VALUES (?, ?)",
                    params![id, address],
                )?;
            }

            // Retention is across all inboxes: the limits bound the disk, and
            // the disk is shared.
            if self.limits.max_messages > 0 {
                let mut stmt = tx
                    .prepare("SELECT id, inbox FROM messages ORDER BY id DESC LIMIT -1 OFFSET ?")?;
                let rows = stmt.query_map([self.limits.max_messages as i64], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
                for row in rows {
                    pruned.push(row?);
                }
            }
            if self.limits.max_storage_bytes > 0 {
                let mut total: i64 =
                    tx.query_row("SELECT COALESCE(SUM(size), 0) FROM messages", [], |r| {
                        r.get(0)
                    })?;
                let mut stmt = tx.prepare(
                    "SELECT id, size, inbox FROM messages WHERE id <> ? ORDER BY id ASC",
                )?;
                let mut rows = stmt.query([id])?;
                while total as u64 > self.limits.max_storage_bytes {
                    let Some(row) = rows.next()? else { break };
                    let oldest: i64 = row.get(0)?;
                    if !pruned.iter().any(|(id, _)| *id == oldest) {
                        pruned.push((oldest, row.get(2)?));
                    }
                    total -= row.get::<_, i64>(1)?;
                }
            }
            for (old, _) in &pruned {
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
            inbox_name: self
                .inbox_name(&incoming.inbox)?
                .unwrap_or_else(|| incoming.inbox.clone()),
            inbox: incoming.inbox,
            recipients,
            source: incoming.source,
        };
        for (id, inbox) in pruned {
            self.emit(Event::Deleted { id, inbox });
        }
        self.emit(Event::New {
            message: Box::new(summary.clone()),
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

    fn inbox_name(&self, id: &str) -> Result<Option<String>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT name FROM inboxes WHERE id = ?", [id], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// The inbox a message is in. What callers check before letting a reader
    /// limited to one inbox touch a message by id.
    pub fn message_inbox(&self, id: i64) -> Result<Option<String>> {
        let conn = self.conn();
        Ok(conn
            .query_row("SELECT inbox FROM messages WHERE id = ?", [id], |row| {
                row.get(0)
            })
            .optional()?)
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
        let Some(inbox) = self.message_inbox(id)? else {
            return Ok(false);
        };
        self.conn().execute(
            "UPDATE messages SET read = COALESCE(?1, read), starred = COALESCE(?2, starred) \
             WHERE id = ?3",
            params![read, starred, id],
        )?;
        self.emit(Event::Updated { id, inbox });
        Ok(true)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        let Some(inbox) = self.message_inbox(id)? else {
            return Ok(false);
        };
        self.conn()
            .execute("DELETE FROM messages WHERE id = ?", [id])?;
        self.emit(Event::Deleted { id, inbox });
        Ok(true)
    }

    /// Mark read every message the filter matches. Paging fields are ignored:
    /// this acts on the whole match, not on one page of it.
    pub fn mark_all_read(&self, filter: &ListFilter) -> Result<usize> {
        let (where_sql, values) = where_clause(filter, false);
        let changed = self.conn().execute(
            &format!(
                "UPDATE messages SET read = 1 WHERE read = 0 AND id IN \
                 (SELECT m.id FROM messages m {where_sql})"
            ),
            params_from_iter(values),
        )?;
        if changed > 0 {
            self.emit(Event::ReadAll {
                inbox: filter.inbox.clone(),
            });
        }
        Ok(changed)
    }

    /// Delete every message the filter matches; an empty filter empties the
    /// store. Paging fields are ignored.
    pub fn clear(&self, filter: &ListFilter) -> Result<usize> {
        let (where_sql, values) = where_clause(filter, false);
        let changed = self.conn().execute(
            &format!("DELETE FROM messages WHERE id IN (SELECT m.id FROM messages m {where_sql})"),
            params_from_iter(values),
        )?;
        if changed > 0 {
            self.emit(Event::Cleared {
                inbox: filter.inbox.clone(),
            });
        }
        Ok(changed)
    }

    /// Counts for one inbox, or for the whole store.
    pub fn stats(&self, inbox: Option<&str>) -> Result<Stats> {
        let conn = self.conn();
        Ok(conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(read = 0), 0), COALESCE(SUM(starred), 0), \
             COALESCE(SUM(size), 0) FROM messages WHERE (?1 IS NULL OR inbox = ?1)",
            [inbox],
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

    /// A number that changes whenever an inbox or key is added or removed, for
    /// noticing changes made by another process.
    pub fn inbox_revision(&self) -> Result<i64> {
        let conn = self.conn();
        Ok(conn.query_row(
            "SELECT (SELECT COUNT(*) FROM inboxes) * 100003 \
                  + (SELECT COALESCE(MAX(id), 0) + COUNT(*) FROM api_keys)",
            [],
            |row| row.get(0),
        )?)
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

    fn mail_in(inbox: &str, from: &str, to: &str, subject: &str, body: &str) -> Incoming {
        Incoming {
            raw: format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n")
                .into_bytes(),
            inbox: inbox.to_string(),
            envelope_from: Some(from.to_string()),
            envelope_to: vec![to.to_string()],
            source: Source::Smtp,
        }
    }

    fn mail(from: &str, to: &str, subject: &str, body: &str) -> Incoming {
        mail_in(DEFAULT_INBOX, from, to, subject, body)
    }

    fn all() -> ListFilter {
        ListFilter::default()
    }

    fn in_inbox(inbox: &str) -> ListFilter {
        ListFilter {
            inbox: Some(inbox.into()),
            ..Default::default()
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
        assert_eq!(first.recipients, vec!["bob@x.test"]);
        assert_eq!(first.inbox, DEFAULT_INBOX);

        let page = store.list(&all()).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.unread, 2);
        assert_eq!(page.messages[0].id, second.id, "newest first");

        let detail = store.get(first.id).unwrap().unwrap();
        assert_eq!(detail.summary.subject, "Hello");
        assert_eq!(detail.text.as_deref().map(str::trim), Some("first body"));
        assert!(store.get(999).unwrap().is_none());
    }

    #[test]
    fn a_default_inbox_always_exists() {
        let store = Store::in_memory().unwrap();
        let inboxes = store.inboxes().unwrap();
        assert_eq!(inboxes.len(), 1);
        assert_eq!(inboxes[0].id, DEFAULT_INBOX);
        assert_eq!(inboxes[0].name, "Default");
        let error = store.delete_inbox(DEFAULT_INBOX).unwrap_err();
        assert_eq!(
            error.downcast_ref::<InboxError>(),
            Some(&InboxError::Protected)
        );
    }

    #[test]
    fn inboxes_keep_their_mail_apart() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        store
            .insert(mail_in("billing", "a@x.test", "bob@x.test", "Invoice", "x"))
            .unwrap();
        store
            .insert(mail_in("billing", "a@x.test", "bob@x.test", "Receipt", "x"))
            .unwrap();
        let promo = store
            .insert(mail_in("marketing", "a@x.test", "bob@x.test", "Sale", "x"))
            .unwrap();

        assert_eq!(store.list(&in_inbox("billing")).unwrap().total, 2);
        assert_eq!(store.list(&in_inbox("marketing")).unwrap().total, 1);
        assert_eq!(store.list(&all()).unwrap().total, 3);
        assert_eq!(
            store.message_inbox(promo.id).unwrap().as_deref(),
            Some("marketing")
        );
        assert_eq!(store.stats(Some("billing")).unwrap().total, 2);

        // Listed with the default first, then by name, with their counts.
        let inboxes = store.inboxes().unwrap();
        let summary: Vec<_> = inboxes
            .iter()
            .map(|i| (i.id.as_str(), i.total, i.unread))
            .collect();
        assert_eq!(
            summary,
            vec![("default", 0, 0), ("billing", 2, 2), ("marketing", 1, 1)]
        );

        // Clearing one leaves the other alone.
        assert_eq!(store.clear(&in_inbox("billing")).unwrap(), 2);
        assert_eq!(store.list(&all()).unwrap().total, 1);

        let error = store
            .insert(mail_in("nowhere", "a@x.test", "b@x.test", "s", "x"))
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<InboxError>(),
            Some(&InboxError::NotFound("nowhere".into()))
        );
    }

    #[test]
    fn inbox_ids_are_validated_and_unique() {
        let store = Store::in_memory().unwrap();
        for good in ["billing", "my-app_2", "a", "9lives"] {
            assert!(valid_inbox_id(good), "{good}");
        }
        for bad in [
            "",
            "Billing",
            "has space",
            "-leading",
            "a/b",
            "é",
            &"x".repeat(64),
        ] {
            assert!(!valid_inbox_id(bad), "{bad}");
            assert!(store.create_inbox(bad).is_err(), "{bad}");
        }
        store.create_inbox("billing").unwrap();
        let error = store.create_inbox("billing").unwrap_err();
        assert_eq!(
            error.downcast_ref::<InboxError>(),
            Some(&InboxError::Exists("billing".into()))
        );
    }

    #[test]
    fn a_named_inbox_comes_with_a_generated_id_and_a_first_key() {
        let store = Store::in_memory().unwrap();
        let (inbox, key) = store
            .create_inbox_named(NewInbox {
                name: "  Billing   App ".into(),
                description: "Invoices and receipts".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(inbox.name, "Billing App", "tidied");
        assert_eq!(inbox.description, "Invoices and receipts");
        assert_eq!(inbox.id, "billing-app", "the id is the name, as a slug");
        assert_eq!(inbox.keys, 1);
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some(inbox.id.as_str())
        );

        // Mail delivered to it carries the name for display.
        let message = store
            .insert(mail_in(&inbox.id, "a@x.test", "b@x.test", "s", "x"))
            .unwrap();
        assert_eq!(message.inbox_name, "Billing App");
        assert_eq!(
            store.list(&all()).unwrap().messages[0].inbox_name,
            "Billing App"
        );

        // Names are unique whatever their case, and required; ids differ.
        let again = NewInbox {
            name: "billing app".into(),
            ..Default::default()
        };
        let error = store.create_inbox_named(again).unwrap_err();
        assert_eq!(
            error.downcast_ref::<InboxError>(),
            Some(&InboxError::Exists("billing app".into()))
        );
        for bad in ["", "   ", &"x".repeat(81)] {
            let error = store
                .create_inbox_named(NewInbox {
                    name: bad.into(),
                    ..Default::default()
                })
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<InboxError>(),
                Some(&InboxError::InvalidName),
                "{bad:?}"
            );
        }
        let (other, _) = store
            .create_inbox_named(NewInbox {
                name: "Marketing".into(),
                ..Default::default()
            })
            .unwrap();
        assert_ne!(other.id, inbox.id);
        assert_eq!(other.description, "");

        // A second inbox whose name makes the same slug gets a numbered id.
        let (twin, _) = store
            .create_inbox_named(NewInbox {
                name: "Billing-App!".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(twin.id, "billing-app-2");
        assert_eq!(
            store.suggest_inbox_id("billing app").unwrap(),
            "billing-app-3"
        );
        // A name with nothing to make a slug from still gets a usable id.
        let (unslugged, _) = store
            .create_inbox_named(NewInbox {
                name: "日本語 📮".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(unslugged.id.starts_with("ibx_") && valid_inbox_id(&unslugged.id));

        // Found by id or by name.
        assert_eq!(
            store.resolve_inbox("BILLING APP").unwrap().as_deref(),
            Some(inbox.id.as_str())
        );
        assert_eq!(
            store.resolve_inbox(&inbox.id).unwrap().as_deref(),
            Some(inbox.id.as_str())
        );
        assert_eq!(store.resolve_inbox("nope").unwrap(), None);
    }

    #[test]
    fn slugs_are_valid_ids() {
        for (name, expected) in [
            ("Billing App", "billing-app"),
            ("  My  App -- v2!  ", "my-app-v2"),
            ("UPPER_case.name", "upper-case-name"),
            ("---", ""),
            ("9 lives", "9-lives"),
        ] {
            assert_eq!(slug(name), expected, "{name:?}");
            assert!(expected.is_empty() || valid_inbox_id(expected));
        }
        assert!(slug(&"long name ".repeat(20)).len() <= 63);
    }

    #[test]
    fn a_draft_shown_to_the_user_is_created_exactly_as_shown() {
        let store = Store::in_memory().unwrap();
        let draft = NewInbox {
            name: "Orders".into(),
            description: String::new(),
            id: Some("ibx_0123456789".into()),
            key: Some("emu_a-key-the-user-has-already-copied".into()),
        };
        let (inbox, key) = store.create_inbox_named(draft.clone()).unwrap();
        assert_eq!(inbox.id, "ibx_0123456789");
        assert_eq!(key, "emu_a-key-the-user-has-already-copied");
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some("ibx_0123456789")
        );

        // Neither the id nor the key can be claimed twice.
        let same_id = NewInbox {
            name: "Other".into(),
            key: None,
            ..draft.clone()
        };
        assert!(store.create_inbox_named(same_id).is_err());
        let same_key = NewInbox {
            name: "Third".into(),
            id: None,
            ..draft.clone()
        };
        assert!(store.create_inbox_named(same_key).is_err());
        let weak = NewInbox {
            name: "Weak".into(),
            id: None,
            key: Some("short".into()),
            ..Default::default()
        };
        assert!(store.create_inbox_named(weak).is_err());
        assert_eq!(
            store.inboxes().unwrap().len(),
            2,
            "nothing half-made is left behind"
        );
    }

    #[test]
    fn an_inbox_can_be_renamed_without_changing_its_id() {
        let store = Store::in_memory().unwrap();
        let (inbox, key) = store
            .create_inbox_named(NewInbox {
                name: "Billing".into(),
                ..Default::default()
            })
            .unwrap();
        store
            .create_inbox_named(NewInbox {
                name: "Marketing".into(),
                ..Default::default()
            })
            .unwrap();

        let renamed = store
            .update_inbox(&inbox.id, Some("Payments"), Some("Card and invoice mail"))
            .unwrap();
        assert_eq!(
            (renamed.id.as_str(), renamed.name.as_str()),
            (inbox.id.as_str(), "Payments")
        );
        assert_eq!(renamed.description, "Card and invoice mail");
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some(inbox.id.as_str()),
            "keys keep working"
        );

        assert!(
            store
                .update_inbox(&inbox.id, Some("marketing"), None)
                .is_err(),
            "taken"
        );
        assert!(
            store
                .update_inbox(&inbox.id, Some("payments"), None)
                .is_ok(),
            "its own name, recased"
        );
        assert!(store.update_inbox("nowhere", Some("x"), None).is_err());
    }

    #[test]
    fn deleting_an_inbox_takes_its_mail_and_keys() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        let (_, key) = store.create_key("billing", "ci").unwrap();
        store
            .insert(mail_in("billing", "a@x.test", "bob@x.test", "Invoice", "x"))
            .unwrap();
        store
            .insert(mail("a@x.test", "bob@x.test", "Kept", "x"))
            .unwrap();

        store.delete_inbox("billing").unwrap();
        assert_eq!(store.list(&all()).unwrap().total, 1);
        assert!(store.inbox_for_key(&key).unwrap().is_none());
        assert!(
            store
                .keys(None)
                .unwrap()
                .iter()
                .all(|k| k.inbox == DEFAULT_INBOX)
        );
        assert!(store.delete_inbox("billing").is_err(), "it is gone");
    }

    #[test]
    fn keys_open_their_own_inbox_only() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        let (billing, billing_key) = store.create_key("billing", "laravel app").unwrap();
        let (_, rotated) = store.create_key("billing", "").unwrap();
        let (_, marketing_key) = store.create_key("marketing", "site").unwrap();

        assert_eq!(
            store.inbox_for_key(&billing_key).unwrap().as_deref(),
            Some("billing")
        );
        assert_eq!(
            store.inbox_for_key(&rotated).unwrap().as_deref(),
            Some("billing")
        );
        assert_eq!(
            store.inbox_for_key(&marketing_key).unwrap().as_deref(),
            Some("marketing")
        );
        assert!(store.inbox_for_key("emu_not-a-real-key").unwrap().is_none());
        assert!(store.inbox_for_key("").unwrap().is_none());

        // What is kept can identify a key but not reproduce it.
        assert_eq!(billing.label, "laravel app");
        assert!(billing_key.starts_with(&billing.prefix));
        assert!(billing.prefix.len() < 12);
        let listed = store.keys(Some("billing")).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].label, "key", "an empty label gets a default");
        assert!(listed[0].last_used_at.is_some(), "use is recorded");

        // Revoking is limited to the inbox it is asked through.
        assert!(!store.revoke_key(billing.id, Some("marketing")).unwrap());
        assert!(store.revoke_key(billing.id, Some("billing")).unwrap());
        assert!(store.inbox_for_key(&billing_key).unwrap().is_none());
        assert!(
            store.inbox_for_key(&rotated).unwrap().is_some(),
            "the other key still works"
        );
        assert!(store.create_key("nowhere", "x").is_err());
    }

    #[test]
    fn regenerating_a_key_replaces_its_value_and_keeps_its_identity() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        let (record, old) = store.create_key("billing", "laravel app").unwrap();
        assert!(store.inbox_for_key(&old).unwrap().is_some());

        // Not through another inbox, and not a key that does not exist.
        assert!(
            store
                .regenerate_key(record.id, Some("marketing"))
                .unwrap()
                .is_none()
        );
        assert!(store.regenerate_key(999, None).unwrap().is_none());
        assert!(
            store.inbox_for_key(&old).unwrap().is_some(),
            "untouched by the refusals"
        );

        let (renewed, new) = store
            .regenerate_key(record.id, Some("billing"))
            .unwrap()
            .unwrap();
        assert_ne!(new, old);
        assert_eq!(
            (renewed.id, renewed.label.as_str()),
            (record.id, "laravel app")
        );
        assert!(new.starts_with(&renewed.prefix));
        assert!(
            renewed.last_used_at.is_none(),
            "the new value has never been used"
        );
        assert!(
            store.inbox_for_key(&old).unwrap().is_none(),
            "the old value is dead"
        );
        assert_eq!(
            store.inbox_for_key(&new).unwrap().as_deref(),
            Some("billing")
        );
        assert_eq!(
            store.keys(Some("billing")).unwrap().len(),
            1,
            "replaced, not added"
        );
    }

    #[test]
    fn provisioning_is_repeatable_and_refuses_weak_or_shared_keys() {
        let store = Store::in_memory().unwrap();
        let key = "a-key-chosen-by-the-deployment";
        store.provision_key("orders", key).unwrap();
        store.provision_key("orders", key).unwrap();
        assert_eq!(store.inbox_for_key(key).unwrap().as_deref(), Some("orders"));
        assert_eq!(store.keys(Some("orders")).unwrap().len(), 1);

        assert!(store.provision_key("orders", "short").is_err());
        assert!(store.provision_key("Bad Id", key).is_err());
        assert!(
            store.provision_key("other", key).is_err(),
            "a key opens one inbox"
        );
    }

    #[test]
    fn recipients_follow_the_envelope_and_include_bcc() {
        let store = Store::in_memory().unwrap();
        let mut incoming = mail("a@x.test", "bob@x.test", "Hi", "body");
        incoming.envelope_to.push("hidden@x.test".into());
        let summary = store.insert(incoming).unwrap();
        assert_eq!(summary.recipients, vec!["bob@x.test", "hidden@x.test"]);

        let filter = ListFilter {
            to: Some("HIDDEN@x.test".into()),
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
        assert_eq!(summary.recipients, vec!["bob@x.test"]);
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
    fn bulk_changes_act_on_exactly_what_the_filter_matches() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        let a = store
            .insert(mail("a@x.test", "bob@x.test", "Invoice A", "a"))
            .unwrap();
        store
            .insert(mail("a@x.test", "carol@x.test", "Invoice B", "b"))
            .unwrap();
        store
            .insert(mail_in(
                "billing",
                "a@x.test",
                "bob@x.test",
                "Invoice C",
                "c",
            ))
            .unwrap();
        store
            .insert(mail("a@x.test", "bob@x.test", "Newsletter", "d"))
            .unwrap();

        let invoices_here = ListFilter {
            inbox: Some(DEFAULT_INBOX.into()),
            query: Some("subject:invoice".into()),
            // Paging must not limit a bulk change to one page.
            limit: Some(1),
            before_id: Some(a.id),
            ..Default::default()
        };
        assert_eq!(store.mark_all_read(&invoices_here).unwrap(), 2);
        assert_eq!(store.stats(None).unwrap().unread, 2);
        assert_eq!(
            store.mark_all_read(&invoices_here).unwrap(),
            0,
            "nothing left to mark"
        );

        assert_eq!(store.clear(&invoices_here).unwrap(), 2);
        let left: Vec<_> = store
            .list(&all())
            .unwrap()
            .messages
            .into_iter()
            .map(|m| m.subject)
            .collect();
        assert_eq!(left, vec!["Newsletter", "Invoice C"]);

        assert_eq!(store.clear(&all()).unwrap(), 2);
        assert_eq!(store.stats(None).unwrap().total, 0);
    }

    #[test]
    fn flags_and_deletes() {
        let store = Store::in_memory().unwrap();
        let a = store
            .insert(mail("a@x.test", "bob@x.test", "A", "a"))
            .unwrap();
        assert!(store.set_flags(a.id, Some(true), None).unwrap());
        assert!(!store.set_flags(999, Some(true), None).unwrap());
        assert_eq!(store.stats(None).unwrap().unread, 0);
        assert!(store.delete(a.id).unwrap());
        assert!(!store.delete(a.id).unwrap());
        assert_eq!(store.stats(None).unwrap().total, 0);
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
        assert_eq!(store.stats(None).unwrap().total, 2);
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
            store.stats(None).unwrap().total,
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
    fn events_announce_changes_with_their_inbox() {
        let store = Store::in_memory().unwrap();
        store.create_inbox("billing").unwrap();
        let mut events = store.subscribe();
        let message = store
            .insert(mail_in("billing", "a@x.test", "b@x.test", "1", "x"))
            .unwrap();
        let new = events.try_recv().unwrap();
        assert!(matches!(&new, Event::New { message: m } if m.id == message.id));
        assert!(new.concerns("billing") && !new.concerns("default"));

        store.delete(message.id).unwrap();
        assert_eq!(
            events.try_recv().unwrap(),
            Event::Deleted {
                id: message.id,
                inbox: "billing".into()
            }
        );
    }

    fn scratch_db(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("emailulator-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        (dir, path)
    }

    #[test]
    fn the_default_inbox_starts_with_a_readable_key() {
        let store = Store::in_memory().unwrap();
        let keys = store.keys(Some(DEFAULT_INBOX)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].label, STARTER_KEY_LABEL);
        let key = keys[0].key.clone().expect("the starter key is readable");
        assert!(key.starts_with(&keys[0].prefix));
        assert_eq!(
            store.inbox_for_key(&key).unwrap().as_deref(),
            Some(DEFAULT_INBOX)
        );

        // Every other key stays hash-only.
        store.create_inbox("billing").unwrap();
        store.create_key("billing", "ci").unwrap();
        assert!(store.keys(Some("billing")).unwrap()[0].key.is_none());
    }

    #[test]
    fn regenerating_the_starter_key_makes_it_an_ordinary_key() {
        let store = Store::in_memory().unwrap();
        let starter = store.keys(Some(DEFAULT_INBOX)).unwrap().remove(0);
        let old = starter.key.clone().unwrap();
        let (renewed, new) = store.regenerate_key(starter.id, None).unwrap().unwrap();
        assert!(
            renewed.key.is_none(),
            "the new value is shown once, not kept"
        );
        assert!(store.keys(Some(DEFAULT_INBOX)).unwrap()[0].key.is_none());
        assert!(store.inbox_for_key(&old).unwrap().is_none());
        assert_eq!(
            store.inbox_for_key(&new).unwrap().as_deref(),
            Some(DEFAULT_INBOX)
        );
    }

    #[test]
    fn a_revoked_starter_key_does_not_come_back() {
        let (dir, path) = scratch_db("starter-revoked");
        let store = Store::open(Some(&path), Limits::default()).unwrap();
        let starter = store.keys(Some(DEFAULT_INBOX)).unwrap().remove(0);
        assert!(store.revoke_key(starter.id, None).unwrap());
        drop(store);

        let store = Store::open(Some(&path), Limits::default()).unwrap();
        assert!(store.keys(Some(DEFAULT_INBOX)).unwrap().is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_store_with_hash_only_keys_gains_a_starter_key() {
        let (dir, path) = scratch_db("starter-migrate");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE inboxes (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, \
                 name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '') WITHOUT ROWID;
                 CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 inbox TEXT NOT NULL REFERENCES inboxes(id) ON DELETE CASCADE, label TEXT NOT NULL, \
                 prefix TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, \
                 last_used_at INTEGER);
                 INSERT INTO inboxes (id, created_at, name) VALUES ('billing', 1, 'Billing');
                 INSERT INTO api_keys (inbox, label, prefix, hash, created_at) \
                 VALUES ('billing', 'ci', 'emu_abc', 'not-a-real-hash', 1);",
            )
            .unwrap();
        }
        let store = Store::open(Some(&path), Limits::default()).unwrap();
        assert!(store.keys(Some("billing")).unwrap()[0].key.is_none());
        let starter = store.keys(Some(DEFAULT_INBOX)).unwrap();
        assert_eq!(starter.len(), 1);
        assert!(starter[0].key.is_some());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_default_inbox_with_keys_gets_no_starter_key() {
        let (dir, path) = scratch_db("starter-existing");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE inboxes (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, \
                 name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '') WITHOUT ROWID;
                 CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 inbox TEXT NOT NULL REFERENCES inboxes(id) ON DELETE CASCADE, label TEXT NOT NULL, \
                 prefix TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, \
                 last_used_at INTEGER);
                 INSERT INTO inboxes (id, created_at, name) VALUES ('default', 1, 'Default');
                 INSERT INTO api_keys (inbox, label, prefix, hash, created_at) \
                 VALUES ('default', 'ci', 'emu_abc', 'not-a-real-hash', 1);",
            )
            .unwrap();
        }
        let store = Store::open(Some(&path), Limits::default()).unwrap();
        let keys = store.keys(Some(DEFAULT_INBOX)).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].label, "ci");
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_store_from_before_inboxes_is_carried_over() {
        let dir = std::env::temp_dir().join(format!("emailulator-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, received_at INTEGER NOT NULL, \
                 source TEXT NOT NULL, envelope_from TEXT, from_name TEXT, from_address TEXT, \
                 to_json TEXT NOT NULL, cc_json TEXT NOT NULL, recipients_text TEXT NOT NULL, \
                 subject TEXT NOT NULL, snippet TEXT NOT NULL, search_text TEXT NOT NULL, \
                 size INTEGER NOT NULL, attachment_count INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0, \
                 starred INTEGER NOT NULL DEFAULT 0, raw BLOB NOT NULL);
                 INSERT INTO messages (received_at, source, to_json, cc_json, recipients_text, subject, \
                 snippet, search_text, size, attachment_count, raw) \
                 VALUES (1, 'smtp', '[]', '[]', '', 'Old mail', '', '', 3, 0, x'616263');",
            )
            .unwrap();
        }
        let store = Store::open(Some(&path), Limits::default()).unwrap();
        let page = store.list(&in_inbox(DEFAULT_INBOX)).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.messages[0].subject, "Old mail");
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
