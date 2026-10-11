//! Types shared by the store, the HTTP API, the MCP server and the desktop app.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub address: String,
}

impl Address {
    /// `Name <addr>` when a display name is present, the bare address otherwise.
    pub fn display(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => format!("{name} <{}>", self.address),
            _ => self.address.clone(),
        }
    }

    /// The display name, falling back to the address.
    pub fn label(&self) -> &str {
        match &self.name {
            Some(name) if !name.is_empty() => name,
            _ => &self.address,
        }
    }
}

/// How a message reached the catcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Smtp,
    Api,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Smtp => "smtp",
            Source::Api => "api",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "api" => Source::Api,
            _ => Source::Smtp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Position among the message's attachments; the handle used to fetch it.
    pub index: usize,
    pub filename: Option<String>,
    pub content_type: String,
    pub size: usize,
    pub content_id: Option<String>,
    pub inline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub id: i64,
    /// Unix milliseconds at which the catcher accepted the message.
    pub received_at: i64,
    pub from: Option<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub subject: String,
    pub snippet: String,
    pub size: usize,
    pub read: bool,
    pub starred: bool,
    pub attachment_count: usize,
    /// The id of the inbox this message was delivered into.
    pub inbox: String,
    /// That inbox's name, for showing to people.
    pub inbox_name: String,
    /// Envelope recipients: everyone the message was delivered to, including
    /// Bcc recipients that appear in no header.
    pub recipients: Vec<String>,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    pub summary: MessageSummary,
    pub envelope_from: Option<String>,
    pub bcc: Vec<Address>,
    pub reply_to: Vec<Address>,
    /// The Date header as RFC 3339, when the message carries one.
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub headers: Vec<Header>,
    pub attachments: Vec<AttachmentMeta>,
}

/// A named container for one application's mail, with its own API keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbox {
    /// Generated when the inbox is created, and never changed: it is the
    /// inbox's SMTP username, so applications are configured with it.
    pub id: String,
    /// What people call the inbox. Free text, unique, and may be changed.
    pub name: String,
    pub description: String,
    pub created_at: i64,
    pub total: usize,
    pub unread: usize,
    pub latest_at: Option<i64>,
    /// How many API keys the inbox has.
    pub keys: usize,
}

/// An API key as it can be shown after creation: never the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: i64,
    pub inbox: String,
    pub label: String,
    /// The first characters of the key, enough to tell keys apart.
    pub prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub total: usize,
    pub unread: usize,
    pub starred: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub messages: Vec<MessageSummary>,
    /// Messages matching the filter, ignoring paging.
    pub total: usize,
    /// Unread messages matching the filter, ignoring paging.
    pub unread: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListFilter {
    /// Only messages in this inbox.
    pub inbox: Option<String>,
    /// Only messages delivered to this address.
    pub to: Option<String>,
    /// Search terms; see [`crate::store`] for the syntax.
    pub query: Option<String>,
    pub unread: Option<bool>,
    pub starred: Option<bool>,
    /// Paging cursor: only messages older than this id.
    pub before_id: Option<i64>,
    /// Only messages newer than this id.
    pub after_id: Option<i64>,
    /// Only messages received at or after this Unix millisecond timestamp.
    pub since: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub url: String,
    /// The anchor text for links found in HTML.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// A change to the store, broadcast to live viewers. Each names the inbox it
/// happened in, so a viewer limited to one inbox can be told only about that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Boxed so the common, small events are not sized for a whole message.
    New {
        message: Box<MessageSummary>,
    },
    Updated {
        id: i64,
        inbox: String,
    },
    Deleted {
        id: i64,
        inbox: String,
    },
    /// Several messages were marked read, in one inbox or across all of them.
    ReadAll {
        inbox: Option<String>,
    },
    /// Several messages were deleted, in one inbox or across all of them.
    Cleared {
        inbox: Option<String>,
    },
    /// An inbox or one of its keys was created or removed.
    Inboxes,
}

impl Event {
    /// Whether a viewer limited to `inbox` should hear of this event.
    pub fn concerns(&self, inbox: &str) -> bool {
        match self {
            Event::New { message } => message.inbox == inbox,
            Event::Updated { inbox: i, .. } | Event::Deleted { inbox: i, .. } => i == inbox,
            Event::ReadAll { inbox: i } | Event::Cleared { inbox: i } => {
                i.as_deref().is_none_or(|i| i == inbox)
            }
            Event::Inboxes => true,
        }
    }
}
