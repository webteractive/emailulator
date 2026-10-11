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
    /// Envelope recipients: the mailboxes this message was delivered to,
    /// including Bcc recipients that appear in no header.
    pub mailboxes: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub address: String,
    pub total: usize,
    pub unread: usize,
    pub latest_at: i64,
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
    /// Only messages delivered to this address.
    pub mailbox: Option<String>,
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

/// A change to the store, broadcast to live viewers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    New {
        message: MessageSummary,
    },
    Updated {
        id: i64,
    },
    Deleted {
        id: i64,
    },
    /// Every message was marked read, in one mailbox or in all of them.
    ReadAll {
        mailbox: Option<String>,
    },
    /// Every message was deleted, in one mailbox or in all of them.
    Cleared {
        mailbox: Option<String>,
    },
}
