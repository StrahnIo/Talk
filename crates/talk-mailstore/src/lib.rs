//! MailStore trait and SQLite/SQLCipher-backed mailbox storage.
//!
//! The store is synchronous; callers (e.g. the IMAP server) should run it via
//! `tokio::task::spawn_blocking`. Message bodies are stored as opaque ciphertext
//! per Model A — the store never inspects content.

pub mod password;
pub mod sqlite;

pub use password::{hash_password, verify_password};
pub use sqlite::SqliteMailStore;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A user's immutable identity within the mailbox.
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    /// Encoded master public key (DK wrap target for compatible clients).
    pub master_pubkey: Vec<u8>,
    /// Optional IVK commitment (dynamic-address mode). `None` = static mode.
    pub ivk_commitment: Option<String>,
    /// The registration attestation `R` (tamper-evident username↔pubkey binding).
    pub registration_attestation: Option<String>,
}

/// Metadata for a message — everything the IMAP server can expose without
/// touching the ciphertext body.
#[derive(Debug, Clone)]
pub struct MessageMeta {
    pub id: i64,
    pub message_id: String,
    pub uid: u32,
    pub uidvalidity: u32,
    pub internaldate: SystemTime,
    pub flags: MessageFlags,
    pub subject: String,
    pub size: u64,
    /// Sender mailbox (`user@domain`), empty if anonymous.
    pub sender: String,
    /// Sender trust state: `trusted` | `untrusted` | `unverified`.
    pub trust_state: String,
}

/// A full message including its opaque (ciphertext) body.
#[derive(Debug, Clone)]
pub struct Message {
    pub meta: MessageMeta,
    pub body: Vec<u8>,
}

/// A new message to append to a mailbox.
#[derive(Debug, Clone)]
pub struct NewMessage {
    /// The ZSMTP message id (dedup key).
    pub message_id: String,
    pub subject: String,
    pub body: Vec<u8>,
    pub flags: MessageFlags,
    /// The sender mailbox (`user@domain`), stored as `From:`. Empty if
    /// anonymous.
    pub sender: String,
    /// Sender trust state: `trusted` | `untrusted` | `unverified`.
    pub trust_state: String,
}

impl NewMessage {
    /// Build a new message with no sender and unverified trust.
    pub fn invoice(
        message_id: impl Into<String>,
        subject: impl Into<String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            subject: subject.into(),
            body,
            flags: MessageFlags::default(),
            sender: String::new(),
            trust_state: "unverified".to_string(),
        }
    }
}

/// IMAP system flags, stored as a bitmask.
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageFlags(u32);

impl MessageFlags {
    pub const SEEN: u32 = 1 << 0;
    pub const ANSWERED: u32 = 1 << 1;
    pub const FLAGGED: u32 = 1 << 2;
    pub const DELETED: u32 = 1 << 3;

    pub fn new(bits: u32) -> Self {
        Self(bits)
    }

    pub fn bits(&self) -> u32 {
        self.0
    }

    pub fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn insert(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn remove(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    pub fn is_seen(&self) -> bool {
        self.contains(Self::SEEN)
    }

    pub fn is_deleted(&self) -> bool {
        self.contains(Self::DELETED)
    }
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

/// Error type for mailbox storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("user {0} not found")]
    UserNotFound(String),
    #[error("user id {0} not found")]
    UserIdNotFound(i64),
    #[error("mailbox not found")]
    MailboxNotFound,
    #[error("message not found")]
    MessageNotFound,
    #[error("duplicate message id {0}")]
    DuplicateMessage(String),
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal lock poisoned")]
    Poisoned,
}
