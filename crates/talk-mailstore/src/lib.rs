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

/// The inbox mailbox name.
pub const INBOX: &str = "INBOX";
/// The sent mailbox name.
pub const SENT: &str = "Sent";

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

/// A user as shown in listings (no sensitive key material).
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub has_ivk: bool,
    pub has_attestation: bool,
}

/// Direction of a ledger transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDirection {
    /// Received (an invoice delivered into the mailbox).
    In,
    /// Sent (an invoice the local user delivered to another server).
    Out,
}

impl TxDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxDirection::In => "in",
            TxDirection::Out => "out",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in" => Some(TxDirection::In),
            "out" => Some(TxDirection::Out),
            _ => None,
        }
    }
}

/// Lifecycle state of a ledger transaction.
///
/// Inbound: `opaque` (awaiting the on-chain binding) → `resolved` (binding
/// matched) → `spent` (the underlying note spent). Outbound: `sent` (accepted
/// by the receiving server) / `failed` (permanent) / `retrying` (transient,
/// re-send pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    Opaque,
    Resolved,
    Spent,
    Sent,
    Failed,
    Retrying,
}

impl TxState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxState::Opaque => "opaque",
            TxState::Resolved => "resolved",
            TxState::Spent => "spent",
            TxState::Sent => "sent",
            TxState::Failed => "failed",
            TxState::Retrying => "retrying",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "opaque" => Some(TxState::Opaque),
            "resolved" => Some(TxState::Resolved),
            "spent" => Some(TxState::Spent),
            "sent" => Some(TxState::Sent),
            "failed" => Some(TxState::Failed),
            "retrying" => Some(TxState::Retrying),
            _ => None,
        }
    }
}

/// Parameters for creating a ledger transaction.
#[derive(Debug, Clone)]
pub struct NewTransaction {
    pub direction: TxDirection,
    pub state: TxState,
    pub sender_mailbox: String,
    pub recipient_mailbox: String,
    /// Decimal ZEC amount.
    pub amount: String,
    /// On-chain binding (`K` hex or `H(invoice)`), when known.
    pub binding: Option<String>,
    pub message_id: String,
    /// Outbound only: the persisted invoice body (retry / Sent view).
    pub outbound_body: Option<Vec<u8>>,
}

/// A ledger transaction: the email-analogous record of a send or receive.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: i64,
    pub direction: TxDirection,
    pub state: TxState,
    pub sender_mailbox: String,
    pub recipient_mailbox: String,
    /// Decimal ZEC amount (emulation fills it; real ZSMTP may leave empty).
    pub amount: String,
    /// On-chain binding: `K` (hex) or `H(invoice)`, when known.
    pub binding: Option<String>,
    pub message_id: String,
    /// Inbound: the INBOX message row it produced; outbound: the Sent copy.
    pub message_row_id: Option<i64>,
    /// Outbound only: the persisted invoice body (enables retry / Sent view).
    pub outbound_body: Option<Vec<u8>>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A pinned sender keyring entry for a user.
#[derive(Debug, Clone)]
pub struct KeyringEntry {
    pub sender_mailbox: String,
    pub sender_pubkey: String,
    pub state: String,
    pub first_seen: i64,
}

/// A DK wrapper share: `(share_id, wrapped_dk, revoked)`.
#[derive(Debug, Clone)]
pub struct ShareEntry {
    pub share_id: String,
    pub wrapped_dk: Vec<u8>,
    pub revoked: bool,
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
    /// Ledger transaction state for this message's transaction, if linked.
    pub tx_state: Option<String>,
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

/// Resolve a login username against the daemon's local domain.
///
/// A bare local part (`alice`) is always accepted. A qualified form
/// (`alice@<local_domain>`, case-insensitive on the domain) resolves to the
/// local part. Any other domain is rejected (`None`), so a foreign
/// `alice@elsewhere` cannot alias a local user.
pub fn local_username<'a>(login: &'a str, local_domain: &str) -> Option<&'a str> {
    let login = login.trim();
    if login.is_empty() {
        return None;
    }
    match login.split_once('@') {
        None => Some(login),
        Some((local, domain)) => {
            if local.is_empty() {
                return None;
            }
            if domain.eq_ignore_ascii_case(local_domain) {
                Some(local)
            } else {
                None
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::local_username;

    #[test]
    fn bare_username_always_ok() {
        assert_eq!(local_username("alice", "talk.local"), Some("alice"));
        assert_eq!(local_username(" alice ", "talk.local"), Some("alice"));
    }

    #[test]
    fn matching_domain_resolves_to_local_part() {
        assert_eq!(
            local_username("alice@talk.local", "talk.local"),
            Some("alice")
        );
        // Domain match is case-insensitive.
        assert_eq!(
            local_username("alice@TALK.LOCAL", "talk.local"),
            Some("alice")
        );
    }

    #[test]
    fn foreign_domain_rejected() {
        assert_eq!(local_username("alice@evil.org", "talk.local"), None);
        assert_eq!(local_username("alice@", "talk.local"), None);
    }

    #[test]
    fn empty_rejected() {
        assert_eq!(local_username("", "talk.local"), None);
        assert_eq!(local_username("  ", "talk.local"), None);
    }
}
