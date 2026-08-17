//! Delivery sink: routes ZSMTP INVOICE deliveries into the mailbox store.

use ed25519_dalek::SigningKey;
use std::path::Path;
use std::sync::Arc;
use talk_imap::server::MailboxEvent;
use talk_mailstore::{MessageFlags, NewMessage, NewTransaction, SqliteMailStore, TxDirection, TxState};
use talk_protocol::{DeliveryOutcome, DeliverySink, Keyring, Payload, TrustState, UserDirectory};
use tokio::sync::broadcast;
use tracing::warn;

/// Registered-user directory backed by the mailstore. Lets the ZSMTP session
/// reject unknown recipients with 550.
pub struct StoreUserDirectory {
    store: Arc<SqliteMailStore>,
}

impl StoreUserDirectory {
    pub fn new(store: Arc<SqliteMailStore>) -> Self {
        Self { store }
    }
}

impl UserDirectory for StoreUserDirectory {
    fn user_exists(&self, username: &str) -> bool {
        matches!(self.store.get_user(username), Ok(Some(_)))
    }
}

/// Per-user sender keyring backed by the mailstore.
pub struct StoreKeyring {
    store: Arc<SqliteMailStore>,
}

impl StoreKeyring {
    pub fn new(store: Arc<SqliteMailStore>) -> Self {
        Self { store }
    }
}

impl Keyring for StoreKeyring {
    fn state(&self, user_id: i64, sender_mailbox: &str) -> TrustState {
        if sender_mailbox.is_empty() {
            return TrustState::Unverified;
        }
        match self.store.keyring_sender_key(user_id, sender_mailbox) {
            Ok(Some(_)) => TrustState::Trusted,
            _ => TrustState::Unverified,
        }
    }
}

/// Load the domain signing key from `data_dir/domainkey`, or create + persist
/// it on first boot. The public half is what peers verify against (published
/// in DNS in a future milestone).
pub fn load_or_create_domain_key(data_dir: &Path) -> Result<SigningKey, std::io::Error> {
    use ed25519_dalek::SecretKey;
    let path = data_dir.join("domainkey");
    if let Ok(raw) = std::fs::read(&path) {
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad domain key"))?;
        let secret = SecretKey::from(bytes);
        return Ok(SigningKey::from(&secret));
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&path, key.to_bytes())?;
    Ok(key)
}

/// Delivers invoices into a user's mailbox, then notifies IDLE sessions.
pub struct StoreDeliverySink {
    store: Arc<SqliteMailStore>,
    events: Option<broadcast::Sender<MailboxEvent>>,
}

impl StoreDeliverySink {
    pub fn new(store: Arc<SqliteMailStore>) -> Self {
        Self {
            store,
            events: None,
        }
    }

    /// Attach the IMAP event broadcaster so IDLE sessions are notified.
    pub fn with_events(mut self, events: broadcast::Sender<MailboxEvent>) -> Self {
        self.events = Some(events);
        self
    }
}

impl StoreDeliverySink {
    /// Resolve the local user for a mailbox's user half, mapping failures to
    /// `DeliveryOutcome` the same way the wire path does.
    fn recipient_user(
        &self,
        recipient_mailbox: &str,
    ) -> Result<talk_mailstore::User, DeliveryOutcome> {
        let user = match recipient_mailbox.split('@').next() {
            Some(u) if !u.is_empty() => u,
            _ => {
                return Err(DeliveryOutcome::Rejected {
                    reason: "malformed recipient mailbox".into(),
                });
            }
        };
        match self.store.get_user(user) {
            Ok(Some(u)) => Ok(u),
            Ok(None) => Err(DeliveryOutcome::Rejected {
                reason: format!("no such recipient: {user}"),
            }),
            Err(e) => {
                warn!(error = %e, "recipient lookup failed");
                Err(DeliveryOutcome::RetryLater {
                    reason: "storage error".into(),
                })
            }
        }
    }

    /// Append a message to a user's INBOX, notify IDLE sessions, and return
    /// the appended message metadata (for ledger linking).
    fn append_and_broadcast(
        &self,
        user_id: i64,
        msg: NewMessage,
        message_id: &str,
    ) -> Result<talk_mailstore::MessageMeta, DeliveryOutcome> {
        let meta = match self.store.append_message(user_id, msg) {
            Ok(m) => m,
            Err(talk_mailstore::StoreError::DuplicateMessage(_)) => {
                return Err(DeliveryOutcome::Rejected {
                    reason: format!("duplicate message id: {message_id}"),
                });
            }
            Err(e) => {
                warn!(error = %e, "append failed");
                return Err(DeliveryOutcome::RetryLater {
                    reason: "storage error".into(),
                });
            }
        };
        if let Some(events) = &self.events {
            let _ = events.send(MailboxEvent::MessageAppended { user_id });
        }
        Ok(meta)
    }

    /// Record an inbound ledger transaction for a delivered message
    /// (best-effort: a ledger failure never fails delivery).
    fn record_inbound_tx(
        &self,
        sender_mailbox: &str,
        recipient_mailbox: &str,
        amount: &str,
        message_id: &str,
        message_row_id: i64,
    ) {
        let result = self.store.tx_create(NewTransaction {
            direction: TxDirection::In,
            state: TxState::Opaque,
            sender_mailbox: sender_mailbox.to_string(),
            recipient_mailbox: recipient_mailbox.to_string(),
            amount: amount.to_string(),
            binding: None,
            message_id: message_id.to_string(),
            outbound_body: None,
            payload: "sealed".to_string(),
        });
        match result {
            Ok(tx) => {
                let _ = self.store.tx_link_message(tx.id, message_row_id);
            }
            Err(e) => warn!(error = %e, "ledger record failed"),
        }
    }

    /// Deliver an already-rendered message for a local user (used by local
    /// payment emulation). Trust state follows the sender label via the
    /// keyring, exactly like the wire path.
    pub fn deliver_emulated(
        &self,
        recipient_user: &str,
        sender_label: &str,
        amount: &str,
        message_id: &str,
        subject: &str,
        body: &[u8],
    ) -> DeliveryOutcome {
        let user = match self.recipient_user(recipient_user) {
            Ok(u) => u,
            Err(outcome) => return outcome,
        };
        let trust_state = StoreKeyring::new(self.store.clone())
            .state(user.id, sender_label)
            .as_str()
            .to_string();
        let msg = NewMessage {
            message_id: message_id.to_string(),
            subject: subject.to_string(),
            body: body.to_vec(),
            flags: MessageFlags::default(),
            sender: sender_label.to_string(),
            trust_state,
        };
        match self.append_and_broadcast(user.id, msg, message_id) {
            Ok(meta) => {
                self.record_inbound_tx(sender_label, recipient_user, amount, message_id, meta.id);
                DeliveryOutcome::Accepted {
                    message_id: message_id.to_string(),
                }
            }
            Err(outcome) => outcome,
        }
    }
}

impl DeliverySink for StoreDeliverySink {
    fn deliver(
        &self,
        sender_mailbox: &str,
        message_id: &str,
        recipient_mailbox: &str,
        payload: Payload,
        body: &[u8],
    ) -> DeliveryOutcome {
        let user = match self.recipient_user(recipient_mailbox) {
            Ok(u) => u,
            Err(outcome) => return outcome,
        };
        let subject = match payload {
            Payload::Sealed => "New sealed invoice".to_string(),
            Payload::Plaintext => "New invoice".to_string(),
        };
        // Trust state via the keyring: trusted if pinned, else unverified.
        let trust_state = StoreKeyring::new(self.store.clone())
            .state(user.id, sender_mailbox)
            .as_str()
            .to_string();
        let msg = NewMessage {
            message_id: message_id.to_string(),
            subject,
            body: body.to_vec(),
            flags: MessageFlags::default(),
            sender: sender_mailbox.to_string(),
            trust_state,
        };
        match self.append_and_broadcast(user.id, msg, message_id) {
            Ok(meta) => {
                self.record_inbound_tx(sender_mailbox, recipient_mailbox, "", message_id, meta.id);
                DeliveryOutcome::Accepted {
                    message_id: message_id.to_string(),
                }
            }
            Err(outcome) => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talk_protocol::Payload as P;

    fn store_with_user() -> (tempfile::TempDir, Arc<SqliteMailStore>, i64) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(SqliteMailStore::open(dir.path().join("m.db")).expect("open"));
        let hash = talk_mailstore::hash_password("pw").expect("hash");
        let user_id = store
            .create_user("alice", &hash, &[0u8; 32])
            .expect("user")
            .id;
        (dir, store, user_id)
    }

    #[test]
    fn unpinned_sender_is_unverified() {
        let (_dir, store, user_id) = store_with_user();
        let sink = StoreDeliverySink::new(store.clone());
        let outcome = sink.deliver(
            "bob@example.org",
            "m1",
            "alice@example.org",
            P::Sealed,
            b"body",
        );
        assert!(matches!(outcome, DeliveryOutcome::Accepted { .. }));
        let list = store.list_messages(user_id).expect("list");
        assert_eq!(list[0].sender, "bob@example.org");
        assert_eq!(list[0].trust_state, "unverified");
    }

    #[test]
    fn deliver_records_inbound_transaction() {
        let (_dir, store, user_id) = store_with_user();
        let sink = StoreDeliverySink::new(store.clone());
        let outcome = sink.deliver(
            "bob@example.org",
            "tx-1",
            "alice@example.org",
            P::Plaintext,
            b"body",
        );
        assert!(matches!(outcome, DeliveryOutcome::Accepted { .. }));

        let tx = store
            .tx_by_message_id(TxDirection::In, "tx-1")
            .expect("get")
            .expect("exists");
        assert_eq!(tx.state, TxState::Opaque);
        assert_eq!(tx.recipient_mailbox, "alice@example.org");
        assert_eq!(tx.sender_mailbox, "bob@example.org");
        assert!(tx.amount.is_empty(), "real ZSMTP has no amount");

        // The inbox message is linked to the opaque transaction.
        let msgs = store.list_messages(user_id).expect("list");
        assert_eq!(msgs[0].tx_state.as_deref(), Some("opaque"));
    }

    #[test]
    fn pinned_sender_is_trusted() {
        let (_dir, store, user_id) = store_with_user();
        store
            .keyring_set_trusted(user_id, "bob@example.org", "pubkey", b"att")
            .expect("pin");
        let sink = StoreDeliverySink::new(store.clone());
        let outcome = sink.deliver(
            "bob@example.org",
            "m1",
            "alice@example.org",
            P::Sealed,
            b"body",
        );
        assert!(matches!(outcome, DeliveryOutcome::Accepted { .. }));
        let list = store.list_messages(user_id).expect("list");
        assert_eq!(list[0].trust_state, "trusted");
    }

    #[test]
    fn anonymous_sender_is_unverified() {
        let (_dir, store, user_id) = store_with_user();
        let sink = StoreDeliverySink::new(store.clone());
        let outcome = sink.deliver("", "m1", "alice@example.org", P::Sealed, b"body");
        assert!(matches!(outcome, DeliveryOutcome::Accepted { .. }));
        let list = store.list_messages(user_id).expect("list");
        assert_eq!(list[0].sender, "");
        assert_eq!(list[0].trust_state, "unverified");
    }
}
