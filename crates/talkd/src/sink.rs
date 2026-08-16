//! Delivery sink: routes ZSMTP INVOICE deliveries into the mailbox store.

use ed25519_dalek::SigningKey;
use std::path::Path;
use std::sync::Arc;
use talk_imap::server::MailboxEvent;
use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore};
use talk_protocol::{DeliveryOutcome, DeliverySink, Payload, UserDirectory};
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

impl DeliverySink for StoreDeliverySink {
    fn deliver(
        &self,
        _sender_server: &str,
        message_id: &str,
        recipient_mailbox: &str,
        payload: Payload,
        body: &[u8],
    ) -> DeliveryOutcome {
        // The recipient mailbox is `user@domain`; look up the local user.
        let user = match recipient_mailbox.split('@').next() {
            Some(u) if !u.is_empty() => u,
            _ => {
                return DeliveryOutcome::Rejected {
                    reason: "malformed recipient mailbox".into(),
                };
            }
        };
        let user = match self.store.get_user(user) {
            Ok(Some(u)) => u,
            Ok(None) => {
                return DeliveryOutcome::Rejected {
                    reason: format!("no such recipient: {user}"),
                };
            }
            Err(e) => {
                warn!(error = %e, "recipient lookup failed");
                return DeliveryOutcome::RetryLater {
                    reason: "storage error".into(),
                };
            }
        };

        let subject = match payload {
            Payload::Sealed => "New sealed invoice".to_string(),
            Payload::Plaintext => "New invoice".to_string(),
        };
        let msg = NewMessage {
            message_id: message_id.to_string(),
            subject,
            body: body.to_vec(),
            flags: MessageFlags::default(),
        };

        match self.store.append_message(user.id, msg) {
            Ok(_) => {}
            Err(talk_mailstore::StoreError::DuplicateMessage(_)) => {
                return DeliveryOutcome::Rejected {
                    reason: format!("duplicate message id: {message_id}"),
                };
            }
            Err(e) => {
                warn!(error = %e, "append failed");
                return DeliveryOutcome::RetryLater {
                    reason: "storage error".into(),
                };
            }
        }

        if let Some(events) = &self.events {
            let _ = events.send(MailboxEvent::MessageAppended { user_id: user.id });
        }

        DeliveryOutcome::Accepted {
            message_id: message_id.to_string(),
        }
    }
}
