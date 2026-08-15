//! Delivery sink: routes ZSMTP INVOICE deliveries into the mailbox store.

use std::sync::Arc;
use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore};
use talk_protocol::{DeliveryOutcome, DeliverySink, Payload};
use tracing::warn;

/// Delivers invoices into a user's mailbox.
pub struct StoreDeliverySink {
    store: Arc<SqliteMailStore>,
}

impl StoreDeliverySink {
    pub fn new(store: Arc<SqliteMailStore>) -> Self {
        Self { store }
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
            Ok(_) => DeliveryOutcome::Accepted {
                message_id: message_id.to_string(),
            },
            Err(talk_mailstore::StoreError::DuplicateMessage(_)) => DeliveryOutcome::Rejected {
                reason: format!("duplicate message id: {message_id}"),
            },
            Err(e) => {
                warn!(error = %e, "append failed");
                DeliveryOutcome::RetryLater {
                    reason: "storage error".into(),
                }
            }
        }
    }
}
