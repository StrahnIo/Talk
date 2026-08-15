//! The ZSMTP envelope: metadata about delivery, distinct from the payload.

use serde::{Deserialize, Serialize};

/// The recipient of a delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// The recipient's federated mailbox, e.g. `alice@example.com`.
    pub mailbox: String,
}

/// How the invoice payload is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Payload {
    /// Shielded: the invoice is sealed (encrypted with `K`; `K` in the memo).
    Sealed,
    /// Transparent: the invoice is sealed to the recipient's public key.
    Plaintext,
}

/// The ZSMTP envelope — SMTP's `MAIL FROM` / `RCPT TO` analog.
///
/// Carries two identities per the design (see `docs/decisions.md` O6):
/// - `sender_server`: the DNS-verified sending server (like `MAIL FROM`).
/// - the authorizing user's spend-auth signature is carried in the payload
///   channel (see `docs/architecture.md`), not the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version, e.g. "1.0".
    pub version: String,
    /// The sending server's domain, DNS-verified.
    pub sender_server: String,
    /// Globally-unique message id, used for dedup (SMTP `Message-ID` analog).
    pub message_id: String,
    pub recipient: Recipient,
    pub payload: Payload,
    /// Creation time as Unix seconds.
    pub created_at: i64,
}

impl Envelope {
    /// Build a new envelope with the current time.
    pub fn new(
        sender_server: impl Into<String>,
        message_id: impl Into<String>,
        recipient: Recipient,
        payload: Payload,
    ) -> Self {
        Self {
            version: "1.0".to_string(),
            sender_server: sender_server.into(),
            message_id: message_id.into(),
            recipient,
            payload,
            created_at: now_secs(),
        }
    }

    pub fn is_duplicate_of(&self, other: &Envelope) -> bool {
        self.sender_server == other.sender_server && self.message_id == other.message_id
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(mid: &str) -> Envelope {
        Envelope::new(
            "sender.example.com",
            mid,
            Recipient {
                mailbox: "alice@example.com".to_string(),
            },
            Payload::Sealed,
        )
    }

    #[test]
    fn envelope_has_default_version() {
        let e = env("msg-1");
        assert_eq!(e.version, "1.0");
        assert!(e.created_at > 0);
    }

    #[test]
    fn duplicate_detection() {
        let a = env("msg-1");
        let b = env("msg-1");
        let c = env("msg-2");
        assert!(a.is_duplicate_of(&b));
        assert!(!a.is_duplicate_of(&c));
        // Same message id from a different server is not a duplicate.
        let mut d = env("msg-1");
        d.sender_server = "other.example.com".to_string();
        assert!(!a.is_duplicate_of(&d));
    }

    #[test]
    fn envelope_serializes_to_json() {
        let e = env("msg-1");
        let json = serde_json::to_string(&e).expect("serialize");
        let back: Envelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(e, back);
    }

    #[test]
    fn payload_serde_roundtrip() {
        for p in [Payload::Sealed, Payload::Plaintext] {
            let s = serde_json::to_string(&p).unwrap();
            let back: Payload = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
    }
}
