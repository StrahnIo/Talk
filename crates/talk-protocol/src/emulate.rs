//! Local payment-emulation payload for the `secure_mailbox` control channel.
//!
//! `EMULATE` carries everything needed to simulate a received transparent
//! payment: the sender's name and address, an amount, and the ASCII invoice
//! text. The payload is serialized as JSON inside the command's opaque blob,
//! consistent with `INVOICE` (the protocol never interprets the payload).

use serde::{Deserialize, Serialize};

/// The emulation payload sent by the client and rendered by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatePayload {
    /// The sender's display name.
    pub sender_name: String,
    /// The transparent source address.
    pub sender_address: String,
    /// The amount, as a decimal string (ZEC).
    pub amount: String,
    /// The ASCII invoice text.
    pub invoice: Vec<u8>,
}

impl EmulatePayload {
    /// Serialize for the wire (JSON).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("emulate payload serializes")
    }

    /// Parse from the wire (JSON).
    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrips() {
        let p = EmulatePayload {
            sender_name: "Alice Smith".to_string(),
            sender_address: "t1abc123".to_string(),
            amount: "1.5".to_string(),
            invoice: b"line one\nline two".to_vec(),
        };
        let back = EmulatePayload::from_json(&p.to_json()).expect("parse");
        assert_eq!(p, back);
    }

    #[test]
    fn payload_handles_arbitrary_ascii() {
        let p = EmulatePayload {
            sender_name: "exchange".to_string(),
            sender_address: "t1xyz".to_string(),
            amount: "0.001".to_string(),
            invoice: b"\x00\x01\x02not ascii".to_vec(),
        };
        let back = EmulatePayload::from_json(&p.to_json()).expect("parse");
        assert_eq!(p.invoice, back.invoice);
    }

    #[test]
    fn garbage_is_none() {
        assert!(EmulatePayload::from_json("not json").is_none());
    }
}
