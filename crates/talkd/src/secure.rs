//! The secure_mailbox handler: what the local client can ask the daemon to do.

use ed25519_dalek::SigningKey;
use talk_protocol::attestation::{Attestation, AttestationMode, mint_pair};
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{AttestResult, SecureMailboxHandler, SendResult};
use talk_protocol::{DohDomainKeyResolver, DomainKeyResolver, connect_tcp};

/// Handles secure_mailbox commands, driving `ZsmptClient` to send invoices to
/// other daemons, and issuing signed address attestations with the daemon's
/// persisted domain key.
///
/// v1 connects to the recipient daemon over TCP at `send_endpoint` (DNS SRV
/// discovery is a later milestone).
pub struct SecureMailboxService {
    /// Our domain (the sender).
    pub sender_domain: String,
    /// The recipient daemon's TCP endpoint, e.g. `receiver.example.org:2525`.
    pub send_endpoint: String,
    /// Resolves the receiver's public domain key for verification.
    resolver: DohDomainKeyResolver,
    /// Our domain signing key (persisted; the public half is published in DNS).
    domain_key: SigningKey,
}

impl SecureMailboxService {
    pub fn new(
        sender_domain: impl Into<String>,
        send_endpoint: impl Into<String>,
        domain_key: SigningKey,
    ) -> Self {
        Self {
            sender_domain: sender_domain.into(),
            send_endpoint: send_endpoint.into(),
            resolver: DohDomainKeyResolver::default(),
            domain_key,
        }
    }
}

impl SecureMailboxHandler for SecureMailboxService {
    fn send(
        &self,
        recipient_mailbox: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> SendResult {
        let outcome = tokio::runtime::Handle::current().block_on(async {
            // The receiver's domain is the part after '@' in the mailbox.
            let Some(receiver_domain) = recipient_mailbox.split('@').nth(1) else {
                return Err("malformed recipient mailbox".to_string());
            };
            // Resolve the receiver's public key.
            let receiver_pub = match self.resolver.resolving_key(receiver_domain) {
                Ok(k) => k,
                Err(e) => return Err(format!("cannot resolve domain key: {e}")),
            };
            // Connect and run the full ZSMTP send flow.
            let mut client = match connect_tcp(&self.send_endpoint, &self.sender_domain).await {
                Ok(c) => c,
                Err(e) => return Err(format!("connect: {e}")),
            };
            if let Err(e) = client.hello().await {
                return Err(format!("hello: {e}"));
            }
            if let Err(e) = client.authenticate(&receiver_pub).await {
                return Err(format!("auth: {e}"));
            }
            // Request an ephemeral address for the recipient user.
            let user = recipient_mailbox.split('@').next().unwrap_or("");
            if let Err(e) = client
                .request_address(user, AttestationMode::Ephemeral, &receiver_pub)
                .await
            {
                return Err(format!("addr: {e}"));
            }
            if let Err(e) = client.send_invoice(message_id, payload, body).await {
                return Err(format!("invoice: {e}"));
            }
            let _ = client.quit().await;
            Ok(())
        });
        match outcome {
            Ok(()) => SendResult::Ok(format!("delivered {message_id} to {recipient_mailbox}")),
            Err(e) => SendResult::Error(e),
        }
    }

    fn attest(&self, user: &str, mode: AttestationMode) -> AttestResult {
        if user.is_empty() {
            return AttestResult::Error("attest requires a user".to_string());
        }
        let (address, pubkey) = mint_pair(mode);
        let attestation = Attestation::sign(
            &self.sender_domain,
            user,
            mode,
            address,
            pubkey,
            &self.domain_key,
        );
        AttestResult::Ok(attestation.to_json().into_bytes())
    }

    fn status(&self) -> String {
        format!(
            "talkd {} sender={} endpoint={}",
            env!("CARGO_PKG_VERSION"),
            self.sender_domain,
            self.send_endpoint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talk_protocol::attestation::Attestation;

    fn service() -> SecureMailboxService {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        SecureMailboxService::new("example.org", "receiver.example.org:2525", key)
    }

    #[test]
    fn attest_produces_verifiable_signed_attestation() {
        let svc = service();
        let AttestResult::Ok(blob) = svc.attest("alice", AttestationMode::Ephemeral) else {
            panic!("expected Ok");
        };
        let att = Attestation::from_json(&String::from_utf8(blob).unwrap()).expect("parse");
        assert_eq!(att.domain, "example.org");
        assert_eq!(att.user, "alice");
        assert_eq!(att.mode, AttestationMode::Ephemeral);
        assert_eq!(att.pubkey.len(), 64);
        // The attestation verifies against the daemon's domain public key.
        att.verify(&svc.domain_key.verifying_key(), "example.org")
            .expect("must verify");
    }

    #[test]
    fn attest_rejects_empty_user() {
        let svc = service();
        let AttestResult::Error(e) = svc.attest("", AttestationMode::Attested) else {
            panic!("expected Error");
        };
        assert!(e.contains("requires a user"), "got: {e}");
    }

    #[test]
    fn attest_modes_differ() {
        let svc = service();
        let AttestResult::Ok(a) = svc.attest("alice", AttestationMode::Ephemeral) else {
            panic!("expected Ok");
        };
        let AttestResult::Ok(b) = svc.attest("alice", AttestationMode::Attested) else {
            panic!("expected Ok");
        };
        let a = Attestation::from_json(&String::from_utf8(a).unwrap()).unwrap();
        let b = Attestation::from_json(&String::from_utf8(b).unwrap()).unwrap();
        assert_ne!(a.mode, b.mode);
        assert_ne!(a.address, b.address, "ephemeral addresses rotate");
    }
}
