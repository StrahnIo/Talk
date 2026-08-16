//! The secure_mailbox handler: what the local client can ask the daemon to do.

use talk_protocol::attestation::AttestationMode;
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{AttestResult, SecureMailboxHandler, SendResult};
use talk_protocol::{DohDomainKeyResolver, DomainKeyResolver, connect_tcp};

/// Handles secure_mailbox commands, driving `ZsmptClient` to send invoices to
/// other daemons.
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
}

impl SecureMailboxService {
    pub fn new(sender_domain: impl Into<String>, send_endpoint: impl Into<String>) -> Self {
        Self {
            sender_domain: sender_domain.into(),
            send_endpoint: send_endpoint.into(),
            resolver: DohDomainKeyResolver::default(),
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
        // v1: attestations are produced by the ZSMTP server's own domain key.
        // The local interface delegates to the stored domain key. For now, we
        // return an error unless wired (the server session handles ADDR).
        let _ = (user, mode);
        AttestResult::Error("local attestation not wired yet".to_string())
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
