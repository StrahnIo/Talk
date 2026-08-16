//! The secure_mailbox handler: what the local client can ask the daemon to do.

use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use talk_mailstore::{SqliteMailStore, hash_password};
use talk_protocol::attestation::{Attestation, AttestationMode, mint_pair};
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{AttestResult, RegisterResult, SecureMailboxHandler, SendResult};
use talk_protocol::{DohDomainKeyResolver, DomainKeyResolver, connect_tcp};

/// The registration attestation `R` content version tag.
const REGISTRATION_ATTR_V1: &str = "reg-v1";

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
    /// The mailbox store (users, keyring, inboxes).
    store: Arc<SqliteMailStore>,
}

impl SecureMailboxService {
    pub fn new(
        sender_domain: impl Into<String>,
        send_endpoint: impl Into<String>,
        domain_key: SigningKey,
        store: Arc<SqliteMailStore>,
    ) -> Self {
        Self {
            sender_domain: sender_domain.into(),
            send_endpoint: send_endpoint.into(),
            resolver: DohDomainKeyResolver::default(),
            domain_key,
            store,
        }
    }

    /// Build the registration attestation `R`: a domain-key-signed binding of
    /// `{domain, username, master_pubkey, [ivk_commitment]}`. This is the
    /// tamper-evident source of truth; live `ADDR` attestations anchor to it.
    fn build_registration_attestation(
        &self,
        username: &str,
        master_pubkey: &[u8],
        ivk_commitment: &Option<String>,
    ) -> String {
        // R is a self-describing signed structure (JSON for now). The
        // signature covers the canonical binding.
        let body = RegistrationAttestation {
            domain: self.sender_domain.clone(),
            username: username.to_string(),
            master_pubkey: hex::encode(master_pubkey),
            ivk_commitment: ivk_commitment.clone(),
            registered_at: unix_now(),
            signature: Vec::new(),
        };
        let digest = body.digest();
        let sig = self.domain_key.sign(&digest);
        RegistrationAttestation {
            signature: sig.to_bytes().to_vec(),
            ..body
        }
        .to_json()
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

    fn register(
        &self,
        username: &str,
        password: &str,
        pubkey_hex: &str,
        ivk_hex: Option<&str>,
    ) -> RegisterResult {
        // Validate the pubkey is hex of 32 bytes.
        let pubkey_bytes = match decode_hex_32(pubkey_hex) {
            Some(b) => b,
            None => return RegisterResult::Error("pubkey must be 32 bytes of hex".to_string()),
        };
        // Optional IVK commitment: hex of 32 bytes.
        let ivk = match ivk_hex {
            Some(hex) => match decode_hex_32(hex) {
                Some(_) => Some(hex.to_string()),
                None => return RegisterResult::Error("ivk must be 32 bytes of hex".to_string()),
            },
            None => None,
        };
        if username.is_empty() || password.is_empty() {
            return RegisterResult::Error("username and password are required".to_string());
        }

        // Hash the password (argon2) and build the registration attestation R.
        let hash = match hash_password(password) {
            Ok(h) => h,
            Err(e) => return RegisterResult::Error(format!("password hash failed: {e}")),
        };
        let registration_attestation =
            self.build_registration_attestation(username, &pubkey_bytes, &ivk);

        match self.store.create_user_full(
            username,
            &hash,
            &pubkey_bytes,
            ivk,
            Some(registration_attestation),
        ) {
            Ok(_) => RegisterResult::Ok,
            Err(e) => RegisterResult::Error(e.to_string()),
        }
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

/// The registration attestation `R` content.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RegistrationAttestation {
    domain: String,
    username: String,
    master_pubkey: String,
    ivk_commitment: Option<String>,
    registered_at: i64,
    signature: Vec<u8>,
}

impl RegistrationAttestation {
    fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(REGISTRATION_ATTR_V1);
        h.update(self.domain.as_bytes());
        h.update([0u8]);
        h.update(self.username.as_bytes());
        h.update([0u8]);
        h.update(self.master_pubkey.as_bytes());
        h.update([0u8]);
        h.update(self.ivk_commitment.as_deref().unwrap_or("").as_bytes());
        h.update([0u8]);
        h.update(self.registered_at.to_be_bytes());
        h.finalize().into()
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("registration attestation serializes")
    }
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use talk_protocol::attestation::Attestation;

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

    #[test]
    fn register_creates_user_with_attestation_and_argon2() {
        let (svc, store) = service_with_store();
        let pubkey = [7u8; 32];
        let pubkey_hex = hex::encode(pubkey);
        let r = svc.register("alice", "s3cret", &pubkey_hex, None);
        assert_eq!(r, RegisterResult::Ok);

        let user = store.get_user("alice").expect("get").expect("exists");
        assert_eq!(user.master_pubkey, pubkey);
        assert_eq!(user.ivk_commitment, None);
        // Password hash must not be the plaintext and must verify.
        assert_ne!(user.username, "s3cret");
        let stored_hash = store_password_hash(&store, "alice");
        assert!(talk_mailstore::verify_password("s3cret", &stored_hash).expect("verify"));
        // Registration attestation R is stored and non-empty.
        let r_att = user.registration_attestation.expect("R stored");
        let parsed: RegistrationAttestation = serde_json::from_str(&r_att).expect("R parses");
        assert_eq!(parsed.domain, "example.org");
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.master_pubkey, pubkey_hex);
        assert!(!parsed.signature.is_empty());
    }

    #[test]
    fn register_rejects_bad_pubkey() {
        let (svc, _store) = service_with_store();
        let r = svc.register("bob", "pw", "nothex", None);
        let RegisterResult::Error(e) = r else {
            panic!("expected error");
        };
        assert!(e.contains("32 bytes"), "got: {e}");
    }

    #[test]
    fn register_rejects_empty_username() {
        let (svc, _store) = service_with_store();
        let pubkey = hex::encode([0u8; 32]);
        let r = svc.register("", "pw", &pubkey, None);
        let RegisterResult::Error(e) = r else {
            panic!("expected error");
        };
        assert!(e.contains("username"), "got: {e}");
    }

    #[test]
    fn register_rejects_bad_ivk() {
        let (svc, _store) = service_with_store();
        let pubkey = hex::encode([0u8; 32]);
        let r = svc.register("carol", "pw", &pubkey, Some("nope"));
        let RegisterResult::Error(e) = r else {
            panic!("expected error");
        };
        assert!(e.contains("ivk"), "got: {e}");
    }

    #[test]
    fn register_duplicate_username_fails() {
        let (svc, _store) = service_with_store();
        let pubkey = hex::encode([1u8; 32]);
        assert_eq!(
            svc.register("dave", "pw", &pubkey, None),
            RegisterResult::Ok
        );
        let r = svc.register("dave", "pw2", &pubkey, None);
        let RegisterResult::Error(e) = r else {
            panic!("expected error");
        };
        assert!(e.contains("UNIQUE"), "got: {e}");
    }

    fn service() -> SecureMailboxService {
        service_with_store().0
    }

    fn service_with_store() -> (SecureMailboxService, Arc<SqliteMailStore>) {
        use std::sync::Arc;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            Arc::new(SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open store"));
        (
            SecureMailboxService::new(
                "example.org",
                "receiver.example.org:2525",
                key,
                store.clone(),
            ),
            store,
        )
    }

    /// Read the stored argon2 hash for a user.
    fn store_password_hash(store: &SqliteMailStore, username: &str) -> String {
        store.password_hash(username).expect("get").expect("exists")
    }
}
