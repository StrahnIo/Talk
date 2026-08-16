//! The secure_mailbox handler: what the local client can ask the daemon to do.

use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use talk_mailstore::{SqliteMailStore, hash_password};
use talk_protocol::attestation::{Attestation, AttestationMode, mint_pair};
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{AsyncSecureMailboxHandler, AttestResult, RegisterResult, SendResult};
use talk_protocol::{
    DohDomainKeyResolver, DohEndpointResolver, DomainKeyResolver, EndpointResolver, connect_tcp_tls,
};
use tracing::warn;

/// The registration attestation `R` content version tag.
const REGISTRATION_ATTR_V1: &str = "reg-v1";

/// Handles secure_mailbox commands, driving `ZsmptClient` to send invoices to
/// other daemons, and issuing signed address attestations with the daemon's
/// persisted domain key.
///
/// The recipient daemon's endpoint is discovered via DNS SRV
/// (`_zpayments._tcp.<domain>`); `send_endpoint` is a dev override used only
/// when SRV finds nothing. Sends use implicit TLS (accept-any-cert; server
/// identity comes from the domain-key handshake).
pub struct SecureMailboxService {
    /// Our domain (the sender).
    pub sender_domain: String,
    /// Optional dev override for the recipient daemon's TCP endpoint
    /// (`host:port`). `None` = always use SRV discovery.
    pub send_endpoint: Option<String>,
    /// Resolves the receiver's public domain key for verification.
    resolver: Arc<dyn DomainKeyResolver>,
    /// Resolves the receiver's ZSMTP TCP endpoint via DNS SRV.
    endpoint_resolver: Arc<dyn EndpointResolver>,
    /// Our domain signing key (persisted; the public half is published in DNS).
    domain_key: SigningKey,
    /// The mailbox store (users, keyring, inboxes).
    store: Arc<SqliteMailStore>,
}

impl SecureMailboxService {
    pub fn new(
        sender_domain: impl Into<String>,
        send_endpoint: Option<String>,
        domain_key: SigningKey,
        store: Arc<SqliteMailStore>,
    ) -> Self {
        Self {
            sender_domain: sender_domain.into(),
            send_endpoint,
            resolver: Arc::new(DohDomainKeyResolver::default()),
            endpoint_resolver: Arc::new(DohEndpointResolver::default()),
            domain_key,
            store,
        }
    }

    /// Override the domain-key resolver (tests / dev).
    #[allow(dead_code)]
    pub fn with_key_resolver(mut self, resolver: Arc<dyn DomainKeyResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Override the endpoint resolver (tests / dev).
    #[allow(dead_code)]
    pub fn with_endpoint_resolver(mut self, resolver: Arc<dyn EndpointResolver>) -> Self {
        self.endpoint_resolver = resolver;
        self
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

#[async_trait::async_trait]
impl AsyncSecureMailboxHandler for SecureMailboxService {
    async fn send(
        &self,
        sender_username: &str,
        recipient_mailbox: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> SendResult {
        if sender_username.is_empty() {
            return SendResult::Error("sender username is required".to_string());
        }
        // The receiver's domain is the part after '@' in the mailbox.
        let Some(receiver_domain) = recipient_mailbox.split('@').nth(1) else {
            return SendResult::Error("malformed recipient mailbox".to_string());
        };
        // Resolve the receiver's public key.
        let receiver_pub = match self.resolver.resolving_key(receiver_domain) {
            Ok(k) => k,
            Err(e) => return SendResult::Error(format!("cannot resolve domain key: {e}")),
        };
        // Resolve the receiver's ZSMTP endpoint: SRV discovery, with the
        // config `send_endpoint` as a dev override when SRV finds nothing.
        let endpoint = match self.endpoint_resolver.resolve_endpoint(receiver_domain) {
            Ok(ep) => ep,
            Err(e) => match &self.send_endpoint {
                Some(override_ep) => {
                    warn!(error = %e, override = %override_ep, "SRV lookup failed; using send_endpoint override");
                    override_ep.clone()
                }
                None => return SendResult::Error(format!("cannot resolve endpoint: {e}")),
            },
        };
        // Connect over implicit TLS (accept-any-cert; server identity is
        // the domain-key handshake).
        let mut client = match connect_tcp_tls(
            &endpoint,
            receiver_domain,
            talk_protocol::accept_any_cert_client_config(),
            &self.sender_domain,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => return SendResult::Error(format!("connect: {e}")),
        };
        if let Err(e) = client.hello().await {
            return SendResult::Error(format!("hello: {e}"));
        }
        if let Err(e) = client.authenticate(&receiver_pub).await {
            return SendResult::Error(format!("auth: {e}"));
        }
        // Request an ephemeral address for the recipient user.
        let user = recipient_mailbox.split('@').next().unwrap_or("");
        if let Err(e) = client
            .request_address(user, AttestationMode::Ephemeral, &receiver_pub)
            .await
        {
            return SendResult::Error(format!("addr: {e}"));
        }
        if let Err(e) = client
            .send_invoice(sender_username, message_id, payload, body)
            .await
        {
            return SendResult::Error(format!("invoice: {e}"));
        }
        let _ = client.quit().await;
        SendResult::Ok(format!("delivered {message_id} to {recipient_mailbox}"))
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
        let endpoint = self.send_endpoint.as_deref().unwrap_or("srv");
        format!(
            "talkd {} sender={} endpoint={}",
            env!("CARGO_PKG_VERSION"),
            self.sender_domain,
            endpoint
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
                Some("receiver.example.org:2525".to_string()),
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

    #[tokio::test]
    async fn send_resolves_endpoint_via_srv_and_delivers_over_tls() {
        use crate::sink::StoreUserDirectory;
        use rcgen::{CertificateParams, KeyPair};
        use talk_mailstore::NewMessage;
        use talk_protocol::handshake::DomainKey;
        use talk_protocol::session::{DeliveryOutcome, DeliverySink};
        use talk_protocol::{StaticDomainKeyResolver, StaticEndpointResolver};
        use tokio::net::TcpListener;

        // Self-signed TLS server config.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let kp = KeyPair::generate().expect("kp");
        let params = CertificateParams::new(vec!["receiver.example.org".to_string()]).expect("p");
        let cert = params.self_signed(&kp).expect("cert");
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(kp.serialize_der()),
        );
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .expect("server config");

        // A store-backed sink for the receiving side.
        struct Sink(Arc<SqliteMailStore>);
        impl DeliverySink for Sink {
            fn deliver(
                &self,
                _s: &str,
                message_id: &str,
                recipient: &str,
                _p: Payload,
                _b: &[u8],
            ) -> DeliveryOutcome {
                let user = recipient.split('@').next().unwrap_or("");
                let u = self.0.get_user(user).expect("get").expect("exists");
                self.0
                    .append_message(u.id, NewMessage::invoice(message_id, "s", b"body".to_vec()))
                    .expect("append");
                DeliveryOutcome::Accepted {
                    message_id: message_id.to_string(),
                }
            }
        }

        // Fresh stores for sender and receiver sides.
        let dir = tempfile::tempdir().expect("tempdir");
        let sender_store =
            Arc::new(SqliteMailStore::open(dir.path().join("sender.db")).expect("open"));
        let hash = talk_mailstore::hash_password("pw").expect("hash");
        sender_store
            .create_user("alice", &hash, &[0u8; 32])
            .expect("sender user");
        let recv_store = Arc::new(SqliteMailStore::open(dir.path().join("recv.db")).expect("open"));
        recv_store
            .create_user("bob", &hash, &[0u8; 32])
            .expect("recipient user");

        // Boot a TLS ZSMTP server on an ephemeral port, in its own thread/runtime.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let receiver_key = Arc::new(DomainKey::generate("receiver.example.org"));
        let sink = Arc::new(Sink(recv_store.clone()));
        let directory = Arc::new(StoreUserDirectory::new(recv_store.clone()));
        let server_key = receiver_key.signing.clone();
        let server_config = Arc::new(server_config);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            rt.block_on(async move {
                let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
                talk_protocol::server::serve_tcp(
                    "receiver.example.org".to_string(),
                    server_key,
                    sink,
                    directory,
                    Some(server_config),
                    listener,
                )
                .await;
            });
        });

        // Static resolvers so no real DNS is needed.
        let mut key_resolver = StaticDomainKeyResolver::new();
        key_resolver.insert("receiver.example.org", receiver_key.verifying());
        let mut ep_resolver = StaticEndpointResolver::new();
        ep_resolver.insert("receiver.example.org", format!("127.0.0.1:{port}"));

        let domain_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let svc =
            SecureMailboxService::new("sender.example.org", None, domain_key, sender_store.clone())
                .with_key_resolver(Arc::new(key_resolver))
                .with_endpoint_resolver(Arc::new(ep_resolver));

        // Give the server thread a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let result = svc
            .send(
                "alice",
                "bob@receiver.example.org",
                "msg-srv-1",
                Payload::Sealed,
                b"opaque",
            )
            .await;
        assert!(
            matches!(result, SendResult::Ok(_)),
            "send should succeed via SRV+TLS: {result:?}"
        );
        // The receiving store must have the delivered message.
        let bob = recv_store.get_user("bob").expect("get").expect("exists");
        let msgs = recv_store.list_messages(bob.id).expect("list");
        assert_eq!(msgs.len(), 1, "delivered message present");
    }
}
