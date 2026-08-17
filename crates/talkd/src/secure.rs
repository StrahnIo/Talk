//! The secure_mailbox handler: what the local client can ask the daemon to do.

use crate::sink::StoreDeliverySink;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::Arc;
use talk_core::template::{TeraEngine, TemplateEngine, TemplateSpec};
use talk_mailstore::{MessageFlags, NewMessage, NewTransaction, SqliteMailStore, TxDirection, TxState, hash_password};
use talk_protocol::attestation::{
    Attestation, AttestationMode, RegistrationAttestation, mint_pair,
};
use talk_protocol::emulate::EmulatePayload;
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{
    AsyncSecureMailboxHandler, AttestResult, EmulateResult, RegisterResult, SendResult,
};
use talk_protocol::{
    DohDomainKeyResolver, DohEndpointResolver, DomainKeyResolver, EndpointResolver, connect_tcp_tls,
};
use tracing::warn;

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
    /// Delivery sink used by local payment emulation.
    sink: Arc<StoreDeliverySink>,
    /// Explicit `[mailbox] template_path` override, if configured.
    template_path: Option<PathBuf>,
    /// The daemon data dir, where `<data_dir>/template.toml` may live.
    data_dir: PathBuf,
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
            store: store.clone(),
            sink: Arc::new(StoreDeliverySink::new(store)),
            template_path: None,
            data_dir: PathBuf::new(),
        }
    }

    /// Override the delivery sink (the daemon wires the IMAP event broadcaster).
    pub fn with_sink(mut self, sink: Arc<StoreDeliverySink>) -> Self {
        self.sink = sink;
        self
    }

    /// Configure template resolution: an explicit `template_path` (if any) and
    /// the data dir where `<data_dir>/template.toml` is discovered.
    pub fn with_template(mut self, template_path: Option<PathBuf>, data_dir: PathBuf) -> Self {
        self.template_path = template_path;
        self.data_dir = data_dir;
        self
    }

    /// Resolve the template spec: explicit `template_path` if set (must
    /// exist), else `<data_dir>/template.toml` if present, else the built-in
    /// default.
    fn resolve_template(&self) -> Result<TemplateSpec, talk_core::TemplateError> {
        if let Some(path) = &self.template_path {
            return TemplateSpec::load(path, "invoice")?.ok_or_else(|| {
                talk_core::TemplateError::Render(format!(
                    "configured template file {} not found",
                    path.display()
                ))
            });
        }
        match TemplateSpec::load(&self.data_dir.join("template.toml"), "invoice")? {
            Some(spec) => Ok(spec),
            None => Ok(TemplateSpec::default_invoice()),
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
        RegistrationAttestation::sign(
            &self.sender_domain,
            username,
            master_pubkey,
            ivk_commitment.as_deref(),
            unix_now(),
            &self.domain_key,
        )
        .to_json()
    }
}

impl SecureMailboxService {
    /// Record an outbound ledger transaction (and a Sent-mailbox copy).
    ///
    /// Idempotent per (direction, message_id): a retry transitions the
    /// existing row instead of duplicating it.
    fn record_outbound_tx(
        &self,
        sender_username: &str,
        recipient_mailbox: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
        state: TxState,
    ) {
        let payload_str = match payload {
            Payload::Sealed => "sealed",
            Payload::Plaintext => "plaintext",
        };
        let sender_mailbox = format!("{sender_username}@{}", self.sender_domain);
        let tx = match self
            .store
            .tx_by_message_id(TxDirection::Out, message_id)
            .ok()
            .flatten()
        {
            Some(existing) => {
                let _ = self.store.tx_transition(existing.id, state);
                existing
            }
            None => match self.store.tx_create(NewTransaction {
                direction: TxDirection::Out,
                state,
                sender_mailbox,
                recipient_mailbox: recipient_mailbox.to_string(),
                amount: String::new(),
                binding: None,
                message_id: message_id.to_string(),
                outbound_body: Some(body.to_vec()),
                payload: payload_str.to_string(),
            }) {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "outbound ledger record failed");
                    return;
                }
            },
        };
        // A copy in the sender's Sent mailbox (best-effort; dedup on message_id).
        let Some(user) = self.store.get_user(sender_username).ok().flatten() else {
            return;
        };
        let msg = NewMessage {
            message_id: message_id.to_string(),
            subject: "Sent invoice".to_string(),
            body: body.to_vec(),
            flags: MessageFlags::default(),
            sender: recipient_mailbox.to_string(),
            trust_state: "unverified".to_string(),
        };
        if let Ok(meta) = self.store.append_message_to(user.id, talk_mailstore::SENT, msg) {
            let _ = self.store.tx_link_message(tx.id, meta.id);
        }
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
            Err(e) => {
                self.record_outbound_tx(sender_username, recipient_mailbox, message_id, payload, body, TxState::Failed);
                return SendResult::Error(format!("cannot resolve domain key: {e}"));
            }
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
                None => {
                    self.record_outbound_tx(sender_username, recipient_mailbox, message_id, payload, body, TxState::Failed);
                    return SendResult::Error(format!("cannot resolve endpoint: {e}"));
                }
            },
        };
        // Connect over implicit TLS (accept-any-cert; server identity is
        // the domain-key handshake).
        let client = match connect_tcp_tls(
            &endpoint,
            receiver_domain,
            talk_protocol::accept_any_cert_client_config(),
            &self.sender_domain,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                self.record_outbound_tx(sender_username, recipient_mailbox, message_id, payload, body, TxState::Retrying);
                return SendResult::Error(format!("connect: {e}"));
            }
        };
        let user = recipient_mailbox.split('@').next().unwrap_or("");
        if let Err(e) = talk_protocol::send_invoice_over(
            client,
            sender_username,
            user,
            &receiver_pub,
            message_id,
            payload,
            body,
        )
        .await
        {
            let state = if matches!(e, talk_protocol::ClientError::RetryLater(_)) {
                TxState::Retrying
            } else {
                TxState::Failed
            };
            self.record_outbound_tx(sender_username, recipient_mailbox, message_id, payload, body, state);
            return SendResult::Error(format!("deliver: {e}"));
        }
        self.record_outbound_tx(sender_username, recipient_mailbox, message_id, payload, body, TxState::Sent);
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

    fn emulate(&self, recipient_user: &str, payload: &EmulatePayload) -> EmulateResult {
        if recipient_user.is_empty() {
            return EmulateResult::Error("recipient user is required".to_string());
        }
        let spec = match self.resolve_template() {
            Ok(s) => s,
            Err(e) => return EmulateResult::Error(format!("template: {e}")),
        };
        let data = serde_json::json!({
            "sender_name": payload.sender_name,
            "sender_address": payload.sender_address,
            "amount": payload.amount,
            "invoice": String::from_utf8_lossy(&payload.invoice),
            "received_at": received_at(),
        });
        let engine = TeraEngine;
        let subject = match engine.render(&spec.subject, &data) {
            Ok(s) => s,
            Err(e) => return EmulateResult::Error(format!("template subject: {e}")),
        };
        let body = match engine.render(&spec.body, &data) {
            Ok(s) => s,
            Err(e) => return EmulateResult::Error(format!("template body: {e}")),
        };
        let message_id = format!("emul-{}", random_hex(8));
        match self.sink.deliver_emulated(
            recipient_user,
            &payload.sender_name,
            &payload.amount,
            &message_id,
            &subject,
            body.as_bytes(),
        ) {
            talk_protocol::session::DeliveryOutcome::Accepted { .. } => {
                EmulateResult::Ok(format!("delivered {message_id} to {recipient_user}"))
            }
            talk_protocol::session::DeliveryOutcome::Rejected { reason } => {
                EmulateResult::Error(reason)
            }
            talk_protocol::session::DeliveryOutcome::RetryLater { reason } => {
                EmulateResult::Error(format!("retry later: {reason}"))
            }
        }
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

/// A human-readable UTC timestamp for the template context.
fn received_at() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// `n` random bytes as hex (message ids etc.).
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
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

    fn payload() -> EmulatePayload {
        EmulatePayload {
            sender_name: "Alice Smith".to_string(),
            sender_address: "t1abc123".to_string(),
            amount: "1.5".to_string(),
            invoice: b"line one\nline two".to_vec(),
        }
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

        // The sender's store records an outbound transaction + a Sent copy.
        let out = sender_store.tx_list(Some(TxDirection::Out), None).expect("out list");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, TxState::Sent);
        assert_eq!(out[0].recipient_mailbox, "bob@receiver.example.org");
        assert_eq!(out[0].outbound_body.as_deref(), Some(&b"opaque"[..]));
        let alice = sender_store.get_user("alice").expect("get").expect("exists");
        let sent = sender_store
            .list_messages_in(alice.id, talk_mailstore::SENT)
            .expect("sent list");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].sender, "bob@receiver.example.org");
    }

    #[test]
    fn emulate_delivers_rendered_message() {
        let (svc, store) = service_with_store();
        let pubkey = hex::encode([3u8; 32]);
        assert_eq!(svc.register("bob", "pw", &pubkey, None), RegisterResult::Ok);

        let result = svc.emulate("bob", &payload());
        let EmulateResult::Ok(text) = result else {
            panic!("expected Ok, got {result:?}");
        };
        assert!(text.contains("emul-"), "message id format: {text}");

        let bob = store.get_user("bob").expect("get").expect("exists");
        let msgs = store.list_messages(bob.id).expect("list");
        assert_eq!(msgs.len(), 1);
        let msg = store.fetch_message(bob.id, msgs[0].id).expect("fetch");
        assert_eq!(msg.meta.subject, "Invoice from Alice Smith");
        assert_eq!(msg.meta.trust_state, "unverified");
        let body = String::from_utf8(msg.body).expect("utf8");
        assert!(body.contains("Alice Smith"), "{body}");
        assert!(body.contains("t1abc123"), "{body}");
        assert!(body.contains("1.5 ZEC"), "{body}");
        assert!(body.contains("line one\nline two"), "{body}");
    }

    #[test]
    fn emulate_broadcasts_idle_event() {
        use talk_imap::server::MailboxEvent;
        let (svc, store) = service_with_store();
        let pubkey = hex::encode([3u8; 32]);
        assert_eq!(svc.register("bob", "pw", &pubkey, None), RegisterResult::Ok);

        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let sink = Arc::new(crate::sink::StoreDeliverySink::new(store).with_events(tx));
        let svc = svc.with_sink(sink);

        let EmulateResult::Ok(_) = svc.emulate("bob", &payload()) else {
            panic!("expected Ok");
        };
        let event = rx.try_recv().expect("broadcast");
        assert!(matches!(event, MailboxEvent::MessageAppended { .. }));
    }

    #[test]
    fn emulate_unknown_user_errors() {
        let (svc, _store) = service_with_store();
        let EmulateResult::Error(e) = svc.emulate("ghost", &payload()) else {
            panic!("expected Error");
        };
        assert!(e.contains("no such recipient"), "got: {e}");
    }

    #[test]
    fn emulate_rejects_empty_recipient() {
        let (svc, _store) = service_with_store();
        let EmulateResult::Error(e) = svc.emulate("", &payload()) else {
            panic!("expected Error");
        };
        assert!(e.contains("recipient"), "got: {e}");
    }

    #[test]
    fn emulate_creates_inbound_transaction_with_amount() {
        let (svc, store) = service_with_store();
        let pubkey = hex::encode([3u8; 32]);
        assert_eq!(svc.register("bob", "pw", &pubkey, None), RegisterResult::Ok);

        let EmulateResult::Ok(_) = svc.emulate("bob", &payload()) else {
            panic!("expected Ok");
        };
        let txs = store.tx_list(Some(TxDirection::In), None).expect("list");
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].state, TxState::Opaque);
        assert_eq!(txs[0].amount, "1.5");
        assert_eq!(txs[0].recipient_mailbox, "bob");
    }

    #[test]
    fn emulate_uses_template_toml_override() {
        let (svc, store) = service_with_store();
        let pubkey = hex::encode([3u8; 32]);
        assert_eq!(svc.register("bob", "pw", &pubkey, None), RegisterResult::Ok);

        let dir = tempfile::tempdir().expect("tempdir");
        let template = dir.path().join("template.toml");
        std::fs::write(
            &template,
            "[invoice]\nsubject = \"Money from {{ sender_name }}\"\nbody = \"AMOUNT: {{ amount }} ZEC\"\n",
        )
        .expect("write template");
        let svc = svc.with_template(None, dir.path().to_path_buf());

        let EmulateResult::Ok(_) = svc.emulate("bob", &payload()) else {
            panic!("expected Ok");
        };
        let bob = store.get_user("bob").expect("get").expect("exists");
        let msgs = store.list_messages(bob.id).expect("list");
        let msg = store.fetch_message(bob.id, msgs[0].id).expect("fetch");
        assert_eq!(msg.meta.subject, "Money from Alice Smith");
        assert_eq!(
            String::from_utf8(msg.body).expect("utf8"),
            "AMOUNT: 1.5 ZEC"
        );
    }

    #[test]
    fn emulate_explicit_template_path_missing_errors() {
        let (svc, _store) = service_with_store();
        let svc = svc.with_template(
            Some(PathBuf::from("/nonexistent/template.toml")),
            PathBuf::new(),
        );
        let EmulateResult::Error(e) = svc.emulate("bob", &payload()) else {
            panic!("expected Error");
        };
        assert!(e.contains("template"), "got: {e}");
    }
}
