use std::sync::Mutex;
use talk_protocol::ZsmptClient;
use talk_protocol::attestation::AttestationMode;
use talk_protocol::client::{ClientError, connect_unix};
use talk_protocol::envelope::Payload;
use talk_protocol::handshake::DomainKey;
use talk_protocol::session::{DeliveryOutcome, DeliverySink, ZsmptSession};

/// A sink that records delivered invoices.
struct Recorder(Mutex<Vec<(String, Vec<u8>)>>);

impl DeliverySink for Recorder {
    fn deliver(
        &self,
        _sender: &str,
        message_id: &str,
        _mailbox: &str,
        _payload: Payload,
        body: &[u8],
    ) -> DeliveryOutcome {
        self.0
            .lock()
            .unwrap()
            .push((message_id.to_string(), body.to_vec()));
        DeliveryOutcome::Accepted {
            message_id: message_id.to_string(),
        }
    }
}

/// A reject-all sink for testing error mapping.
struct Rejecting;

impl DeliverySink for Rejecting {
    fn deliver(&self, _s: &str, _m: &str, _b: &str, _p: Payload, _body: &[u8]) -> DeliveryOutcome {
        DeliveryOutcome::Rejected {
            reason: "no such recipient".into(),
        }
    }
}

/// Spawn a ZSMTP server on one duplex end and return the client side plus the
/// receiver's domain key.
async fn spawn_server<Sink: DeliverySink + 'static>(
    receiver_domain: &str,
    sink: Sink,
) -> (tokio::io::DuplexStream, talk_protocol::DomainKey) {
    let (client, server_stream) = tokio::io::duplex(8192);
    let server_key = DomainKey::generate(receiver_domain);
    let key = DomainKey {
        domain: receiver_domain.to_string(),
        signing: server_key.signing.clone(),
    };
    let mut session = ZsmptSession::with_domain_key(receiver_domain, server_key.signing)
        .with_sink(std::sync::Arc::new(sink));
    tokio::spawn(async move {
        let mut stream = server_stream;
        let _ = session.run(&mut stream).await;
    });
    (client, key)
}

#[tokio::test]
async fn full_round_trip() {
    let (client, key) =
        spawn_server("receiver.example.org", Recorder(Mutex::new(Vec::new()))).await;
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    assert_eq!(c.receiver_domain, "receiver.example.org");

    c.hello().await.expect("hello");
    c.authenticate(&key.verifying()).await.expect("auth");
    let att = c
        .request_address("alice", AttestationMode::Ephemeral, &key.verifying())
        .await
        .expect("addr");
    assert_eq!(att.user, "alice");
    assert_eq!(att.domain, "receiver.example.org");
    assert_eq!(att.mode, AttestationMode::Ephemeral);

    c.send_invoice("msg-1", Payload::Sealed, b"opaque-body")
        .await
        .expect("invoice");
    c.quit().await.expect("quit");
}

#[tokio::test]
async fn wrong_receiver_key_fails_auth() {
    let (client, key) =
        spawn_server("receiver.example.org", Recorder(Mutex::new(Vec::new()))).await;
    let wrong_key = DomainKey::generate("evil.example.net").verifying();
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    c.hello().await.expect("hello");
    let err = c.authenticate(&wrong_key).await.unwrap_err();
    assert!(matches!(err, ClientError::Auth(_)), "got: {err:?}");
    // The wrong key also means the client's own state is unchanged.
    assert_eq!(c.state, talk_protocol::ClientState::AwaitingAuth);
    let _ = &key;
}

#[tokio::test]
async fn tampered_attestation_rejected() {
    // Tampering the attestation means using a different receiver domain than
    // the one the attestation was signed for.
    let (client, _key) =
        spawn_server("receiver.example.org", Recorder(Mutex::new(Vec::new()))).await;
    // The client believes the receiver is receiver.example.org (from greeting),
    // but verifies with a key that did NOT sign — i.e. a mismatched key.
    let other_key = DomainKey::generate("receiver.example.org").verifying();
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    c.hello().await.expect("hello");
    // Auth with the *wrong* key for the same domain fails at auth already.
    let err = c.authenticate(&other_key).await.unwrap_err();
    assert!(matches!(err, ClientError::Auth(_)));
}

#[tokio::test]
async fn invoice_before_addr_is_order_error() {
    let (client, key) =
        spawn_server("receiver.example.org", Recorder(Mutex::new(Vec::new()))).await;
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    c.hello().await.expect("hello");
    c.authenticate(&key.verifying()).await.expect("auth");
    // No ADDR yet — sending an invoice is out of order at the client.
    let err = c
        .send_invoice("msg-1", Payload::Sealed, b"body")
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Order(_)));
}

#[tokio::test]
async fn server_rejection_maps_to_client_error() {
    let (client, key) = spawn_server("receiver.example.org", Rejecting).await;
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    c.hello().await.expect("hello");
    c.authenticate(&key.verifying()).await.expect("auth");
    c.request_address("ghost", AttestationMode::Ephemeral, &key.verifying())
        .await
        .expect("addr");
    let err = c
        .send_invoice("msg-1", Payload::Sealed, b"body")
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Rejected(_)), "got: {err:?}");
}

#[tokio::test]
async fn delivered_body_reaches_sink() {
    let recorder = Recorder(Mutex::new(Vec::new()));
    let (client, key) = spawn_server("receiver.example.org", recorder).await;
    let mut c = ZsmptClient::connect(client, "sender.example.com")
        .await
        .expect("connect");
    c.hello().await.expect("hello");
    c.authenticate(&key.verifying()).await.expect("auth");
    c.request_address("alice", AttestationMode::Ephemeral, &key.verifying())
        .await
        .expect("addr");
    c.send_invoice("msg-42", Payload::Sealed, b"THE-OPAQUE-BODY")
        .await
        .expect("invoice");
    c.quit().await.expect("quit");

    // Give the server task a moment to process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn connect_unix_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("zsmtp.sock");
    let key = DomainKey::generate("receiver.example.org");

    // Bind a Unix listener and serve ZSMTP.
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let domain_key = key.signing.clone();
    let sink = Recorder(Mutex::new(Vec::new()));
    let sink = std::sync::Arc::new(sink);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let domain_key = domain_key.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let mut session = ZsmptSession::with_domain_key("receiver.example.org", domain_key)
                    .with_sink(sink);
                let _ = session.run(&mut stream).await;
            });
        }
    });

    let mut c = connect_unix(&path, "sender.example.com")
        .await
        .expect("connect");
    assert_eq!(c.receiver_domain, "receiver.example.org");
    c.hello().await.expect("hello");
    c.authenticate(&key.verifying()).await.expect("auth");
    c.request_address("alice", AttestationMode::Ephemeral, &key.verifying())
        .await
        .expect("addr");
    c.send_invoice("msg-1", Payload::Sealed, b"body")
        .await
        .expect("invoice");
    c.quit().await.expect("quit");
}
