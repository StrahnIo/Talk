//! ZSMTP over TCP: implicit-TLS (SMTPS-style) and plaintext round-trips.

use rcgen::{CertificateParams, KeyPair};
use std::sync::{Arc, Mutex};
use talk_protocol::attestation::AttestationMode;
use talk_protocol::envelope::Payload;
use talk_protocol::handshake::DomainKey;
use talk_protocol::session::{DeliveryOutcome, DeliverySink};
use talk_protocol::{ZsmptClient, connect_tcp, connect_tcp_tls};

struct Sink(Mutex<Vec<String>>);

impl DeliverySink for Sink {
    fn deliver(
        &self,
        _sender: &str,
        message_id: &str,
        _recipient: &str,
        _payload: Payload,
        _body: &[u8],
    ) -> DeliveryOutcome {
        self.0.lock().unwrap().push(message_id.to_string());
        DeliveryOutcome::Accepted {
            message_id: message_id.to_string(),
        }
    }
}

struct Dir;

impl talk_protocol::UserDirectory for Dir {
    fn user_exists(&self, username: &str) -> bool {
        username == "alice"
    }
}

/// Generate a self-signed cert/key pair, return rustls server + client configs.
fn make_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let key_pair = KeyPair::generate().expect("key");
    let params = CertificateParams::new(vec!["talk.test".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("cert");
    let cert_der = cert.der().clone();
    let key_der = key_pair.serialize_der();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
    );

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

async fn boot_tcp_server(tls: Option<Arc<rustls::ServerConfig>>) -> (u16, Arc<DomainKey>) {
    let key = Arc::new(DomainKey::generate("receiver.example.org"));
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind");
    let sink = Arc::new(Sink(Mutex::new(Vec::new())));
    let directory = Arc::new(Dir);
    let domain_key = key.signing.clone();
    tokio::spawn(talk_protocol::server::serve_tcp(
        "receiver.example.org".to_string(),
        domain_key,
        sink,
        directory,
        tls,
        listener,
    ));
    (port, key)
}

async fn full_flow(
    client: &mut ZsmptClient<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    key: &DomainKey,
) {
    client.hello().await.expect("hello");
    client.authenticate(&key.verifying()).await.expect("auth");
    let att = client
        .request_address("alice", AttestationMode::Ephemeral, &key.verifying())
        .await
        .expect("addr");
    assert_eq!(att.user, "alice");
    client
        .send_invoice("bob", "msg-1", Payload::Sealed, b"body")
        .await
        .expect("invoice");
    client.quit().await.expect("quit");
}

#[tokio::test]
async fn plaintext_tcp_round_trip() {
    let (port, key) = boot_tcp_server(None).await;
    let mut client = connect_tcp(("127.0.0.1", port), "sender.example.com")
        .await
        .expect("connect");
    assert_eq!(client.receiver_domain, "receiver.example.org");
    full_flow(&mut client, &key).await;
}

#[tokio::test]
async fn tls_tcp_round_trip() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (server_tls, client_tls) = make_tls_configs();
    let (port, key) = boot_tcp_server(Some(server_tls)).await;
    let mut client = connect_tcp_tls(
        ("127.0.0.1", port),
        "talk.test",
        client_tls,
        "sender.example.com",
    )
    .await
    .expect("connect over TLS");
    assert_eq!(client.receiver_domain, "receiver.example.org");
    full_flow(&mut client, &key).await;
}
