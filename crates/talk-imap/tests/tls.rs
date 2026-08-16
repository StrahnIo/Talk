//! TLS (IMAPS) integration test: a rustls client connects to the TLS-wrapped
//! IMAP server and completes a session.

use rcgen::{CertificateParams, KeyPair};
use std::sync::Arc;
use talk_imap::server::ImapServer;
use talk_imap::tls::load_server_config;
use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore};
use tokio::net::TcpListener;

/// Generate a self-signed cert/key pair as PEM bytes.
fn make_cert() -> Result<(Vec<u8>, Vec<u8>), rcgen::Error> {
    let key_pair = KeyPair::generate()?;
    let params = CertificateParams::new(vec!["talk.test".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

/// Boot a TLS-wrapped IMAP server on an ephemeral port.
async fn boot_tls_server() -> (u16, Arc<SqliteMailStore>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open"));
    let user_id = store
        .create_user(
            "alice",
            &talk_mailstore::hash_password("secret").expect("hash"),
            &[0u8; 32],
        )
        .expect("create user")
        .id;
    store
        .append_message(
            user_id,
            NewMessage {
                message_id: "msg-1".to_string(),
                subject: "Hello".to_string(),
                body: b"body".to_vec(),
                flags: MessageFlags::default(),
            },
        )
        .expect("append");

    let (cert_pem, key_pem) = make_cert().expect("cert");
    let dir2 = tempfile::tempdir().expect("tempdir");
    let cert_path = dir2.path().join("cert.pem");
    let key_path = dir2.path().join("key.pem");
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");

    let config = load_server_config(&cert_path, &key_path).expect("tls config");

    // Find a free port, then let the server bind it (with TLS wrapping).
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);

    let server = ImapServer::new(store.clone(), "talk.test").with_tls(config);
    let addr = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = server.listen(&addr).await;
    });
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (port, store)
}

#[tokio::test]
async fn tls_client_completes_session() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (port, _store) = boot_tls_server().await;

    // A rustls client with a dangerous verifier (self-signed cert).
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("talk.test").expect("name");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    // Drive the session with async-imap over the TLS stream.
    let compat = tokio_util::compat::TokioAsyncReadCompatExt::compat(tls);
    let client = async_imap::Client::new(compat);
    let mut session = client.login("alice", "secret").await.expect("login");
    let mailbox = session.select("INBOX").await.expect("select");
    assert_eq!(mailbox.exists, 1);
    session.logout().await.expect("logout");
}

/// Accept any certificate (test-only; self-signed cert).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}
