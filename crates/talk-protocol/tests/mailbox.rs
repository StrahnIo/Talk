use std::sync::{Arc, Mutex};
use talk_protocol::attestation::AttestationMode;
use talk_protocol::emulate::EmulatePayload;
use talk_protocol::envelope::Payload;
use talk_protocol::mailbox::{
    AsyncSecureMailboxHandler, AttestResult, EmulateResult, RegisterResult, SecureMailboxClient,
    SendResult, serve,
};

struct MockHandler {
    sent: Mutex<Vec<(String, String, Vec<u8>)>>,
    emulated: Mutex<Vec<(String, EmulatePayload)>>,
}

impl MockHandler {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            emulated: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl AsyncSecureMailboxHandler for MockHandler {
    async fn send(
        &self,
        _sender: &str,
        recipient: &str,
        message_id: &str,
        _payload: Payload,
        body: &[u8],
    ) -> SendResult {
        self.sent.lock().unwrap().push((
            recipient.to_string(),
            message_id.to_string(),
            body.to_vec(),
        ));
        SendResult::Ok(format!("delivered {message_id}"))
    }

    fn attest(&self, user: &str, _mode: AttestationMode) -> AttestResult {
        AttestResult::Ok(format!("attestation-for-{user}").into_bytes())
    }

    fn register(
        &self,
        _username: &str,
        _password: &str,
        _pubkey_hex: &str,
        _ivk_hex: Option<&str>,
    ) -> RegisterResult {
        RegisterResult::Ok
    }

    fn status(&self) -> String {
        "mock-ok".to_string()
    }

    fn emulate(&self, recipient_user: &str, payload: &EmulatePayload) -> EmulateResult {
        self.emulated
            .lock()
            .unwrap()
            .push((recipient_user.to_string(), payload.clone()));
        EmulateResult::Ok(format!("delivered to {recipient_user}"))
    }
}

#[tokio::test]
async fn send_command_reaches_handler() {
    let (client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    let handler2 = handler.clone();
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler2.as_ref()).await;
    });

    let mut c = SecureMailboxClient::new(client);
    let reply = c
        .send(
            "alice",
            "bob@example.org",
            "msg-1",
            Payload::Sealed,
            b"opaque",
        )
        .await
        .expect("send");
    assert!(reply.starts_with("OK delivered msg-1"), "got: {reply}");

    let sent = handler.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "bob@example.org");
    assert_eq!(sent[0].1, "msg-1");
    assert_eq!(sent[0].2, b"opaque");
}

#[tokio::test]
async fn status_and_quit() {
    let (client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    let handler2 = handler.clone();
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler2.as_ref()).await;
    });

    let mut c = SecureMailboxClient::new(client);
    let status = c.status().await.expect("status");
    assert!(status.starts_with("OK mock-ok"), "got: {status}");
    let quit = c.quit().await.expect("quit");
    assert!(quit.starts_with("OK bye"), "got: {quit}");
}

#[tokio::test]
async fn unknown_command_errors() {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let (mut client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler.as_ref()).await;
    });

    client.write_all(b"FROBNICATE\r\n").await.unwrap();
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(reply.contains("ERR unknown command"), "got: {reply}");
}

#[tokio::test]
async fn malformed_send_errors() {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let (mut client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler.as_ref()).await;
    });

    // SEND with a bad payload type.
    client
        .write_all(b"SEND alice@example.org msg-1 bogus\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(reply.contains("ERR malformed SEND"), "got: {reply}");
}

#[tokio::test]
async fn register_command_reaches_handler() {
    let (client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    let handler2 = handler.clone();
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler2.as_ref()).await;
    });

    let mut c = SecureMailboxClient::new(client);
    let reply = c
        .register("alice", "s3cret", "abcd1234", None)
        .await
        .expect("register");
    assert!(reply.starts_with("OK registered"), "got: {reply}");
}

#[tokio::test]
async fn register_with_ivk() {
    let (client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    let handler2 = handler.clone();
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler2.as_ref()).await;
    });

    let mut c = SecureMailboxClient::new(client);
    let reply = c
        .register("bob", "pw", "beef", Some("cafe"))
        .await
        .expect("register");
    assert!(reply.starts_with("OK registered"), "got: {reply}");
}

#[tokio::test]
async fn emulate_command_reaches_handler() {
    let (client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    let handler2 = handler.clone();
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler2.as_ref()).await;
    });

    let mut c = SecureMailboxClient::new(client);
    let reply = c
        .emulate(
            "bob",
            "Alice Smith",
            "t1abc123",
            "1.5",
            b"line one\nline two",
        )
        .await
        .expect("emulate");
    assert!(reply.starts_with("OK delivered to bob"), "got: {reply}");

    let emulated = handler.emulated.lock().unwrap().clone();
    assert_eq!(emulated.len(), 1);
    assert_eq!(emulated[0].0, "bob");
    assert_eq!(emulated[0].1.sender_name, "Alice Smith");
    assert_eq!(emulated[0].1.sender_address, "t1abc123");
    assert_eq!(emulated[0].1.amount, "1.5");
    assert_eq!(emulated[0].1.invoice, b"line one\nline two");
}

#[tokio::test]
async fn emulate_missing_recipient_errors() {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let (mut client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler.as_ref()).await;
    });

    client.write_all(b"EMULATE\r\n").await.unwrap();
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(
        reply.contains("ERR EMULATE requires a recipient user"),
        "got: {reply}"
    );
}

#[tokio::test]
async fn emulate_malformed_blob_errors() {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let (mut client, server) = tokio::io::duplex(8192);
    let handler = Arc::new(MockHandler::new());
    tokio::spawn(async move {
        let mut server = server;
        let _ = serve(&mut server, handler.as_ref()).await;
    });

    client.write_all(b"EMULATE bob\r\n").await.unwrap();
    client.write_all(b"BLOB 4\r\nnope").await.unwrap();
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert!(
        reply.contains("ERR malformed EMULATE payload"),
        "got: {reply}"
    );
}
