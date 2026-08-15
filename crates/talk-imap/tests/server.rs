use std::sync::Arc;
use talk_imap::server::{ImapServer, serve_connection};
use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn seed_store(dir: &tempfile::TempDir) -> Arc<SqliteMailStore> {
    let store =
        Arc::new(SqliteMailStore::open(dir.path().join("mailbox.db"), false, None).expect("open"));
    let user_id = store
        .create_user("alice", "hash", &[0u8; 32])
        .expect("create user")
        .id;
    store
        .append_message(
            user_id,
            NewMessage {
                message_id: "msg-1".to_string(),
                subject: "New sealed invoice".to_string(),
                body: b"opaque-ciphertext".to_vec(),
                flags: MessageFlags::default(),
            },
        )
        .expect("append");
    store
}

/// Read from `client` until `needle` appears, appending to `got`.
async fn read_until(
    client: &mut tokio::io::DuplexStream,
    buf: &mut [u8],
    got: &mut String,
    needle: &str,
) -> std::io::Result<()> {
    while !got.contains(needle) {
        let n = client.read(buf).await?;
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    Ok(())
}

/// Drive one scripted client session against the server over a duplex socket.
async fn scripted_session(store: Arc<SqliteMailStore>) -> tokio::io::Result<String> {
    let (mut client, server_stream) = tokio::io::duplex(8192);
    let server = ImapServer::new(store, "talk.test");
    tokio::spawn(async move {
        let mut stream = server_stream;
        let _ = serve_connection(&mut stream, &server).await;
    });

    let mut buf = [0u8; 4096];
    let mut got = String::new();

    // Greeting.
    read_until(&mut client, &mut buf, &mut got, "* OK").await?;

    for (cmd, needle) in [
        ("A1 CAPABILITY\r\n", "A1 OK"),
        ("A2 LOGIN alice secret\r\n", "A2 OK"),
        ("A3 SELECT INBOX\r\n", "A3 OK"),
        ("A4 FETCH 1 BODY[]\r\n", "A4 OK"),
        ("A5 LOGOUT\r\n", "A5 OK"),
    ] {
        client.write_all(cmd.as_bytes()).await?;
        read_until(&mut client, &mut buf, &mut got, needle).await?;
    }
    Ok(got)
}

#[tokio::test]
async fn full_client_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = seed_store(&dir);
    let transcript = scripted_session(store).await.expect("session");

    assert!(transcript.contains("* OK"), "greeting: {transcript}");
    assert!(
        transcript.contains("A1 OK CAPABILITY"),
        "capa: {transcript}"
    );
    assert!(transcript.contains("A2 OK LOGIN"), "login: {transcript}");
    assert!(transcript.contains("* 1 EXISTS"), "select: {transcript}");
    assert!(
        transcript.contains("A3 OK [READ-WRITE]"),
        "select ok: {transcript}"
    );
    assert!(
        transcript.contains("opaque-ciphertext"),
        "body: {transcript}"
    );
    assert!(transcript.contains("A5 OK LOGOUT"), "logout: {transcript}");
}

#[tokio::test]
async fn listens_on_tcp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = seed_store(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = ImapServer::new(store, "talk.test");
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = listener.accept().await.expect("accept");
            let server = server.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = serve_connection(&mut stream, &server).await;
            });
        }
    });

    let mut conn = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await.expect("read greeting");
    let greeting = String::from_utf8_lossy(&buf[..n]);
    assert!(greeting.contains("* OK"), "greeting: {greeting}");
    assert!(greeting.contains("CAPABILITY"), "caps: {greeting}");
}
