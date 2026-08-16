use std::sync::Arc;
use talk_imap::server::{ImapServer, serve_connection};
use talk_mailstore::{NewMessage, SqliteMailStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn seed_store(dir: &tempfile::TempDir) -> Arc<SqliteMailStore> {
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
            NewMessage::invoice(
                "msg-1".to_string(),
                "New sealed invoice".to_string(),
                b"opaque-ciphertext".to_vec(),
            ),
        )
        .expect("append");
    store
}

/// Read from `client` until `needle` appears, appending to `got`.
async fn read_until<R: AsyncRead + Unpin>(
    client: &mut R,
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

#[tokio::test]
async fn idle_receives_new_message_event() {
    use talk_imap::server::MailboxEvent;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = seed_store(&dir);
    let server = ImapServer::new(store.clone(), "talk.test");
    let events = server.event_sender();

    let (mut client, server_stream) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        let mut stream = server_stream;
        let _ = serve_connection(&mut stream, &server).await;
    });

    let mut buf = [0u8; 4096];
    let mut got = String::new();
    read_until(&mut client, &mut buf, &mut got, "* OK")
        .await
        .unwrap();
    client
        .write_all(b"A1 LOGIN alice secret\r\n")
        .await
        .unwrap();
    read_until(&mut client, &mut buf, &mut got, "A1 OK")
        .await
        .unwrap();
    client.write_all(b"A2 SELECT INBOX\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "A2 OK")
        .await
        .unwrap();

    // Enter IDLE: server replies `+ idle`, then waits.
    client.write_all(b"A3 IDLE\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "+ idle")
        .await
        .unwrap();

    // Append a message for alice and fire the event.
    let user_id = store
        .get_user("alice")
        .expect("get user")
        .expect("exists")
        .id;
    store
        .append_message(
            user_id,
            NewMessage::invoice(
                "msg-2".to_string(),
                "New sealed invoice".to_string(),
                b"more".to_vec(),
            ),
        )
        .expect("append");
    events
        .send(MailboxEvent::MessageAppended { user_id })
        .expect("send");

    // The IDLE session must emit `* 2 EXISTS` (now two messages).
    read_until(&mut client, &mut buf, &mut got, "2 EXISTS")
        .await
        .unwrap();

    // Leave IDLE and log out cleanly.
    client.write_all(b"DONE\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "A3 OK")
        .await
        .unwrap();
    client.write_all(b"A4 LOGOUT\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "A4 OK")
        .await
        .unwrap();
    assert!(got.contains("2 EXISTS"), "got: {got}");
}

#[tokio::test]
async fn capture_dir_writes_per_session_transcripts() {
    use std::io::Read as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = seed_store(&dir);
    let capture_dir = dir.path().join("caps");

    // Find a free port for the IMAP listener.
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);

    let server = ImapServer::new(store, "talk.test").with_capture_dir(capture_dir.clone());
    let addr = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = server.listen(&addr).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut buf = [0u8; 4096];
    let mut got = String::new();
    read_until(&mut client, &mut buf, &mut got, "* OK")
        .await
        .expect("greeting");
    client
        .write_all(b"A1 LOGIN alice secret\r\n")
        .await
        .unwrap();
    read_until(&mut client, &mut buf, &mut got, "A1 OK")
        .await
        .expect("login");
    client.write_all(b"A2 SELECT INBOX\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "A2 OK")
        .await
        .expect("select");
    client.write_all(b"A3 LOGOUT\r\n").await.unwrap();
    read_until(&mut client, &mut buf, &mut got, "A3 OK")
        .await
        .expect("logout");

    // Give the connection task a moment to finish the capture file.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries: Vec<_> = std::fs::read_dir(&capture_dir)
        .expect("capture dir")
        .collect::<Result<_, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 1, "one transcript per session");

    let path = entries[0].path();
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("imap-"), "{name}");
    assert!(name.ends_with(".pcap.txt"), "{name}");

    let mut contents = String::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    assert!(
        contents.contains("# talkd IMAP session capture"),
        "{contents}"
    );
    assert!(contents.contains("# peer="), "{contents}");
    assert!(contents.contains("* OK [CAPABILITY"), "{contents}");
    assert!(contents.contains("A1 LOGIN alice secret"), "{contents}");
    assert!(contents.contains("LOGIN completed"), "{contents}");
    assert!(contents.contains("C> 23 bytes"), "{contents}");
    assert!(
        contents.contains("C> hex: 4131204c4f47494e20"),
        "{contents}"
    );
    assert!(contents.contains("S> 172 bytes"), "{contents}");
    assert!(contents.contains("# ended="), "{contents}");
}
