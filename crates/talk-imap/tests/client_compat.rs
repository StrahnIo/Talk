//! Real-client compatibility: drive the hand-rolled IMAP server with the
//! `async-imap` client library to prove actual IMAP4rev1 interop.

use futures::StreamExt;
use std::sync::Arc;
use talk_imap::server::{ImapServer, serve_connection};
use talk_mailstore::{NewMessage, SqliteMailStore};
use tokio::net::TcpListener;

/// Seed a store with one user + one message and bind the IMAP server on an
/// ephemeral port. Returns the port and a store handle for assertions.
async fn boot_server() -> (u16, Arc<SqliteMailStore>) {
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
            NewMessage::invoice(
                "msg-1".to_string(),
                "Hello from Talk".to_string(),
                b"opaque-sealed-invoice-body".to_vec(),
            ),
        )
        .expect("append");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = ImapServer::new(store.clone(), "talk.test");
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
    (addr.port(), store)
}

/// Connect a plaintext async-imap client to the local server and log in.
async fn login_session(
    port: u16,
) -> async_imap::Session<tokio_util::compat::Compat<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let client =
        async_imap::Client::new(tokio_util::compat::TokioAsyncReadCompatExt::compat(stream));
    client.login("alice", "secret").await.expect("login")
}

#[tokio::test]
async fn login_select_fetch_logout() {
    let (port, _store) = boot_server().await;
    let mut session = login_session(port).await;

    let mailbox = session.select("INBOX").await.expect("select");
    assert_eq!(mailbox.exists, 1, "one message in INBOX");

    // FETCH the body and flags.
    let fetches: Vec<Result<async_imap::types::Fetch, _>> = session
        .fetch("1", "(FLAGS BODY[])")
        .await
        .expect("fetch")
        .collect()
        .await;
    assert_eq!(fetches.len(), 1);
    let fetch = fetches.into_iter().next().unwrap().expect("fetch ok");
    assert_eq!(fetch.size, Some(26));
    assert!(
        fetch
            .body()
            .map(|b| b == b"opaque-sealed-invoice-body")
            .unwrap_or(false),
        "body must round-trip"
    );

    session.logout().await.expect("logout");
}

#[tokio::test]
async fn store_and_search_flow() {
    let (port, _store) = boot_server().await;
    let mut session = login_session(port).await;
    let _mailbox = session.select("INBOX").await.expect("select");

    // Search before seen: the message is unseen.
    let unseen = session.search("UNSEEN").await.expect("search");
    assert_eq!(unseen.len(), 1, "one unseen before STORE");

    // Mark seen.
    let store_res: Vec<_> = session
        .store("1", "+FLAGS (\\Seen)")
        .await
        .expect("store")
        .collect()
        .await;
    eprintln!("store results: {store_res:?}");
    for r in &store_res {
        r.as_ref().expect("store fetch ok");
    }

    // Search again: now none unseen.
    let unseen = session.search("UNSEEN").await.expect("search");
    assert!(unseen.is_empty(), "no unseen after STORE");

    session.logout().await.expect("logout");
}

#[tokio::test]
async fn wrong_password_rejected() {
    let (port, _store) = boot_server().await;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let client =
        async_imap::Client::new(tokio_util::compat::TokioAsyncReadCompatExt::compat(stream));
    let err = client.login("alice", "wrong").await;
    assert!(err.is_err(), "wrong password must be rejected");
}

#[tokio::test]
async fn list_shows_inbox() {
    let (port, _store) = boot_server().await;
    let mut session = login_session(port).await;

    let names: Vec<String> = session
        .list(None, Some("*"))
        .await
        .expect("list")
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|m| m.expect("name").name().to_string())
        .collect();
    assert!(names.contains(&"INBOX".to_string()), "got: {names:?}");

    session.logout().await.expect("logout");
}
