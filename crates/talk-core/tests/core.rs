use std::io::Write;
use std::path::PathBuf;
use talk_core::config::Config;
use talk_core::sockets::SocketListener;

#[test]
fn socket_creates_parent_dirs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested/deep/socket.sock");
    let sock = SocketListener::bind(&path).expect("bind");
    assert!(path.parent().expect("parent").exists());
    assert_eq!(sock.local_path(), &path);
}

#[test]
fn socket_removes_stale_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("socket.sock");
    // Leave a stale (non-socket) file where the socket should go.
    std::fs::write(&path, b"stale").expect("write stale");
    let sock = SocketListener::bind(&path).expect("bind");
    assert!(path.exists());
    drop(sock);
    assert!(!path.exists(), "drop must remove the socket file");
}

#[test]
fn socket_accept_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("accept.sock");
    let sock = SocketListener::bind(&path).expect("bind");

    let sock_path = path.clone();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime.block_on(async move {
            let sock = sock;
            let (stream, _) = sock.accept().await.expect("accept");
            stream
        });
    });

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let stream = runtime.block_on(async move {
        tokio::net::UnixStream::connect(&sock_path)
            .await
            .expect("connect")
    });

    handle.join().expect("thread");
    let _ = (stream, ());
}

#[test]
fn socket_drop_removes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("drop.sock");
    {
        let sock = SocketListener::bind(&path).expect("bind");
        assert!(path.exists());
        drop(sock);
    }
    assert!(!path.exists());
}

#[test]
fn config_missing_file_errors() {
    let err = Config::load(PathBuf::from("/nonexistent/talk-config.toml"));
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("failed to read config"), "got: {msg}");
}

#[test]
fn config_invalid_toml_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, b"this is not [ valid toml ===\n").expect("write");
    let err = Config::load(&path);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("failed to parse config"), "got: {msg}");
}

#[test]
fn config_missing_required_field_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("partial.toml");
    std::fs::write(&path, b"[general]\ndata_dir = \"/tmp/talk\"\n").expect("write");
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_unknown_field_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("unknown.toml");
    let raw = r#"
        [general]
        data_dir = "/tmp/talk"
        log_level = "info"
        bogus_field = 1

        [network]
        indexer_url = "x:1"
        send_endpoint = "y:2"

        [sockets]
        secure_mailbox = "/tmp/a.sock"
        zsmtp = "/tmp/b.sock"
        zsmtp_listen = "127.0.0.1:1465"
        imap_listen = "127.0.0.1:1143"

        [tls]
        cert = "/tmp/c.pem"
        key = "/tmp/k.pem"

        [mailbox]
        wallet_dir = "/tmp/w"
    "#;
    std::fs::write(&path, raw).expect("write");
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_roundtrip_example() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let cfg = Config::load(&example).expect("example config must parse");
    assert_eq!(cfg.general.log_level, "info");
    assert!(cfg.mailbox.encrypt_db);
    assert_eq!(
        cfg.mailbox.wallet_dir,
        PathBuf::from("/var/lib/talk/wallets")
    );
    assert_eq!(cfg.sockets.imap_listen, "127.0.0.1:1143");
}

#[test]
fn socket_bind_second_fails_when_first_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("live.sock");
    let _first = SocketListener::bind(&path).expect("first bind");
    // A second bind on the same live socket should fail.
    assert!(SocketListener::bind(&path).is_err());
}

#[test]
fn socket_file_content_discarded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("discard.sock");
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(b"leftover").expect("write");
    drop(f);
    let sock = SocketListener::bind(&path).expect("bind");
    assert!(path.exists(), "stale file replaced by live socket");
    drop(sock);
}
