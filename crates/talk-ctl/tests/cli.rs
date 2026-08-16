//! End-to-end talkctl integration tests against a temp data dir + config.
//!
//! These exercise the real binary; management/config/settings ops are
//! offline-capable (direct store + config access).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_talkctl")
}

/// A temp daemon data dir + config that points at it.
struct Setup {
    _dir: tempfile::TempDir,
    cfg: PathBuf,
    data: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("mkdir data");
    // A daemon that has booted once leaves a domain key here; the CLI signs
    // registration attestations with it but never creates it.
    std::fs::write(data.join("domainkey"), [7u8; 32]).expect("domainkey");
    let cfg = dir.path().join("config.toml");
    let d = data.display();
    std::fs::write(
        &cfg,
        format!(
            r#"
[general]
data_dir = "{d}"
domain = "talk.local"
log_level = "info"

[network]
indexer_url = "lwd.example.com:9067"
send_endpoint = ""

[sockets]
secure_mailbox = "{d}/run/secure.sock"
zsmtp = "{d}/run/zsmtp.sock"
zsmtp_listen = "127.0.0.1:1465"
imap_listen = "127.0.0.1:1143"

[tls]
cert = "{d}/cert.pem"
key = "{d}/key.pem"

[mailbox]
encrypt_db = false
passphrase = ""
wallet_dir = "{d}/wallets"
"#
        ),
    )
    .expect("write config");
    Setup {
        _dir: dir,
        cfg,
        data,
    }
}

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    cmd.output().expect("spawn talkctl")
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn talkctl");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn err_contains(out: &Output, needle: &str, what: &str) {
    assert!(!out.status.success(), "{what} should have failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(needle),
        "{what}: expected stderr containing {needle:?}, got {stderr}"
    );
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn cfg_flag(cfg: &Path) -> String {
    format!("--config={}", cfg.display())
}

const PUBKEY: &str = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

#[test]
fn status_reports_domain_and_users() {
    let s = setup();
    let out = run(&[&cfg_flag(&s.cfg), "status"]);
    ok(&out, "status");
    let text = stdout(&out);
    assert!(text.contains("domain         talk.local"), "{text}");
    assert!(text.contains("users          0"), "{text}");
}

#[test]
fn config_validate_and_get() {
    let s = setup();
    let out = run(&[&cfg_flag(&s.cfg), "config", "validate"]);
    ok(&out, "config validate");
    assert!(stdout(&out).contains("is valid"));

    let out = run(&[&cfg_flag(&s.cfg), "config", "get", "general.domain"]);
    ok(&out, "config get");
    assert_eq!(stdout(&out).trim(), "\"talk.local\"");
}

#[test]
fn config_set_roundtrip_and_unknown_key_rejected() {
    let s = setup();
    let out = run(&[
        &cfg_flag(&s.cfg),
        "config",
        "set",
        "general.domain",
        "example.org",
    ]);
    ok(&out, "config set");
    let out = run(&[&cfg_flag(&s.cfg), "config", "get", "general.domain"]);
    assert_eq!(stdout(&out).trim(), "\"example.org\"");

    // Unknown keys are refused (deny_unknown_fields would reject them anyway).
    let out = run(&[&cfg_flag(&s.cfg), "config", "set", "nope.x", "1"]);
    err_contains(&out, "unknown key", "config set unknown key");

    // Setting an invalid domain is refused and does not corrupt the file.
    let out = run(&[
        &cfg_flag(&s.cfg),
        "config",
        "set",
        "general.domain",
        "bad domain",
    ]);
    err_contains(
        &out,
        "refusing to write invalid config",
        "config set invalid domain",
    );
    let out = run(&[&cfg_flag(&s.cfg), "config", "get", "general.domain"]);
    assert_eq!(stdout(&out).trim(), "\"example.org\"");
}

#[test]
fn user_lifecycle() {
    let s = setup();
    let out = run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "alice",
        "--password",
        "s3cret",
        "--pubkey",
        PUBKEY,
    ]);
    ok(&out, "user create");
    assert!(stdout(&out).contains("ok: registered alice"));

    let out = run(&[&cfg_flag(&s.cfg), "user", "list"]);
    ok(&out, "user list");
    assert!(stdout(&out).contains("alice"));

    let out = run(&[&cfg_flag(&s.cfg), "user", "show", "alice"]);
    ok(&out, "user show");
    let text = stdout(&out);
    assert!(text.contains("username      alice"));
    assert!(text.contains("attestation   present"));
    assert!(text.contains("R: domain=talk.local"));

    let out = run(&[&cfg_flag(&s.cfg), "user", "delete", "alice"]);
    ok(&out, "user delete");
    let out = run(&[&cfg_flag(&s.cfg), "user", "list"]);
    assert!(!stdout(&out).contains("alice"));
}

#[test]
fn user_create_rejects_bad_pubkey_and_missing_domain_key() {
    let s = setup();
    let out = run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "bob",
        "--password",
        "pw",
        "--pubkey",
        "nope",
    ]);
    err_contains(&out, "32 bytes of hex", "bad pubkey");

    // Remove the domain key: create must refuse (R cannot be signed).
    std::fs::remove_file(s.data.join("domainkey")).expect("remove domainkey");
    let out = run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "bob",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    err_contains(&out, "domain key", "missing domain key");
}

#[test]
fn user_create_rejects_qualified_usernames() {
    let s = setup();
    let out = run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "bob@talk.local",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    err_contains(&out, "bare local name", "username with @ rejected");
    let out = run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "bob:app",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    err_contains(&out, "app passwords", "username with : rejected");
}

#[test]
fn user_lookups_accept_local_domain() {
    let s = setup();
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "user",
            "create",
            "carol",
            "--password",
            "pw",
            "--pubkey",
            PUBKEY,
        ]),
        "create carol",
    );
    let out = run(&[&cfg_flag(&s.cfg), "user", "show", "carol@talk.local"]);
    ok(&out, "user show carol@talk.local");
    assert!(stdout(&out).contains("username      carol"));

    let out = run(&[&cfg_flag(&s.cfg), "user", "show", "carol@evil.org"]);
    err_contains(&out, "no such user", "foreign domain rejected");
}

#[test]
fn shares_init_list_revoke() {
    let s = setup();
    run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "carol",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    let out = run(&[&cfg_flag(&s.cfg), "share", "init", "carol", "--shares", "3"]);
    ok(&out, "share init");
    let text = stdout(&out);
    assert!(text.contains("ok: registered 3 shares"));
    // Each share line prints its secret once.
    let share_ids: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("share id="))
        .map(|l| {
            l.split(' ')
                .find_map(|tok| tok.strip_prefix("id="))
                .unwrap()
        })
        .collect();
    assert_eq!(share_ids.len(), 3);

    let out = run(&[&cfg_flag(&s.cfg), "share", "list", "carol"]);
    ok(&out, "share list");
    let text = stdout(&out);
    assert_eq!(text.lines().filter(|l| l.contains(" active ")).count(), 3);

    let out = run(&[&cfg_flag(&s.cfg), "share", "revoke", "carol", share_ids[0]]);
    ok(&out, "share revoke");
    let out = run(&[&cfg_flag(&s.cfg), "share", "list", "carol"]);
    let text = stdout(&out);
    assert_eq!(text.lines().filter(|l| l.contains(" active ")).count(), 2);
    assert_eq!(text.lines().filter(|l| l.contains(" revoked ")).count(), 1);
}

#[test]
fn keyring_pin_list_unpin() {
    let s = setup();
    run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "dave",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    let out = run(&[
        &cfg_flag(&s.cfg),
        "keyring",
        "pin",
        "dave",
        "bob@example.org",
        "--pubkey",
        "aabb",
    ]);
    ok(&out, "keyring pin");
    let out = run(&[&cfg_flag(&s.cfg), "keyring", "list", "dave"]);
    ok(&out, "keyring list");
    assert!(stdout(&out).contains("bob@example.org"));
    let out = run(&[
        &cfg_flag(&s.cfg),
        "keyring",
        "unpin",
        "dave",
        "bob@example.org",
    ]);
    ok(&out, "keyring unpin");
    let out = run(&[&cfg_flag(&s.cfg), "keyring", "list", "dave"]);
    assert!(stdout(&out).lines().count() == 0);
}

#[test]
fn settings_crud() {
    let s = setup();
    let out = run(&[&cfg_flag(&s.cfg), "settings", "set", "k", "v"]);
    ok(&out, "settings set");
    let out = run(&[&cfg_flag(&s.cfg), "settings", "get", "k"]);
    assert_eq!(stdout(&out).trim(), "v");
    let out = run(&[&cfg_flag(&s.cfg), "settings", "list"]);
    assert!(stdout(&out).contains("k = v"));
    let out = run(&[&cfg_flag(&s.cfg), "settings", "delete", "k"]);
    ok(&out, "settings delete");
    let out = run(&[&cfg_flag(&s.cfg), "settings", "get", "k"]);
    err_contains(&out, "no such setting", "settings get missing");
}

#[test]
fn attest_direct_when_daemon_down() {
    let s = setup();
    run(&[
        &cfg_flag(&s.cfg),
        "user",
        "create",
        "erin",
        "--password",
        "pw",
        "--pubkey",
        PUBKEY,
    ]);
    let out = run(&[&cfg_flag(&s.cfg), "attest", "erin", "ephemeral"]);
    ok(&out, "attest");
    let text = stdout(&out);
    assert!(text.contains("user        erin"));
    assert!(text.contains("mode        ephemeral"));
    assert!(text.contains("signature   "));
}

#[test]
fn key_generate_to_file_and_pubkey_matches() {
    let s = setup();
    let priv_file = s.data.join("master.key");
    let out = run(&[
        &cfg_flag(&s.cfg),
        "key",
        "generate",
        "--out",
        priv_file.to_str().unwrap(),
    ]);
    ok(&out, "key generate");
    let public_line = stdout(&out);
    let pub_hex = public_line
        .lines()
        .find_map(|l| l.strip_prefix("public: "))
        .expect("public: line")
        .to_string();
    assert_eq!(pub_hex.len(), 64);

    // The private file is raw 32 bytes, mode 0600.
    let bytes = std::fs::read(&priv_file).expect("read key");
    assert_eq!(bytes.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&priv_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must be mode 0600");
    }

    // key pubkey from the file reproduces the public half.
    let out = run(&[
        &cfg_flag(&s.cfg),
        "key",
        "pubkey",
        "--key",
        priv_file.to_str().unwrap(),
    ]);
    ok(&out, "key pubkey");
    assert_eq!(stdout(&out).trim(), pub_hex);

    // key pubkey from hex also matches (the private key, hex-encoded).
    let priv_hex = hex::encode(&bytes);
    let out = run(&[&cfg_flag(&s.cfg), "key", "pubkey", "--hex", &priv_hex]);
    ok(&out, "key pubkey --hex");
    assert_eq!(stdout(&out).trim(), pub_hex);
}

#[test]
fn key_generate_refuses_overwrite_without_force() {
    let s = setup();
    let priv_file = s.data.join("master.key");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            priv_file.to_str().unwrap(),
        ]),
        "generate",
    );
    let out = run(&[
        &cfg_flag(&s.cfg),
        "key",
        "generate",
        "--out",
        priv_file.to_str().unwrap(),
    ]);
    err_contains(&out, "already exists", "overwrite refusal");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            priv_file.to_str().unwrap(),
            "--force",
        ]),
        "generate --force",
    );
}

#[test]
fn key_seal_unseal_roundtrip_files() {
    let s = setup();
    let priv_file = s.data.join("master.key");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            priv_file.to_str().unwrap(),
        ]),
        "generate",
    );

    let payload = s.data.join("payload.bin");
    let sealed = s.data.join("sealed.bin");
    let plain = s.data.join("plain.bin");
    std::fs::write(&payload, b"opaque invoice body \x00\x01\x02").expect("payload");

    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "seal",
            "--key",
            priv_file.to_str().unwrap(),
            "--input",
            payload.to_str().unwrap(),
            "--output",
            sealed.to_str().unwrap(),
        ]),
        "seal",
    );
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "unseal",
            "--key",
            priv_file.to_str().unwrap(),
            "--input",
            sealed.to_str().unwrap(),
            "--output",
            plain.to_str().unwrap(),
        ]),
        "unseal",
    );
    assert_eq!(
        std::fs::read(&plain).expect("plain"),
        b"opaque invoice body \x00\x01\x02"
    );

    // The sealed envelope is versioned and larger than the input.
    let sealed_bytes = std::fs::read(&sealed).expect("sealed");
    assert!(sealed_bytes.len() > 32);
    assert_eq!(&sealed_bytes[..4], b"TKS1");
}

#[test]
fn key_seal_to_explicit_pub_and_wrong_key_fails() {
    let s = setup();
    let priv_key = s.data.join("master.key");
    let other_priv = s.data.join("other.key");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            priv_key.to_str().unwrap(),
        ]),
        "generate a",
    );
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            other_priv.to_str().unwrap(),
        ]),
        "generate b",
    );

    let out = run(&[
        &cfg_flag(&s.cfg),
        "key",
        "pubkey",
        "--key",
        priv_key.to_str().unwrap(),
    ]);
    let pub_hex = stdout(&out).trim().to_string();

    // Seal to the explicit public key, decrypt with the matching private key.
    let payload = s.data.join("p.bin");
    let sealed = s.data.join("s.bin");
    std::fs::write(&payload, b"to-explicit-pub").expect("payload");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "seal",
            "--key",
            priv_key.to_str().unwrap(),
            "--to",
            &pub_hex,
            "--input",
            payload.to_str().unwrap(),
            "--output",
            sealed.to_str().unwrap(),
        ]),
        "seal to pub",
    );

    // Wrong private key cannot decrypt.
    let out = run(&[
        &cfg_flag(&s.cfg),
        "key",
        "unseal",
        "--key",
        other_priv.to_str().unwrap(),
        "--input",
        sealed.to_str().unwrap(),
    ]);
    err_contains(&out, "unseal failed", "wrong key unseal");
}

#[test]
fn key_seal_unseal_via_stdin_stdout() {
    let s = setup();
    let priv_file = s.data.join("master.key");
    ok(
        &run(&[
            &cfg_flag(&s.cfg),
            "key",
            "generate",
            "--out",
            priv_file.to_str().unwrap(),
        ]),
        "generate",
    );

    // echo "..." | seal | unseal == "..."
    let seal = run_with_stdin(
        &[
            &cfg_flag(&s.cfg),
            "key",
            "seal",
            "--key",
            priv_file.to_str().unwrap(),
        ],
        b"piped data",
    );
    ok(&seal, "seal stdin");
    let unseal = run_with_stdin(
        &[
            &cfg_flag(&s.cfg),
            "key",
            "unseal",
            "--key",
            priv_file.to_str().unwrap(),
        ],
        &seal.stdout,
    );
    ok(&unseal, "unseal stdout");
    assert_eq!(unseal.stdout, b"piped data");
}

struct MockHandler(Arc<Mutex<Vec<(String, talk_protocol::emulate::EmulatePayload)>>>);

#[async_trait::async_trait]
impl talk_protocol::mailbox::AsyncSecureMailboxHandler for MockHandler {
    async fn send(
        &self,
        _s: &str,
        _r: &str,
        _m: &str,
        _p: talk_protocol::envelope::Payload,
        _b: &[u8],
    ) -> talk_protocol::mailbox::SendResult {
        talk_protocol::mailbox::SendResult::Ok("delivered".to_string())
    }
    fn attest(
        &self,
        _u: &str,
        _m: talk_protocol::attestation::AttestationMode,
    ) -> talk_protocol::mailbox::AttestResult {
        talk_protocol::mailbox::AttestResult::Ok(Vec::new())
    }
    fn register(
        &self,
        _u: &str,
        _p: &str,
        _k: &str,
        _i: Option<&str>,
    ) -> talk_protocol::mailbox::RegisterResult {
        talk_protocol::mailbox::RegisterResult::Ok
    }
    fn status(&self) -> String {
        "mock".to_string()
    }
    fn emulate(
        &self,
        recipient_user: &str,
        payload: &talk_protocol::emulate::EmulatePayload,
    ) -> talk_protocol::mailbox::EmulateResult {
        self.0
            .lock()
            .unwrap()
            .push((recipient_user.to_string(), payload.clone()));
        talk_protocol::mailbox::EmulateResult::Ok(format!("delivered to {recipient_user}"))
    }
}

#[test]
fn emulate_payment_reaches_daemon_socket() {
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;

    let s = setup();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sock_path = s.data.join("run/secure.sock");
    std::fs::create_dir_all(sock_path.parent().unwrap()).expect("mkdir run");

    let path = sock_path.clone();
    let cap = captured.clone();
    std::thread::spawn(move || {
        let listener = UnixListener::bind(&path).expect("bind socket");
        let (stream, _) = listener.accept().expect("accept");
        stream.set_nonblocking(true).expect("nonblocking");
        let rt = tokio::runtime::Runtime::new().expect("rt");
        rt.block_on(async move {
            let stream = tokio::net::UnixStream::from_std(stream).expect("tokio stream");
            let mut stream = stream;
            let handler = MockHandler(cap);
            let _ = talk_protocol::mailbox::serve(&mut stream, &handler).await;
        });
    });

    let invoice = s.data.join("inv.txt");
    std::fs::write(&invoice, b"line one\nline two").expect("invoice");

    let out = run(&[
        &cfg_flag(&s.cfg),
        "emulate",
        "payment",
        "alice",
        "--from-name",
        "Alice Smith",
        "--from-address",
        "t1abc123",
        "--amount",
        "1.5",
        "--invoice",
        invoice.to_str().unwrap(),
    ]);
    ok(&out, "emulate");
    assert!(
        stdout(&out).contains("OK delivered to alice"),
        "{}",
        stdout(&out)
    );

    let got = captured.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "alice");
    assert_eq!(got[0].1.sender_name, "Alice Smith");
    assert_eq!(got[0].1.sender_address, "t1abc123");
    assert_eq!(got[0].1.amount, "1.5");
    assert_eq!(got[0].1.invoice, b"line one\nline two");
}

#[test]
fn emulate_fails_when_daemon_down() {
    let s = setup();
    let invoice = s.data.join("inv.txt");
    std::fs::write(&invoice, b"hi").expect("invoice");
    let out = run(&[
        &cfg_flag(&s.cfg),
        "emulate",
        "payment",
        "alice",
        "--from-name",
        "x",
        "--from-address",
        "t1",
        "--amount",
        "0.1",
        "--invoice",
        invoice.to_str().unwrap(),
    ]);
    err_contains(&out, "daemon not running", "emulate with daemon down");
}
