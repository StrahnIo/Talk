//! End-to-end talkctl integration tests against a temp data dir + config.
//!
//! These exercise the real binary; management/config/settings ops are
//! offline-capable (direct store + config access).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
