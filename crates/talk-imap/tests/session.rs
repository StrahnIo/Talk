use std::sync::Arc;
use talk_imap::parse::{CommandReader, ParsedCommand};
use talk_imap::response;
use talk_imap::session::{Session, State};
use talk_mailstore::{NewMessage, SqliteMailStore};

fn setup() -> (tempfile::TempDir, Arc<SqliteMailStore>, i64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open"));
    let hash = talk_mailstore::hash_password("secret").expect("hash");
    let user_id = store
        .create_user("alice", &hash, &[0u8; 32])
        .expect("create user")
        .id;
    store
        .append_message(
            user_id,
            NewMessage::invoice(
                "msg-1".to_string(),
                "New sealed invoice".to_string(),
                b"ciphertext-blob".to_vec(),
            ),
        )
        .expect("append");
    (dir, store, user_id)
}

fn session_with(store: Arc<SqliteMailStore>) -> Session {
    Session {
        state: State::NotAuthenticated,
        username: String::new(),
        user_id: 0,
        store,
        auth_mode: talk_imap::AuthMode::Database,
    }
}

fn parse_cmd(line: &str) -> ParsedCommand {
    let mut reader = CommandReader::default();
    reader
        .feed(format!("{line}\r\n").as_bytes())
        .expect("parse")
        .remove(0)
}

#[test]
fn login_then_select_flow() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);

    let out = s.handle(&parse_cmd("A1 CAPABILITY"));
    assert!(out.contains("CAPABILITY IMAP4rev1"));
    assert!(out.contains("A1 OK"));

    let out = s.handle(&parse_cmd("A2 LOGIN alice secret"));
    assert!(out.contains("A2 OK"));
    assert_eq!(s.state, State::Authenticated);
    assert_eq!(s.username, "alice");

    let out = s.handle(&parse_cmd("A3 SELECT INBOX"));
    assert!(out.contains("* 1 EXISTS"));
    assert!(out.contains("A3 OK [READ-WRITE]"));
    assert_eq!(s.state, State::Selected);
}

#[test]
fn login_rejected_for_unknown_user() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 LOGIN eve secret"));
    assert!(out.contains("A1 NO"));
    assert_eq!(s.state, State::NotAuthenticated);
}

#[test]
fn app_password_share_unlocks_dk() {
    use talk_keys::{DataKey, PerShareWrapper, Share, ShareScheme};

    let (_dir, store, _) = setup();
    let alice = store.get_user("alice").expect("get").expect("exists");

    // Wrap a data key under a share and register the wrapper for alice.
    let mut rng = rand::thread_rng();
    let dk = DataKey::generate(&mut rng);
    let share = Share::generate(&mut rng);
    let scheme = PerShareWrapper;
    let set = scheme.wrap(&dk, std::slice::from_ref(&share));
    store
        .add_share(alice.id, "share-1", &set.wrappers[0].wrapped)
        .expect("add share");

    // Login with the share as the app password (hex).
    let share_hex = share
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut s = session_with(Arc::clone(&store));
    let out = s.handle(&parse_cmd(&format!("A1 LOGIN alice:app {share_hex}")));
    assert!(out.contains("A1 OK"), "got: {out}");
    assert_eq!(s.username, "alice");
}

#[test]
fn app_password_wrong_share_rejected() {
    use talk_keys::{DataKey, PerShareWrapper, Share, ShareScheme};

    let (_dir, store, _) = setup();
    let alice = store.get_user("alice").expect("get").expect("exists");

    let mut rng = rand::thread_rng();
    let dk = DataKey::generate(&mut rng);
    let share = Share::generate(&mut rng);
    let scheme = PerShareWrapper;
    let set = scheme.wrap(&dk, std::slice::from_ref(&share));
    store
        .add_share(alice.id, "share-1", &set.wrappers[0].wrapped)
        .expect("add share");

    // A different share must not authenticate.
    let wrong = Share::generate(&mut rng);
    let wrong_hex = wrong
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut s = session_with(Arc::clone(&store));
    let out = s.handle(&parse_cmd(&format!("A1 LOGIN alice:app {wrong_hex}")));
    assert!(out.contains("A1 NO"), "got: {out}");
    assert_eq!(s.state, State::NotAuthenticated);
}

#[test]
fn app_password_non_hex_rejected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    let out = s.handle(&parse_cmd("A1 LOGIN alice:app not-hex!!"));
    assert!(out.contains("A1 NO"));
}

#[test]
fn select_requires_auth() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 SELECT INBOX"));
    assert!(out.contains("A1 BAD"));
}

#[test]
fn fetch_returns_body_literal() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));

    let out = s.handle(&parse_cmd("A3 FETCH 1 BODY[]"));
    assert!(out.contains("* 1 FETCH (FLAGS () UID 1 RFC822.SIZE 15 BODY[] {15}"));
    assert!(out.contains("ciphertext-blob"));
    assert!(out.contains("A3 OK FETCH completed"));
}

#[test]
fn store_marks_seen() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));

    let out = s.handle(&parse_cmd("A3 STORE 1 +FLAGS (\\Seen)"));
    assert!(out.contains("A3 OK STORE completed"));

    let list = store.list_messages(s.user_id).expect("list");
    assert!(list[0].flags.is_seen());
}

#[test]
fn search_unseen() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));

    let out = s.handle(&parse_cmd("A3 SEARCH UNSEEN"));
    assert!(out.contains("SEARCH 1"));
    assert!(out.contains("A3 OK SEARCH completed"));
}

#[test]
fn expunge_and_close() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));

    s.handle(&parse_cmd("A3 STORE 1 +FLAGS (\\Deleted)"));
    let out = s.handle(&parse_cmd("A4 EXPUNGE"));
    assert!(out.contains("* 1 EXPUNGE"));
    assert!(store.list_messages(s.user_id).expect("list").is_empty());
    let out = s.handle(&parse_cmd("A5 CLOSE"));
    assert!(out.contains("A5 OK CLOSE completed"));
    assert_eq!(s.state, State::Authenticated);
}

#[test]
fn uid_fetch_and_uid_store() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));

    let out = s.handle(&parse_cmd("A3 UID FETCH 1 BODY[]"));
    assert!(out.contains("BODY[] {15}"));
    assert!(out.contains("ciphertext-blob"));
    assert!(out.contains("A3 OK FETCH completed"));

    let out = s.handle(&parse_cmd("A4 UID STORE 1 +FLAGS (\\Seen)"));
    assert!(out.contains("A4 OK STORE completed"));
    let list = store.list_messages(s.user_id).expect("list");
    assert!(list[0].flags.is_seen());
}

#[test]
fn logout_sends_bye() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 LOGOUT"));
    assert!(out.contains("BYE"));
    assert!(out.contains("A1 OK LOGOUT completed"));
}

#[test]
fn unknown_command_is_bad() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 FROBNICATE"));
    assert!(out.contains("A1 BAD"));
}

#[test]
fn response_helpers() {
    assert_eq!(
        response::tagged("A1", response::Status::Ok, "done"),
        "A1 OK done\r\n"
    );
    assert_eq!(response::untagged("2 EXISTS"), "* 2 EXISTS\r\n");
}

#[test]
fn login_with_wrong_user_rejected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 LOGIN nosuchuser secret"));
    assert!(out.contains("A1 NO"));
    assert_eq!(s.state, State::NotAuthenticated);
}

#[test]
fn login_with_empty_password_rejected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 LOGIN alice \"\""));
    assert!(out.contains("A1 NO"));
}

#[test]
fn double_login_is_bad() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 LOGIN alice secret"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn authenticate_plain_flow() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    // SASL PLAIN token: authzid \0 authcid \0 password
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "\0alice\0secret",
    );
    let out = s.handle(&parse_cmd(&format!("A1 AUTHENTICATE PLAIN {token}")));
    assert!(out.contains("A1 OK"));
    assert_eq!(s.state, State::Authenticated);
}

#[test]
fn authenticate_plain_malformed_payload() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let token =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"too-few-parts");
    let out = s.handle(&parse_cmd(&format!("A1 AUTHENTICATE PLAIN {token}")));
    assert!(out.contains("A1 BAD"));
}

#[test]
fn authenticate_plain_bad_base64() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 AUTHENTICATE PLAIN !!!not-base64!!!"));
    assert!(out.contains("A1 BAD"));
}

#[test]
fn select_nonexistent_mailbox() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 SELECT NOSUCH"));
    assert!(out.contains("A2 NO"));
    assert_eq!(
        s.state,
        State::Authenticated,
        "state unchanged on failed select"
    );
}

#[test]
fn list_shows_inbox() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 LIST \"\" \"*\""));
    assert!(out.contains("INBOX"));
    assert!(out.contains("A2 OK"));
}

#[test]
fn list_requires_auth() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 LIST \"\" \"*\""));
    assert!(out.contains("A1 BAD"));
}

#[test]
fn fetch_requires_selected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 FETCH 1 BODY[]"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn fetch_empty_range_ok() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 FETCH 999 BODY[]"));
    assert!(out.contains("A3 OK FETCH completed"));
}

#[test]
fn store_without_selected_is_bad() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 STORE 1 +FLAGS (\\Seen)"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn store_unsupported_flag_is_bad() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 STORE 1 +FLAGS (\\NoSuchFlag)"));
    assert!(out.contains("A3 BAD"));
}

#[test]
fn store_remove_flag() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    s.handle(&parse_cmd("A3 STORE 1 +FLAGS (\\Seen)"));
    let out = s.handle(&parse_cmd("A4 STORE 1 -FLAGS (\\Seen)"));
    assert!(out.contains("A4 OK STORE completed"));
    let list = store.list_messages(s.user_id).expect("list");
    assert!(!list[0].flags.is_seen());
}

#[test]
fn search_all_matches_everything() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 SEARCH ALL"));
    assert!(out.contains("SEARCH 1"));
}

#[test]
fn uid_search_unseen() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 UID SEARCH UNSEEN"));
    assert!(out.contains("SEARCH 1"));
    assert!(out.contains("A3 OK"));
}

#[test]
fn expunge_requires_selected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 EXPUNGE"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn close_requires_selected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 CLOSE"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn examine_is_like_select() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 EXAMINE INBOX"));
    assert!(out.contains("* 1 EXISTS"));
    assert!(out.contains("A2 OK"));
    assert_eq!(s.state, State::Selected);
}

#[test]
fn idle_requires_selected() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 IDLE"));
    assert!(out.contains("A2 BAD"));
}

#[test]
fn noop_works_in_any_state() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 NOOP"));
    assert!(out.contains("A1 OK NOOP completed"));
}

#[test]
fn capability_reports_imap4rev1() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 CAPABILITY"));
    assert!(out.contains("IMAP4rev1"));
    assert!(out.contains("IDLE"));
    assert!(out.contains("AUTH=PLAIN"));
}

#[test]
fn uid_fetch_range() {
    let (_dir, store, _) = setup();
    let mut s = session_with(Arc::clone(&store));
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 UID FETCH 1:2 BODY[]"));
    assert!(out.contains("A3 OK FETCH completed"));
}

#[test]
fn fetch_range_star() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    s.handle(&parse_cmd("A2 SELECT INBOX"));
    let out = s.handle(&parse_cmd("A3 FETCH * BODY[]"));
    assert!(out.contains("* 1 FETCH"));
    assert!(out.contains("A3 OK FETCH completed"));
}

#[test]
fn namespace_returns_default() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 NAMESPACE"));
    assert!(
        out.contains("NAMESPACE ((\"\" \"/\")) NIL NIL"),
        "got: {out}"
    );
    assert!(out.contains("A2 OK NAMESPACE completed"));
}

#[test]
fn status_reports_counts() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 STATUS INBOX (MESSAGES UNSEEN)"));
    assert!(out.contains("MESSAGES 1"), "got: {out}");
    assert!(out.contains("UNSEEN 1"), "got: {out}");
    assert!(out.contains("A2 OK STATUS completed"));
}

#[test]
fn status_nonexistent_mailbox() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 STATUS NOSUCH (MESSAGES)"));
    assert!(out.contains("A2 NO"));
}

#[test]
fn unsupported_command_is_no_not_bad() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    s.handle(&parse_cmd("A1 LOGIN alice secret"));
    let out = s.handle(&parse_cmd("A2 MOVE 1 INBOX"));
    assert!(out.contains("A2 NO command not supported"), "got: {out}");
}

#[test]
fn capability_advertises_namespace() {
    let (_dir, store, _) = setup();
    let mut s = session_with(store);
    let out = s.handle(&parse_cmd("A1 CAPABILITY"));
    assert!(out.contains("NAMESPACE"), "got: {out}");
}
