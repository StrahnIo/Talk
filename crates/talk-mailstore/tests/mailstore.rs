use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore, StoreError};

fn test_store() -> (tempfile::TempDir, SqliteMailStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open store");
    (dir, store)
}

fn make_user(store: &SqliteMailStore, name: &str) -> i64 {
    store
        .create_user(name, "hash", &[0u8; 32])
        .expect("create user")
        .id
}

#[test]
fn open_creates_schema() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "alice");
    assert!(user_id > 0);
    let user = store.get_user("alice").expect("get user").expect("exists");
    assert_eq!(user.username, "alice");
}

#[test]
fn duplicate_username_rejected() {
    let (_dir, store) = test_store();
    make_user(&store, "bob");
    let err = store.create_user("bob", "hash", &[0u8; 32]).unwrap_err();
    assert!(matches!(err, StoreError::Storage(_)));
}

#[test]
fn append_and_list_messages() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "carol");

    let msg = NewMessage::invoice(
        "abc-1".to_string(),
        "New sealed invoice".to_string(),
        b"ciphertext-blob".to_vec(),
    );
    let meta = store.append_message(user_id, msg).expect("append");
    assert_eq!(meta.uid, 1);
    assert_eq!(meta.size, b"ciphertext-blob".len() as u64);

    let list = store.list_messages(user_id).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].message_id, "abc-1");
    assert_eq!(list[0].uidvalidity, meta.uidvalidity);
}

#[test]
fn uid_increments_per_mailbox() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "dave");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());

    let a = store.append_message(user_id, mk("a")).expect("a");
    let b = store.append_message(user_id, mk("b")).expect("b");
    assert_eq!(a.uid, 1);
    assert_eq!(b.uid, 2);

    let other = make_user(&store, "erin");
    let c = store.append_message(other, mk("c")).expect("c");
    assert_eq!(c.uid, 1, "uid is per-mailbox");
}

#[test]
fn duplicate_message_id_rejected() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "frank");

    let mk = NewMessage::invoice("dup".to_string(), "s".to_string(), b"b".to_vec());
    store.append_message(user_id, mk.clone()).expect("first");
    let err = store.append_message(user_id, mk).unwrap_err();
    assert!(matches!(err, StoreError::DuplicateMessage(_)));
}

#[test]
fn fetch_returns_body() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "grace");

    let msg = NewMessage::invoice("m".to_string(), "s".to_string(), b"secret-blob".to_vec());
    let meta = store.append_message(user_id, msg).expect("append");
    let fetched = store.fetch_message(user_id, meta.id).expect("fetch");
    assert_eq!(fetched.body, b"secret-blob");
}

#[test]
fn flags_and_expunge() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "heidi");

    let msg = NewMessage::invoice("m".to_string(), "s".to_string(), b"b".to_vec());
    let meta = store.append_message(user_id, msg).expect("append");

    store
        .set_flags(user_id, meta.id, MessageFlags::SEEN, true)
        .expect("set seen");
    let list = store.list_messages(user_id).expect("list");
    assert!(list[0].flags.is_seen());

    store
        .set_flags(user_id, meta.id, MessageFlags::DELETED, true)
        .expect("set deleted");
    let expunged = store.expunge(user_id).expect("expunge");
    assert_eq!(expunged, vec![1]);
    assert!(store.list_messages(user_id).expect("list").is_empty());
}

#[test]
fn store_reopen_preserves_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen.db");

    let store = SqliteMailStore::open(&path).expect("open");
    let user_id = make_user(&store, "ivan");

    let msg = NewMessage::invoice("m".to_string(), "s".to_string(), b"data".to_vec());
    store.append_message(user_id, msg).expect("append");
    drop(store);

    let store = SqliteMailStore::open(&path).expect("reopen");
    assert_eq!(store.list_messages(user_id).expect("list").len(), 1);
}

#[test]
fn users_are_isolated() {
    let (_dir, store) = test_store();
    let alice = make_user(&store, "alice2");
    let bob = make_user(&store, "bob2");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    store.append_message(alice, mk("alice-1")).expect("alice");
    store.append_message(bob, mk("bob-1")).expect("bob");

    let alice_msgs = store.list_messages(alice).expect("alice list");
    let bob_msgs = store.list_messages(bob).expect("bob list");
    assert_eq!(alice_msgs.len(), 1);
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(alice_msgs[0].message_id, "alice-1");
    assert_eq!(bob_msgs[0].message_id, "bob-1");
}

#[test]
fn list_is_newest_first() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "newest");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    store.append_message(user_id, mk("first")).expect("first");
    store.append_message(user_id, mk("second")).expect("second");

    let list = store.list_messages(user_id).expect("list");
    assert_eq!(list[0].message_id, "second", "newest uid first");
    assert_eq!(list[1].message_id, "first");
}

#[test]
fn uid_continues_after_delete() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "uidcont");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    let first = store.append_message(user_id, mk("a")).expect("a");
    store
        .set_flags(user_id, first.id, MessageFlags::DELETED, true)
        .expect("del");
    store.expunge(user_id).expect("expunge");

    let next = store.append_message(user_id, mk("b")).expect("b");
    assert_eq!(next.uid, 2, "uid must not be reused after expunge");
}

#[test]
fn uid_validity_stable_for_user() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "uidval");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    let a = store.append_message(user_id, mk("a")).expect("a");
    let b = store.append_message(user_id, mk("b")).expect("b");
    assert_eq!(a.uidvalidity, b.uidvalidity);
}

#[test]
fn unknown_user_append_fails() {
    let (_dir, store) = test_store();
    let mk = NewMessage::invoice("x".to_string(), "s".to_string(), b"b".to_vec());
    assert!(store.append_message(999, mk).is_err());
}

#[test]
fn unknown_user_list_is_empty_error() {
    let (_dir, store) = test_store();
    assert!(store.list_messages(999).is_err());
}

#[test]
fn fetch_missing_message_fails() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "missing");
    assert!(store.fetch_message(user_id, 12345).is_err());
}

#[test]
fn set_flags_missing_message_is_ok_noop() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "noop");
    // Setting flags on a non-existent message should not error.
    store
        .set_flags(user_id, 9999, MessageFlags::SEEN, true)
        .expect("noop set");
}

#[test]
fn message_id_unique_across_users() {
    let (_dir, store) = test_store();
    let alice = make_user(&store, "dup-a");
    let bob = make_user(&store, "dup-b");

    let mk = NewMessage::invoice("shared-id".to_string(), "s".to_string(), b"b".to_vec());
    // The same message_id is allowed across different users' mailboxes.
    store.append_message(alice, mk.clone()).expect("alice");
    store.append_message(bob, mk).expect("bob");
}

#[test]
fn flags_mask_operations() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "flags");
    let mk = NewMessage::invoice("m".to_string(), "s".to_string(), b"b".to_vec());
    let meta = store.append_message(user_id, mk).expect("append");

    store
        .set_flags(user_id, meta.id, MessageFlags::SEEN, true)
        .expect("seen on");
    store
        .set_flags(user_id, meta.id, MessageFlags::SEEN, false)
        .expect("seen off");
    let list = store.list_messages(user_id).expect("list");
    assert!(!list[0].flags.is_seen(), "flag must be removable");
}

#[test]
fn empty_expunge_is_noop() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "emptydel");
    let uids = store.expunge(user_id).expect("expunge empty");
    assert!(uids.is_empty());
}

#[test]
fn expunge_returns_sorted_uids() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "sorted");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    let a = store.append_message(user_id, mk("a")).expect("a");
    let b = store.append_message(user_id, mk("b")).expect("b");
    store
        .set_flags(user_id, a.id, MessageFlags::DELETED, true)
        .expect("del a");
    store
        .set_flags(user_id, b.id, MessageFlags::DELETED, true)
        .expect("del b");

    let uids = store.expunge(user_id).expect("expunge");
    assert_eq!(uids, vec![1, 2], "expunged uids in ascending order");
}

#[test]
fn expunge_keeps_undeleted() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "partial");

    let mk = |mid: &str| NewMessage::invoice(mid.to_string(), "s".to_string(), b"b".to_vec());
    let keep = store.append_message(user_id, mk("keep")).expect("keep");
    let del = store.append_message(user_id, mk("del")).expect("del");
    store
        .set_flags(user_id, del.id, MessageFlags::DELETED, true)
        .expect("del");

    let uids = store.expunge(user_id).expect("expunge");
    assert_eq!(uids, vec![2]);

    let list = store.list_messages(user_id).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, keep.id);
}

#[test]
fn message_stores_sender() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "sender-test");
    let mut msg = NewMessage::invoice("m1", "s", b"b".to_vec());
    msg.sender = "alice@example.org".to_string();
    store.append_message(user_id, msg).expect("append");
    let list = store.list_messages(user_id).expect("list");
    assert_eq!(list[0].sender, "alice@example.org");
    assert_eq!(list[0].trust_state, "unverified");
}

#[test]
fn keyring_pin_and_lookup() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "kr");
    // Not pinned yet.
    assert!(
        store
            .keyring_sender_key(user_id, "alice@example.org")
            .expect("lookup")
            .is_none()
    );
    // Pin.
    store
        .keyring_set_trusted(user_id, "alice@example.org", "pubkey-hex", b"attestation")
        .expect("pin");
    assert_eq!(
        store
            .keyring_sender_key(user_id, "alice@example.org")
            .expect("lookup")
            .as_deref(),
        Some("pubkey-hex")
    );
    // Different user's keyring is independent.
    let other = make_user(&store, "kr2");
    assert!(
        store
            .keyring_sender_key(other, "alice@example.org")
            .expect("lookup")
            .is_none()
    );
}

#[test]
fn keyring_pin_updates_existing() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "kr3");
    store
        .keyring_set_trusted(user_id, "bob@example.org", "key1", b"att1")
        .expect("pin1");
    store
        .keyring_set_trusted(user_id, "bob@example.org", "key2", b"att2")
        .expect("pin2");
    assert_eq!(
        store
            .keyring_sender_key(user_id, "bob@example.org")
            .expect("lookup")
            .as_deref(),
        Some("key2"),
        "re-pin must update the key"
    );
}

#[test]
fn message_trust_state_roundtrip() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "ts");
    let mut msg = NewMessage::invoice("m1", "s", b"b".to_vec());
    msg.sender = "alice@example.org".to_string();
    msg.trust_state = "trusted".to_string();
    store.append_message(user_id, msg).expect("append");
    let list = store.list_messages(user_id).expect("list");
    assert_eq!(list[0].sender, "alice@example.org");
    assert_eq!(list[0].trust_state, "trusted");
}

#[test]
fn list_users_reports_summaries() {
    let (_dir, store) = test_store();
    make_user(&store, "zeta");
    store
        .create_user_full(
            "alistair",
            "hash",
            &[1u8; 32],
            Some("ivk-hex".into()),
            Some("R".into()),
        )
        .expect("create full");

    let users = store.list_users().expect("list");
    assert_eq!(users.len(), 2);
    let alistair = users.iter().find(|u| u.username == "alistair").unwrap();
    assert!(alistair.has_ivk);
    assert!(alistair.has_attestation);
    let zeta = users.iter().find(|u| u.username == "zeta").unwrap();
    assert!(!zeta.has_ivk);
    assert!(!zeta.has_attestation);
    assert!(alistair.created_at > 0);
}

#[test]
fn set_password_changes_hash() {
    let (_dir, store) = test_store();
    make_user(&store, "pwuser");
    store.set_password("pwuser", "new-hash").expect("set");
    assert_eq!(
        store.password_hash("pwuser").expect("get").as_deref(),
        Some("new-hash")
    );
    assert!(store.set_password("missing", "h").is_err());
}

#[test]
fn set_ivk_sets_and_clears() {
    let (_dir, store) = test_store();
    make_user(&store, "ivkuser");
    store.set_ivk("ivkuser", Some("ivk-hex")).expect("set");
    assert_eq!(
        store
            .get_user("ivkuser")
            .expect("get")
            .unwrap()
            .ivk_commitment
            .as_deref(),
        Some("ivk-hex")
    );
    store.set_ivk("ivkuser", None).expect("clear");
    assert!(
        store
            .get_user("ivkuser")
            .expect("get")
            .unwrap()
            .ivk_commitment
            .is_none()
    );
    assert!(store.set_ivk("missing", None).is_err());
}

#[test]
fn delete_user_cascades() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "doomed");
    store.add_share(user_id, "s1", b"wrapped").expect("share");
    store
        .keyring_set_trusted(user_id, "alice@example.org", "k", b"att")
        .expect("pin");
    store
        .append_message(user_id, NewMessage::invoice("m", "s", b"b".to_vec()))
        .expect("append");

    store.delete_user("doomed").expect("delete");
    assert!(store.get_user("doomed").expect("get").is_none());
    assert!(store.list_messages(user_id).is_err(), "mailbox gone");
    assert!(store.list_shares(user_id).expect("shares").is_empty());
    assert!(store.list_keyring(user_id).expect("keyring").is_empty());
    assert!(store.delete_user("doomed").is_err(), "second delete fails");
}

#[test]
fn shares_list_revoked_and_add() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "shares");
    store.add_share(user_id, "s1", b"w1").expect("add1");
    store.add_share(user_id, "s2", b"w2").expect("add2");

    let list = store.list_shares(user_id).expect("list");
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|s| !s.revoked));

    store.revoke_share(user_id, "s1").expect("revoke");
    let list = store.list_shares(user_id).expect("list");
    let s1 = list.iter().find(|s| s.share_id == "s1").unwrap();
    assert!(s1.revoked);
    assert_eq!(s1.wrapped_dk, b"w1", "wrapped dk retained after revoke");

    // Revoked shares are excluded from the active (app-password) set.
    let active = store.get_shares(user_id).expect("active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, "s2");

    assert!(store.revoke_share(user_id, "nope").is_err());
}

#[test]
fn keyring_list_and_unpin() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "krlist");
    store
        .keyring_set_trusted(user_id, "a@example.org", "ka", b"att")
        .expect("pin a");
    store
        .keyring_set_trusted(user_id, "b@example.org", "kb", b"att")
        .expect("pin b");

    let entries = store.list_keyring(user_id).expect("list");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.state == "trusted"));
    assert!(entries.iter().all(|e| e.first_seen > 0));

    store
        .unpin_keyring(user_id, "a@example.org")
        .expect("unpin");
    let entries = store.list_keyring(user_id).expect("list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sender_mailbox, "b@example.org");
    assert!(store.unpin_keyring(user_id, "missing@example.org").is_err());
}

#[test]
fn settings_crud() {
    let (_dir, store) = test_store();
    assert!(store.get_setting("k").expect("get").is_none());

    store.set_setting("k", "v1").expect("set");
    store.set_setting("k", "v2").expect("overwrite");
    assert_eq!(store.get_setting("k").expect("get").as_deref(), Some("v2"));

    store.set_setting("other", "x").expect("set other");
    let all = store.list_settings().expect("list");
    assert_eq!(
        all,
        vec![
            ("k".to_string(), "v2".to_string()),
            ("other".to_string(), "x".to_string())
        ]
    );

    store.delete_setting("k").expect("delete");
    assert!(store.get_setting("k").expect("get").is_none());
    assert!(store.delete_setting("k").is_err());
}

#[test]
fn users_have_inbox_and_sent() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "multibox");
    let inbox = store.list_messages_in(user_id, talk_mailstore::INBOX).expect("inbox");
    let sent = store.list_messages_in(user_id, talk_mailstore::SENT).expect("sent");
    assert!(inbox.is_empty());
    assert!(sent.is_empty());

    // Same message id can live in both mailboxes independently.
    let mk = |mid: &str, sub: &str| NewMessage::invoice(mid.to_string(), sub.to_string(), b"b".to_vec());
    store
        .append_message_to(user_id, talk_mailstore::INBOX, mk("m1", "received"))
        .expect("append inbox");
    store
        .append_message_to(user_id, talk_mailstore::SENT, mk("m1", "sent copy"))
        .expect("append sent");

    assert_eq!(store.list_messages_in(user_id, talk_mailstore::INBOX).expect("inbox").len(), 1);
    let sent = store.list_messages_in(user_id, talk_mailstore::SENT).expect("sent");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "sent copy");
    assert_eq!(sent[0].uid, 1, "uids are per-mailbox");
    assert_eq!(store.uidnext_in(user_id, talk_mailstore::SENT).expect("uidnext"), 2);
}

#[test]
fn transactions_ledger_crud() {
    let (_dir, store) = test_store();
    let t = store
        .tx_create(talk_mailstore::NewTransaction {
            direction: talk_mailstore::TxDirection::In,
            state: talk_mailstore::TxState::Opaque,
            sender_mailbox: "alice@example.org".to_string(),
            recipient_mailbox: "bob@talk.local".to_string(),
            amount: "1.5".to_string(),
            binding: None,
            message_id: "msg-tx-1".to_string(),
            outbound_body: None,
            payload: "sealed".to_string(),
        })
        .expect("create");

    assert_eq!(t.state, talk_mailstore::TxState::Opaque);
    assert!(t.created_at > 0);
    assert_eq!(t.amount, "1.5");

    // Lookup by id and by (direction, message_id).
    let got = store.tx_get(t.id).expect("get").expect("exists");
    assert_eq!(got.message_id, "msg-tx-1");
    let by_mid = store
        .tx_by_message_id(talk_mailstore::TxDirection::In, "msg-tx-1")
        .expect("by mid")
        .expect("exists");
    assert_eq!(by_mid.id, t.id);

    // Transition + list filters.
    store
        .tx_transition(t.id, talk_mailstore::TxState::Resolved)
        .expect("transition");
    let got = store.tx_get(t.id).expect("get").expect("exists");
    assert_eq!(got.state, talk_mailstore::TxState::Resolved);

    let out = store
        .tx_create(talk_mailstore::NewTransaction {
            direction: talk_mailstore::TxDirection::Out,
            state: talk_mailstore::TxState::Sent,
            sender_mailbox: "bob@talk.local".to_string(),
            recipient_mailbox: "alice@example.org".to_string(),
            amount: String::new(),
            binding: None,
            message_id: "msg-tx-2".to_string(),
            outbound_body: Some(b"invoice body".to_vec()),
            payload: "sealed".to_string(),
        })
        .expect("create out");
    assert_eq!(out.outbound_body.as_deref(), Some(&b"invoice body"[..]));

    let all = store.tx_list(None, None).expect("all");
    assert_eq!(all.len(), 2);
    let in_only = store.tx_list(Some(talk_mailstore::TxDirection::In), None).expect("in");
    assert_eq!(in_only.len(), 1);
    let resolved = store.tx_list(None, Some(talk_mailstore::TxState::Resolved)).expect("resolved");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].id, t.id);
}

#[test]
fn message_links_to_transaction_state() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "txlink");

    let meta = store
        .append_message(user_id, NewMessage::invoice("m1", "s", b"b".to_vec()))
        .expect("append");
    // No tx yet → tx_state None.
    let listed = store.list_messages(user_id).expect("list");
    assert!(listed[0].tx_state.is_none());

    let tx = store
        .tx_create(talk_mailstore::NewTransaction {
            direction: talk_mailstore::TxDirection::In,
            state: talk_mailstore::TxState::Opaque,
            sender_mailbox: "alice@example.org".to_string(),
            recipient_mailbox: "txlink@talk.local".to_string(),
            amount: "0.5".to_string(),
            binding: None,
            message_id: "m1".to_string(),
            outbound_body: None,
            payload: "sealed".to_string(),
        })
        .expect("tx");
    store.tx_link_message(tx.id, meta.id).expect("link");

    let listed = store.list_messages(user_id).expect("list");
    assert_eq!(listed[0].tx_state.as_deref(), Some("opaque"));
}
