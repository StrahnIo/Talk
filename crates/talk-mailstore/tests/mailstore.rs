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

    let msg = NewMessage {
        message_id: "abc-1".to_string(),
        subject: "New sealed invoice".to_string(),
        body: b"ciphertext-blob".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };

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

    let mk = NewMessage {
        message_id: "dup".to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
    store.append_message(user_id, mk.clone()).expect("first");
    let err = store.append_message(user_id, mk).unwrap_err();
    assert!(matches!(err, StoreError::DuplicateMessage(_)));
}

#[test]
fn fetch_returns_body() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "grace");

    let msg = NewMessage {
        message_id: "m".to_string(),
        subject: "s".to_string(),
        body: b"secret-blob".to_vec(),
        flags: MessageFlags::default(),
    };
    let meta = store.append_message(user_id, msg).expect("append");
    let fetched = store.fetch_message(user_id, meta.id).expect("fetch");
    assert_eq!(fetched.body, b"secret-blob");
}

#[test]
fn flags_and_expunge() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "heidi");

    let msg = NewMessage {
        message_id: "m".to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let msg = NewMessage {
        message_id: "m".to_string(),
        subject: "s".to_string(),
        body: b"data".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
    let a = store.append_message(user_id, mk("a")).expect("a");
    let b = store.append_message(user_id, mk("b")).expect("b");
    assert_eq!(a.uidvalidity, b.uidvalidity);
}

#[test]
fn unknown_user_append_fails() {
    let (_dir, store) = test_store();
    let mk = NewMessage {
        message_id: "x".to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = NewMessage {
        message_id: "shared-id".to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
    // The same message_id is allowed across different users' mailboxes.
    store.append_message(alice, mk.clone()).expect("alice");
    store.append_message(bob, mk).expect("bob");
}

#[test]
fn flags_mask_operations() {
    let (_dir, store) = test_store();
    let user_id = make_user(&store, "flags");
    let mk = NewMessage {
        message_id: "m".to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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

    let mk = |mid: &str| NewMessage {
        message_id: mid.to_string(),
        subject: "s".to_string(),
        body: b"b".to_vec(),
        flags: MessageFlags::default(),
    };
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
