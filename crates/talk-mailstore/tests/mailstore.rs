use talk_mailstore::{MessageFlags, NewMessage, SqliteMailStore, StoreError};

fn test_store() -> (tempfile::TempDir, SqliteMailStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        SqliteMailStore::open(dir.path().join("mailbox.db"), false, None).expect("open store");
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
fn sqlcipher_key_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("enc.db");

    let store = SqliteMailStore::open(&path, true, Some("correct horse")).expect("open");
    let user_id = make_user(&store, "ivan");

    let msg = NewMessage {
        message_id: "m".to_string(),
        subject: "s".to_string(),
        body: b"ciphertext".to_vec(),
        flags: MessageFlags::default(),
    };
    store.append_message(user_id, msg).expect("append");
    drop(store);

    // Reopen with the same key must succeed and see the data.
    let store = SqliteMailStore::open(&path, true, Some("correct horse")).expect("reopen");
    assert_eq!(store.list_messages(user_id).expect("list").len(), 1);

    drop(store);

    // Reopening with the wrong key must fail.
    assert!(SqliteMailStore::open(&path, true, Some("wrong key")).is_err());
}
