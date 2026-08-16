use talk_mailstore::{hash_password, SqliteMailStore};
use talk_wallet::WalletResolver;

#[test]
fn resolver_maps_username_to_wallet_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open");
    let pubkey = [9u8; 32];
    let hash = hash_password("pw").expect("hash");
    store
        .create_user_full("alice", &hash, &pubkey, Some("ivk-commit".to_string()), None)
        .expect("create");

    let resolver = WalletResolver::new(dir.path().join("wallets"), store);
    let binding = resolver.resolve("alice").expect("resolve");
    assert_eq!(binding.username, "alice");
    assert_eq!(binding.master_pubkey, pubkey);
    assert_eq!(binding.ivk_commitment.as_deref(), Some("ivk-commit"));
    let path_str = binding.wallet_db_path.to_string_lossy().to_string();
    assert!(path_str.ends_with("/wallets/1/wallet.db"), "got: {path_str}");
}

#[test]
fn resolver_rejects_unknown_user() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteMailStore::open(dir.path().join("mailbox.db")).expect("open");
    let resolver = WalletResolver::new(dir.path().join("wallets"), store);
    assert!(resolver.resolve("ghost").is_err());
}
