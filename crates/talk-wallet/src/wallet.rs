//! Per-user wallet: one zcash_client_sqlite WalletDb per user, and the
//! username↔wallet resolver that binds a mailbox identity to key material.

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("user not found: {0}")]
    UserNotFound(String),
}

/// The resolved wallet binding for a username.
#[derive(Debug, Clone)]
pub struct WalletBinding {
    pub username: String,
    /// The wallet's public encryption key (hex, from registration).
    pub master_pubkey: Vec<u8>,
    /// Optional IVK commitment (hex) — present if the user enabled dynamic
    /// addresses. The IVK itself never lives on the server.
    pub ivk_commitment: Option<String>,
    /// Path to the user's wallet database.
    pub wallet_db_path: PathBuf,
}

/// The wallet manager owns one `zcash_client_sqlite` wallet database per user,
/// stored under `wallet_dir/<user_id>/wallet.db`.
pub struct UserWallet {
    pub user_id: i64,
    path: PathBuf,
}

impl UserWallet {
    /// Open (or create) the wallet for `user_id` under `wallet_dir`.
    pub fn open(wallet_dir: &Path, user_id: i64) -> Result<Self, WalletError> {
        let path = wallet_dir.join(user_id.to_string()).join("wallet.db");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { user_id, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Resolves a username to its wallet binding, backed by the mailbox store.
///
/// The store is the source of truth for the registration (pubkey + IVK
/// commitment); this resolver bridges the mailbox identity to wallet key
/// material and the per-user wallet DB path.
pub struct WalletResolver {
    wallet_dir: PathBuf,
    store: talk_mailstore::SqliteMailStore,
}

impl WalletResolver {
    pub fn new(wallet_dir: impl Into<PathBuf>, store: talk_mailstore::SqliteMailStore) -> Self {
        Self {
            wallet_dir: wallet_dir.into(),
            store,
        }
    }

    /// Resolve `username` to its wallet binding.
    pub fn resolve(&self, username: &str) -> Result<WalletBinding, WalletError> {
        let user = self
            .store
            .get_user(username)
            .map_err(|_| WalletError::UserNotFound(username.to_string()))?
            .ok_or_else(|| WalletError::UserNotFound(username.to_string()))?;
        let wallet_db_path = self.wallet_dir.join(user.id.to_string()).join("wallet.db");
        Ok(WalletBinding {
            username: user.username,
            master_pubkey: user.master_pubkey,
            ivk_commitment: user.ivk_commitment,
            wallet_db_path,
        })
    }
}
