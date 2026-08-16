//! Per-user wallet: one zcash_client_sqlite WalletDb per user.

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The wallet manager owns one `zcash_client_sqlite` wallet database per user,
/// stored under `wallet_dir/<user_id>/wallet.db`. This is the v1 skeleton:
/// opening a wallet for a user ensures the directory and wallet file exist.
///
/// The actual scan loop (lightwalletd sync + note scanning) is wired up in M3.
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
