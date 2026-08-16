//! talkctl — the Talk daemon's account and settings CLI.
//!
//! Management, config, and settings ops act directly on the mailbox DB and
//! config file (offline-capable, run as the daemon's OS user). `attest` and
//! `send` prefer the running daemon's `secure_mailbox.sock` and fall back to
//! direct domain-key signing / an outbound ZSMTP client when the daemon is
//! down.

pub mod config_cmd;
pub mod key;
pub mod remote;
pub mod store;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "talkctl",
    version,
    about = "Manage Talk daemon accounts and settings"
)]
pub struct Cli {
    /// Path to the daemon TOML config (default: config.toml in the cwd).
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Daemon, store, and domain summary.
    Status,
    /// Inspect and edit the daemon config file.
    Config {
        #[command(subcommand)]
        action: config_cmd::ConfigAction,
    },
    /// Server-side key/value settings.
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
    },
    /// User account management.
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// App-password shares (DK wrappers).
    Share {
        #[command(subcommand)]
        action: ShareAction,
    },
    /// Sender keyring (trusted senders).
    Keyring {
        #[command(subcommand)]
        action: KeyringAction,
    },
    /// X25519 master keypair and ECIES seal/unseal.
    Key {
        #[command(subcommand)]
        action: key::KeyAction,
    },
    /// Request an address attestation for a user.
    Attest {
        user: String,
        #[arg(value_parser = ["ephemeral", "attested"])]
        mode: String,
    },
    /// Deliver an invoice to a recipient mailbox.
    Send {
        sender: String,
        recipient: String,
        /// File containing the opaque invoice body.
        file: PathBuf,
        /// Mark the payload as plaintext (default: sealed).
        #[arg(long)]
        plaintext: bool,
        /// Explicit message id (default: auto-generated).
        #[arg(long)]
        message_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SettingsAction {
    /// List all settings.
    List,
    /// Read one setting.
    Get { key: String },
    /// Set (or upsert) one setting.
    Set { key: String, value: String },
    /// Delete one setting.
    Delete { key: String },
}

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// List all users.
    List,
    /// Show one user in detail.
    Show { username: String },
    /// Create a user (register).
    Create {
        username: String,
        /// Plaintext password (prompts securely if omitted).
        #[arg(long)]
        password: Option<String>,
        /// Client-supplied master public key, 32 bytes of hex (required).
        #[arg(long)]
        pubkey: String,
        /// Optional IVK commitment, 32 bytes of hex.
        #[arg(long)]
        ivk: Option<String>,
        /// Also generate this many app-password shares (fresh DK).
        #[arg(long, default_value_t = 0)]
        shares: u32,
    },
    /// Delete a user and all their data.
    Delete { username: String },
    /// Change a user's password.
    Passwd {
        username: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Set a user's IVK commitment.
    SetIvk { username: String, ivk: String },
    /// Clear a user's IVK commitment.
    UnsetIvk { username: String },
}

#[derive(Debug, Subcommand)]
pub enum ShareAction {
    /// List a user's shares (with revoked state).
    List { username: String },
    /// Generate a fresh DK and wrap it under N shares (prints secrets once).
    Init {
        username: String,
        #[arg(long, default_value_t = 8)]
        shares: u32,
    },
    /// Revoke a share by id.
    Revoke { username: String, share_id: String },
}

#[derive(Debug, Subcommand)]
pub enum KeyringAction {
    /// Pin a sender as trusted for a user.
    Pin {
        username: String,
        sender: String,
        /// Sender's attested pubkey (hex). Required for a meaningful pin.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// List a user's pinned senders.
    List { username: String },
    /// Remove a pinned sender.
    Unpin { username: String, sender: String },
}

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("{0}")]
    Config(#[from] talk_core::config::ConfigError),
    #[error("{0}")]
    Store(#[from] talk_mailstore::StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] talk_protocol::framing::FramingError),
    #[error("{0}")]
    Message(String),
}

impl CtlError {
    pub fn msg(s: impl Into<String>) -> Self {
        CtlError::Message(s.into())
    }
}

/// Run a parsed CLI to completion.
pub fn run(cli: Cli) -> Result<(), CtlError> {
    let config = cli.config.as_deref();
    match cli.command {
        Command::Status => store::status(config),
        Command::Config { action } => config_cmd::run(config, action),
        Command::Settings { action } => store::settings_run(config, action),
        Command::User { action } => store::user_run(config, action),
        Command::Share { action } => store::share_run(config, action),
        Command::Keyring { action } => store::keyring_run(config, action),
        Command::Key { action } => key::run(action),
        Command::Attest { user, mode } => remote::attest(config, &user, &mode),
        Command::Send {
            sender,
            recipient,
            file,
            plaintext,
            message_id,
        } => remote::send(
            config,
            &sender,
            &recipient,
            &file,
            plaintext,
            message_id.as_deref(),
        ),
    }
}
