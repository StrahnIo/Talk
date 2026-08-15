use clap::Parser;
use std::sync::Arc;
use talk_core::{config::Config, logging, sockets::SocketListener};
use talk_imap::server::ImapServer;
use talk_mailstore::SqliteMailStore;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(name = "talkd", version, about = "ZSMTP mail daemon for Zcash")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    logging::init(&cfg.general.log_level);
    info!(config = %cli.config.display(), "loading config");

    if let Err(e) = run(cfg).await {
        error!(error = %e, "talkd exiting with error");
        std::process::exit(1);
    }
}

async fn run(cfg: talk_core::config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let secure_mailbox = SocketListener::bind(&cfg.sockets.secure_mailbox)?;
    info!(path = %secure_mailbox.local_path().display(), "secure_mailbox.sock listening");

    let zsmtp = SocketListener::bind(&cfg.sockets.zsmtp)?;
    info!(path = %zsmtp.local_path().display(), "zsmtp.sock listening");

    // Open the mailbox store (SQLCipher when encrypt_db is set).
    let mailbox_db = cfg.general.data_dir.join("mailbox.db");
    let passphrase = if cfg.mailbox.encrypt_db {
        Some(cfg.mailbox.passphrase.as_str())
    } else {
        None
    };
    let store = SqliteMailStore::open(&mailbox_db, cfg.mailbox.encrypt_db, passphrase)?;
    info!(path = %mailbox_db.display(), encrypted = cfg.mailbox.encrypt_db, "mailbox store open");

    let imap = ImapServer::new(Arc::new(store), "talkd");
    let imap_addr = cfg.sockets.imap_listen.clone();
    tokio::spawn(async move {
        if let Err(e) = imap.listen(&imap_addr).await {
            error!(error = %e, "IMAP listener failed");
        }
    });

    // TODO(M3): connect to lightwalletd indexer, spawn per-user wallet scan loops.

    let (ctrlc_tx, mut ctrlc_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = ctrlc_tx.send(()).await;
    });

    info!("talkd ready; awaiting shutdown signal");
    let _ = ctrlc_rx.recv().await;
    info!("shutting down");

    drop(secure_mailbox);
    drop(zsmtp);
    Ok(())
}
