use clap::Parser;
use talk_core::{config::Config, logging, sockets::SocketListener};
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

    let imap_listen = cfg.sockets.imap_listen.clone();
    info!(addr = %imap_listen, "IMAP listener placeholder (M2)");

    // TODO(M2): bind the IMAP TCP listener.
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
