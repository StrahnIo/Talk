use clap::Parser;
use std::sync::Arc;
use talk_core::{config::Config, logging, sockets::SocketListener};
use talk_imap::server::ImapServer;
use talk_mailstore::SqliteMailStore;
use talk_protocol::server as zsmpt_server;
use talk_wallet::LightwalletdClient;
use tracing::{error, info, warn};

mod sink;

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

    // Open the mailbox store.
    let mailbox_db = cfg.general.data_dir.join("mailbox.db");
    let store = Arc::new(SqliteMailStore::open(&mailbox_db)?);
    info!(path = %mailbox_db.display(), "mailbox store open");

    // Serve ZSMTP sessions on the zsmtp socket, delivering into the store.
    let zsmtp_domain = cfg
        .general
        .data_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "talkd.local".to_string());
    let zsmtp_listener = zsmtp.to_tokio()?;

    let imap = ImapServer::new(store.clone(), "talkd");
    let sink = Arc::new(sink::StoreDeliverySink::new(store).with_events(imap.event_sender()));
    tokio::spawn(zsmpt_server::serve(zsmtp_domain, sink, zsmtp_listener));

    let imap_addr = cfg.sockets.imap_listen.clone();
    tokio::spawn(async move {
        if let Err(e) = imap.listen(&imap_addr).await {
            error!(error = %e, "IMAP listener failed");
        }
    });

    // Connect to the lightwalletd indexer. A failure here is non-fatal at boot
    // (the daemon can start without the indexer and retry), but we log it and
    // still report the last-known height if a connection is made.
    let indexer_url = cfg.network.indexer_url.clone();
    tokio::spawn(async move {
        match LightwalletdClient::connect(&indexer_url).await {
            Ok(mut client) => match client.latest_height().await {
                Ok(height) => {
                    info!(indexer = %indexer_url, height, "lightwalletd indexer connected")
                }
                Err(e) => warn!(error = %e, "indexer height fetch failed"),
            },
            Err(e) => warn!(error = %e, "indexer connect failed"),
        }
    });

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
