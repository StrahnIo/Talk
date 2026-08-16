use clap::Parser;
use std::sync::Arc;
use talk_core::{config::Config, logging, sockets::SocketListener};
use talk_imap::server::ImapServer;
use talk_mailstore::SqliteMailStore;
use talk_protocol::server as zsmtp_server;
use talk_wallet::LightwalletdClient;
use tracing::{error, info, warn};

mod secure;
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
    // Select the ring-based crypto provider before any rustls use.
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    // Serve the local user↔daemon interface.
    let sender_domain = cfg
        .general
        .data_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "talkd.local".to_string());

    // The stable domain signing key. Persisted so DNS-published attestations
    // verify across restarts.
    let domain_key = sink::load_or_create_domain_key(&cfg.general.data_dir)?;

    // Open the mailbox store.
    let mailbox_db = cfg.general.data_dir.join("mailbox.db");
    let store = Arc::new(SqliteMailStore::open(&mailbox_db)?);
    info!(path = %mailbox_db.display(), "mailbox store open");

    let handler = std::sync::Arc::new(secure::SecureMailboxService::new(
        &sender_domain,
        &cfg.network.send_endpoint,
        domain_key.clone(),
        store.clone(),
    ));
    let mailbox_listener = secure_mailbox.to_tokio()?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match mailbox_listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "secure_mailbox accept failed");
                    continue;
                }
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = talk_protocol::mailbox::serve(&mut stream, handler.as_ref()).await;
            });
        }
    });

    let zsmtp = SocketListener::bind(&cfg.sockets.zsmtp)?;
    info!(path = %zsmtp.local_path().display(), "zsmtp.sock listening");

    // Serve ZSMTP sessions on the zsmtp socket, delivering into the store.
    let zsmtp_listener = zsmtp.to_tokio()?;
    let zsmtp_domain = sender_domain.clone();

    let mut imap = ImapServer::new(store.clone(), "talkd");
    // Set the user auth mode from config.
    let imap_auth = match cfg.auth.mode {
        talk_core::config::AuthMode::Database => talk_imap::AuthMode::Database,
        talk_core::config::AuthMode::LocalAuth => talk_imap::AuthMode::LocalAuth,
    };
    imap = imap.with_auth_mode(imap_auth);
    // Load the TLS server config once (shared by IMAPS and ZSMTP-over-TLS).
    let tls_config: Option<std::sync::Arc<rustls::ServerConfig>> =
        if cfg.tls.cert.exists() && cfg.tls.key.exists() {
            match talk_imap::tls::load_server_config(&cfg.tls.cert, &cfg.tls.key) {
                Ok(config) => {
                    info!(cert = %cfg.tls.cert.display(), "TLS enabled");
                    Some(config)
                }
                Err(e) => {
                    error!(error = %e, "failed to load TLS config");
                    None
                }
            }
        } else {
            info!("no TLS cert/key configured; plaintext only");
            None
        };
    if let Some(config) = &tls_config {
        imap = imap.with_tls(config.clone());
    }
    let sink =
        Arc::new(sink::StoreDeliverySink::new(store.clone()).with_events(imap.event_sender()));
    let directory = Arc::new(sink::StoreUserDirectory::new(store.clone()));
    tokio::spawn(zsmtp_server::serve(
        zsmtp_domain.clone(),
        domain_key.clone(),
        sink.clone(),
        directory.clone(),
        zsmtp_listener,
    ));

    // ZSMTP over TCP (implicit TLS, SMTPS-style). If no TLS config, serve
    // plaintext with a warning.
    let zsmtp_listen = cfg.sockets.zsmtp_listen.clone();
    let tcp_listener = match tokio::net::TcpListener::bind(&zsmtp_listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %zsmtp_listen, "ZSMTP TCP listener failed to bind");
            return Err(e.into());
        }
    };
    info!(addr = %zsmtp_listen, tls = tls_config.is_some(), "ZSMTP TCP listening");
    tokio::spawn(zsmtp_server::serve_tcp(
        zsmtp_domain,
        domain_key,
        sink,
        directory,
        tls_config,
        tcp_listener,
    ));

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
