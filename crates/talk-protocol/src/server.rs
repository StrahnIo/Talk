//! ZSMTP server-side connection handling over a Unix socket and/or TCP.
//!
//! The transport is abstracted: both Unix and TCP listeners hand each accepted
//! stream to the same per-connection session runner. TCP may be wrapped in
//! implicit TLS (SMTPS-style, like port 465) using the configured `[tls]`
//! cert/key.

use crate::session::{DeliverySink, UserDirectory, ZsmptSession};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tracing::{info, warn};

/// Serve ZSMTP on a Unix socket, one session per connection.
///
/// `domain` is this server's domain (used for the greeting and as the
/// responder in the domain-key handshake). `domain_key` is the stable signing
/// key published in DNS, so attestations verify across sessions. Every
/// delivered invoice is handed to `sink`; recipients are validated against
/// `directory` (unknown users rejected with 550).
pub async fn serve(
    domain: String,
    domain_key: ed25519_dalek::SigningKey,
    sink: Arc<dyn DeliverySink>,
    directory: Arc<dyn UserDirectory>,
    listener: UnixListener,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let domain = domain.clone();
        let sink = sink.clone();
        let directory = directory.clone();
        let domain_key = domain_key.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            if let Err(e) = serve_connection(&mut stream, domain, domain_key, sink, directory).await
            {
                warn!(error = %e, "zsmtp session closed with error");
            }
        });
    }
}

/// Serve ZSMTP on a TCP listener, optionally wrapped in implicit TLS.
///
/// When `tls` is `Some`, every accepted connection is TLS-wrapped immediately
/// (SMTPS-style, no STARTTLS). When `None`, plaintext is served (dev/testing).
pub async fn serve_tcp(
    domain: String,
    domain_key: ed25519_dalek::SigningKey,
    sink: Arc<dyn DeliverySink>,
    directory: Arc<dyn UserDirectory>,
    tls: Option<Arc<rustls::ServerConfig>>,
    listener: TcpListener,
) {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        info!(peer = %peer, tls = acceptor.is_some(), "zsmtp TCP connection accepted");
        let domain = domain.clone();
        let sink = sink.clone();
        let directory = directory.clone();
        let domain_key = domain_key.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(acceptor) = &acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let mut tls_stream = tls_stream;
                        if let Err(e) =
                            serve_connection(&mut tls_stream, domain, domain_key, sink, directory)
                                .await
                        {
                            warn!(error = %e, "zsmtp TLS session closed with error");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "zsmtp TLS handshake failed");
                    }
                }
            } else if let Err(e) =
                serve_connection(&mut stream, domain, domain_key, sink, directory).await
            {
                warn!(error = %e, "zsmtp session closed with error");
            }
        });
    }
}

/// Run one ZSMTP session over an arbitrary stream.
async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    domain: String,
    domain_key: ed25519_dalek::SigningKey,
    sink: Arc<dyn DeliverySink>,
    directory: Arc<dyn UserDirectory>,
) -> Result<(), crate::framing::FramingError> {
    let mut session = ZsmptSession::with_domain_key(domain, domain_key)
        .with_sink(sink)
        .with_directory(directory);
    info!("zsmtp session started");
    session.run(stream).await
}
