//! ZSMTP server-side connection handling over a Unix socket.

use crate::session::{DeliverySink, ZsmptSession};
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{info, warn};

/// Serve ZSMTP on a Unix socket, one session per connection.
///
/// `domain` is this server's domain (used for the greeting and as the
/// responder in the domain-key handshake). `domain_key` is the stable signing
/// key published in DNS, so attestations verify across sessions. Every
/// delivered invoice is handed to `sink`.
pub async fn serve(
    domain: String,
    domain_key: ed25519_dalek::SigningKey,
    sink: Arc<dyn DeliverySink>,
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
        let domain_key = domain_key.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut session = ZsmptSession::with_domain_key(domain, domain_key).with_sink(sink);
            info!("zsmpt session started");
            if let Err(e) = session.run(&mut stream).await {
                warn!(error = %e, "zsmpt session closed with error");
            }
        });
    }
}
