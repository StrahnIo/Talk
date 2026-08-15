//! ZSMTP server-side connection handling over a Unix socket.

use crate::session::{DeliverySink, ZsmptSession};
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{info, warn};

/// Serve ZSMTP on a Unix socket, one session per connection.
///
/// `domain` is this server's domain (used for the greeting and as the
/// responder in the domain-key handshake). Every delivered invoice is handed
/// to `sink`.
pub async fn serve(domain: String, sink: Arc<dyn DeliverySink>, listener: UnixListener) {
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
        tokio::spawn(async move {
            let mut stream = stream;
            let mut session = ZsmptSession::new(domain).with_sink(sink);
            info!("zsmpt session started");
            if let Err(e) = session.run(&mut stream).await {
                warn!(error = %e, "zsmpt session closed with error");
            }
        });
    }
}
