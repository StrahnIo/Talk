//! IMAP server: connection handling and session loop.

use crate::parse::{CommandReader, ParseError};
use crate::response;
use crate::session::{Session, State};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use talk_mailstore::SqliteMailStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// A mailbox event broadcast to IDLE sessions.
#[derive(Debug, Clone)]
pub enum MailboxEvent {
    /// A message was appended to a user's INBOX.
    MessageAppended { user_id: i64 },
}

/// Server handle holding shared state.
pub struct ImapServer {
    store: Arc<SqliteMailStore>,
    hostname: String,
    events: broadcast::Sender<MailboxEvent>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    auth_mode: crate::session::AuthMode,
    /// The daemon's local domain; login accepts `user@<domain>` for it.
    domain: String,
    /// Optional directory for per-session IMAP transcript capture
    /// (`talkd --capture-dir`).
    capture_dir: Option<std::path::PathBuf>,
    /// Per-server connection sequence for capture filenames.
    capture_seq: Arc<AtomicU64>,
}

impl ImapServer {
    pub fn new(store: Arc<SqliteMailStore>, hostname: impl Into<String>) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            store,
            hostname: hostname.into(),
            events,
            tls: None,
            auth_mode: crate::session::AuthMode::Database,
            domain: String::new(),
            capture_dir: None,
            capture_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Set the daemon's local domain, enabling `user@<domain>` logins.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Capture every IMAP session to a timestamped transcript file in `dir`.
    pub fn with_capture_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.capture_dir = Some(dir.into());
        self
    }

    /// Enable IMAPS: wrap every accepted connection in TLS.
    pub fn with_tls(mut self, config: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(tokio_rustls::TlsAcceptor::from(config));
        self
    }

    /// Set the user authentication mode.
    pub fn with_auth_mode(mut self, mode: crate::session::AuthMode) -> Self {
        self.auth_mode = mode;
        self
    }

    /// The event sender, used by the delivery path to notify IDLE sessions.
    pub fn event_sender(&self) -> broadcast::Sender<MailboxEvent> {
        self.events.clone()
    }

    fn new_session(&self) -> Session {
        Session {
            state: State::NotAuthenticated,
            username: String::new(),
            user_id: 0,
            store: self.store.clone(),
            auth_mode: self.auth_mode,
            domain: self.domain.clone(),
        }
    }

    /// Bind and accept connections on a TCP address.
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, tls = self.tls.is_some(), "IMAP listening");
        if let Some(dir) = &self.capture_dir {
            std::fs::create_dir_all(dir)?;
            info!(dir = %dir.display(), "capturing IMAP sessions to");
        }
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            let seq = self.capture_seq.fetch_add(1, Ordering::Relaxed);
            info!(peer = %peer, "IMAP connection accepted");
            tokio::spawn(async move {
                if let Some(acceptor) = &server.tls {
                    // Capture after TLS decryption, so transcripts are the
                    // readable IMAP protocol, not TLS records.
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => serve_conn(&server, tls_stream, peer, seq).await,
                        Err(e) => {
                            warn!(error = %e, "IMAP TLS handshake failed");
                        }
                    }
                } else {
                    serve_conn(&server, stream, peer, seq).await;
                }
            });
        }
    }
}

/// Serve one connection, wrapping the stream in a transcript capture when the
/// server is configured with a capture directory.
async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
    server: &ImapServer,
    stream: S,
    peer: std::net::SocketAddr,
    seq: u64,
) {
    if let Some(dir) = &server.capture_dir {
        match crate::capture::CaptureFile::open(dir, seq, &peer.to_string()) {
            Ok(capture) => {
                let mut captured = crate::capture::Captured::new(stream, capture);
                let res = serve_connection(&mut captured, server).await;
                captured.finish();
                if let Err(e) = res {
                    warn!(error = %e, "IMAP connection closed with error");
                }
                return;
            }
            Err(e) => {
                warn!(error = %e, dir = %dir.display(), "capture file failed; serving uncaptured");
            }
        }
    }
    let mut stream = stream;
    if let Err(e) = serve_connection(&mut stream, server).await {
        warn!(error = %e, "IMAP connection closed with error");
    }
}

impl Clone for ImapServer {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            hostname: self.hostname.clone(),
            events: self.events.clone(),
            tls: self.tls.clone(),
            auth_mode: self.auth_mode,
            domain: self.domain.clone(),
            capture_dir: self.capture_dir.clone(),
            capture_seq: self.capture_seq.clone(),
        }
    }
}

/// Run the server loop for one connection.
pub async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server: &ImapServer,
) -> std::io::Result<()> {
    let mut session = server.new_session();
    let mut reader = CommandReader::default();
    let mut buf = [0u8; 4096];
    let mut out = response::greeting(&server.hostname);
    let mut events_rx = server.events.subscribe();

    stream.write_all(out.as_bytes()).await?;
    stream.flush().await?;

    loop {
        out.clear();
        let n = match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "read error, closing connection");
                return Err(e);
            }
        };
        let commands = match reader.feed(&buf[..n]) {
            Ok(c) => c,
            Err(ParseError::Unterminated) => {
                stream
                    .write_all(
                        response::tagged("", crate::response::Status::Bad, "malformed line")
                            .as_bytes(),
                    )
                    .await?;
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, "parse error");
                stream
                    .write_all(response::untagged(&format!("BAD Invalid command: {e}")).as_bytes())
                    .await?;
                continue;
            }
        };

        if reader.needs_continuation() {
            stream
                .write_all(response::continuation("send literal").as_bytes())
                .await?;
        }

        for cmd in commands {
            if cmd.name == "IDLE" {
                stream
                    .write_all(response::continuation("idle").as_bytes())
                    .await?;
                stream.flush().await?;
                let done = idle_until_done(stream, &mut reader, &mut buf, &mut events_rx, &session)
                    .await?;
                if done {
                    return Ok(());
                }
                // IDLE terminated: emit the tagged completion.
                out.push_str(&response::tagged(
                    &cmd.tag,
                    crate::response::Status::Ok,
                    "IDLE terminated",
                ));
                continue;
            }
            if cmd.name == "LOGOUT" {
                out.push_str(&session.handle(&cmd));
                stream.write_all(out.as_bytes()).await?;
                stream.flush().await?;
                return Ok(());
            }
            out.push_str(&session.handle(&cmd));
        }
        if !out.is_empty() {
            stream.write_all(out.as_bytes()).await?;
            stream.flush().await?;
        }
    }
}

/// While in IDLE, wait for either `DONE` or a mailbox event for this session.
///
/// On an event for the session's user, emit `* n EXISTS` (recomputed from the
/// store) and keep idling.
async fn idle_until_done<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    reader: &mut CommandReader,
    buf: &mut [u8],
    events_rx: &mut broadcast::Receiver<MailboxEvent>,
    session: &Session,
) -> std::io::Result<bool> {
    loop {
        tokio::select! {
            n = stream.read(buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(true);
                }
                let commands = match reader.feed(&buf[..n]) {
                    Ok(c) => c,
                    Err(_) => return Ok(true),
                };
                for cmd in commands {
                    if cmd.name == "DONE" {
                        return Ok(false);
                    }
                }
            }
            ev = events_rx.recv() => {
                match ev {
                    Ok(MailboxEvent::MessageAppended { user_id }) if user_id == session.user_id => {
                        let count = session.store.list_messages(user_id)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        stream.write_all(response::untagged(&format!("{count} EXISTS")).as_bytes()).await?;
                        stream.flush().await?;
                    }
                    Ok(_) => { /* event for another user; ignore */ }
                    Err(broadcast::error::RecvError::Lagged(_)) => { /* client resyncs on NOOP */ }
                    Err(broadcast::error::RecvError::Closed) => return Ok(true),
                }
            }
        }
    }
}
