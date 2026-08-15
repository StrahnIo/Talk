//! IMAP server: connection handling and session loop.

use crate::parse::{CommandReader, ParseError};
use crate::response;
use crate::session::{Session, State};
use std::sync::Arc;
use talk_mailstore::SqliteMailStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Server handle holding shared state.
pub struct ImapServer {
    store: Arc<SqliteMailStore>,
    hostname: String,
}

impl ImapServer {
    pub fn new(store: Arc<SqliteMailStore>, hostname: impl Into<String>) -> Self {
        Self {
            store,
            hostname: hostname.into(),
        }
    }

    fn new_session(&self) -> Session {
        Session {
            state: State::NotAuthenticated,
            username: String::new(),
            user_id: 0,
            store: self.store.clone(),
        }
    }

    /// Bind and accept connections on a TCP address.
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, "IMAP listening");
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            info!(peer = %peer, "IMAP connection accepted");
            tokio::spawn(async move {
                let mut stream = stream;
                if let Err(e) = serve_connection(&mut stream, &server).await {
                    warn!(error = %e, "IMAP connection closed with error");
                }
            });
        }
    }
}

impl Clone for ImapServer {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            hostname: self.hostname.clone(),
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
                let done = idle_until_done(stream, &mut reader, &mut buf).await?;
                if done {
                    return Ok(());
                }
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

/// After an IDLE continuation, read until `DONE` (case-insensitive) or EOF.
async fn idle_until_done<S: AsyncRead + Unpin>(
    stream: &mut S,
    reader: &mut CommandReader,
    buf: &mut [u8],
) -> std::io::Result<bool> {
    loop {
        let n = match stream.read(buf).await? {
            0 => return Ok(true),
            n => n,
        };
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
}
