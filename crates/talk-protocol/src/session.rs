//! ZSMTP server-side session: state machine over the command vocabulary.

use crate::codec::{AddrMode, Command};
use crate::handshake::{Challenge, ChallengeResponse, DomainKey};
use crate::status::{Status, StatusCode};
use std::sync::Arc;
use thiserror::Error;

/// Session phases, mirroring SMTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Awaiting `HELLO`.
    Greeting,
    /// `HELLO` received; awaiting `AUTH`.
    AwaitingAuth,
    /// Domain key verified.
    Authenticated,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session state error: {0}")]
    State(String),
}

/// Outcome of a delivery attempt, mapped to a ZSMTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Accepted (250 queued).
    Accepted { message_id: String },
    /// Permanently rejected (550) — e.g. unknown recipient or duplicate.
    Rejected { reason: String },
    /// Transient failure (450) — retry later.
    RetryLater { reason: String },
}

/// A sink that receives delivered invoices. Implemented by the daemon to wire
/// ZSMTP delivery into the mailbox store, keeping `talk-protocol` decoupled
/// from storage.
pub trait DeliverySink: Send + Sync {
    fn deliver(
        &self,
        sender_server: &str,
        message_id: &str,
        recipient_mailbox: &str,
        payload: crate::envelope::Payload,
        body: &[u8],
    ) -> DeliveryOutcome;
}

/// A reply to a client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A single status line.
    Status(Status),
    /// A status line plus a binary blob (e.g. an attested address).
    StatusWithBlob(Status, Vec<u8>),
}

/// The ZSMTP server session bound to one connection.
///
/// v1 covers the handshake (HELLO/AUTH), address attestation (ADDR), and
/// invoice delivery (INVOICE -> 250 queued) via a pluggable `DeliverySink`.
pub struct ZsmptSession {
    pub state: SessionState,
    pub domain: String,
    domain_key: DomainKey,
    /// The peer domain after a successful AUTH.
    pub peer_domain: Option<String>,
    /// The user requested in the last ADDR command (delivery recipient).
    addr_user: Option<String>,
    /// Where delivered invoices go.
    sink: Option<Arc<dyn DeliverySink>>,
}

impl ZsmptSession {
    pub fn new(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        Self {
            state: SessionState::Greeting,
            domain_key: DomainKey::generate(&domain),
            domain: domain.clone(),
            peer_domain: None,
            addr_user: None,
            sink: None,
        }
    }

    /// Attach a delivery sink. Without one, INVOICE is accepted without
    /// storing (used by standalone tests).
    pub fn with_sink(mut self, sink: Arc<dyn DeliverySink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The greeting banner sent on connection.
    pub fn greeting(&self) -> String {
        format!("ZSMTP 1.0 {}", self.domain)
    }

    /// Handle one decoded client command.
    pub fn handle(&mut self, cmd: &Command) -> Result<Reply, SessionError> {
        match cmd {
            Command::Hello { domain } => self.on_hello(domain),
            Command::Auth { challenge } => self.on_auth(challenge),
            Command::Addr { mode, user } => self.on_addr(*mode, user),
            Command::Invoice {
                message_id,
                payload,
                body,
            } => self.on_invoice(message_id, *payload, body),
            Command::Status { .. } => {
                Err(SessionError::State("unexpected STATUS from client".into()))
            }
            Command::Quit => Ok(Reply::Status(Status::new(
                StatusCode::new(221),
                format!("{} closing connection", self.domain),
            ))),
        }
    }

    /// Run a full ZSMTP server session over an async stream: greeting, then
    /// loop reading commands until the peer quits or the connection closes.
    pub async fn run<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<(), crate::framing::FramingError> {
        use crate::framing::{read_line, write_line};
        use tokio::io::BufReader;
        let mut stream = BufReader::new(stream);
        write_line(&mut stream, &self.greeting()).await?;
        loop {
            let line = match read_line(&mut stream).await {
                Ok(l) => l,
                Err(crate::framing::FramingError::Protocol(_)) => return Ok(()),
                Err(e) => return Err(e),
            };
            let cmd = match crate::codec::decode_line(&line) {
                Ok(c) => c,
                Err(_) => {
                    write_line(
                        &mut stream,
                        &Status::new(StatusCode::SYNTAX, "unknown command").render(),
                    )
                    .await?;
                    continue;
                }
            };
            let is_quit = matches!(cmd, Command::Quit);
            match self.handle(&cmd) {
                Ok(reply) => write_reply(&mut stream, &reply).await?,
                Err(_) => {
                    write_line(
                        &mut stream,
                        &Status::new(StatusCode::BAD_SEQUENCE, "command not allowed now").render(),
                    )
                    .await?;
                }
            }
            if is_quit {
                return Ok(());
            }
        }
    }

    fn on_hello(&mut self, domain: &str) -> Result<Reply, SessionError> {
        if self.state != SessionState::Greeting {
            return Err(SessionError::State("HELLO already sent".into()));
        }
        if domain.is_empty() {
            return Ok(Reply::Status(Status::new(
                StatusCode::SYNTAX,
                "HELLO requires a domain",
            )));
        }
        self.state = SessionState::AwaitingAuth;
        Ok(Reply::Status(Status::new(
            StatusCode::OK,
            format!("Hello {domain}"),
        )))
    }

    fn on_auth(&mut self, challenge_wire: &[u8]) -> Result<Reply, SessionError> {
        if self.state != SessionState::AwaitingAuth {
            return Ok(Reply::Status(Status::new(
                StatusCode::BAD_SEQUENCE,
                "AUTH not expected now",
            )));
        }
        let challenge_str = String::from_utf8_lossy(challenge_wire);
        let Some(challenge) = Challenge::from_wire(&challenge_str) else {
            return Ok(Reply::Status(Status::new(
                StatusCode::SYNTAX,
                "malformed challenge",
            )));
        };
        // The receiver signs the challenge with its domain key. The sender
        // verifies against this server's DNS-published key.
        let response = ChallengeResponse::respond(&challenge, &self.domain_key.signing);
        let wire = format!("{}|{}", challenge.to_wire(), hex(&response.signature));
        self.state = SessionState::Authenticated;
        self.peer_domain = Some(challenge.sender_domain.clone());
        Ok(Reply::StatusWithBlob(
            Status::new(StatusCode::OK, "authenticated"),
            wire.into_bytes(),
        ))
    }

    fn on_addr(&mut self, mode: AddrMode, user: &str) -> Result<Reply, SessionError> {
        if self.state != SessionState::Authenticated {
            return Ok(Reply::Status(Status::new(
                StatusCode::NOT_AUTHED,
                "authenticate first",
            )));
        }
        if user.is_empty() {
            return Ok(Reply::Status(Status::new(
                StatusCode::SYNTAX,
                "ADDR requires a user",
            )));
        }
        // v1: attestation of an ephemeral/attested address is a placeholder
        // envelope. The actual shielded-address generation and domain-key
        // signature over (address, pubkey) is wired up in M5b.
        let mode = match mode {
            AddrMode::Ephemeral => "ephemeral",
            AddrMode::Attested => "attested",
        };
        self.addr_user = Some(user.to_string());
        let payload = format!("{mode}|{user}");
        Ok(Reply::StatusWithBlob(
            Status::new(StatusCode::OK, "address attestation"),
            payload.into_bytes(),
        ))
    }

    fn on_invoice(
        &mut self,
        message_id: &str,
        payload: crate::envelope::Payload,
        body: &[u8],
    ) -> Result<Reply, SessionError> {
        if self.state != SessionState::Authenticated {
            return Ok(Reply::Status(Status::new(
                StatusCode::NOT_AUTHED,
                "authenticate first",
            )));
        }
        if message_id.is_empty() {
            return Ok(Reply::Status(Status::new(
                StatusCode::SYNTAX,
                "INVOICE requires a message id",
            )));
        }
        let Some(recipient_user) = self.addr_user.clone() else {
            return Ok(Reply::Status(Status::new(
                StatusCode::BAD_SEQUENCE,
                "INVOICE requires a prior ADDR",
            )));
        };
        let Some(sender) = self.peer_domain.clone() else {
            return Ok(Reply::Status(Status::new(
                StatusCode::BAD_SEQUENCE,
                "INVOICE requires a sender",
            )));
        };
        let Some(sink) = &self.sink else {
            // No sink attached: accept without storing (standalone testing).
            return Ok(Reply::Status(Status::new(
                StatusCode::OK_QUEUED,
                format!("accepted into inbox ({message_id})"),
            )));
        };
        let mailbox = format!("{recipient_user}@{}", self.domain);
        match sink.deliver(&sender, message_id, &mailbox, payload, body) {
            DeliveryOutcome::Accepted { message_id } => Ok(Reply::Status(Status::new(
                StatusCode::OK_QUEUED,
                format!("accepted into inbox ({message_id})"),
            ))),
            DeliveryOutcome::Rejected { reason } => {
                Ok(Reply::Status(Status::new(StatusCode::PERM_REJECT, reason)))
            }
            DeliveryOutcome::RetryLater { reason } => {
                Ok(Reply::Status(Status::new(StatusCode::TRY_LATER, reason)))
            }
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a reply to the wire: a status line, optionally followed by a blob.
async fn write_reply<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    reply: &Reply,
) -> Result<(), crate::framing::FramingError> {
    use crate::framing::{write_blob, write_line};
    match reply {
        Reply::Status(status) => {
            write_line(stream, &status.render()).await?;
        }
        Reply::StatusWithBlob(status, blob) => {
            write_line(stream, &status.render()).await?;
            write_blob(stream, blob).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_banner() {
        let s = ZsmptSession::new("example.org");
        assert_eq!(s.greeting(), "ZSMTP 1.0 example.org");
        assert_eq!(s.state, SessionState::Greeting);
    }

    #[test]
    fn hello_sets_state() {
        let mut s = ZsmptSession::new("example.org");
        let reply = s
            .handle(&Command::Hello {
                domain: "sender.example.com".into(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(StatusCode::OK, "Hello sender.example.com"))
        );
        assert_eq!(s.state, SessionState::AwaitingAuth);
    }

    #[test]
    fn hello_requires_domain() {
        let mut s = ZsmptSession::new("example.org");
        let reply = s
            .handle(&Command::Hello {
                domain: String::new(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(StatusCode::SYNTAX, "HELLO requires a domain"))
        );
    }

    #[test]
    fn double_hello_is_state_error() {
        let mut s = ZsmptSession::new("example.org");
        s.handle(&Command::Hello {
            domain: "a.com".into(),
        })
        .unwrap();
        let err = s
            .handle(&Command::Hello {
                domain: "b.com".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("HELLO already sent"));
    }

    #[test]
    fn auth_signs_challenge_and_authenticates() {
        let mut s = ZsmptSession::new("receiver.example.org");
        s.handle(&Command::Hello {
            domain: "sender.example.com".into(),
        })
        .unwrap();

        let challenge = Challenge::issue("sender.example.com", "receiver.example.org");
        let reply = s
            .handle(&Command::Auth {
                challenge: challenge.to_wire().into_bytes(),
            })
            .unwrap();

        // The response must be a signed challenge-response blob.
        let Reply::StatusWithBlob(status, blob) = reply else {
            panic!("expected StatusWithBlob");
        };
        assert!(status.code.is_success());
        assert_eq!(s.state, SessionState::Authenticated);
        assert_eq!(s.peer_domain.as_deref(), Some("sender.example.com"));

        // The blob is `challenge|signature`; the signature must verify against
        // this server's public key (published in DNS).
        let wire = String::from_utf8(blob).unwrap();
        let (chal_wire, sig_hex) = wire.rsplit_once('|').unwrap();
        assert_eq!(chal_wire, challenge.to_wire());
        let signature = hex::decode(sig_hex).unwrap();
        let response = ChallengeResponse {
            challenge: Challenge::from_wire(chal_wire).unwrap(),
            signature,
        };
        assert!(response.verify(&s.domain_key.verifying(), 300).is_ok());
    }

    #[test]
    fn auth_out_of_sequence() {
        let mut s = ZsmptSession::new("example.org");
        let reply = s
            .handle(&Command::Auth {
                challenge: b"x".to_vec(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(
                StatusCode::BAD_SEQUENCE,
                "AUTH not expected now"
            ))
        );
    }

    #[test]
    fn addr_requires_auth() {
        let mut s = ZsmptSession::new("example.org");
        s.handle(&Command::Hello {
            domain: "a.com".into(),
        })
        .unwrap();
        let reply = s
            .handle(&Command::Addr {
                mode: AddrMode::Ephemeral,
                user: "alice@example.org".into(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(StatusCode::NOT_AUTHED, "authenticate first"))
        );
    }

    #[test]
    fn addr_returns_attestation_placeholder() {
        let mut s = authenticated_session();
        let reply = s
            .handle(&Command::Addr {
                mode: AddrMode::Ephemeral,
                user: "alice@example.org".into(),
            })
            .unwrap();
        let Reply::StatusWithBlob(status, blob) = reply else {
            panic!("expected StatusWithBlob");
        };
        assert!(status.code.is_success());
        assert_eq!(
            String::from_utf8(blob).unwrap(),
            "ephemeral|alice@example.org"
        );
    }

    #[test]
    fn invoice_requires_auth() {
        let mut s = ZsmptSession::new("example.org");
        s.handle(&Command::Hello {
            domain: "a.com".into(),
        })
        .unwrap();
        let reply = s
            .handle(&Command::Invoice {
                message_id: "m1".into(),
                payload: crate::envelope::Payload::Sealed,
                body: vec![1, 2, 3],
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(StatusCode::NOT_AUTHED, "authenticate first"))
        );
    }

    #[test]
    fn invoice_accepted_when_authenticated() {
        let mut s = authenticated_session();
        s.handle(&Command::Addr {
            mode: AddrMode::Ephemeral,
            user: "alice".into(),
        })
        .unwrap();
        let reply = s
            .handle(&Command::Invoice {
                message_id: "m1".into(),
                payload: crate::envelope::Payload::Sealed,
                body: vec![1, 2, 3],
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(
                StatusCode::OK_QUEUED,
                "accepted into inbox (m1)"
            ))
        );
    }

    #[test]
    fn invoice_without_addr_is_sequence_error() {
        let mut s = authenticated_session();
        let reply = s
            .handle(&Command::Invoice {
                message_id: "m1".into(),
                payload: crate::envelope::Payload::Sealed,
                body: vec![1, 2, 3],
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(
                StatusCode::BAD_SEQUENCE,
                "INVOICE requires a prior ADDR"
            ))
        );
    }

    #[test]
    fn invoice_delivers_to_sink() {
        use std::sync::Mutex;
        struct Sink(Mutex<Vec<(String, String, String)>>);
        impl DeliverySink for Sink {
            fn deliver(
                &self,
                sender: &str,
                message_id: &str,
                mailbox: &str,
                _payload: crate::envelope::Payload,
                _body: &[u8],
            ) -> DeliveryOutcome {
                self.0.lock().unwrap().push((
                    sender.to_string(),
                    message_id.to_string(),
                    mailbox.to_string(),
                ));
                DeliveryOutcome::Accepted {
                    message_id: message_id.to_string(),
                }
            }
        }

        let sink = Arc::new(Sink(Mutex::new(Vec::new())));
        let mut s = authenticated_session().with_sink(sink.clone());
        s.handle(&Command::Addr {
            mode: AddrMode::Ephemeral,
            user: "alice".into(),
        })
        .unwrap();
        s.handle(&Command::Invoice {
            message_id: "m42".into(),
            payload: crate::envelope::Payload::Sealed,
            body: b"blob".to_vec(),
        })
        .unwrap();

        let calls = sink.0.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "sender.example.com");
        assert_eq!(calls[0].1, "m42");
        assert_eq!(calls[0].2, "alice@receiver.example.org");
    }

    #[test]
    fn invoice_rejected_by_sink_maps_to_550() {
        struct Reject;
        impl DeliverySink for Reject {
            fn deliver(
                &self,
                _s: &str,
                _m: &str,
                _b: &str,
                _p: crate::envelope::Payload,
                _body: &[u8],
            ) -> DeliveryOutcome {
                DeliveryOutcome::Rejected {
                    reason: "no such recipient".into(),
                }
            }
        }

        let mut s = authenticated_session().with_sink(Arc::new(Reject));
        s.handle(&Command::Addr {
            mode: AddrMode::Ephemeral,
            user: "ghost".into(),
        })
        .unwrap();
        let reply = s
            .handle(&Command::Invoice {
                message_id: "m1".into(),
                payload: crate::envelope::Payload::Plaintext,
                body: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(StatusCode::PERM_REJECT, "no such recipient"))
        );
    }

    #[test]
    fn invoice_empty_message_id_is_syntax_error() {
        let mut s = authenticated_session();
        s.handle(&Command::Addr {
            mode: AddrMode::Ephemeral,
            user: "alice".into(),
        })
        .unwrap();
        let reply = s
            .handle(&Command::Invoice {
                message_id: String::new(),
                payload: crate::envelope::Payload::Plaintext,
                body: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(
                StatusCode::SYNTAX,
                "INVOICE requires a message id"
            ))
        );
    }

    #[test]
    fn quit_returns_221() {
        let mut s = ZsmptSession::new("example.org");
        let reply = s.handle(&Command::Quit).unwrap();
        assert_eq!(
            reply,
            Reply::Status(Status::new(
                StatusCode::new(221),
                "example.org closing connection"
            ))
        );
    }

    #[test]
    fn client_sending_status_is_error() {
        let mut s = ZsmptSession::new("example.org");
        let err = s
            .handle(&Command::Status {
                code: 250,
                message: "x".into(),
            })
            .unwrap_err();
        assert!(err.to_string().contains("unexpected STATUS"));
    }

    #[tokio::test]
    async fn full_session_over_stream() {
        use crate::framing::write_line;
        use tokio::io::AsyncReadExt;

        let (mut client, server_stream) = tokio::io::duplex(8192);
        let mut session = ZsmptSession::new("receiver.example.org");
        let mut server_stream = server_stream;
        let handle = tokio::spawn(async move {
            let _ = session.run(&mut server_stream).await;
        });

        let mut buf = [0u8; 2048];

        // Greeting.
        let mut line = read_some(&mut client, &mut buf).await;
        assert_eq!(line.trim_end(), "ZSMTP 1.0 receiver.example.org");

        // HELLO.
        write_line(&mut client, "HELLO sender.example.com")
            .await
            .unwrap();
        line = read_some(&mut client, &mut buf).await;
        assert!(
            line.starts_with("250 Hello sender.example.com"),
            "got: {line}"
        );

        // AUTH.
        let challenge =
            crate::handshake::Challenge::issue("sender.example.com", "receiver.example.org");
        let auth_line = {
            use base64::Engine;
            let b64 =
                base64::engine::general_purpose::STANDARD.encode(challenge.to_wire().as_bytes());
            format!("AUTH {b64}")
        };
        write_line(&mut client, &auth_line).await.unwrap();
        line = read_some(&mut client, &mut buf).await;
        assert!(line.starts_with("250 authenticated"), "got: {line}");
        // The reply carries a blob (signed challenge). If the status line read
        // already pulled it in, do nothing; otherwise consume it now.
        if !line.contains("BLOB") {
            let n = client.read(&mut buf).await.unwrap();
            let _blob = String::from_utf8_lossy(&buf[..n]).to_string();
        }

        // QUIT.
        write_line(&mut client, "QUIT").await.unwrap();
        line = read_some(&mut client, &mut buf).await;
        assert!(line.starts_with("221"), "got: {line}");

        handle.abort();
    }

    /// Read until a CRLF-terminated line arrives, returning it.
    async fn read_some(client: &mut tokio::io::DuplexStream, buf: &mut [u8]) -> String {
        use tokio::io::AsyncReadExt;
        let mut acc = String::new();
        loop {
            let n = client.read(buf).await.unwrap();
            if n == 0 {
                break;
            }
            acc.push_str(&String::from_utf8_lossy(&buf[..n]));
            if acc.contains('\n') {
                break;
            }
        }
        acc
    }

    fn authenticated_session() -> ZsmptSession {
        let mut s = ZsmptSession::new("receiver.example.org");
        s.handle(&Command::Hello {
            domain: "sender.example.com".into(),
        })
        .unwrap();
        let challenge = Challenge::issue("sender.example.com", "receiver.example.org");
        s.handle(&Command::Auth {
            challenge: challenge.to_wire().into_bytes(),
        })
        .unwrap();
        s
    }
}
