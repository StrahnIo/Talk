//! ZSMTP client: the outbound engine that reaches other daemons.
//!
//! Mirror of [`ZsmptSession`](crate::session::ZsmptSession). The client
//! initiates a connection, drives the command vocabulary in order, and
//! *verifies* the receiver's identity: the signed challenge response (AUTH)
//! and the address attestation (ADDR) are both checked against the receiver's
//! DNS-published domain key.
//!
//! Ordering is enforced by an internal state machine — you cannot send an
//! INVOICE before requesting an address, matching the server's `addr_user`
//! requirement.

use crate::attestation::{Attestation, AttestationMode};
use crate::envelope::Payload;
use crate::framing::{read_blob, read_line, write_blob, write_line};
use crate::handshake::{Challenge, ChallengeResponse, MAX_CHALLENGE_AGE};
use crate::status::StatusCode;
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncWrite};

/// Client-side session phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Greeting read; ready for HELLO.
    Connected,
    /// HELLO sent; awaiting AUTH.
    AwaitingAuth,
    /// Receiver's domain key verified; ready for ADDR.
    Authenticated,
    /// Address requested; ready for INVOICE.
    Addressed,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("framing: {0}")]
    Framing(#[from] crate::framing::FramingError),
    #[error("transport: {0}")]
    Io(#[from] std::io::Error),
    #[error("unexpected greeting: {0}")]
    BadGreeting(String),
    #[error("server rejected: {0}")]
    Rejected(String),
    #[error("transient server failure: {0}")]
    RetryLater(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("address attestation invalid: {0}")]
    BadAttestation(String),
    #[error("protocol order error: {0}")]
    Order(String),
}

/// The ZSMTP client bound to one connection.
pub struct ZsmptClient<S> {
    stream: tokio::io::BufReader<S>,
    pub state: ClientState,
    /// Our domain (the sender).
    pub sender_domain: String,
    /// The receiver's domain, from the greeting.
    pub receiver_domain: String,
    /// The user we requested an address for (delivery recipient).
    pub addr_user: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ZsmptClient<S> {
    /// Open a client session: reads and validates the greeting.
    pub async fn connect(stream: S, sender_domain: impl Into<String>) -> Result<Self, ClientError> {
        let mut client = Self {
            stream: tokio::io::BufReader::new(stream),
            state: ClientState::Connected,
            sender_domain: sender_domain.into(),
            receiver_domain: String::new(),
            addr_user: None,
        };
        let greeting = read_line(&mut client.stream).await?;
        let receiver = greeting
            .strip_prefix("ZSMTP 1.0 ")
            .ok_or_else(|| ClientError::BadGreeting(greeting.clone()))?;
        if receiver.is_empty() {
            return Err(ClientError::BadGreeting(greeting));
        }
        client.receiver_domain = receiver.to_string();
        Ok(client)
    }

    /// `HELLO <domain>` — announce ourselves.
    pub async fn hello(&mut self) -> Result<(), ClientError> {
        if self.state != ClientState::Connected {
            return Err(ClientError::Order("hello already sent".into()));
        }
        write_line(&mut self.stream, &format!("HELLO {}", self.sender_domain)).await?;
        let status = read_line(&mut self.stream).await?;
        if !status.starts_with("250 ") {
            return Err(self.status_error(&status));
        }
        self.state = ClientState::AwaitingAuth;
        Ok(())
    }

    /// `AUTH <challenge>` — prove the receiver's identity. The receiver signs
    /// our challenge; we verify against `receiver_pub`.
    pub async fn authenticate(&mut self, receiver_pub: &VerifyingKey) -> Result<(), ClientError> {
        if self.state != ClientState::AwaitingAuth {
            return Err(ClientError::Order("authenticate out of sequence".into()));
        }
        let challenge = Challenge::issue(&self.sender_domain, &self.receiver_domain);
        let auth_line = {
            use base64::Engine;
            let b64 =
                base64::engine::general_purpose::STANDARD.encode(challenge.to_wire().as_bytes());
            format!("AUTH {b64}")
        };
        write_line(&mut self.stream, &auth_line).await?;
        let status = read_line(&mut self.stream).await?;
        if !status.starts_with("250 ") {
            return Err(self.status_error(&status));
        }
        // The reply carries `challenge|signature` as a blob.
        let blob = read_blob(&mut self.stream).await?;
        let wire = String::from_utf8_lossy(&blob);
        let (chal_wire, sig_hex) = wire
            .rsplit_once('|')
            .ok_or_else(|| ClientError::Auth("malformed auth response".into()))?;
        let response = ChallengeResponse {
            challenge: Challenge::from_wire(chal_wire)
                .ok_or_else(|| ClientError::Auth("malformed challenge".into()))?,
            signature: hex::decode(sig_hex)
                .map_err(|_| ClientError::Auth("malformed signature".into()))?,
        };
        response
            .verify(receiver_pub, MAX_CHALLENGE_AGE)
            .map_err(|e| ClientError::Auth(e.to_string()))?;
        self.state = ClientState::Authenticated;
        Ok(())
    }

    /// `ADDR <mode> <user>` — request an address attestation and verify it.
    pub async fn request_address(
        &mut self,
        user: &str,
        mode: AttestationMode,
        receiver_pub: &VerifyingKey,
    ) -> Result<Attestation, ClientError> {
        if self.state != ClientState::Authenticated {
            return Err(ClientError::Order("request_address out of sequence".into()));
        }
        let mode_str = match mode {
            AttestationMode::Ephemeral => "ephemeral",
            AttestationMode::Attested => "attested",
        };
        write_line(&mut self.stream, &format!("ADDR {mode_str} {user}")).await?;
        let status = read_line(&mut self.stream).await?;
        if !status.starts_with("250 ") {
            return Err(self.status_error(&status));
        }
        let blob = read_blob(&mut self.stream).await?;
        let att = Attestation::from_json(&String::from_utf8_lossy(&blob))
            .map_err(|e| ClientError::BadAttestation(e.to_string()))?;
        att.verify(receiver_pub, &self.receiver_domain)
            .map_err(|e| ClientError::BadAttestation(e.to_string()))?;
        self.addr_user = Some(user.to_string());
        self.state = ClientState::Addressed;
        Ok(att)
    }

    /// `INVOICE <sender-user> <message-id> <payload>` + blob — deliver the
    /// sealed invoice. `sender_username` is the authorizing local user.
    pub async fn send_invoice(
        &mut self,
        sender_username: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> Result<(), ClientError> {
        if self.state != ClientState::Addressed {
            return Err(ClientError::Order("send_invoice out of sequence".into()));
        }
        let payload_str = match payload {
            Payload::Sealed => "sealed",
            Payload::Plaintext => "plaintext",
        };
        write_line(
            &mut self.stream,
            &format!("INVOICE {sender_username} {message_id} {payload_str}"),
        )
        .await?;
        write_blob(&mut self.stream, body).await?;
        let status = read_line(&mut self.stream).await?;
        if !status.starts_with("250 ") {
            return Err(self.status_error(&status));
        }
        Ok(())
    }

    /// `QUIT` — end the session.
    pub async fn quit(&mut self) -> Result<(), ClientError> {
        write_line(&mut self.stream, "QUIT").await?;
        let status = read_line(&mut self.stream).await?;
        if !status.starts_with("221 ") {
            return Err(self.status_error(&status));
        }
        Ok(())
    }

    /// Map a status line to the appropriate error.
    fn status_error(&self, status: &str) -> ClientError {
        let code = status
            .split_whitespace()
            .next()
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        if StatusCode::new(code).is_transient() {
            ClientError::RetryLater(status.to_string())
        } else {
            ClientError::Rejected(status.to_string())
        }
    }
}

/// Convenience: connect to a Unix socket path.
pub async fn connect_unix(
    path: impl AsRef<std::path::Path>,
    sender_domain: impl Into<String>,
) -> Result<ZsmptClient<tokio::net::UnixStream>, ClientError> {
    let stream = tokio::net::UnixStream::connect(path).await?;
    ZsmptClient::connect(stream, sender_domain).await
}

/// Convenience: connect to a TCP address.
pub async fn connect_tcp(
    addr: impl tokio::net::ToSocketAddrs,
    sender_domain: impl Into<String>,
) -> Result<ZsmptClient<tokio::net::TcpStream>, ClientError> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    ZsmptClient::connect(stream, sender_domain).await
}

/// Convenience: connect to a TCP address over implicit TLS (SMTPS-style).
///
/// `server_name` is the SNI / certificate hostname (e.g. the receiver's
/// domain). `config` is the client TLS config (verifier choice is the
/// caller's: use webpki roots, or a custom verifier for self-signed dev certs).
pub async fn connect_tcp_tls(
    addr: impl tokio::net::ToSocketAddrs,
    server_name: &str,
    config: std::sync::Arc<rustls::ClientConfig>,
    sender_domain: impl Into<String>,
) -> Result<ZsmptClient<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, ClientError> {
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| ClientError::Auth(format!("invalid server name: {e}")))?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = connector.connect(server_name, stream).await?;
    ZsmptClient::connect(tls, sender_domain).await
}
