//! `secure_mailbox.sock`: the local user↔daemon interface.
//!
//! A client on the same machine asks the daemon to send Zcash, request address
//! attestations, or report status. This is *not* ZSMTP — it is the local
//! control channel. It uses the same line/blob framing for consistency.
//!
//! Commands:
//! - `SEND <recipient-mailbox> <message-id> <sealed|plaintext>` + blob — ask
//!   the daemon to deliver an invoice to another server.
//! - `ATTEST <user> <ephemeral|attested>` — request a local address
//!   attestation.
//! - `EMULATE <recipient-user>` + blob — simulate a received payment for a
//!   local user (dev/testing).
//! - `STATUS` — daemon state.
//! - `QUIT` — end the session.
//!
//! Replies are status lines: `OK <text>` or `ERR <text>`.

use crate::emulate::EmulatePayload;
use crate::envelope::Payload;
use crate::framing::{read_blob, read_line, write_blob, write_line};
use tokio::io::{AsyncRead, AsyncWrite};

/// Outcome of a SEND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendResult {
    Ok(String),
    Error(String),
}

/// Outcome of an ATTEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestResult {
    Ok(Vec<u8>),
    Error(String),
}

/// Outcome of a REGISTER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterResult {
    Ok,
    Error(String),
}

/// Outcome of an EMULATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulateResult {
    Ok(String),
    Error(String),
}

/// What the daemon can do on behalf of a local client.
pub trait SecureMailboxHandler: Send + Sync {
    fn send(
        &self,
        sender_username: &str,
        recipient_mailbox: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> SendResult;
    fn attest(&self, user: &str, mode: crate::attestation::AttestationMode) -> AttestResult;
    fn register(
        &self,
        username: &str,
        password: &str,
        pubkey_hex: &str,
        ivk_hex: Option<&str>,
    ) -> RegisterResult;
    fn status(&self) -> String;
}

/// Like [`SecureMailboxHandler`], but with an async `send` (SEND performs
/// network I/O — DNS SRV lookup + a TLS connection to the recipient daemon).
///
/// Keeping `send` async avoids blocking the daemon's tokio runtime, which a
/// synchronous `block_on` would do when invoked from within a runtime.
#[async_trait::async_trait]
pub trait AsyncSecureMailboxHandler: Send + Sync {
    async fn send(
        &self,
        sender_username: &str,
        recipient_mailbox: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> SendResult;
    fn attest(&self, user: &str, mode: crate::attestation::AttestationMode) -> AttestResult;
    fn register(
        &self,
        username: &str,
        password: &str,
        pubkey_hex: &str,
        ivk_hex: Option<&str>,
    ) -> RegisterResult;
    fn status(&self) -> String;
    /// Simulate a received payment for a local user (local emulation only).
    fn emulate(&self, recipient_user: &str, payload: &EmulatePayload) -> EmulateResult;
}

/// Run a secure_mailbox session over a stream: read commands until QUIT/EOF.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &dyn AsyncSecureMailboxHandler,
) -> Result<(), crate::framing::FramingError> {
    use tokio::io::BufReader;

    let mut stream = BufReader::new(stream);
    loop {
        let line = match read_line(&mut stream).await {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };
        let mut parts = line.splitn(5, ' ');
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        match verb.as_str() {
            "SEND" => {
                // SEND <sender> <recipient> <message-id> <sealed|plaintext>
                let sender = parts.next().unwrap_or("");
                let recipient = parts.next().unwrap_or("");
                let message_id = parts.next().unwrap_or("");
                let payload = match parts.next() {
                    Some("sealed") => Payload::Sealed,
                    Some("plaintext") => Payload::Plaintext,
                    _ => {
                        write_line(&mut stream, "ERR malformed SEND").await?;
                        continue;
                    }
                };
                let body = match read_blob(&mut stream).await {
                    Ok(b) => b,
                    Err(_) => {
                        write_line(&mut stream, "ERR missing SEND blob").await?;
                        continue;
                    }
                };
                let result = handler
                    .send(sender, recipient, message_id, payload, &body)
                    .await;
                match result {
                    SendResult::Ok(text) => write_line(&mut stream, &format!("OK {text}")).await?,
                    SendResult::Error(text) => {
                        write_line(&mut stream, &format!("ERR {text}")).await?
                    }
                }
            }
            "REGISTER" => {
                // REGISTER <username> <password> <pubkey-hex> [ivk-hex]
                let username = parts.next().unwrap_or("");
                let password = parts.next().unwrap_or("");
                let pubkey_hex = parts.next().unwrap_or("");
                let ivk_hex = parts.next();
                if username.is_empty() || password.is_empty() || pubkey_hex.is_empty() {
                    write_line(
                        &mut stream,
                        "ERR REGISTER requires username, password, and pubkey",
                    )
                    .await?;
                    continue;
                }
                match handler.register(username, password, pubkey_hex, ivk_hex) {
                    RegisterResult::Ok => write_line(&mut stream, "OK registered").await?,
                    RegisterResult::Error(text) => {
                        write_line(&mut stream, &format!("ERR {text}")).await?
                    }
                }
            }
            "ATTEST" => {
                let user = parts.next().unwrap_or("");
                let mode = match parts.next() {
                    Some("ephemeral") => crate::attestation::AttestationMode::Ephemeral,
                    Some("attested") => crate::attestation::AttestationMode::Attested,
                    _ => {
                        write_line(&mut stream, "ERR malformed ATTEST").await?;
                        continue;
                    }
                };
                match handler.attest(user, mode) {
                    AttestResult::Ok(blob) => {
                        write_line(&mut stream, "OK attestation").await?;
                        write_blob(&mut stream, &blob).await?;
                    }
                    AttestResult::Error(text) => {
                        write_line(&mut stream, &format!("ERR {text}")).await?
                    }
                }
            }
            "EMULATE" => {
                // EMULATE <recipient-user> + blob (JSON EmulatePayload)
                let recipient_user = parts.next().unwrap_or("");
                if recipient_user.is_empty() {
                    write_line(&mut stream, "ERR EMULATE requires a recipient user").await?;
                    continue;
                }
                let blob = match read_blob(&mut stream).await {
                    Ok(b) => b,
                    Err(_) => {
                        write_line(&mut stream, "ERR missing EMULATE blob").await?;
                        continue;
                    }
                };
                let payload = match EmulatePayload::from_json(&String::from_utf8_lossy(&blob)) {
                    Some(p) => p,
                    None => {
                        write_line(&mut stream, "ERR malformed EMULATE payload").await?;
                        continue;
                    }
                };
                match handler.emulate(recipient_user, &payload) {
                    EmulateResult::Ok(text) => write_line(&mut stream, &format!("OK {text}")).await?,
                    EmulateResult::Error(text) => {
                        write_line(&mut stream, &format!("ERR {text}")).await?
                    }
                }
            }
            "STATUS" => {
                let s = handler.status();
                write_line(&mut stream, &format!("OK {s}")).await?;
            }
            "QUIT" => {
                write_line(&mut stream, "OK bye").await?;
                return Ok(());
            }
            _ => {
                write_line(&mut stream, "ERR unknown command").await?;
            }
        }
    }
}

/// A minimal client for the secure_mailbox interface (used by tests and the
/// future CLI).
pub struct SecureMailboxClient<S> {
    stream: tokio::io::BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureMailboxClient<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream: tokio::io::BufReader::new(stream),
        }
    }

    /// `SEND <sender> <recipient> <message-id> <payload>` + blob.
    pub async fn send(
        &mut self,
        sender: &str,
        recipient: &str,
        message_id: &str,
        payload: Payload,
        body: &[u8],
    ) -> Result<String, crate::framing::FramingError> {
        let payload = match payload {
            Payload::Sealed => "sealed",
            Payload::Plaintext => "plaintext",
        };
        write_line(
            &mut self.stream,
            &format!("SEND {sender} {recipient} {message_id} {payload}"),
        )
        .await?;
        write_blob(&mut self.stream, body).await?;
        let line = read_line(&mut self.stream).await?;
        Ok(line)
    }

    pub async fn status(&mut self) -> Result<String, crate::framing::FramingError> {
        write_line(&mut self.stream, "STATUS").await?;
        read_line(&mut self.stream).await
    }

    /// `REGISTER <username> <password> <pubkey-hex> [ivk-hex]`.
    pub async fn register(
        &mut self,
        username: &str,
        password: &str,
        pubkey_hex: &str,
        ivk_hex: Option<&str>,
    ) -> Result<String, crate::framing::FramingError> {
        let ivk = ivk_hex.map(|s| format!(" {s}")).unwrap_or_default();
        write_line(
            &mut self.stream,
            &format!("REGISTER {username} {password} {pubkey_hex}{ivk}"),
        )
        .await?;
        read_line(&mut self.stream).await
    }

    pub async fn quit(&mut self) -> Result<String, crate::framing::FramingError> {
        write_line(&mut self.stream, "QUIT").await?;
        read_line(&mut self.stream).await
    }

    /// `EMULATE <recipient-user>` + blob — simulate a received payment.
    pub async fn emulate(
        &mut self,
        recipient_user: &str,
        sender_name: &str,
        sender_address: &str,
        amount: &str,
        invoice: &[u8],
    ) -> Result<String, crate::framing::FramingError> {
        let payload = EmulatePayload {
            sender_name: sender_name.to_string(),
            sender_address: sender_address.to_string(),
            amount: amount.to_string(),
            invoice: invoice.to_vec(),
        };
        write_line(&mut self.stream, &format!("EMULATE {recipient_user}")).await?;
        write_blob(&mut self.stream, payload.to_json().as_bytes()).await?;
        read_line(&mut self.stream).await
    }

    /// `ATTEST <user> <ephemeral|attested>` — request an address attestation.
    /// Returns the signed attestation blob, or the server's `ERR` line.
    pub async fn attest(
        &mut self,
        user: &str,
        mode: crate::attestation::AttestationMode,
    ) -> Result<Vec<u8>, String> {
        let mode = match mode {
            crate::attestation::AttestationMode::Ephemeral => "ephemeral",
            crate::attestation::AttestationMode::Attested => "attested",
        };
        write_line(&mut self.stream, &format!("ATTEST {user} {mode}"))
            .await
            .map_err(|e| e.to_string())?;
        let line = read_line(&mut self.stream)
            .await
            .map_err(|e| e.to_string())?;
        if !line.starts_with("OK ") {
            return Err(line);
        }
        read_blob(&mut self.stream).await.map_err(|e| e.to_string())
    }
}
