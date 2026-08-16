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
//! - `STATUS` — daemon state.
//! - `QUIT` — end the session.
//!
//! Replies are status lines: `OK <text>` or `ERR <text>`.

use crate::envelope::Payload;
use crate::framing::{read_line, write_blob, write_line};
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

/// Run a secure_mailbox session over a stream: read commands until QUIT/EOF.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    handler: &dyn SecureMailboxHandler,
) -> Result<(), crate::framing::FramingError> {
    use crate::framing::read_blob;
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
                match handler.send(sender, recipient, message_id, payload, &body) {
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
}
