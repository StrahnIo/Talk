//! ZSMTP command vocabulary: encoding and decoding of commands.
//!
//! Commands are space-separated line tokens plus optional blob payloads:
//!
//! - `HELLO <domain>`                       — greet (like SMTP `EHLO`)
//! - `AUTH <challenge-b64>`                 — server auth (challenge blob)
//! - `ADDR <ephemeral|attested> <user>`     — request an address attestation
//! - `INVOICE <message-id> <payload-type>`  — deliver a sealed invoice (blob)
//! - `STATUS <code> <message>`              — server replies
//! - `QUIT`                                 — end session

use crate::envelope::Payload;
use crate::status::{Status, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Command {
    Hello {
        domain: String,
    },
    Auth {
        challenge: Vec<u8>,
    },
    Addr {
        mode: AddrMode,
        user: String,
    },
    Invoice {
        message_id: String,
        payload: Payload,
        body: Vec<u8>,
    },
    Status {
        code: u16,
        message: String,
    },
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrMode {
    Ephemeral,
    Attested,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("unknown command line: {0}")]
    Unknown(String),
    #[error("malformed command: {0}")]
    Malformed(String),
}

/// Encode a command (without any blob) to a single line.
pub fn encode_line(cmd: &Command) -> Result<String, CodecError> {
    match cmd {
        Command::Hello { domain } => Ok(format!("HELLO {domain}")),
        Command::Auth { challenge } => {
            let b64 = base64_encode(challenge);
            Ok(format!("AUTH {b64}"))
        }
        Command::Addr { mode, user } => {
            let mode = match mode {
                AddrMode::Ephemeral => "ephemeral",
                AddrMode::Attested => "attested",
            };
            Ok(format!("ADDR {mode} {user}"))
        }
        Command::Invoice {
            message_id,
            payload,
            ..
        } => {
            let payload = match payload {
                Payload::Sealed => "sealed",
                Payload::Plaintext => "plaintext",
            };
            Ok(format!("INVOICE {message_id} {payload}"))
        }
        Command::Status { code, message } => Ok(format!("STATUS {code} {message}")),
        Command::Quit => Ok("QUIT".to_string()),
    }
}

/// Parse a command line. Blob-bearing commands return a partial command; the
/// caller supplies the blob bytes separately.
pub fn decode_line(line: &str) -> Result<Command, CodecError> {
    let mut parts = line.splitn(3, ' ');
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();
    match verb.as_str() {
        "HELLO" => {
            let domain = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            Ok(Command::Hello {
                domain: domain.to_string(),
            })
        }
        "AUTH" => {
            let b64 = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let challenge = base64_decode(b64).ok_or_else(|| CodecError::Malformed(line.into()))?;
            Ok(Command::Auth { challenge })
        }
        "ADDR" => {
            let mode = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let user = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let mode = match mode.to_ascii_lowercase().as_str() {
                "ephemeral" => AddrMode::Ephemeral,
                "attested" => AddrMode::Attested,
                _ => return Err(CodecError::Malformed(line.into())),
            };
            Ok(Command::Addr {
                mode,
                user: user.to_string(),
            })
        }
        "INVOICE" => {
            let message_id = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let payload = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let payload = match payload.to_ascii_lowercase().as_str() {
                "sealed" => Payload::Sealed,
                "plaintext" => Payload::Plaintext,
                _ => return Err(CodecError::Malformed(line.into())),
            };
            Ok(Command::Invoice {
                message_id: message_id.to_string(),
                payload,
                body: Vec::new(),
            })
        }
        "STATUS" => {
            let code = parts
                .next()
                .ok_or_else(|| CodecError::Malformed(line.into()))?;
            let message = parts.next().unwrap_or("");
            let code: u16 = code
                .parse()
                .map_err(|_| CodecError::Malformed(line.into()))?;
            Ok(Command::Status {
                code,
                message: message.to_string(),
            })
        }
        "QUIT" => Ok(Command::Quit),
        _ => Err(CodecError::Unknown(line.to_string())),
    }
}

/// Convert a Status to a Command::Status for the wire.
pub fn status_command(status: &Status) -> Command {
    Command::Status {
        code: status.code.value(),
        message: status.message.clone(),
    }
}

pub fn ok_status(message: impl Into<String>) -> Status {
    Status::new(StatusCode::OK, message)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let c = Command::Hello {
            domain: "example.com".into(),
        };
        let line = encode_line(&c).unwrap();
        assert_eq!(line, "HELLO example.com");
        assert_eq!(decode_line(&line).unwrap(), c);
    }

    #[test]
    fn auth_roundtrip_preserves_bytes() {
        let challenge = vec![1u8, 2, 3, 255, 0];
        let c = Command::Auth {
            challenge: challenge.clone(),
        };
        let line = encode_line(&c).unwrap();
        assert!(line.starts_with("AUTH "));
        assert_eq!(decode_line(&line).unwrap(), c);
        if let Command::Auth { challenge: got } = decode_line(&line).unwrap() {
            assert_eq!(got, challenge);
        }
    }

    #[test]
    fn addr_modes() {
        for (mode, expected) in [
            (AddrMode::Ephemeral, "ADDR ephemeral bob@example.com"),
            (AddrMode::Attested, "ADDR attested bob@example.com"),
        ] {
            let c = Command::Addr {
                mode,
                user: "bob@example.com".into(),
            };
            let line = encode_line(&c).unwrap();
            assert_eq!(line, expected);
            let back = decode_line(&line).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn invoice_roundtrip() {
        let c = Command::Invoice {
            message_id: "msg-42".into(),
            payload: Payload::Sealed,
            body: Vec::new(),
        };
        let line = encode_line(&c).unwrap();
        assert_eq!(line, "INVOICE msg-42 sealed");
        assert_eq!(decode_line(&line).unwrap(), c);
    }

    #[test]
    fn status_roundtrip() {
        let c = Command::Status {
            code: 550,
            message: "permanently rejected".into(),
        };
        let line = encode_line(&c).unwrap();
        assert_eq!(line, "STATUS 550 permanently rejected");
        assert_eq!(decode_line(&line).unwrap(), c);
    }

    #[test]
    fn quit_roundtrip() {
        assert_eq!(encode_line(&Command::Quit).unwrap(), "QUIT");
        assert_eq!(decode_line("QUIT").unwrap(), Command::Quit);
    }

    #[test]
    fn unknown_verb() {
        assert!(decode_line("FROBNICATE").is_err());
    }

    #[test]
    fn malformed_addr_mode() {
        assert!(decode_line("ADDR bogus user").is_err());
    }

    #[test]
    fn bad_base64_auth() {
        assert!(decode_line("AUTH !!!").is_err());
    }

    #[test]
    fn addr_accepts_lowercase_mode() {
        let line = "ADDR ephemeral user";
        let back = decode_line(line).unwrap();
        assert_eq!(
            back,
            Command::Addr {
                mode: AddrMode::Ephemeral,
                user: "user".into(),
            }
        );
    }

    #[test]
    fn invoice_accepts_lowercase_payload() {
        let back = decode_line("INVOICE mid plaintext").unwrap();
        assert_eq!(
            back,
            Command::Invoice {
                message_id: "mid".into(),
                payload: Payload::Plaintext,
                body: Vec::new(),
            }
        );
    }
}
