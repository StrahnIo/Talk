//! ZSMTP status codes, SMTP-style.

use std::fmt;

/// A three-digit ZSMTP status code.
///
/// Classes follow SMTP:
/// - `2xx`: success
/// - `3xx`: continue (need more input)
/// - `4xx`: transient failure (retry later)
/// - `5xx`: permanent failure (give up)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);

impl StatusCode {
    // 2xx success
    pub const OK: Self = Self(250);
    pub const OK_QUEUED: Self = Self(250);
    pub const OK_SENT: Self = Self(251);

    // 3xx continue
    pub const CONTINUE: Self = Self(354);

    // 4xx transient
    pub const TRY_LATER: Self = Self(450);
    pub const BUSY: Self = Self(451);

    // 5xx permanent
    pub const SYNTAX: Self = Self(500);
    pub const BAD_SEQUENCE: Self = Self(503);
    pub const PERM_REJECT: Self = Self(550);
    pub const MAILBOX_UNAVAILABLE: Self = Self(550);
    pub const NOT_AUTHED: Self = Self(530);

    pub fn new(code: u16) -> Self {
        Self(code)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A full status line: `<code> <message>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: StatusCode,
    pub message: String,
}

impl Status {
    pub fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Render as a wire line without trailing CRLF.
    pub fn render(&self) -> String {
        format!("{} {}", self.code.value(), self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_classification() {
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::TRY_LATER.is_transient());
        assert!(StatusCode::PERM_REJECT.is_permanent());
        assert!(!StatusCode::CONTINUE.is_success());
    }

    #[test]
    fn status_renders() {
        let s = Status::new(StatusCode::OK, "accepted into inbox");
        assert_eq!(s.render(), "250 accepted into inbox");
    }

    #[test]
    fn status_code_display() {
        assert_eq!(StatusCode::OK.to_string(), "250");
        assert_eq!(StatusCode::PERM_REJECT.to_string(), "550");
    }
}
