//! IMAP response serialization.

use crate::parse::ParseError;

/// The status class of a tagged/untagged completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    No,
    Bad,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::No => "NO",
            Status::Bad => "BAD",
        }
    }
}

/// Build an untagged response, e.g. `* 3 EXISTS`.
pub fn untagged(body: &str) -> String {
    format!("* {body}\r\n")
}

/// Build a tagged response, e.g. `A1 OK SELECT completed`.
pub fn tagged(tag: &str, status: Status, text: &str) -> String {
    format!("{tag} {} {text}\r\n", status.as_str())
}

/// Build a continuation response, e.g. `+ Ready for literal`.
pub fn continuation(text: &str) -> String {
    format!("+ {text}\r\n")
}

/// The greeting banner sent on connection.
pub fn greeting(hostname: &str) -> String {
    format!("* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN] {hostname} Talk IMAP ready\r\n")
}

/// Render a status message from a parse error.
pub fn status_from_parse_error(tag: &str, err: &ParseError) -> String {
    tagged(tag, Status::Bad, &format!("Invalid command: {err}"))
}

/// Render the EXISTS/UNSEEN etc. responses for a mailbox SELECT.
pub fn select_responses(exists: u32, unseen: u32, uidvalidity: u32, uidnext: u32) -> String {
    let mut s = String::new();
    s.push_str(&untagged(&format!("{exists} EXISTS")));
    s.push_str(&untagged("0 RECENT"));
    s.push_str(&untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted)"));
    s.push_str(&untagged(&format!("OK [UNSEEN {unseen}]")));
    s.push_str(&untagged(&format!("OK [UIDVALIDITY {uidvalidity}]")));
    s.push_str(&untagged(&format!("OK [UIDNEXT {uidnext}]")));
    s
}

/// Quote an IMAP atom/string for a quoted-string response.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_response_format() {
        assert_eq!(tagged("A1", Status::Ok, "completed"), "A1 OK completed\r\n");
    }

    #[test]
    fn untagged_response_format() {
        assert_eq!(untagged("3 EXISTS"), "* 3 EXISTS\r\n");
    }

    #[test]
    fn select_responses_format() {
        let s = select_responses(2, 1, 12345, 42);
        assert!(s.contains("* 2 EXISTS\r\n"));
        assert!(s.contains("OK [UNSEEN 1]"));
        assert!(s.contains("OK [UIDVALIDITY 12345]"));
        assert!(s.contains("OK [UIDNEXT 42]"));
    }

    #[test]
    fn quote_escapes() {
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("plain"), "\"plain\"");
    }
}
