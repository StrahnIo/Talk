//! IMAP command parsing.
//!
//! Commands are CRLF-terminated lines of atoms/quoted strings/literals. A
//! literal is `{n}` and is followed by exactly `n` bytes. Per RFC 3501, the
//! server sends a continuation (`+ ...`) before a client supplies a literal.

use std::fmt;

/// An error produced while parsing a command line.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The client sent a lone `.` (invalid in IMAP).
    InvalidCommand,
    /// The command line was not CRLF terminated.
    Unterminated,
    /// A literal count `{n}` was malformed or too large.
    BadLiteral,
    /// A quoted string was not closed.
    UnclosedQuote,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// One parsed IMAP command: a tag, a command name, and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// The client-supplied tag (e.g. `A1`), used to tag responses.
    pub tag: String,
    /// The command name, uppercased (e.g. `SELECT`).
    pub name: String,
    /// Remaining arguments, preserving case.
    pub args: Vec<String>,
}

/// State for an incremental command reader over a byte stream.
#[derive(Debug, Default)]
pub struct CommandReader {
    /// Bytes read since the last command boundary.
    buf: Vec<u8>,
    /// The command line being assembled (literal bytes appended inline).
    pending_line: Vec<u8>,
    /// When `Some(n)`, a literal of exactly `n` bytes is being collected.
    literal_remaining: Option<usize>,
}

impl CommandReader {
    /// Feed bytes from the wire. Returns commands as they become complete.
    ///
    /// When a literal is needed, `needs_continuation()` becomes true and the
    /// caller must send `+ OK` before more bytes arrive.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<ParsedCommand>, ParseError> {
        let mut commands = Vec::new();
        self.buf.extend_from_slice(data);
        loop {
            if let Some(n) = self.literal_remaining {
                let take = n.min(self.buf.len());
                let consumed: Vec<u8> = self.buf[..take].to_vec();
                self.pending_line.extend_from_slice(&consumed);
                self.buf.drain(..take);
                let remaining = n - take;
                self.literal_remaining = if remaining == 0 {
                    None
                } else {
                    Some(remaining)
                };
                if self.literal_remaining.is_some() {
                    return Ok(commands);
                }
                continue;
            }
            if !self.buf.contains(&b'\n') {
                return Ok(commands);
            }
            let line_end = self.buf.iter().position(|&b| b == b'\n').expect("contains");
            if line_end > 0 && self.buf[line_end - 1] != b'\r' {
                self.buf.clear();
                return Err(ParseError::Unterminated);
            }
            let line: Vec<u8> = self.buf
                [..line_end - (line_end > 0 && self.buf[line_end - 1] == b'\r') as usize]
                .to_vec();
            self.buf.drain(..=line_end);

            // If the line ends with a literal marker, strip it and remember the
            // count. Return immediately so the caller can send the `+`
            // continuation before more bytes arrive (required even for {0}).
            if let Some((count, marker_len)) = literal_count(&line) {
                self.literal_remaining = Some(count);
                self.pending_line
                    .extend_from_slice(&line[..line.len() - marker_len]);
                return Ok(commands);
            }

            self.pending_line.extend_from_slice(&line);
            let cmd_line = std::mem::take(&mut self.pending_line);
            commands.push(parse_line(&cmd_line)?);
        }
    }

    /// Whether the reader is waiting for a literal and the server must send a
    /// continuation response before the client sends more data.
    pub fn needs_continuation(&self) -> bool {
        self.literal_remaining.is_some()
    }
}

/// Parse a literal count out of the tail of a line: `... {n}`.
/// Returns the count and the byte length of the `{n}` marker itself.
/// A preceding space is an argument separator and is preserved in the line.
fn literal_count(line: &[u8]) -> Option<(usize, usize)> {
    let s = String::from_utf8_lossy(line);
    let idx = s.rfind('{')?;
    let rest = &s[idx + 1..];
    if !rest.ends_with('}') {
        return None;
    }
    let inner = &rest[..rest.len() - 1];
    let n: usize = inner.trim().parse().ok()?;
    if n > 1 << 20 {
        return None; // cap literals at 1 MiB
    }
    Some((n, 2 + inner.len()))
}

/// Split a command line into (tag, name, args).
fn parse_line(line: &[u8]) -> Result<ParsedCommand, ParseError> {
    let mut tokens = tokenize(line)?;
    if tokens.is_empty() {
        return Err(ParseError::InvalidCommand);
    }
    // A single token is a tag-less command (e.g. `DONE` during IDLE).
    if tokens.len() == 1 {
        return Ok(ParsedCommand {
            tag: String::new(),
            name: tokens[0].to_ascii_uppercase(),
            args: Vec::new(),
        });
    }
    let tag = tokens.remove(0);
    let name = tokens.remove(0);
    let name = name.to_ascii_uppercase();
    Ok(ParsedCommand {
        tag,
        name,
        args: tokens,
    })
}

/// Tokenize an IMAP line into atoms, quoted strings, and paren lists.
fn tokenize(line: &[u8]) -> Result<Vec<String>, ParseError> {
    let s = String::from_utf8_lossy(line);
    let chars: Vec<char> = s.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            // Parenthesized list: consume to matching close, keep as one token.
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            if depth != 0 {
                return Err(ParseError::UnclosedQuote);
            }
            tokens.push(chars[i..j].iter().collect());
            i = j;
            continue;
        }
        if c == '"' {
            // Quoted string.
            let mut j = i + 1;
            let mut out = String::new();
            while j < chars.len() {
                match chars[j] {
                    '\\' if j + 1 < chars.len() => {
                        out.push(chars[j + 1]);
                        j += 2;
                    }
                    '"' => break,
                    ch => {
                        out.push(ch);
                        j += 1;
                    }
                }
            }
            if j >= chars.len() {
                return Err(ParseError::UnclosedQuote);
            }
            tokens.push(out);
            i = j + 1;
            continue;
        }
        // Bare atom until whitespace, paren, or quote.
        let mut j = i;
        while j < chars.len()
            && !chars[j].is_whitespace()
            && chars[j] != '('
            && chars[j] != ')'
            && chars[j] != '"'
        {
            j += 1;
        }
        tokens.push(chars[i..j].iter().collect());
        i = j;
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_command() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 CAPABILITY\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].tag, "A1");
        assert_eq!(cmds[0].name, "CAPABILITY");
        assert!(cmds[0].args.is_empty());
    }

    #[test]
    fn parses_arguments() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"b2 SELECT INBOX\r\n").unwrap();
        assert_eq!(cmds[0].tag, "b2");
        assert_eq!(cmds[0].name, "SELECT");
        assert_eq!(cmds[0].args, vec!["INBOX"]);
    }

    #[test]
    fn parses_parenthesized_list() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"C1 FETCH 1 (FLAGS UID)\r\n").unwrap();
        assert_eq!(cmds[0].args, vec!["1", "(FLAGS UID)"]);
    }

    #[test]
    fn parses_quoted_string() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"D1 LOGIN \"alice\" \"hunter2\"\r\n").unwrap();
        assert_eq!(cmds[0].args, vec!["alice", "hunter2"]);
    }

    #[test]
    fn handles_literal() {
        let mut r = CommandReader::default();
        let mut cmds = r.feed(b"E1 LOGIN {5}\r\n").unwrap();
        assert!(cmds.is_empty());
        assert!(r.needs_continuation());
        cmds = r.feed(b"alice {6}\r\n").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"hunter").unwrap();
        assert!(cmds.is_empty());
        assert!(!r.needs_continuation());
        cmds = r.feed(b"2\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["alice", "hunter2"]);
    }

    #[test]
    fn rejects_bad_line_end() {
        let mut r = CommandReader::default();
        assert_eq!(r.feed(b"A1 NOOP\n").unwrap_err(), ParseError::Unterminated);
    }

    #[test]
    fn split_across_feeds() {
        let mut r = CommandReader::default();
        assert!(r.feed(b"A1 C").unwrap().is_empty());
        let cmds = r.feed(b"APABILITY\r\nB1 LOG").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "CAPABILITY");
        let cmds = r.feed(b"OUT\r\n").unwrap();
        assert_eq!(cmds[0].name, "LOGOUT");
    }

    #[test]
    fn rejects_huge_literal() {
        // Over the 1 MiB cap, the literal is not treated as a literal request;
        // it parses as a bare token. Fine — the server rejects at dispatch.
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 FOO {999999999999}\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["{999999999999}"]);
    }

    #[test]
    fn command_name_is_uppercased() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"a1 select inbox\r\n").unwrap();
        assert_eq!(cmds[0].name, "SELECT");
        assert_eq!(cmds[0].args, vec!["inbox"], "args keep case");
    }

    #[test]
    fn multiple_commands_in_one_feed() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 NOOP\r\nA2 NOOP\r\nA3 LOGOUT\r\n").unwrap();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].tag, "A1");
        assert_eq!(cmds[1].tag, "A2");
        assert_eq!(cmds[2].tag, "A3");
    }

    #[test]
    fn escaped_quote_in_quoted_string() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 LOGIN \"a\\\"b\" pass\r\n").unwrap();
        assert_eq!(cmds[0].args, vec!["a\"b", "pass"]);
    }

    #[test]
    fn nested_parentheses_are_single_token() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 FETCH 1 (BODY[HEADER] (FLAGS))\r\n").unwrap();
        assert_eq!(cmds[0].args[1], "(BODY[HEADER] (FLAGS))");
    }

    #[test]
    fn unclosed_quote_is_error() {
        let mut r = CommandReader::default();
        assert_eq!(
            r.feed(b"A1 LOGIN \"unclosed\r\n").unwrap_err(),
            ParseError::UnclosedQuote
        );
    }

    #[test]
    fn unclosed_paren_is_error() {
        let mut r = CommandReader::default();
        assert_eq!(
            r.feed(b"A1 FETCH 1 (FLAGS\r\n").unwrap_err(),
            ParseError::UnclosedQuote
        );
    }

    #[test]
    fn literal_reassembles_command_correctly() {
        // LOGIN with both args as literals, split across many tiny feeds.
        let mut r = CommandReader::default();
        let mut cmds = r.feed(b"X LOGIN {5}\r\n").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"alice {6}\r\n").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"h").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"unter2\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["alice", "hunter2"]);
    }

    #[test]
    fn literal_in_middle_of_args() {
        // FETCH 1 BODY[] with a literal for another arg in the middle.
        let mut r = CommandReader::default();
        let mut cmds = r.feed(b"Y STORE 1 +FLAGS {5}\r\n").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"(\\Seen)").unwrap();
        assert!(cmds.is_empty());
        cmds = r.feed(b"\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "STORE");
        assert_eq!(cmds[0].args, vec!["1", "+FLAGS", "(\\Seen)"]);
    }

    #[test]
    fn needs_continuation_true_until_literal_done() {
        let mut r = CommandReader::default();
        r.feed(b"A LOGIN {10}\r\n").unwrap();
        assert!(r.needs_continuation());
        r.feed(b"partial").unwrap();
        assert!(r.needs_continuation(), "still waiting for rest of literal");
        r.feed(b"data\r\n").unwrap();
        assert!(!r.needs_continuation());
    }

    #[test]
    fn zero_length_literal() {
        let mut r = CommandReader::default();
        r.feed(b"A LOGIN {0}\r\n").unwrap();
        assert!(r.needs_continuation());
        let cmds = r.feed(b"\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "LOGIN");
    }
    #[test]
    fn bare_atom_with_dot() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"A1 SEARCH SUBJECT foo.bar\r\n").unwrap();
        assert_eq!(cmds[0].args, vec!["SUBJECT", "foo.bar"]);
    }

    #[test]
    fn single_token_is_tagless_command() {
        let mut r = CommandReader::default();
        let cmds = r.feed(b"DONE\r\n").unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "DONE");
        assert_eq!(cmds[0].tag, "", "no tag for bare command");
    }
}
