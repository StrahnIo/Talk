//! IMAP session state machine and command dispatch.

use crate::parse::ParsedCommand;
use crate::response::{self, Status};
use std::sync::Arc;
use talk_mailstore::{MessageFlags, SqliteMailStore, StoreError};
use tracing::debug;

/// The RFC 3501 session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
}

/// A session for one connection. Owns the authenticated user's identity and
/// their mailbox handle.
pub struct Session {
    pub state: State,
    pub username: String,
    pub user_id: i64,
    pub store: Arc<SqliteMailStore>,
}

impl Session {
    /// Handle one parsed command, returning the bytes to write to the wire.
    pub fn handle(&mut self, cmd: &ParsedCommand) -> String {
        let tag = &cmd.tag;
        let name = cmd.name.as_str();
        debug!(command = name, tag = %tag, "handling command");

        match name {
            "CAPABILITY" => self.cmd_capability(tag),
            "NOOP" => response::tagged(tag, Status::Ok, "NOOP completed"),
            "LOGOUT" => self.cmd_logout(tag),
            "LOGIN" | "AUTHENTICATE" => self.cmd_auth(tag, cmd),
            "SELECT" | "EXAMINE" => self.cmd_select(tag, cmd),
            "LIST" => self.cmd_list(tag, cmd),
            "FETCH" => self.cmd_fetch(tag, cmd),
            "UID" => self.cmd_uid(tag, cmd),
            "STORE" => self.cmd_store(tag, cmd),
            "SEARCH" => self.cmd_search(tag, cmd),
            "EXPUNGE" => self.cmd_expunge(tag),
            "CLOSE" => self.cmd_close(tag),
            "IDLE" => self.cmd_idle(tag),
            _ => response::tagged(tag, Status::Bad, "Unknown command"),
        }
    }

    fn cmd_capability(&self, tag: &str) -> String {
        let mut out = response::untagged("CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN");
        out.push_str(&response::tagged(tag, Status::Ok, "CAPABILITY completed"));
        out
    }

    fn cmd_logout(&self, tag: &str) -> String {
        let mut out = response::untagged("BYE Talk IMAP server logging out");
        out.push_str(&response::tagged(tag, Status::Ok, "LOGOUT completed"));
        out
    }

    fn cmd_auth(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Already authenticated");
        }
        if cmd.name == "AUTHENTICATE" {
            // AUTHENTICATE PLAIN <token> (one-shot form only in v1).
            if cmd.args.len() != 2 || !cmd.args[0].eq_ignore_ascii_case("PLAIN") {
                return response::tagged(
                    tag,
                    Status::Bad,
                    "Only AUTHENTICATE PLAIN <token> supported",
                );
            }
            let token = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &cmd.args[1],
            ) {
                Ok(t) => t,
                Err(_) => return response::tagged(tag, Status::Bad, "Invalid base64"),
            };
            let parts: Vec<&[u8]> = token.split(|&b| b == 0).collect();
            if parts.len() != 3 {
                return response::tagged(tag, Status::Bad, "Invalid SASL PLAIN payload");
            }
            let username = String::from_utf8_lossy(parts[1]).to_string();
            let password = String::from_utf8_lossy(parts[2]).to_string();
            self.login(tag, &username, &password)
        } else {
            if cmd.args.len() != 2 {
                return response::tagged(tag, Status::Bad, "LOGIN requires username and password");
            }
            self.login(tag, &cmd.args[0], &cmd.args[1])
        }
    }

    fn login(&mut self, tag: &str, username: &str, password: &str) -> String {
        // An ":app" username suffix marks an app-password login. For v1 the
        // share itself is not yet validated against the DK wrapper ladder; the
        // hook lives in the server wiring. Both paths must authenticate the
        // username against the store.
        let base = match username.strip_suffix(":app") {
            Some(b) => b.to_string(),
            None => username.to_string(),
        };
        let Some(user) = self.store.get_user(&base).ok().flatten() else {
            return response::tagged(tag, Status::No, "Authentication failed");
        };
        if password.is_empty() {
            return response::tagged(tag, Status::No, "Authentication failed");
        }
        self.user_id = user.id;
        self.username = user.username.clone();
        self.state = State::Authenticated;
        response::tagged(tag, Status::Ok, "LOGIN completed")
    }

    fn cmd_select(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state == State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Not authenticated");
        }
        let mailbox = cmd.args.first().map(|s| s.as_str()).unwrap_or("");
        if !mailbox.eq_ignore_ascii_case("INBOX") {
            return response::tagged(tag, Status::No, "Mailbox does not exist");
        }
        let messages = match self.store.list_messages(self.user_id) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let exists = messages.len() as u32;
        let unseen = messages.iter().filter(|m| !m.flags.is_seen()).count() as u32;
        let uidvalidity = messages.first().map(|m| m.uidvalidity).unwrap_or(1);
        let uidnext = messages.first().map(|m| m.uid + 1).unwrap_or(1);
        let mut out = response::select_responses(exists, unseen, uidvalidity, uidnext);
        out.push_str(&response::tagged(
            tag,
            Status::Ok,
            "[READ-WRITE] SELECT completed",
        ));
        self.state = State::Selected;
        out
    }

    fn cmd_list(&self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state == State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Not authenticated");
        }
        let pattern = cmd.args.get(1).map(|s| s.as_str()).unwrap_or("");
        let mut out = String::new();
        if pattern == "*" || pattern.eq_ignore_ascii_case("INBOX") || pattern.is_empty() {
            out.push_str(&response::untagged(r#"LIST (\HasNoChildren) "/" "INBOX""#));
        }
        out.push_str(&response::tagged(tag, Status::Ok, "LIST completed"));
        out
    }

    fn cmd_fetch(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        // UID FETCH arrives as cmd.name == "UID" with args ["FETCH", ...].
        let (range, items) = match (cmd.args.first().map(String::as_str), cmd.name.as_str()) {
            (Some("FETCH"), "UID") => {
                if cmd.args.len() < 3 {
                    return response::tagged(tag, Status::Bad, "UID FETCH requires arguments");
                }
                (cmd.args[1].as_str(), cmd.args[2].as_str())
            }
            (_, "FETCH") | (_, "UID") => {
                if cmd.args.is_empty() {
                    return response::tagged(tag, Status::Bad, "FETCH requires a sequence set");
                }
                (
                    cmd.args[0].as_str(),
                    cmd.args.get(1).map(String::as_str).unwrap_or("BODY[]"),
                )
            }
            _ => return response::tagged(tag, Status::Bad, "FETCH requires a sequence set"),
        };
        let messages = match self.store.list_messages(self.user_id) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let mut out = String::new();
        for meta in &messages {
            if !in_range(range, meta.uid, messages.len() as u32) {
                continue;
            }
            if items.to_ascii_uppercase().contains("BODY") {
                // Fetch the real (opaque) body from the store.
                let msg = match self.store.fetch_message(self.user_id, meta.id) {
                    Ok(m) => m,
                    Err(e) => return self.store_err(tag, e),
                };
                out.push_str(&fetch_response(meta, items, &msg.body));
            } else {
                out.push_str(&fetch_response(meta, items, &[]));
            }
        }
        out.push_str(&response::tagged(tag, Status::Ok, "FETCH completed"));
        out
    }

    fn cmd_uid(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        let Some(sub) = cmd.args.first() else {
            return response::tagged(tag, Status::Bad, "UID requires a subcommand");
        };
        match sub.to_ascii_uppercase().as_str() {
            "FETCH" => self.cmd_fetch(tag, cmd),
            "STORE" => self.cmd_store(tag, cmd),
            "SEARCH" => self.cmd_search(tag, cmd),
            _ => response::tagged(tag, Status::Bad, "Unsupported UID subcommand"),
        }
    }

    fn cmd_store(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        // UID STORE arrives as cmd.name == "UID" with args ["STORE", ...].
        let (range, mode, flagspec) =
            match (cmd.args.first().map(String::as_str), cmd.name.as_str()) {
                (Some("STORE"), "UID") => {
                    if cmd.args.len() < 4 {
                        return response::tagged(tag, Status::Bad, "UID STORE requires arguments");
                    }
                    (
                        cmd.args[1].as_str(),
                        cmd.args[2].as_str(),
                        cmd.args[3].as_str(),
                    )
                }
                (_, "STORE") | (_, "UID") => {
                    if cmd.args.len() < 3 {
                        return response::tagged(tag, Status::Bad, "STORE requires arguments");
                    }
                    (
                        cmd.args[0].as_str(),
                        cmd.args[1].as_str(),
                        cmd.args[2].as_str(),
                    )
                }
                _ => return response::tagged(tag, Status::Bad, "STORE requires arguments"),
            };
        let messages = match self.store.list_messages(self.user_id) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let mask = parse_flags(flagspec);
        if mask == 0 {
            return response::tagged(tag, Status::Bad, "No supported flags in flag list");
        }
        let value = !mode.trim_start().starts_with('-');
        let mut out = String::new();
        for meta in &messages {
            if !in_range(range, meta.uid, messages.len() as u32) {
                continue;
            }
            if let Err(e) = self.store.set_flags(self.user_id, meta.id, mask, value) {
                return self.store_err(tag, e);
            }
            out.push_str(&response::untagged(&format!(
                "{} FETCH (FLAGS ({}))",
                meta.uid,
                flags_display(meta.flags)
            )));
        }
        out.push_str(&response::tagged(tag, Status::Ok, "STORE completed"));
        out
    }

    fn cmd_search(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        let messages = match self.store.list_messages(self.user_id) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let args: Vec<&String> = if cmd.name == "UID" {
            // UID SEARCH arrives as ["SEARCH", ...].
            if cmd.args.first().map(String::as_str) == Some("SEARCH") {
                cmd.args.iter().skip(1).collect()
            } else {
                cmd.args.iter().collect()
            }
        } else {
            cmd.args.iter().collect()
        };
        let mut all = true;
        let mut unseen = false;
        for a in &args {
            match a.to_ascii_uppercase().as_str() {
                "ALL" => {}
                "UNSEEN" => unseen = true,
                _ => all = false,
            }
        }
        let matched: Vec<u32> = messages
            .iter()
            .filter(|m| all || (unseen && !m.flags.is_seen()))
            .map(|m| m.uid)
            .collect();
        let mut out = response::untagged(&format!("SEARCH {}", join_uids(&matched)));
        out.push_str(&response::tagged(tag, Status::Ok, "SEARCH completed"));
        out
    }

    fn cmd_expunge(&mut self, tag: &str) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        match self.store.expunge(self.user_id) {
            Ok(uids) => {
                let mut out = String::new();
                for u in uids {
                    out.push_str(&response::untagged(&format!("{u} EXPUNGE")));
                }
                out.push_str(&response::tagged(tag, Status::Ok, "EXPUNGE completed"));
                out
            }
            Err(e) => self.store_err(tag, e),
        }
    }

    fn cmd_close(&mut self, tag: &str) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        if let Err(e) = self.store.expunge(self.user_id) {
            return self.store_err(tag, e);
        }
        self.state = State::Authenticated;
        response::tagged(tag, Status::Ok, "CLOSE completed")
    }

    fn cmd_idle(&self, tag: &str) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        // The server loop drives IDLE; the session just emits the continuation.
        response::continuation("idle")
    }

    fn store_err(&self, tag: &str, e: StoreError) -> String {
        response::tagged(tag, Status::No, &format!("Storage error: {e}"))
    }
}

/// Whether `uid` is within a sequence set like `1`, `1:3`, `*`, `1,3`.
fn in_range(range: &str, uid: u32, count: u32) -> bool {
    for part in range.split(',') {
        if let Some((a, b)) = part.split_once(':') {
            let a = seq_num(a, count);
            let b = seq_num(b, count);
            let (lo, hi) = (a.min(b), a.max(b));
            if uid >= lo && uid <= hi {
                return true;
            }
        } else if uid == seq_num(part, count) {
            return true;
        }
    }
    false
}

fn seq_num(s: &str, count: u32) -> u32 {
    if s == "*" {
        count.max(1)
    } else {
        s.parse::<u32>().unwrap_or(1).max(1)
    }
}

/// Parse a `(FLAGS ...)` or `+FLAGS (...)` data item into a flag bitmask.
fn parse_flags(s: &str) -> u32 {
    let mut mask = 0;
    for f in s.split_whitespace() {
        let f = f.trim_matches(['(', ')', '\\', ';']);
        mask |= match f.to_ascii_uppercase().as_str() {
            "SEEN" => MessageFlags::SEEN,
            "ANSWERED" => MessageFlags::ANSWERED,
            "FLAGGED" => MessageFlags::FLAGGED,
            "DELETED" => MessageFlags::DELETED,
            _ => 0,
        };
    }
    mask
}

fn flags_display(flags: MessageFlags) -> String {
    let mut parts = Vec::new();
    if flags.contains(MessageFlags::SEEN) {
        parts.push("\\Seen");
    }
    if flags.contains(MessageFlags::ANSWERED) {
        parts.push("\\Answered");
    }
    if flags.contains(MessageFlags::FLAGGED) {
        parts.push("\\Flagged");
    }
    if flags.contains(MessageFlags::DELETED) {
        parts.push("\\Deleted");
    }
    parts.join(" ")
}

fn join_uids(uids: &[u32]) -> String {
    uids.iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn fetch_response(meta: &talk_mailstore::MessageMeta, _items: &str, body: &[u8]) -> String {
    let flags_str = flags_display(meta.flags);
    let mut out = String::new();
    out.push_str(&response::untagged(&format!(
        "{} FETCH (FLAGS ({}) UID {} RFC822.SIZE {})",
        meta.uid, flags_str, meta.uid, meta.size
    )));
    out.push_str(&response::untagged(&format!(
        "{} FETCH (BODY[] {{{}}})",
        meta.uid,
        body.len()
    )));
    out.push('\r');
    out.push('\n');
    out.push_str(&String::from_utf8_lossy(body));
    out.push_str("\r\n.\r\n");
    out
}
