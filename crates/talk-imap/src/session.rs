//! IMAP session state machine and command dispatch.

use crate::parse::ParsedCommand;
use crate::response::{self, Status};
use std::sync::Arc;
use talk_keys::KeyResolver;
use talk_mailstore::{MessageFlags, SqliteMailStore, StoreError};
use tracing::debug;

/// The RFC 3501 session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
}

/// How the IMAP server authenticates users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Verify the password against the store's argon2 hash.
    Database,
    /// Verify the connecting OS user is a member of the `zsmtp` group.
    LocalAuth,
}

/// A session for one connection. Owns the authenticated user's identity and
/// their mailbox handle.
pub struct Session {
    pub state: State,
    pub username: String,
    pub user_id: i64,
    pub store: Arc<SqliteMailStore>,
    pub auth_mode: AuthMode,
    /// The daemon's local domain. Login accepts `user` or `user@<domain>`;
    /// other domains are rejected.
    pub domain: String,
    /// The currently selected mailbox (INBOX or Sent).
    pub selected_mailbox: String,
}

/// Canonical mailbox names (case-insensitive input).
pub const MAILBOXES: [&str; 2] = [talk_mailstore::INBOX, talk_mailstore::SENT];

/// Resolve a mailbox argument to its canonical name, or `None`.
pub fn canonical_mailbox(name: &str) -> Option<&'static str> {
    MAILBOXES
        .iter()
        .copied()
        .find(|m| m.eq_ignore_ascii_case(name))
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
            "NAMESPACE" => self.cmd_namespace(tag),
            "STATUS" => self.cmd_status(tag, cmd),
            "FETCH" => self.cmd_fetch(tag, cmd),
            "UID" => self.cmd_uid(tag, cmd),
            "STORE" => self.cmd_store(tag, cmd),
            "SEARCH" => self.cmd_search(tag, cmd),
            "EXPUNGE" => self.cmd_expunge(tag),
            "CLOSE" => self.cmd_close(tag),
            "IDLE" => self.cmd_idle(tag),
            // Unsupported-but-known commands: reply NO (graceful degradation)
            // rather than BAD (protocol error), so clients fall back cleanly.
            "APPEND" | "COPY" | "MOVE" | "SORT" | "THREAD" | "CREATE" | "DELETE" | "RENAME"
            | "SUBSCRIBE" | "UNSUBSCRIBE" | "LSUB" | "CHECK" | "LANGUAGE" => {
                response::tagged(tag, Status::No, "command not supported")
            }
            _ => response::tagged(tag, Status::Bad, "Unknown command"),
        }
    }

    fn cmd_capability(&self, tag: &str) -> String {
        let mut out = response::untagged("CAPABILITY IMAP4rev1 IDLE NAMESPACE AUTH=PLAIN");
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
        // An ":app" username suffix marks an app-password login: the password
        // is a share, and the session only authenticates if that share unwraps
        // the user's data key (see the DK wrapper ladder in `talk-keys`).
        let (base, is_app) = match username.strip_suffix(":app") {
            Some(b) => (b.to_string(), true),
            None => (username.to_string(), false),
        };
        // Uniform domain support: accept a bare local part or `user@<domain>`
        // (the configured local domain only; foreign domains are rejected).
        let Some(local) = talk_mailstore::local_username(&base, &self.domain) else {
            return response::tagged(tag, Status::No, "Authentication failed");
        };
        let local = local.to_string();
        let Some(user) = self.store.get_user(&local).ok().flatten() else {
            return response::tagged(tag, Status::No, "Authentication failed");
        };
        if is_app {
            let share = match hex::decode(password) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    talk_keys::Share::from_bytes(arr)
                }
                _ => return response::tagged(tag, Status::No, "Authentication failed"),
            };
            let wrappers = match self.store.get_shares(user.id) {
                Ok(w) => w,
                Err(_) => return response::tagged(tag, Status::No, "Authentication failed"),
            };
            let wrapped: Vec<talk_keys::WrappedByShare> = wrappers
                .into_iter()
                .map(|(share_id, wrapped)| {
                    let mut id = [0u8; 16];
                    let _ = share_id;
                    // share_id on the wire is hex of 16 bytes; fall back to
                    // zeros if malformed (the wrapped bytes still authenticate).
                    if let Ok(b) = hex::decode(&share_id)
                        && b.len() == 16
                    {
                        id.copy_from_slice(&b);
                    }
                    talk_keys::WrappedByShare {
                        share_id: id,
                        wrapped,
                    }
                })
                .collect();
            let scheme = talk_keys::PerShareWrapper;
            let set = talk_keys::WrappedDkSet { wrappers: wrapped };
            let resolver = talk_keys::ShareResolver::new(&scheme, &set);
            if resolver
                .unwrap(&talk_keys::Credential::Share(share))
                .is_ok()
            {
                self.user_id = user.id;
                self.username = user.username.clone();
                self.state = State::Authenticated;
                return response::tagged(tag, Status::Ok, "LOGIN completed (app password)");
            }
            return response::tagged(tag, Status::No, "Authentication failed");
        }
        // Standard login: authenticate per the configured auth mode.
        let ok = match self.auth_mode {
            AuthMode::Database => {
                // Verify the password against the stored argon2 hash.
                let Some(hash) = self.store.password_hash(&local).ok().flatten() else {
                    return response::tagged(tag, Status::No, "Authentication failed");
                };
                talk_mailstore::verify_password(password, &hash).unwrap_or(false)
            }
            AuthMode::LocalAuth => {
                // The connecting OS user must be a member of the `zsmtp` group
                // and must match the mailbox username.
                is_in_zsmtp_group(&local)
            }
        };
        if !ok {
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
        let Some(mailbox) = cmd.args.first().and_then(|s| canonical_mailbox(s)) else {
            return response::tagged(tag, Status::No, "Mailbox does not exist");
        };
        let read_only = cmd.name == "EXAMINE";
        let messages = match self.store.list_messages_in(self.user_id, mailbox) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let exists = messages.len() as u32;
        let unseen = messages.iter().filter(|m| !m.flags.is_seen()).count() as u32;
        let uidvalidity = messages.first().map(|m| m.uidvalidity).unwrap_or(1);
        let uidnext = self
            .store
            .uidnext_in(self.user_id, mailbox)
            .unwrap_or(messages.first().map(|m| m.uid + 1).unwrap_or(1));
        let mut out = response::select_responses(exists, unseen, uidvalidity, uidnext);
        let mode = if read_only { "READ-ONLY" } else { "READ-WRITE" };
        out.push_str(&response::tagged(
            tag,
            Status::Ok,
            &format!(
                "[{mode}] {} completed",
                if read_only { "EXAMINE" } else { "SELECT" }
            ),
        ));
        self.selected_mailbox = mailbox.to_string();
        self.state = State::Selected;
        out
    }

    fn cmd_list(&self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state == State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Not authenticated");
        }
        let pattern = cmd.args.get(1).map(|s| s.as_str()).unwrap_or("");
        let mut out = String::new();
        if pattern.is_empty() || pattern == "*" || pattern.eq_ignore_ascii_case("INBOX") {
            out.push_str(&response::untagged(r#"LIST (\HasNoChildren) "/" "INBOX""#));
        }
        if pattern.is_empty() || pattern == "*" || pattern.eq_ignore_ascii_case("Sent") {
            out.push_str(&response::untagged(r#"LIST (\HasNoChildren) "/" "Sent""#));
        }
        out.push_str(&response::tagged(tag, Status::Ok, "LIST completed"));
        out
    }

    fn cmd_namespace(&self, tag: &str) -> String {
        if self.state == State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Not authenticated");
        }
        let mut out = response::untagged(r#"NAMESPACE (("" "/")) NIL NIL"#);
        out.push_str(&response::tagged(tag, Status::Ok, "NAMESPACE completed"));
        out
    }

    fn cmd_status(&self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state == State::NotAuthenticated {
            return response::tagged(tag, Status::Bad, "Not authenticated");
        }
        let Some(mailbox) = cmd.args.first().and_then(|s| canonical_mailbox(s)) else {
            return response::tagged(tag, Status::No, "Mailbox does not exist");
        };
        let messages = match self.store.list_messages_in(self.user_id, mailbox) {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let messages_count = messages.len();
        let unseen = messages.iter().filter(|m| !m.flags.is_seen()).count();
        let uidnext = self
            .store
            .uidnext_in(self.user_id, mailbox)
            .unwrap_or((messages_count as u32) + 1);
        let uidvalidity = messages.first().map(|m| m.uidvalidity).unwrap_or(1);
        let recent = 0; // v1 tracks no RECENT state.
        let mut out = response::untagged(&format!(
            "STATUS \"{}\" (MESSAGES {messages_count} RECENT {recent} UNSEEN {unseen} UIDNEXT {uidnext} UIDVALIDITY {uidvalidity})",
            mailbox
        ));
        out.push_str(&response::tagged(tag, Status::Ok, "STATUS completed"));
        out
    }

    fn cmd_fetch(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        // UID FETCH arrives as cmd.name == "UID" with args ["FETCH", ...] (the
        // subcommand may be any case — e.g. Thunderbird sends `uid fetch`).
        let sub = cmd.args.first().map(|s| s.to_ascii_uppercase());
        let (range, items) = match (sub.as_deref(), cmd.name.as_str()) {
            (Some("FETCH"), "UID") => {
                if cmd.args.len() < 3 {
                    return response::tagged(tag, Status::Bad, "UID FETCH requires arguments");
                }
                (cmd.args[1].clone(), cmd.args[2..].join(" "))
            }
            (_, "FETCH") | (_, "UID") => {
                if cmd.args.is_empty() {
                    return response::tagged(tag, Status::Bad, "FETCH requires a sequence set");
                }
                let items = if cmd.args.len() >= 2 {
                    cmd.args[1..].join(" ")
                } else {
                    "BODY[]".to_string()
                };
                (cmd.args[0].clone(), items)
            }
            _ => return response::tagged(tag, Status::Bad, "FETCH requires a sequence set"),
        };
        let messages = match self
            .store
            .list_messages_in(self.user_id, &self.selected_mailbox)
        {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let mut req = parse_fetch_items(&items);
        // RFC 3501 §6.4.8: the UID is always returned in a UID FETCH response,
        // regardless of the requested data items.
        if cmd.name == "UID" {
            req.uid = true;
        }
        // Only sections that return the stored body need a store read.
        let needs_body = req.body.needs_stored_body();
        let mut out = String::new();
        for meta in &messages {
            if !in_range(&range, meta.uid, messages.len() as u32) {
                continue;
            }
            let body = if needs_body {
                let msg =
                    match self
                        .store
                        .fetch_message_in(self.user_id, &self.selected_mailbox, meta.id)
                    {
                        Ok(m) => m,
                        Err(e) => return self.store_err(tag, e),
                    };
                msg.body
            } else {
                Vec::new()
            };
            out.push_str(&fetch_response(meta, &req, &body));
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
        // UID STORE arrives as cmd.name == "UID" with args ["STORE", ...] (the
        // subcommand may be any case).
        let sub = cmd.args.first().map(|s| s.to_ascii_uppercase());
        let (range, mode, flagspec) = match (sub.as_deref(), cmd.name.as_str()) {
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
        let messages = match self
            .store
            .list_messages_in(self.user_id, &self.selected_mailbox)
        {
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
            if let Err(e) =
                self.store
                    .set_flags_in(self.user_id, &self.selected_mailbox, meta.id, mask, value)
            {
                return self.store_err(tag, e);
            }
            // Reflect the *updated* flag state in the response.
            let mut new_flags = meta.flags;
            if value {
                new_flags.insert(mask);
            } else {
                new_flags.remove(mask);
            }
            out.push_str(&response::untagged(&format!(
                "{} FETCH (FLAGS ({}))",
                meta.uid,
                flags_display(new_flags)
            )));
        }
        out.push_str(&response::tagged(tag, Status::Ok, "STORE completed"));
        out
    }

    fn cmd_search(&mut self, tag: &str, cmd: &ParsedCommand) -> String {
        if self.state != State::Selected {
            return response::tagged(tag, Status::Bad, "No mailbox selected");
        }
        let messages = match self
            .store
            .list_messages_in(self.user_id, &self.selected_mailbox)
        {
            Ok(m) => m,
            Err(e) => return self.store_err(tag, e),
        };
        let args: Vec<&String> = if cmd.name == "UID" {
            // UID SEARCH arrives as ["SEARCH", ...] (any case).
            if cmd
                .args
                .first()
                .map(|s| s.eq_ignore_ascii_case("SEARCH"))
                .unwrap_or(false)
            {
                cmd.args.iter().skip(1).collect()
            } else {
                cmd.args.iter().collect()
            }
        } else {
            cmd.args.iter().collect()
        };
        // No criteria means ALL; `ALL` explicitly matches everything. Any
        // other criterion (UNSEEN, etc.) restricts.
        let mut all = args.is_empty();
        let mut unseen = false;
        for a in &args {
            match a.to_ascii_uppercase().as_str() {
                "ALL" => all = true,
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
        match self.store.expunge_in(self.user_id, &self.selected_mailbox) {
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

/// Which BODY section a FETCH requested.
#[derive(Debug, Clone, Default)]
enum BodySection {
    /// No body item requested.
    #[default]
    None,
    /// `BODY[]` — the full stored body.
    Full,
    /// `BODY[HEADER]` — the synthesized header block.
    Header,
    /// `BODY[HEADER.FIELDS (a b c)]` — a subset of the synthesized headers.
    HeaderFields(Vec<String>),
    /// `BODY[HEADER.FIELDS.NOT (a b c)]` — synthesized headers minus the list.
    HeaderFieldsNot(Vec<String>),
    /// `BODY[TEXT]` — the stored body.
    Text,
    /// `BODY[MIME]` — a minimal MIME part header.
    Mime,
    /// Any other section — served as `BODY[]` (safe default).
    Other(String),
}

impl BodySection {
    /// Whether the response must read the stored body from the store.
    fn needs_stored_body(&self) -> bool {
        matches!(
            self,
            BodySection::Full | BodySection::Text | BodySection::Mime | BodySection::Other(_)
        )
    }

    /// The literal marker for this section, e.g. `BODY[HEADER]`.
    fn label(&self) -> String {
        match self {
            BodySection::None | BodySection::Full => "BODY[]".to_string(),
            BodySection::Header => "BODY[HEADER]".to_string(),
            BodySection::Text => "BODY[TEXT]".to_string(),
            BodySection::Mime => "BODY[MIME]".to_string(),
            BodySection::HeaderFields(fields) => {
                format!("BODY[HEADER.FIELDS ({})]", fields.join(" "))
            }
            BodySection::HeaderFieldsNot(fields) => {
                format!("BODY[HEADER.FIELDS.NOT ({})]", fields.join(" "))
            }
            BodySection::Other(s) => format!("BODY[{s}]"),
        }
    }

    /// The literal bytes served for this section.
    fn content(&self, meta: &talk_mailstore::MessageMeta, body: &[u8]) -> Vec<u8> {
        match self {
            BodySection::None => Vec::new(),
            BodySection::Full | BodySection::Text | BodySection::Other(_) => body.to_vec(),
            BodySection::Mime => b"Content-Type: text/plain\r\n".to_vec(),
            BodySection::Header => header_lines(meta, None),
            BodySection::HeaderFields(fields) => header_lines(meta, Some((fields, false))),
            BodySection::HeaderFieldsNot(fields) => header_lines(meta, Some((fields, true))),
        }
    }
}

/// A parsed FETCH request: which items and which body section (if any).
#[derive(Debug, Clone, Default)]
struct FetchRequest {
    flags: bool,
    uid: bool,
    size: bool,
    internaldate: bool,
    envelope: bool,
    bodystructure: bool,
    body: BodySection,
}

/// Parse the FETCH data-items token into a [`FetchRequest`].
fn parse_fetch_items(items: &str) -> FetchRequest {
    let mut req = FetchRequest::default();
    let inner = items.trim();
    let inner = if inner.starts_with('(') && inner.ends_with(')') {
        &inner[1..inner.len() - 1]
    } else {
        inner
    };
    let upper = inner.to_ascii_uppercase();
    if upper.is_empty() || upper == "*" {
        // No items = the RFC 3501 "fetch all"; `*` is a client superset.
        req.flags = true;
        req.uid = true;
        req.size = true;
        req.internaldate = true;
        req.envelope = true;
        req.bodystructure = true;
        req.body = BodySection::Full;
        return req;
    }
    if upper == "ALL" || upper == "FULL" {
        req.flags = true;
        req.internaldate = true;
        req.size = true;
        req.envelope = true;
        req.body = BodySection::Full;
        return req;
    }
    if upper == "FAST" {
        req.flags = true;
        req.internaldate = true;
        req.size = true;
        return req;
    }
    let (rest, section) = extract_body_section(inner);
    req.body = section.map_or(BodySection::None, |s| parse_body_section(&s));
    for item in rest.split_whitespace() {
        match item.to_ascii_uppercase().as_str() {
            "FLAGS" => req.flags = true,
            "UID" => req.uid = true,
            "RFC822.SIZE" => req.size = true,
            "INTERNALDATE" => req.internaldate = true,
            "ENVELOPE" => req.envelope = true,
            "BODYSTRUCTURE" => req.bodystructure = true,
            _ => {}
        }
    }
    // When a body is requested, real clients also expect the standard trio
    // (FLAGS, UID, RFC822.SIZE) — RFC 3501 §6.4.5 permits extra items.
    if !matches!(req.body, BodySection::None) {
        req.flags = true;
        req.uid = true;
        req.size = true;
    }
    req
}

/// Strip a `BODY[...]`/`BODY.PEEK[...]` token out of the items, returning the
/// remaining items and the bracket section content.
fn extract_body_section(items: &str) -> (String, Option<String>) {
    let bytes = items.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        let at_boundary = i == 0
            || bytes[i - 1].is_ascii_whitespace()
            || bytes[i - 1] == b'('
            || bytes[i - 1] == b'[';
        if at_boundary && items[i..].to_ascii_uppercase().starts_with("BODY") {
            let start = i;
            let mut j = i + 4;
            while j < n && bytes[j] != b'[' {
                j += 1;
            }
            if j < n {
                let mut depth = 0i32;
                let mut k = j;
                while k < n {
                    match bytes[k] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                if k < n && depth == 0 {
                    let section = items[j + 1..k].to_string();
                    let mut rest = String::new();
                    rest.push_str(&items[..start]);
                    rest.push_str(&items[k + 1..]);
                    return (rest, Some(section));
                }
            }
        }
        i += 1;
    }
    (items.to_string(), None)
}

/// Parse a BODY section string (the `[...]` content) into a [`BodySection`].
fn parse_body_section(section: &str) -> BodySection {
    let s = section.trim();
    if s.is_empty() {
        return BodySection::Full;
    }
    let upper = s.to_ascii_uppercase();
    if upper == "HEADER" {
        return BodySection::Header;
    }
    if upper == "TEXT" {
        return BodySection::Text;
    }
    if upper == "MIME" {
        return BodySection::Mime;
    }
    if upper.starts_with("HEADER.FIELDS") {
        let is_not = upper.contains(".NOT");
        if let Some(list) = extract_field_list(s) {
            let fields: Vec<String> = list.split_whitespace().map(str::to_string).collect();
            return if is_not {
                BodySection::HeaderFieldsNot(fields)
            } else {
                BodySection::HeaderFields(fields)
            };
        }
    }
    BodySection::Other(s.to_string())
}

/// The `(a b c)` field list inside `HEADER.FIELDS (...)`, if present.
fn extract_field_list(s: &str) -> Option<&str> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(&s[open + 1..close])
}

/// Synthesize a minimal RFC 2822 header block from the stored metadata, so
/// clients that fetch `BODY[HEADER]` (e.g. Thunderbird's folder sync) see a
/// proper message. `filter` is `Some((fields, negate))` for `HEADER.FIELDS`.
fn header_lines(meta: &talk_mailstore::MessageMeta, filter: Option<(&[String], bool)>) -> Vec<u8> {
    let mut hdrs: Vec<(String, String)> = Vec::new();
    if !meta.sender.is_empty() {
        hdrs.push(("From".to_string(), meta.sender.clone()));
    }
    if !meta.subject.is_empty() {
        hdrs.push(("Subject".to_string(), meta.subject.clone()));
    }
    hdrs.push(("Date".to_string(), format_internaldate(meta.internaldate)));
    hdrs.push(("Message-ID".to_string(), format!("<{}>", meta.message_id)));
    if let Some(state) = &meta.tx_state {
        hdrs.push(("X-Talk-Txn-Status".to_string(), state.clone()));
        if let Some(tx_id) = meta.tx_id {
            hdrs.push(("X-Talk-Txn-Id".to_string(), tx_id.to_string()));
        }
    }
    let mut out = String::new();
    for (name, value) in &hdrs {
        let keep = match &filter {
            None => true,
            Some((fields, negate)) => {
                let listed = fields.iter().any(|f| f.eq_ignore_ascii_case(name));
                if *negate { !listed } else { listed }
            }
        };
        if keep {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push('\n');
    out.into_bytes()
}

fn fetch_response(meta: &talk_mailstore::MessageMeta, req: &FetchRequest, body: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    if req.flags {
        parts.push(format!("FLAGS ({})", flags_display(meta.flags)));
    }
    if req.uid {
        parts.push(format!("UID {}", meta.uid));
    }
    if req.size {
        // RFC822.SIZE is the stored size — never 0 when the body is unread.
        parts.push(format!("RFC822.SIZE {}", meta.size));
    }
    if req.internaldate {
        parts.push(format!(
            "INTERNALDATE \"{}\"",
            format_internaldate(meta.internaldate)
        ));
    }
    if req.envelope {
        parts.push(format!("ENVELOPE ({})", envelope_response(meta)));
    }
    if req.bodystructure {
        let lines = if body.is_empty() {
            1
        } else {
            body.iter().filter(|&&b| b == b'\n').count() + 1
        };
        parts.push(format!(
            "BODYSTRUCTURE (\"text\" \"plain\" NIL NIL NIL NIL {} {lines})",
            meta.size
        ));
    }

    if matches!(req.body, BodySection::None) {
        return response::untagged(&format!("{} FETCH ({})", meta.uid, parts.join(" ")));
    }

    // The body literal is the LAST item in the parenthesized list: the closing
    // `)` comes after the literal data (imap_proto requirement).
    let label = req.body.label();
    let content = req.body.content(meta, body);
    let mut out = String::new();
    out.push_str(&response::untagged(&format!(
        "{} FETCH ({} {label} {{{}}}",
        meta.uid,
        parts.join(" "),
        content.len()
    )));
    out.push_str(&String::from_utf8_lossy(&content));
    out.push_str(")\r\n");
    out
}

/// Format an internal date as `dd-Mon-yyyy hh:mm:ss +ZZZZ` (RFC 3501 date-time).
fn format_internaldate(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64;
    use time::macros::format_description;
    let fmt = format_description!(
        "[day padding:zero]-[month repr:short]-[year] [hour]:[minute]:[second] +0000"
    );
    let offset = time::UtcOffset::UTC;
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => dt
            .to_offset(offset)
            .format(&fmt)
            .unwrap_or_else(|_| "01-Jan-1970 00:00:00 +0000".to_string()),
        Err(_) => "01-Jan-1970 00:00:00 +0000".to_string(),
    }
}

/// Build the IMAP `envelope` struct from the stored message fields.
///
/// We store subject + message-id; From/To/Date are synthesized from the
/// internal date and the stored sender label (the mailbox is an
/// opaque-invoice store).
fn envelope_response(meta: &talk_mailstore::MessageMeta) -> String {
    let date = format_internaldate(meta.internaldate);
    let subject = response::quote(&meta.subject);
    let message_id = response::quote(&meta.message_id);
    format!("{date} {subject} NIL NIL NIL NIL NIL NIL NIL {message_id}")
}

/// Whether `username` is a member of the OS `zsmtp` group. Used by the
/// `localauth` auth mode: the connecting user must be in the group and must
/// match their mailbox username.
fn is_in_zsmtp_group(username: &str) -> bool {
    // A user is "in the zsmtp group" if the zsmtp group's member list contains
    // them. This uses `getgrnam`; if the group does not exist, deny.
    unsafe {
        let gr = libc::getgrnam(c"zsmtp".as_ptr().cast());
        if gr.is_null() {
            return false;
        }
        let mem = (*gr).gr_mem;
        if mem.is_null() {
            return false;
        }
        let mut i = 0;
        while !(*mem.add(i)).is_null() {
            let name = std::ffi::CStr::from_ptr(*mem.add(i));
            if name.to_bytes() == username.as_bytes() {
                return true;
            }
            i += 1;
        }
        false
    }
}
