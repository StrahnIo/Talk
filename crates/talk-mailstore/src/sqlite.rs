use crate::{
    KeyringEntry, Message, MessageFlags, MessageMeta, NewMessage, ShareEntry, StoreError,
    Transaction, TxDirection, TxState, User, UserSummary, now_secs,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

/// A mail store backed by SQLite.
///
/// v1 uses plain bundled SQLite. SQLCipher at-rest encryption is deferred: it
/// cannot coexist in one process with `zcash_client_sqlite`'s plain `bundled`
/// sqlite (the two require mutually-exclusive `libsqlite3-sys` features). If
/// at-rest encryption is required, the mailbox must run as a separate process.
pub struct SqliteMailStore {
    path: PathBuf,
    conn: Mutex<Connection>,
}

impl SqliteMailStore {
    /// Open (or create) the store at `path`.
    ///
    /// The store is INBOX-only for v1: each user gets exactly one mailbox.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            path,
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn.lock().map_err(|_| StoreError::Poisoned)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let guard = self.lock()?;
        guard.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                master_pubkey BLOB NOT NULL,
                created_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS keyring_entries (
                user_id       INTEGER NOT NULL REFERENCES users(id),
                sender_mailbox TEXT   NOT NULL,
                sender_pubkey  TEXT   NOT NULL,
                attestation    BLOB   NOT NULL,
                state          TEXT   NOT NULL,
                first_seen     INTEGER NOT NULL,
                PRIMARY KEY (user_id, sender_mailbox)
            );

            CREATE TABLE IF NOT EXISTS shares (
                user_id     INTEGER NOT NULL REFERENCES users(id),
                share_id    TEXT    NOT NULL,
                wrapped_dk  BLOB    NOT NULL,
                revoked     INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, share_id)
            );

            CREATE TABLE IF NOT EXISTS mailboxes (
                id          INTEGER PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                name        TEXT    NOT NULL,
                uidvalidity INTEGER NOT NULL,
                uidnext     INTEGER NOT NULL DEFAULT 1,
                UNIQUE (user_id, name)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY,
                mailbox_id  INTEGER NOT NULL REFERENCES mailboxes(id),
                message_id  TEXT    NOT NULL,
                uid         INTEGER NOT NULL,
                internaldate INTEGER NOT NULL,
                flags       INTEGER NOT NULL DEFAULT 0,
                subject     TEXT    NOT NULL,
                size        INTEGER NOT NULL,
                body_blob   BLOB    NOT NULL,
                sender      TEXT    NOT NULL DEFAULT '',
                trust_state TEXT    NOT NULL DEFAULT 'unverified',
                UNIQUE (mailbox_id, message_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_mailbox_uid
                ON messages (mailbox_id, uid);
            CREATE INDEX IF NOT EXISTS idx_messages_mailbox_flags
                ON messages (mailbox_id, flags);

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id               INTEGER PRIMARY KEY,
                direction        TEXT NOT NULL,
                state            TEXT NOT NULL,
                sender_mailbox   TEXT NOT NULL,
                recipient_mailbox TEXT NOT NULL,
                amount           TEXT NOT NULL DEFAULT '',
                binding          TEXT,
                message_id       TEXT NOT NULL,
                message_row_id   INTEGER,
                outbound_body    BLOB,
                created_at       INTEGER NOT NULL,
                updated_at       INTEGER NOT NULL,
                UNIQUE (direction, message_id)
            );
            "#,
        )?;
        // Migrations for columns added after the initial schema.
        for (table, col, ddl) in [
            (
                "users",
                "ivk_commitment",
                "ALTER TABLE users ADD COLUMN ivk_commitment TEXT",
            ),
            (
                "users",
                "registration_attestation",
                "ALTER TABLE users ADD COLUMN registration_attestation TEXT",
            ),
            (
                "messages",
                "sender",
                "ALTER TABLE messages ADD COLUMN sender TEXT NOT NULL DEFAULT ''",
            ),
            (
                "messages",
                "trust_state",
                "ALTER TABLE messages ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'unverified'",
            ),
        ] {
            let has: i64 = guard.query_row(
                &format!("SELECT count(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                params![col],
                |r| r.get(0),
            )?;
            if has == 0 {
                guard.execute_batch(ddl)?;
            }
        }
        Ok(())
    }

    /// Create a user and their INBOX.
    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        master_pubkey: &[u8],
    ) -> Result<User, StoreError> {
        self.create_user_full(username, password_hash, master_pubkey, None, None)
    }

    /// Create a user with an optional IVK commitment and registration
    /// attestation, plus their INBOX.
    pub fn create_user_full(
        &self,
        username: &str,
        password_hash: &str,
        master_pubkey: &[u8],
        ivk_commitment: Option<String>,
        registration_attestation: Option<String>,
    ) -> Result<User, StoreError> {
        let now = now_secs();
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO users (username, password_hash, master_pubkey, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, master_pubkey, now],
        )?;
        let user_id = guard.last_insert_rowid();
        if let Some(ivk) = ivk_commitment.as_deref() {
            guard.execute(
                "UPDATE users SET ivk_commitment = ?1 WHERE id = ?2",
                params![ivk, user_id],
            )?;
        }
        if let Some(r) = registration_attestation.as_deref() {
            guard.execute(
                "UPDATE users SET registration_attestation = ?1 WHERE id = ?2",
                params![r, user_id],
            )?;
        }
        let uidvalidity = now as u32;
        guard.execute(
            "INSERT INTO mailboxes (user_id, name, uidvalidity) VALUES (?1, 'INBOX', ?2)",
            params![user_id, uidvalidity],
        )?;
        guard.execute(
            "INSERT INTO mailboxes (user_id, name, uidvalidity) VALUES (?1, 'Sent', ?2)",
            params![user_id, uidvalidity],
        )?;
        Ok(User {
            id: user_id,
            username: username.to_string(),
            master_pubkey: master_pubkey.to_vec(),
            ivk_commitment,
            registration_attestation,
        })
    }

    /// Look up a user by username.
    pub fn get_user(&self, username: &str) -> Result<Option<User>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT id, username, master_pubkey, ivk_commitment, registration_attestation
             FROM users WHERE username = ?1",
        )?;
        let mut rows = stmt.query_map(params![username], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                master_pubkey: row.get(2)?,
                ivk_commitment: row.get(3)?,
                registration_attestation: row.get(4)?,
            })
        })?;
        rows.next().transpose().map_err(StoreError::from)
    }

    /// The stored argon2 password hash for a user, if any.
    pub fn password_hash(&self, username: &str) -> Result<Option<String>, StoreError> {
        let guard = self.lock()?;
        let hash: Option<String> = guard
            .query_row(
                "SELECT password_hash FROM users WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .optional()?;
        Ok(hash)
    }

    /// List all users (id, username, created_at, ivk/attestation presence).
    pub fn list_users(&self) -> Result<Vec<UserSummary>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT id, username, created_at,
                    ivk_commitment IS NOT NULL,
                    registration_attestation IS NOT NULL
             FROM users ORDER BY username",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(UserSummary {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    created_at: row.get(2)?,
                    has_ivk: row.get::<_, i64>(3)? != 0,
                    has_attestation: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replace a user's password hash (password change).
    pub fn set_password(&self, username: &str, password_hash: &str) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute(
            "UPDATE users SET password_hash = ?1 WHERE username = ?2",
            params![password_hash, username],
        )?;
        if n == 0 {
            return Err(StoreError::UserNotFound(username.to_string()));
        }
        Ok(())
    }

    /// Set (or clear, with `None`) a user's IVK commitment.
    pub fn set_ivk(&self, username: &str, ivk_commitment: Option<&str>) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute(
            "UPDATE users SET ivk_commitment = ?1 WHERE username = ?2",
            params![ivk_commitment, username],
        )?;
        if n == 0 {
            return Err(StoreError::UserNotFound(username.to_string()));
        }
        Ok(())
    }

    /// Delete a user and everything they own (shares, keyring, mailbox,
    /// messages) in one transaction.
    pub fn delete_user(&self, username: &str) -> Result<(), StoreError> {
        let user = match self.get_user(username)? {
            Some(u) => u,
            None => return Err(StoreError::UserNotFound(username.to_string())),
        };
        let guard = self.lock()?;
        guard.execute_batch("BEGIN")?;
        let result = (|| -> Result<(), StoreError> {
            guard.execute(
                "DELETE FROM keyring_entries WHERE user_id = ?1",
                params![user.id],
            )?;
            guard.execute("DELETE FROM shares WHERE user_id = ?1", params![user.id])?;
            guard.execute(
                "DELETE FROM transactions WHERE message_row_id IN
                 (SELECT id FROM messages WHERE mailbox_id IN
                 (SELECT id FROM mailboxes WHERE user_id = ?1))
                 OR sender_mailbox LIKE ?2",
                params![user.id, format!("{}@%", user.username)],
            )?;
            guard.execute(
                "DELETE FROM messages WHERE mailbox_id IN
                 (SELECT id FROM mailboxes WHERE user_id = ?1)",
                params![user.id],
            )?;
            guard.execute(
                "DELETE FROM mailboxes WHERE user_id = ?1",
                params![user.id],
            )?;
            guard.execute("DELETE FROM users WHERE id = ?1", params![user.id])?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                guard.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    // -----------------------------------------------------------------------
    // transaction ledger
    // -----------------------------------------------------------------------

    /// Create a ledger transaction.
    pub fn tx_create(&self, t: crate::NewTransaction) -> Result<Transaction, StoreError> {
        let now = now_secs();
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO transactions
             (direction, state, sender_mailbox, recipient_mailbox, amount, binding,
              message_id, outbound_body, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                t.direction.as_str(),
                t.state.as_str(),
                &t.sender_mailbox,
                &t.recipient_mailbox,
                &t.amount,
                t.binding.as_deref(),
                &t.message_id,
                t.outbound_body.as_deref(),
                now,
                now,
            ],
        )?;
        Ok(Transaction {
            id: guard.last_insert_rowid(),
            direction: t.direction,
            state: t.state,
            sender_mailbox: t.sender_mailbox,
            recipient_mailbox: t.recipient_mailbox,
            amount: t.amount,
            binding: t.binding,
            message_id: t.message_id,
            message_row_id: None,
            outbound_body: t.outbound_body,
            created_at: now,
            updated_at: now,
        })
    }

    /// Link a transaction to the message row it produced (or the Sent copy).
    pub fn tx_link_message(&self, tx_id: i64, message_row_id: i64) -> Result<(), StoreError> {
        let guard = self.lock()?;
        guard.execute(
            "UPDATE transactions SET message_row_id = ?1, updated_at = ?2 WHERE id = ?3",
            params![message_row_id, now_secs(), tx_id],
        )?;
        Ok(())
    }

    /// Fetch a transaction by id.
    pub fn tx_get(&self, id: i64) -> Result<Option<Transaction>, StoreError> {
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT id, direction, state, sender_mailbox, recipient_mailbox, amount,
                        binding, message_id, message_row_id, outbound_body, created_at, updated_at
                 FROM transactions WHERE id = ?1",
                params![id],
                row_to_tx,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Fetch a transaction by its (direction, message_id) pair.
    pub fn tx_by_message_id(
        &self,
        direction: TxDirection,
        message_id: &str,
    ) -> Result<Option<Transaction>, StoreError> {
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT id, direction, state, sender_mailbox, recipient_mailbox, amount,
                        binding, message_id, message_row_id, outbound_body, created_at, updated_at
                 FROM transactions WHERE direction = ?1 AND message_id = ?2",
                params![direction.as_str(), message_id],
                row_to_tx,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// List transactions, newest first, optionally filtered.
    pub fn tx_list(
        &self,
        direction: Option<TxDirection>,
        state: Option<TxState>,
    ) -> Result<Vec<Transaction>, StoreError> {
        let guard = self.lock()?;
        let mut sql = String::from(
            "SELECT id, direction, state, sender_mailbox, recipient_mailbox, amount,
                    binding, message_id, message_row_id, outbound_body, created_at, updated_at
             FROM transactions",
        );
        let mut conds: Vec<String> = Vec::new();
        let mut vals: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(d) = direction {
            conds.push("direction = ?".to_string());
            vals.push(Box::new(d.as_str().to_string()));
        }
        if let Some(s) = state {
            conds.push("state = ?".to_string());
            vals.push(Box::new(s.as_str().to_string()));
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC");
        let params = rusqlite::params_from_iter(vals.iter().map(|v| v.as_ref()));
        let mut stmt = guard.prepare(&sql)?;
        let rows = stmt
            .query_map(params, row_to_tx)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Transition a transaction to a new state.
    pub fn tx_transition(&self, id: i64, state: TxState) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute(
            "UPDATE transactions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state.as_str(), now_secs(), id],
        )?;
        if n == 0 {
            return Err(StoreError::UserNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Pin a sender as trusted for a user (client-verified attestation).
    pub fn keyring_set_trusted(
        &self,
        user_id: i64,
        sender_mailbox: &str,
        sender_pubkey: &str,
        attestation: &[u8],
    ) -> Result<(), StoreError> {
        let now = now_secs();
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO keyring_entries
             (user_id, sender_mailbox, sender_pubkey, attestation, state, first_seen)
             VALUES (?1, ?2, ?3, ?4, 'trusted', ?5)
             ON CONFLICT(user_id, sender_mailbox) DO UPDATE SET
               sender_pubkey = excluded.sender_pubkey,
               attestation = excluded.attestation,
               state = 'trusted'",
            params![user_id, sender_mailbox, sender_pubkey, attestation, now],
        )?;
        Ok(())
    }

    /// The pinned sender key for a user, if any.
    pub fn keyring_sender_key(
        &self,
        user_id: i64,
        sender_mailbox: &str,
    ) -> Result<Option<String>, StoreError> {
        let guard = self.lock()?;
        let key: Option<String> = guard
            .query_row(
                "SELECT sender_pubkey FROM keyring_entries
                 WHERE user_id = ?1 AND sender_mailbox = ?2 AND state = 'trusted'",
                params![user_id, sender_mailbox],
                |row| row.get(0),
            )
            .optional()?;
        Ok(key)
    }

    fn mailbox_named(
        &self,
        user_id: i64,
        name: &str,
    ) -> Result<(i64, u32, i64), StoreError> {
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT id, uidvalidity, uidnext FROM mailboxes WHERE user_id = ?1 AND name = ?2",
                params![user_id, name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(StoreError::from)?
            .ok_or(StoreError::MailboxNotFound)
    }

    /// Append a message to a user's INBOX. Fails on duplicate message id.
    ///
    /// UIDs are allocated from the mailbox's monotonic `uidnext` counter and are
    /// never reused, even after expunge (IMAP requirement).
    pub fn append_message(&self, user_id: i64, msg: NewMessage) -> Result<MessageMeta, StoreError> {
        self.append_message_to(user_id, crate::INBOX, msg)
    }

    /// Append a message to a named mailbox. Fails on duplicate message id.
    pub fn append_message_to(
        &self,
        user_id: i64,
        mailbox: &str,
        msg: NewMessage,
    ) -> Result<MessageMeta, StoreError> {
        let (mailbox_id, uidvalidity, uidnext) = self.mailbox_named(user_id, mailbox)?;
        let guard = self.lock()?;
        let exists: i64 = guard.query_row(
            "SELECT count(*) FROM messages WHERE mailbox_id = ?1 AND message_id = ?2",
            params![mailbox_id, msg.message_id],
            |row| row.get(0),
        )?;
        if exists > 0 {
            return Err(StoreError::DuplicateMessage(msg.message_id));
        }
        let uid = uidnext;
        let internaldate = now_secs();
        let size = msg.body.len() as i64;
        let sender = msg.sender.clone();
        guard.execute(
            "INSERT INTO messages
             (mailbox_id, message_id, uid, internaldate, flags, subject, size, body_blob, sender, trust_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                mailbox_id,
                &msg.message_id,
                uid,
                internaldate,
                msg.flags.bits(),
                &msg.subject,
                size,
                &msg.body,
                &sender,
                &msg.trust_state,
            ],
        )?;
        guard.execute(
            "UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = ?1",
            params![mailbox_id],
        )?;
        Ok(MessageMeta {
            id: guard.last_insert_rowid(),
            message_id: msg.message_id,
            uid: uid as u32,
            uidvalidity,
            internaldate: UNIX_EPOCH + Duration::from_secs(internaldate as u64),
            flags: msg.flags,
            subject: msg.subject,
            size: size as u64,
            sender,
            trust_state: msg.trust_state,
            tx_state: None,
        })
    }

    /// List message metadata for a user's INBOX, newest first.
    pub fn list_messages(&self, user_id: i64) -> Result<Vec<MessageMeta>, StoreError> {
        self.list_messages_in(user_id, crate::INBOX)
    }

    /// List message metadata for a named mailbox, newest first.
    pub fn list_messages_in(
        &self,
        user_id: i64,
        mailbox: &str,
    ) -> Result<Vec<MessageMeta>, StoreError> {
        let (mailbox_id, uidvalidity, _) = self.mailbox_named(user_id, mailbox)?;
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT m.id, m.message_id, m.uid, m.internaldate, m.flags, m.subject,
                    m.size, m.sender, m.trust_state, t.state
             FROM messages m
             LEFT JOIN transactions t ON t.message_row_id = m.id
             WHERE m.mailbox_id = ?1
             ORDER BY m.uid DESC",
        )?;
        let rows = stmt
            .query_map(params![mailbox_id], |row| Ok(row_to_meta(row, uidvalidity)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The next UID the mailbox would allocate (UIDNEXT), i.e. the monotonic
    /// counter that is never reused even after expunge.
    pub fn uidnext(&self, user_id: i64) -> Result<u32, StoreError> {
        self.uidnext_in(user_id, crate::INBOX)
    }

    /// UIDNEXT for a named mailbox.
    pub fn uidnext_in(&self, user_id: i64, mailbox: &str) -> Result<u32, StoreError> {
        let (_, _, uidnext) = self.mailbox_named(user_id, mailbox)?;
        Ok(uidnext as u32)
    }

    /// The user's DK wrappers: `(share_id, wrapped_dk)` for every non-revoked
    /// share. Used by app-password login to unwrap the data key.
    pub fn get_shares(&self, user_id: i64) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT share_id, wrapped_dk FROM shares WHERE user_id = ?1 AND revoked = 0",
        )?;
        let rows = stmt
            .query_map(params![user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Register a DK wrapper for a user (app-password share).
    pub fn add_share(
        &self,
        user_id: i64,
        share_id: &str,
        wrapped_dk: &[u8],
    ) -> Result<(), StoreError> {
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO shares (user_id, share_id, wrapped_dk, revoked)
             VALUES (?1, ?2, ?3, 0)",
            params![user_id, share_id, wrapped_dk],
        )?;
        Ok(())
    }

    /// List a user's shares, including revoked ones (with their revoked state).
    pub fn list_shares(&self, user_id: i64) -> Result<Vec<ShareEntry>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT share_id, wrapped_dk, revoked FROM shares WHERE user_id = ?1 ORDER BY share_id",
        )?;
        let rows = stmt
            .query_map(params![user_id], |row| {
                Ok(ShareEntry {
                    share_id: row.get(0)?,
                    wrapped_dk: row.get(1)?,
                    revoked: row.get::<_, i64>(2)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Revoke a share: mark its wrapper revoked. The wrapped DK stays in the
    /// row (dropped on next re-wrap, a client-side operation).
    pub fn revoke_share(&self, user_id: i64, share_id: &str) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute(
            "UPDATE shares SET revoked = 1 WHERE user_id = ?1 AND share_id = ?2",
            params![user_id, share_id],
        )?;
        if n == 0 {
            return Err(StoreError::UserNotFound(share_id.to_string()));
        }
        Ok(())
    }

    /// List a user's keyring entries (pinned senders).
    pub fn list_keyring(&self, user_id: i64) -> Result<Vec<KeyringEntry>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT sender_mailbox, sender_pubkey, state, first_seen
             FROM keyring_entries WHERE user_id = ?1 ORDER BY first_seen",
        )?;
        let rows = stmt
            .query_map(params![user_id], |row| {
                Ok(KeyringEntry {
                    sender_mailbox: row.get(0)?,
                    sender_pubkey: row.get(1)?,
                    state: row.get(2)?,
                    first_seen: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Remove a pinned sender from a user's keyring.
    pub fn unpin_keyring(&self, user_id: i64, sender_mailbox: &str) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute(
            "DELETE FROM keyring_entries WHERE user_id = ?1 AND sender_mailbox = ?2",
            params![user_id, sender_mailbox],
        )?;
        if n == 0 {
            return Err(StoreError::UserNotFound(sender_mailbox.to_string()));
        }
        Ok(())
    }

    /// Read a server-side setting (`None` if unset).
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        let guard = self.lock()?;
        let value: Option<String> = guard
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Set a server-side setting (upsert).
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// All server-side settings, sorted by key.
    pub fn list_settings(&self) -> Result<Vec<(String, String)>, StoreError> {
        let guard = self.lock()?;
        let mut stmt = guard.prepare("SELECT key, value FROM settings ORDER BY key")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a server-side setting.
    pub fn delete_setting(&self, key: &str) -> Result<(), StoreError> {
        let guard = self.lock()?;
        let n = guard.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        if n == 0 {
            return Err(StoreError::UserNotFound(key.to_string()));
        }
        Ok(())
    }

    /// Fetch a full message (including body) by message row id.
    pub fn fetch_message(&self, user_id: i64, message_id: i64) -> Result<Message, StoreError> {
        self.fetch_message_in(user_id, crate::INBOX, message_id)
    }

    /// Fetch a full message from a named mailbox.
    pub fn fetch_message_in(
        &self,
        user_id: i64,
        mailbox: &str,
        message_id: i64,
    ) -> Result<Message, StoreError> {
        let (mailbox_id, uidvalidity, _) = self.mailbox_named(user_id, mailbox)?;
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT m.id, m.message_id, m.uid, m.internaldate, m.flags, m.subject,
                        m.size, m.sender, m.trust_state, t.state, m.body_blob
                 FROM messages m
                 LEFT JOIN transactions t ON t.message_row_id = m.id
                 WHERE m.mailbox_id = ?1 AND m.id = ?2",
                params![mailbox_id, message_id],
                |row| {
                    Ok(Message {
                        meta: row_to_meta(row, uidvalidity),
                        body: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)?
            .ok_or(StoreError::MessageNotFound)
    }

    /// Update flags for a message.
    pub fn set_flags(
        &self,
        user_id: i64,
        message_id: i64,
        mask: u32,
        value: bool,
    ) -> Result<(), StoreError> {
        self.set_flags_in(user_id, crate::INBOX, message_id, mask, value)
    }

    /// Update flags for a message in a named mailbox.
    pub fn set_flags_in(
        &self,
        user_id: i64,
        mailbox: &str,
        message_id: i64,
        mask: u32,
        value: bool,
    ) -> Result<(), StoreError> {
        let (mailbox_id, _, _) = self.mailbox_named(user_id, mailbox)?;
        let guard = self.lock()?;
        if value {
            guard.execute(
                "UPDATE messages SET flags = flags | ?1 WHERE mailbox_id = ?2 AND id = ?3",
                params![mask, mailbox_id, message_id],
            )?;
        } else {
            guard.execute(
                "UPDATE messages SET flags = flags & ~?1 WHERE mailbox_id = ?2 AND id = ?3",
                params![mask, mailbox_id, message_id],
            )?;
        }
        Ok(())
    }

    /// Expunge (delete) messages flagged \Deleted.
    pub fn expunge(&self, user_id: i64) -> Result<Vec<u32>, StoreError> {
        self.expunge_in(user_id, crate::INBOX)
    }

    /// Expunge (delete) messages flagged \Deleted in a named mailbox.
    pub fn expunge_in(&self, user_id: i64, mailbox: &str) -> Result<Vec<u32>, StoreError> {
        let (mailbox_id, _, _) = self.mailbox_named(user_id, mailbox)?;
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT uid FROM messages
             WHERE mailbox_id = ?1 AND (flags & ?2) != 0
             ORDER BY uid",
        )?;
        let uids: Vec<u32> = stmt
            .query_map(params![mailbox_id, MessageFlags::DELETED], |row| {
                row.get::<_, i64>(0).map(|v| v as u32)
            })?
            .collect::<Result<_, _>>()?;
        guard.execute(
            "DELETE FROM messages WHERE mailbox_id = ?1 AND (flags & ?2) != 0",
            params![mailbox_id, MessageFlags::DELETED],
        )?;
        Ok(uids)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn row_to_meta(row: &rusqlite::Row<'_>, uidvalidity: u32) -> MessageMeta {
    let id: i64 = row.get(0).unwrap_or(0);
    let message_id: String = row.get(1).unwrap_or_default();
    let uid: i64 = row.get(2).unwrap_or(0);
    let internaldate: i64 = row.get(3).unwrap_or(0);
    let flags: u32 = row.get(4).unwrap_or(0);
    let subject: String = row.get(5).unwrap_or_default();
    let size: i64 = row.get(6).unwrap_or(0);
    let sender: String = row.get(7).unwrap_or_default();
    let trust_state: String = row.get(8).unwrap_or_else(|_| "unverified".to_string());
    let tx_state: Option<String> = row.get(9).unwrap_or(None);
    MessageMeta {
        id,
        message_id,
        uid: uid as u32,
        uidvalidity,
        internaldate: UNIX_EPOCH + Duration::from_secs(internaldate as u64),
        flags: MessageFlags::new(flags),
        subject,
        size: size as u64,
        sender,
        trust_state,
        tx_state,
    }
}

fn row_to_tx(row: &rusqlite::Row<'_>) -> rusqlite::Result<Transaction> {
    Ok(Transaction {
        id: row.get(0)?,
        direction: TxDirection::parse(&row.get::<_, String>(1)?).unwrap_or(TxDirection::In),
        state: TxState::parse(&row.get::<_, String>(2)?).unwrap_or(TxState::Opaque),
        sender_mailbox: row.get(3)?,
        recipient_mailbox: row.get(4)?,
        amount: row.get(5)?,
        binding: row.get(6)?,
        message_id: row.get(7)?,
        message_row_id: row.get(8)?,
        outbound_body: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}
