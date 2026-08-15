use crate::{Message, MessageFlags, MessageMeta, NewMessage, StoreError, User, now_secs};
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
                UNIQUE (mailbox_id, message_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_mailbox_uid
                ON messages (mailbox_id, uid);
            CREATE INDEX IF NOT EXISTS idx_messages_mailbox_flags
                ON messages (mailbox_id, flags);
            "#,
        )?;
        Ok(())
    }

    /// Create a user and their INBOX.
    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        master_pubkey: &[u8],
    ) -> Result<User, StoreError> {
        let now = now_secs();
        let guard = self.lock()?;
        guard.execute(
            "INSERT INTO users (username, password_hash, master_pubkey, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, master_pubkey, now],
        )?;
        let user_id = guard.last_insert_rowid();
        let uidvalidity = now as u32;
        guard.execute(
            "INSERT INTO mailboxes (user_id, name, uidvalidity) VALUES (?1, 'INBOX', ?2)",
            params![user_id, uidvalidity],
        )?;
        Ok(User {
            id: user_id,
            username: username.to_string(),
            master_pubkey: master_pubkey.to_vec(),
        })
    }

    /// Look up a user by username.
    pub fn get_user(&self, username: &str) -> Result<Option<User>, StoreError> {
        let guard = self.lock()?;
        let mut stmt =
            guard.prepare("SELECT id, username, master_pubkey FROM users WHERE username = ?1")?;
        let mut rows = stmt.query_map(params![username], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                master_pubkey: row.get(2)?,
            })
        })?;
        rows.next().transpose().map_err(StoreError::from)
    }

    fn mailbox_row(&self, user_id: i64) -> Result<(i64, u32, i64), StoreError> {
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT id, uidvalidity, uidnext FROM mailboxes WHERE user_id = ?1 AND name = 'INBOX'",
                params![user_id],
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
        let (mailbox_id, uidvalidity, uidnext) = self.mailbox_row(user_id)?;
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
        guard.execute(
            "INSERT INTO messages
             (mailbox_id, message_id, uid, internaldate, flags, subject, size, body_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                mailbox_id,
                msg.message_id,
                uid,
                internaldate,
                msg.flags.bits(),
                msg.subject,
                size,
                msg.body,
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
        })
    }

    /// List message metadata for a user's INBOX, newest first.
    pub fn list_messages(&self, user_id: i64) -> Result<Vec<MessageMeta>, StoreError> {
        let (mailbox_id, uidvalidity, _) = self.mailbox_row(user_id)?;
        let guard = self.lock()?;
        let mut stmt = guard.prepare(
            "SELECT id, message_id, uid, internaldate, flags, subject, size
             FROM messages WHERE mailbox_id = ?1
             ORDER BY uid DESC",
        )?;
        let rows = stmt
            .query_map(params![mailbox_id], |row| Ok(row_to_meta(row, uidvalidity)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The next UID the mailbox would allocate (UIDNEXT), i.e. the monotonic
    /// counter that is never reused even after expunge.
    pub fn uidnext(&self, user_id: i64) -> Result<u32, StoreError> {
        let (_, _, uidnext) = self.mailbox_row(user_id)?;
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

    /// Fetch a full message (including body) by message row id.
    pub fn fetch_message(&self, user_id: i64, message_id: i64) -> Result<Message, StoreError> {
        let (mailbox_id, uidvalidity, _) = self.mailbox_row(user_id)?;
        let guard = self.lock()?;
        guard
            .query_row(
                "SELECT id, message_id, uid, internaldate, flags, subject, size, body_blob
                 FROM messages WHERE mailbox_id = ?1 AND id = ?2",
                params![mailbox_id, message_id],
                |row| {
                    Ok(Message {
                        meta: row_to_meta(row, uidvalidity),
                        body: row.get(7)?,
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
        let (mailbox_id, _, _) = self.mailbox_row(user_id)?;
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
        let (mailbox_id, _, _) = self.mailbox_row(user_id)?;
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
    MessageMeta {
        id,
        message_id,
        uid: uid as u32,
        uidvalidity,
        internaldate: UNIX_EPOCH + Duration::from_secs(internaldate as u64),
        flags: MessageFlags::new(flags),
        subject,
        size: size as u64,
    }
}
