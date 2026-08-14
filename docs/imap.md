# IMAP Mailbox Server (hand-rolled)

The mailbox server is a minimal, hand-rolled IMAP4rev1 server written in Rust
(`tokio`), with **zero IMAP frameworks**. It stores and serves already-rendered,
opaque messages handed to it by the delivery path. It contains no templating and
no push logic beyond IDLE.

`mailbox.sock` is this IMAP listener. HTTP/2 on the mailbox was not hardline and
is **not** a day-one requirement.

## Scope

- Reference implementation, `tokio`-based, no IMAP crates.
- One mailbox per authenticated user (`INBOX` only in v1).
- Receives pre-rendered MIME bytes (opaque to IMAP) from the delivery path.
- **IMAPS-first** — TLS on connect (port 993). No STARTTLS in v1.
- IDLE-only push.

## Command subset (RFC 3501)

| Command | Purpose |
|---|---|
| `CAPABILITY` | Advertise `IMAP4rev1 IDLE AUTH=PLAIN` (+ TLS) |
| `STARTTLS` / `AUTHENTICATE PLAIN` / `LOGIN` / `LOGOUT` | Session lifecycle |
| `LIST` / `LSUB` / `SELECT` / `EXAMINE` / `STATUS` | Mailbox ops (INBOX-focused) |
| `FETCH` | `ENVELOPE`, `BODYSTRUCTURE`, `BODY[]`, `BODY.PEEK[]`, `FLAGS`, `UID`, `INTERNALDATE`, `RFC822.SIZE` |
| `STORE` | `FLAGS`, `+FLAGS`, `-FLAGS` (`\Seen`, `\Flagged`, `\Answered`, `\Deleted`) |
| `SEARCH` | `ALL`, `UNSEEN`, `UID`, `TEXT`, `FROM`, `SUBJECT`, `SINCE` |
| `UID FETCH` / `UID STORE` / `UID SEARCH` | UID-based access (client requirement) |
| `IDLE` / `DONE` | Push (RFC 2177) |
| `NOOP` / `EXPUNGE` / `CLOSE` | Housekeeping |

**Out of scope (declared; clients degrade gracefully):** `SORT`, `THREAD`,
`MOVE`, `COPY`, `APPEND`, `CREATE`/`DELETE`/`RENAME`, `NAMESPACE`, `NOTIFY`,
`LITERAL+`, `CONDSTORE`/`QRESYNC`, `UID EXPUNGE`, quotas/ACLs, multi-mailbox
search.

## Framing and session model

- Commands: CRLF-terminated lines with `{n}` literal support (required for
  `LOGIN` and large sealed-body `FETCH` output). Synchronous literals only.
- Three response types: tagged (`A1 OK`), untagged (`* n EXISTS`), continuation
  (`+`).
- Parser rejects malformed input → `BAD`; strict RFC status codes
  (`OK` / `NO` / `BAD` / `BYE`).
- Session state machine: **Not Authenticated → Authenticated → Selected**;
  commands gated by state.

## Concurrency and robustness

- One `tokio` task per connection; framing with explicit timeouts (command,
  literal, IDLE).
- Bounded-work guarantees: max literal size, max message size, connection
  limits, backpressure on the store, graceful `BYE` on timeout/logout.
- `tracing` for session logs; every error path returns a valid IMAP response.

## Storage (SQLite + optional SQLCipher)

SQLite via `rusqlite` (with `bundled-sqlcipher` feature), behind the `MailStore`
trait and called through `tokio::task::spawn_blocking`. SQLCipher is a compile-
time/config toggle (`encrypt = true` → operator passphrase → `PRAGMA key`).

### Schema (v1)

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,          -- for standard login
    master_pubkey BLOB NOT NULL,          -- encrypt-all data key (DK wrap)
    created_at    INTEGER NOT NULL
);

CREATE TABLE shares (
    user_id     INTEGER NOT NULL REFERENCES users(id),
    share_id    TEXT    NOT NULL,
    wrapped_dk  BLOB    NOT NULL,         -- DK wrapped under this share
    revoked     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, share_id)
);

CREATE TABLE mailboxes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    name      TEXT    NOT NULL,
    uidvalidity INTEGER NOT NULL
);

CREATE TABLE messages (
    id          INTEGER PRIMARY KEY,
    mailbox_id  INTEGER NOT NULL REFERENCES mailboxes(id),
    message_id  TEXT    NOT NULL,         -- ZSMTP message id (dedup)
    uid         INTEGER NOT NULL,
    internaldate INTEGER NOT NULL,
    flags       INTEGER NOT NULL DEFAULT 0,
    subject     TEXT    NOT NULL,         -- generic for sealed, per template otherwise
    size        INTEGER NOT NULL,
    body_blob   BLOB    NOT NULL          -- encrypted (opaque to server)
);
```

Indexes on `(mailbox_id, uid)` and `(mailbox_id, flags)` for SEARCH/UNSEEN.

### Per-user scoping

After auth, every query is filtered by `user_id` — a session can only ever
reach its own mailbox.

### Message storage is encrypted

Message bodies are stored as **ciphertext** (sealed under the recipient's key
material, per Model A in [`security.md`](security.md)). The server cannot read
them except during an active app-password request.

## IDLE push

- Per-mailbox `tokio::sync::broadcast` channel.
- Delivery path stores the message, then broadcasts → untagged `* n EXISTS` to
  sessions in IDLE on that mailbox.
- No push logic beyond this; IDLE just waits.

## Auth and app passwords

- `AUTHENTICATE PLAIN` (base64) + `LOGIN` over TLS. Dev cert story: self-signed
  + client override; production: reverse-proxy TLS termination.
- **Standard login:** master password; compatible client unwraps DK locally.
- **App-password login:** username with `:app` suffix, password = a share.
  Server resolves the share, unwraps DK in memory, decrypts that request,
  streams plaintext, zeroizes.
- Revocation: drop the revoked share's wrapper, re-wrap DK under survivors; any
  active sessions authenticated with that share are cut (`BYE`).

## Module structure

```
src/imap/
  server.rs       — listener + per-connection task
  state.rs        — NotAuth/Auth/Selected state machine
  parse.rs        — line + literal command parser
  response.rs     — tagged/untagged/continuation serialization
  commands/{auth, mailbox, message, idle}.rs
  store.rs        — MailStore trait (list/add/flags/fetch)
  sqlite.rs       — SQLite-backed MailStore (SQLCipher toggle)
  resolver.rs     — KeyResolver: master key / share unwrap
```

## Testing

- **Scripted harness:** raw-byte command/response tests per command, using
  RFC 3501 example sessions.
- **Integration:** drive the server with a well-tested Rust IMAP *client* crate
  (e.g. `async-imap`) to validate real-client behavior — hand-rolled server,
  tested against a standards-compliant client.
- **Manual:** Thunderbird / Apple Mail smoke test.

## Crates

`tokio`, `tokio-rustls`/`rustls`, `rusqlite` (+ `bundled-sqlcipher`), `base64`,
`time`/`chrono` (dates), `tracing`. No IMAP crates.

## Open decisions

- Exact SEARCH keyword coverage beyond `ALL`/`UNSEEN`/`UID`/`TEXT`.
- Whether `\Answered`/`\Deleted`/EXPUNGE semantics matter for v1, or whether the
  mailbox is effectively append-fetch-delete only.
- Template selection ("when to template what") — explicitly deferred; the
  delivery path produces the final rendered bytes.
