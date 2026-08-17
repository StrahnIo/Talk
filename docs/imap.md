# IMAP Mailbox Server (hand-rolled)

The mailbox server is a minimal, hand-rolled IMAP4rev1 server written in Rust
(`tokio`), with **zero IMAP frameworks**. It stores and serves already-rendered,
opaque messages handed to it by the delivery path. It contains no templating and
no push logic beyond IDLE.

It is validated against the `async-imap` client library (a standards-compliant
client) to prove real-client compatibility.

## Scope

- Reference implementation, `tokio`-based, no IMAP crates.
- Two mailboxes per user: **INBOX** (received) and **Sent** (outbound copies).
- Receives pre-rendered MIME bytes (opaque to IMAP) from the delivery path.
- **IMAPS-first** — TLS on connect. No STARTTLS in v1.
- IDLE-only push.
- Auth modes: `database` (argon2 password against the store) or `localauth`
  (OS user in the `zsmtp` group).

## Command subset (RFC 3501)

| Command | Purpose |
|---|---|
| `CAPABILITY` | Advertise `IMAP4rev1 IDLE NAMESPACE AUTH=PLAIN` (+ TLS) |
| `STARTTLS` / `AUTHENTICATE PLAIN` / `LOGIN` / `LOGOUT` | Session lifecycle |
| `LIST` / `LSUB` / `SELECT` / `EXAMINE` / `STATUS` | Mailbox ops (INBOX-focused) |
| `NAMESPACE` | Return the default namespace |
| `FETCH` | `ENVELOPE`, `BODYSTRUCTURE`, `BODY[]`, `BODY.PEEK[]`, `FLAGS`, `UID`, `INTERNALDATE`, `RFC822.SIZE` |
| `STORE` | `FLAGS`, `+FLAGS`, `-FLAGS` (`\Seen`, `\Flagged`, `\Answered`, `\Deleted`) |
| `SEARCH` | `ALL`, `UNSEEN`, `UID`, `TEXT`, `FROM`, `SUBJECT`, `SINCE` |
| `UID FETCH` / `UID STORE` / `UID SEARCH` | UID-based access (client requirement) |
| `IDLE` / `DONE` | Push (RFC 2177) |
| `NOOP` / `EXPUNGE` / `CLOSE` | Housekeeping |

**Out of scope (declared; clients degrade gracefully):** `SORT`, `THREAD`,
`MOVE`, `COPY`, `APPEND`, `CREATE`/`DELETE`/`RENAME`, `NOTIFY`, `LITERAL+`,
`CONDSTORE`/`QRESYNC`, `UID EXPUNGE`, quotas/ACLs, multi-mailbox search.

### FETCH body sections

Body fetches honor their section (important for Thunderbird and other clients
that build the message list from `BODY[HEADER]`): `BODY[]`/`BODY.PEEK[]`
(full stored body), `BODY[HEADER]`, `BODY[TEXT]`, `BODY[MIME]`, and
`BODY[HEADER.FIELDS (...)]` / `BODY[HEADER.FIELDS.NOT (...)]`. Because the
store keeps opaque bodies, `BODY[HEADER]` is **synthesized** from the stored
metadata (`Date`, `From`, `Subject`, `Message-ID`, plus `X-Talk-Txn-Status`
and `X-Talk-Txn-Id` when the message has a linked ledger transaction);
`BODY[TEXT]` and `BODY[]` return the stored blob. The `ALL` / `FULL` / `FAST`
macros are supported. `RFC822.SIZE` always reflects the stored message size,
even when the body is not fetched.

### Multi-mailbox

`LIST` reports `INBOX` and `Sent`; `SELECT`/`EXAMINE`/`STATUS`/`SEARCH`/
`STORE`/`UID *`/`EXPUNGE`/`FETCH` operate on the selected mailbox. `Sent`
holds a copy of every outbound transaction (persisted at send time), so sent
invoices are readable over IMAP like email's Sent folder.

## Framing and session model

- Commands: CRLF-terminated lines with `{n}` literal support (required for
  `LOGIN` and large sealed-body `FETCH` output). Synchronous literals only.
- Three response types: tagged (`A1 OK`), untagged (`* n EXISTS`), continuation
  (`+`).
- Parser rejects malformed input → `BAD`; strict RFC status codes
  (`OK` / `NO` / `BAD` / `BYE`).
- Session state machine: **Not Authenticated → Authenticated → Selected**;
  commands gated by state.
- FETCH emits a single RFC-conformant response per message with the literal
  inside the parenthesized list (a requirement for `imap_proto` compatibility).

## Concurrency and robustness

- One `tokio` task per connection; framing with explicit timeouts (command,
  literal, IDLE).
- Bounded-work guarantees: max literal size, max message size, connection
  limits, backpressure on the store, graceful `BYE` on timeout/logout.
- `tracing` for session logs; every error path returns a valid IMAP response.

## Storage (SQLite)

SQLite via `rusqlite`, behind the `MailStore` trait and called through
`tokio::task::spawn_blocking`.

> **Note:** SQLCipher at-rest encryption is deferred. It cannot coexist in one
> process with `zcash_client_sqlite`'s plain `bundled` sqlite (mutually
> exclusive `libsqlite3-sys` features). If at-rest encryption is required, the
> mailbox must run as a separate process (D17).

### Schema (v1)

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,          -- argon2 PHC string
    master_pubkey BLOB NOT NULL,          -- client-supplied wallet pubkey
    created_at    INTEGER NOT NULL
);
-- Migration columns: ivk_commitment TEXT, registration_attestation TEXT

CREATE TABLE shares (
    user_id     INTEGER NOT NULL REFERENCES users(id),
    share_id    TEXT    NOT NULL,
    wrapped_dk  BLOB    NOT NULL,         -- DK wrapped under this share
    revoked     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, share_id)
);

CREATE TABLE keyring_entries (
    user_id       INTEGER NOT NULL REFERENCES users(id),
    sender_mailbox TEXT   NOT NULL,
    sender_pubkey  TEXT   NOT NULL,
    attestation    BLOB   NOT NULL,
    state          TEXT   NOT NULL,
    first_seen     INTEGER NOT NULL,
    PRIMARY KEY (user_id, sender_mailbox)
);

CREATE TABLE mailboxes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    name      TEXT    NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uidnext   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE messages (
    id          INTEGER PRIMARY KEY,
    mailbox_id  INTEGER NOT NULL REFERENCES mailboxes(id),
    message_id  TEXT    NOT NULL,         -- ZSMTP message id (dedup)
    uid         INTEGER NOT NULL,
    internaldate INTEGER NOT NULL,
    flags       INTEGER NOT NULL DEFAULT 0,
    subject     TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    body_blob   BLOB    NOT NULL,         -- encrypted (opaque to server)
    sender      TEXT    NOT NULL DEFAULT '',       -- From: user@domain
    trust_state TEXT    NOT NULL DEFAULT 'unverified'
);
```

Indexes on `(mailbox_id, uid)` and `(mailbox_id, flags)` for SEARCH/UNSEEN.
UIDs are allocated from the mailbox's monotonic `uidnext` counter and never
reused after expunge.

### Per-user scoping

After auth, every query is filtered by `user_id` — a session can only ever
reach its own mailbox.

### Message storage is encrypted

Message bodies are stored as **ciphertext** (sealed under the recipient's key
material, per Model A in [`security.md`](security.md)). The server cannot read
them — decryption is the client's job.

## IDLE push

- Per-mailbox `tokio::sync::broadcast` channel.
- Delivery path stores the message, then broadcasts → untagged `* n EXISTS` to
  sessions in IDLE on that mailbox.
- No push logic beyond this; IDLE just waits.

## Auth and app passwords

- `AUTHENTICATE PLAIN` (base64) + `LOGIN` over TLS. Dev cert story: self-signed
  + client override; production: reverse-proxy TLS termination or IMAPS.
- **`database` mode:** standard login verifies the password against the store's
  argon2 hash. Wrong passwords are rejected.
- **`localauth` mode:** the connecting OS user must be a member of the `zsmtp`
  group and match their mailbox username.
- **App-password login:** username with `:app` suffix, password = a share. The
  server uses the share **only to authenticate** (does it unlock any registered
  wrapper?) — it then serves ciphertext. The client decrypts locally; the
  server never decrypts.
- Revocation: drop the revoked share's wrapper, re-wrap DK under survivors (a
  client-side operation; the server never holds DK).

## Module structure

```
crates/talk-imap/src/
  parse.rs        — line + literal command parser
  response.rs     — tagged/untagged/continuation serialization
  server.rs       — accept loop (TLS optional), per-connection task, IDLE push
  session.rs      — session state machine, command dispatch, auth
  tls.rs          — rustls server-config loader (cert/key PEM)
```

## Testing

- **Scripted harness:** raw-byte command/response tests per command, using
  RFC 3501 example sessions.
- **Real-client integration:** drive the server with `async-imap` — login,
  select, fetch, store, search, list, wrong-password rejection. This proved the
  FETCH single-response literal fix and the SEARCH ALL/UNSEEN fix.
- **TLS test:** a rustls client completes a full session over IMAPS (self-
  signed cert via `rcgen`).

## Crates

`tokio`, `tokio-rustls`/`rustls`, `rusqlite`, `base64`, `time`, `hex`,
`libc` (localauth), `tracing`. No IMAP crates.

## Debugging: session capture

`talkd --capture-dir <dir>` writes one timestamped transcript per IMAP
connection (`imap-<UTC>-<seq>.pcap.txt`) to `<dir>`. Each transcript is a
text + hex dump of the session, with `C>` marking bytes read from the client
and `S>` marking bytes written to it — every command, response, literal, and
IDLE push. Useful for debugging what real clients (e.g. Thunderbird) send and
how the server responds. Capture applies to both the IMAPS listener and the
`UNSAFE_NO_TLS` plaintext listener.

## Open decisions

- Whether `\Answered`/`\Deleted`/EXPUNGE semantics matter for v1, or whether the
  mailbox is effectively append-fetch-delete only.
- Template selection ("when to template what") — explicitly deferred; the
  delivery path produces the final rendered bytes.
