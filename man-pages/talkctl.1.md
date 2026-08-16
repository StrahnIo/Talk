# talkctl(1) — Talk daemon account & settings CLI

## NAME

talkctl — manage Talk daemon accounts, shares, keyring, server-side settings,
and the daemon configuration file.

## SYNOPSIS

```
talkctl [OPTIONS] <COMMAND>
```

## DESCRIPTION

`talkctl` is the local administration interface for a **Talk** daemon
(`talkd`). Talk is an SMTP-like P2P protocol for privately sending Zcash
between users; `talkd` runs the daemon, and `talkctl` lets an operator manage
the users, app-password shares, sender keyring, and settings that `talkd`
serves, plus the daemon's own configuration file.

`talkctl` must run on the same machine as the daemon and under the same OS user
(or a user with file access to the daemon's data directory), because several
commands read and write the mailbox database and the persisted domain signing
key directly.

Two classes of commands exist:

**Direct (offline-capable).** `status`, `config`, `settings`, `user`, `share`,
and `keyring` open the mailbox DB and config file directly. They work whether
or not `talkd` is running, which is essential for recovery and repair.

**Hybrid (socket-first).** `attest` and `send` prefer the running daemon's
`secure_mailbox.sock`. If the daemon is down, they fall back to direct
operation: `attest` signs with the persisted domain key, and `send` acts as an
outbound ZSMTP client.

## OPTIONS

`-c, --config <PATH>`
:   Path to the daemon TOML configuration file. Defaults to `config.toml` in
    the current directory. The config locates the mailbox database
    (`[general] data_dir` / `mailbox.db`), the socket paths, the domain, and
    the network settings.

`-h, --help`
:   Print help information and exit.

`-V, --version`
:   Print version information and exit.

## COMMANDS

### status

```
talkctl [OPTIONS] status
```

Print a summary of the daemon and store: version, domain, data directory,
mailbox database path, `secure_mailbox` socket path, indexer URL, send
endpoint mode, user count, settings count, and whether the persisted domain key
is present.

### config

Inspect and edit the daemon TOML configuration file.

```
talkctl [OPTIONS] config show
talkctl [OPTIONS] config get <KEY>
talkctl [OPTIONS] config set <KEY> <VALUE>
talkctl [OPTIONS] config validate
```

`show`
:   Print the effective configuration file. The `mailbox.passphrase` value is
    redacted.

`get <KEY>`
:   Print the value of a dotted configuration key, e.g. `general.domain` or
    `sockets.imap_listen`.

`set <KEY> <VALUE>`
:   Set a dotted configuration key, re-validate the merged configuration, and
    write the file back. Unknown keys, wrong value types, and invalid values
    (e.g. a `[general] domain` containing whitespace) are refused and the file
    is left unchanged. Note that rewriting the file loses comments.

`validate`
:   Parse and validate the configuration file. Reports success or a
    `ConfigError`.

### settings

Manage the server-side key/value settings table (stored in the mailbox
database).

```
talkctl [OPTIONS] settings list
talkctl [OPTIONS] settings get <KEY>
talkctl [OPTIONS] settings set <KEY> <VALUE>
talkctl [OPTIONS] settings delete <KEY>
```

`list`
:   Print every setting as `key = value`, sorted by key.

`get <KEY>`
:   Print the value of one setting. Fails with `no such setting` if unset.

`set <KEY> <VALUE>`
:   Upsert a setting. Values are stored verbatim as text.

`delete <KEY>`
:   Remove a setting. Fails if it does not exist.

### user

Manage user accounts in the mailbox database.

```
talkctl [OPTIONS] user list
talkctl [OPTIONS] user show <USER>
talkctl [OPTIONS] user create <USER> --pubkey <HEX> [--password <PASSWORD>]
                       [--ivk <HEX>] [--shares <N>]
talkctl [OPTIONS] user delete <USER>
talkctl [OPTIONS] user passwd <USER> [--password <PASSWORD>]
talkctl [OPTIONS] user set-ivk <USER> <IVK-HEX>
talkctl [OPTIONS] user unset-ivk <USER>
```

`list`
:   List all users: username, user id, and whether an IVK commitment and a
    registration attestation are present.

`show <USER>`
:   Show a user in detail: username, id, master public key (hex), IVK
    commitment, registration attestation `R` (domain, timestamp, signature),
    and counts of shares and pinned keyring entries.

`create <USER> --pubkey <HEX> [--password <PASSWORD>] [--ivk <HEX>]
[--shares <N>]`
:   Register a user (the equivalent of `REGISTER` over `secure_mailbox.sock`).
    The password is argon2-hashed and never stored in the clear; the pubkey is
    the client-supplied 32-byte master public key (hex); an optional IVK adds
    an `ivk_commitment` to the registration attestation `R`. Requires the
    daemon's domain key (created by `talkd` on first boot) to sign `R`. If
    `--password` is omitted the password is prompted for securely. If `--shares
    N` (default `0`) is given, a fresh data key is generated, wrapped under `N`
    new shares, and each share's secret is printed to stdout exactly once.
    Fails if the username exists, if the pubkey/IVK is not 32 bytes of hex, or
    if the domain key is missing.

`delete <USER>`
:   Delete a user and all associated data — mailbox, messages, shares, keyring
    entries — in a single transaction. Fails if the user does not exist.

`passwd <USER> [--password <PASSWORD>]`
:   Replace a user's password. Prompts securely if `--password` is omitted.

`set-ivk <USER> <IVK-HEX>`
:   Set (or replace) a user's IVK commitment. The IVK must be 32 bytes of hex.

`unset-ivk <USER>`
:   Clear a user's IVK commitment.

### share

Manage app-password shares (DK wrappers).

```
talkctl [OPTIONS] share list <USER>
talkctl [OPTIONS] share init <USER> [--shares <N>]
talkctl [OPTIONS] share revoke <USER> <SHARE-ID>
```

`list <USER>`
:   List the user's shares with their `active`/`revoked` state and the wrapped
    DK (hex).

`init <USER> [--shares <N>]`
:   Generate a fresh data key (DK), wrap it under `N` new independent share
    keys (default `8`), persist the *wrapped* DKs to the store, and print each
    share's secret (the app password) and id to stdout exactly once. `--shares`
    must be at least 1. Because the server never holds the DK, this issues a
    fresh DK (rotation semantics) rather than extending an existing one.

`revoke <USER> <SHARE-ID>`
:   Mark a share wrapper revoked. The wrapped DK row is retained (dropped on a
    future client-side re-wrap).

### keyring

Manage the per-user sender keyring (trusted senders).

```
talkctl [OPTIONS] keyring pin <USER> <SENDER@DOMAIN> [--pubkey <HEX>]
talkctl [OPTIONS] keyring list <USER>
talkctl [OPTIONS] keyring unpin <USER> <SENDER@DOMAIN>
```

`pin <USER> <SENDER@DOMAIN> [--pubkey <HEX>]`
:   Pin a sender mailbox as trusted for a user (upserts). The optional pubkey
    is the sender's attested key; pinning should follow client-side
    verification of the sender's server-attested key (TOFU).

`list <USER>`
:   List the user's pinned senders with trust state, pubkey, and first-seen
    order.

`unpin <USER> <SENDER@DOMAIN>`
:   Remove a pinned sender. Fails if the sender is not pinned.

### attest

```
talkctl [OPTIONS] attest <USER> <MODE>
```

Request an address attestation for a user. `MODE` is `ephemeral` (fresh,
one-shot address) or `attested` (stable address + pubkey). Prefers the running
daemon's `secure_mailbox.sock`; if the daemon is down, signs directly with the
persisted domain key. Prints the domain, user, mode, address, pubkey, and
signature of the signed attestation.

### send

```
talkctl [OPTIONS] send <SENDER> <RECIPIENT> <FILE> [--plaintext]
                [--message-id <ID>]
```

Deliver an opaque invoice body from `<FILE>` to a recipient mailbox
(`user@domain`). `<SENDER>` is the authorizing local username. The payload is
sealed by default; `--plaintext` marks it plaintext. `--message-id` sets an
explicit message id; otherwise one is auto-generated (`talkctl-<hex>`). Prefers
the daemon's `secure_mailbox.sock`; if the daemon is down, resolves the
recipient's endpoint and domain key via DNS (SRV) and delivers over implicit
TLS, using the config `send_endpoint` as a fallback override when SRV fails.

## FILES

`config.toml`
:   The default daemon configuration (overridable with `--config`). See
    `config.example.toml` in the repository for the annotated shape.

`<data_dir>/mailbox.db`
:   The SQLite mailbox database: users, keyring, shares, mailboxes, messages,
    and the `settings` table. Opened directly by the direct-access commands.

`<data_dir>/domainkey`
:   The daemon's persisted domain signing key (32 bytes). Created by `talkd`
    on first boot. Required by `user create` and by the direct `attest` path;
    `talkctl` never creates it.

`<data_dir>/run/secure_mailbox.sock`
:   The daemon's local control socket, used by the socket-first `attest` and
    `send` paths.

## EXIT STATUS

`0`
:   Success.

`1`
:   Any error — configuration, store, protocol, or daemon rejection — with the
    reason written to standard error.

## SECURITY

- **Run as the daemon's OS user.** Direct commands bypass the daemon and reach
  the database and domain key directly; the OS file permissions on the machine
  are the authorization boundary (the same trust model as
  `secure_mailbox.sock`).
- **Stop the daemon for bulk or risky operations.** The store uses SQLite WAL,
  so a single concurrent write is generally safe, but a stopped daemon removes
  write contention entirely.
- **Share secrets are printed once.** `user create --shares N` and `share init`
  print the app-password share secrets to stdout exactly once. The server
  stores only *wrapped* DKs and never the DK itself.
- **Adding a share to an existing DK is client-side.** The server stores only
  wrapped DKs; re-wrapping under new shares requires the DK, which lives with
  the client. `share init` issues a fresh DK, and `share revoke` marks a
  wrapper revoked.
- **`user create` requires `--pubkey`.** The master public key is
  client-supplied; an IVK is optional and, when present, is bound into the
  registration attestation `R` as an `ivk_commitment`.

## EXAMPLES

Show daemon and store summary:

```
talkctl --config /etc/talk/config.toml status
```

Validate the config and change the daemon domain:

```
talkctl config validate
talkctl config set general.domain mail.example.org
```

Register a user with an IVK and three app-password shares:

```
talkctl user create alice --pubkey 00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899 \
    --ivk 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --shares 3
```

Show a user, then delete them:

```
talkctl user show alice
talkctl user delete alice
```

Set and inspect a server-side setting:

```
talkctl settings set max_inbox_bytes 10485760
talkctl settings get max_inbox_bytes
```

Revoke a leaked app password:

```
talkctl share list alice
talkctl share revoke alice eeb3d4c88f7f6397b0ebbb96383df954
```

Pin and unpin a trusted sender:

```
talkctl keyring pin alice bob@example.org --pubkey aabb...
talkctl keyring unpin alice bob@example.org
```

Request an attestation (daemon up: via socket; daemon down: direct):

```
talkctl attest alice ephemeral
```

Deliver an invoice:

```
talkctl send alice bob@example.org invoice.bin
```

## SEE ALSO

- `talkd(1)` — the Talk daemon (repository binary `talkd`)
- `docs/ctl.md` — talkctl command reference
- `docs/architecture.md`, `docs/security.md`, `docs/zsmtp.md`,
  `docs/attestation.md`, `docs/imap.md` — protocol and design documents
- `config.example.toml` — annotated daemon configuration

## AUTHORS

Talk project. This man page describes `talkctl` from the `talk-ctl` crate.
