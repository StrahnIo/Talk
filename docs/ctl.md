# talkctl — account & settings CLI

`talkctl` is the local admin CLI for a Talk daemon. It manages accounts,
app-password shares, the sender keyring, server-side settings, and the daemon's
config file. It runs from the same machine as the daemon.

## Transport model

Two classes of commands, with different availability:

- **Direct (offline-capable).** `status`, `config`, `settings`, `user`,
  `share`, and `keyring` open the mailbox DB and config file directly. They
  work whether or not `talkd` is running — essential for recovery and repair.
  Run them as the daemon's OS user (they need file access to the DB and domain
  key).
- **Hybrid (socket-first).** `attest` and `send` prefer the running daemon's
  `secure_mailbox.sock` (single DB writer, daemon-side handling). If the daemon
  is down, they fall back to direct operation: `attest` signs with the
  persisted domain key, `send` uses an outbound ZSMTP client.

## Setup

`talkctl` finds the daemon the same way `talkd` does: `--config <path>` (default
`config.toml` in the cwd). It needs a config that already boots — in particular
`[general] data_dir`, which locates the mailbox DB (`mailbox.db`) and the domain
key (`domainkey`). The domain key is **created by `talkd` on first boot**; the
CLI never generates it, and operations that sign (`user create`, `attest`)
require it.

```
talkctl --config /path/to/config.toml <command>
```

## Commands

| Command | Purpose |
|---|---|
| `status` | Domain, data dir, DB, socket, listener config, user/settings counts, domain-key presence |
| `config show` | Print the config file (passphrase redacted) |
| `config get <key>` | Read a dotted key, e.g. `general.domain`, `sockets.imap_listen` |
| `config set <key> <value>` | Set a dotted key, re-validate, write back (rejects unknown keys / invalid values) |
| `config validate` | Parse + validate the config file |
| `settings list` / `get <key>` / `set <key> <value>` / `delete <key>` | Server-side key/value settings table |
| `user list` | All users (id, ivk/attestation presence) |
| `user show <user>` | Pubkey, IVK, registration attestation `R`, shares, keyring |
| `user create <user> --pubkey <hex> [--password pw] [--ivk <hex>] [--shares N]` | Register (prompts for password if omitted) |
| `user delete <user>` | Remove user + mailbox + messages + shares + keyring (transactional) |
| `user passwd <user> [--password pw]` | Change password (argon2) |
| `user set-ivk <user> <ivk-hex>` / `unset-ivk <user>` | Set / clear the IVK commitment |
| `share list <user>` | Shares with active/revoked state |
| `share init <user> [--shares N]` | Fresh DK wrapped under N shares; prints each secret (app password) once |
| `share revoke <user> <share-id>` | Revoke a share wrapper |
| `keyring pin <user> <sender@domain> [--pubkey <hex>]` | Pin a trusted sender |
| `keyring list <user>` / `unpin <user> <sender>` | Keyring inspect / remove |
| `attest <user> <ephemeral\|attested>` | Request an address attestation (socket → direct fallback) |
| `send <sender> <recipient> <file> [--plaintext] [--message-id <id>]` | Deliver an invoice (socket → direct fallback) |

## Security notes

- **Run as the daemon's OS user.** Direct commands bypass the daemon and reach
  the DB and domain key directly; the machine boundary is the authorization
  (the same trust model as `secure_mailbox.sock`).
- **Stop the daemon for bulk/risky ops.** The store uses SQLite WAL, so a
  single concurrent CLI write is generally safe, but a stopped daemon avoids
  write contention entirely.
- **Share secrets are printed once.** `user create --shares N` / `share init`
  generate a fresh DK, store only the *wrapped* DK, and print the share secrets
  (the app passwords) to stdout exactly once. The server never holds the DK.
- **Adding a share to an existing DK is client-side.** The server stores only
  wrapped DKs; re-wrapping under new shares needs the DK itself, which lives
  with the client. `share init` issues a fresh DK (rotation semantics), and
  `share revoke` marks a wrapper revoked.
- **`user create` requires `--pubkey`** (client-supplied master pubkey, D20).
  An IVK is optional (`--ivk`); with one, the registration attestation `R`
  carries an `ivk_commitment`.

## Exit codes

`0` on success, `1` on any error (config, store, or daemon rejection), with the
reason on stderr.
