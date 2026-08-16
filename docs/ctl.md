# talkctl — account & settings CLI

`talkctl` is the local admin CLI for a Talk daemon. It manages accounts,
app-password shares, the sender keyring, server-side settings, and the daemon's
config file. It runs from the same machine as the daemon.

> Full reference: see the man page at [`man-pages/talkctl.1.md`](../man-pages/talkctl.1.md).

## Transport model

Two classes of commands, with different availability:

- **Direct (offline-capable).** `status`, `config`, `settings`, `user`,
  `share`, and `keyring` open the mailbox DB and config file directly. They
  work whether or not `talkd` is running — essential for recovery and repair.
  Run them as the daemon's OS user (they need file access to the DB and domain
  key). `key` is pure local crypto: it needs neither the daemon nor the
  config.
- **Hybrid (socket-first).** `attest` and `send` prefer the running daemon's
  `secure_mailbox.sock` (single DB writer, daemon-side handling). If the daemon
  is down, they fall back to direct operation: `attest` signs with the
  persisted domain key, `send` uses an outbound ZSMTP client.
- **Daemon-required.** `emulate payment` has no direct fallback: rendering and
  the inbox delivery (with IMAP IDLE push) are owned by the daemon's delivery
  sink, so `talkd` must be running.

## Templates

`emulate payment` renders a Tera template spec — a `subject` and a `body`
template — from the context `{sender_name, sender_address, amount, invoice,
received_at}`. The spec resolves in order: `[mailbox] template_path` in the
daemon config (if set; the file must exist), else `<data_dir>/template.toml`,
else the built-in default. See `template.toml` in the repository root for an
example.

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
| `key generate [--out <file>] [--pub-out <file>] [--force]` | X25519 master keypair; prints `public:` (the value for `user create --pubkey`), writes the private key with mode 0600 |
| `key pubkey [--key <file> | --hex <priv-hex>]` | Derive the public key from a private key file or hex |
| `key seal --key <file> [--to <pubkey-hex>] [--in <file>] [--out <file>]` | ECIES-encrypt to a public key (default: own); stdin/stdout pipeable |
| `key unseal --key <file> [--in <file>] [--out <file>]` | Decrypt a sealed envelope with the private key |
| `attest <user> <ephemeral\|attested>` | Request an address attestation (socket → direct fallback) |
| `send <sender> <recipient> <file> [--plaintext] [--message-id <id>]` | Deliver an invoice (socket → direct fallback) |
| `emulate payment <user> --from-name ... --from-address ... --amount ... --invoice <file>` | Simulate a received payment through the daemon: Tera-rendered (subject+body) into the inbox via the normal delivery path (daemon required) |

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

## Usernames and domains

Usernames are **local parts** (`alice`). `user` commands and IMAP login also
accept the qualified `alice@<domain>` form, where `<domain>` must be the
daemon's configured `[general] domain` (foreign domains are rejected). The
domain is stripped and the local user resolved. `user create` only accepts a
bare local name (no `@`, and no `:` which is reserved for the `:app`
app-password suffix).

## Exit codes

`0` on success, `1` on any error (config, store, or daemon rejection), with the
reason on stderr.
