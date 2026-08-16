# Security Model

## Model A — server-blind end-to-end

The receiving mailbox server is **blind**: it stores ciphertext only and never
holds any key that can decrypt user data at rest. All message content is
encrypted end-to-end between the sender and the recipient's key material.

**The server never holds the IVK.** Decryption is the client's job — the server
is a dumb ciphertext store. The only exception is the optional, per-user IVK
registration that enables dynamic addresses, and even then the IVK lives inside
a swappable `AddressProvider` boundary, not the main daemon.

This is the trust model for the whole mailbox. It also resolves the
transparent-invoice question: since the server is blind, **every** stored
message is ciphertext to it — including transparent invoices.

## The three layers

| Layer | Mechanism | Protects against |
|---|---|---|
| Transport | TLS / IMAPS (ECDHE) | Network eavesdroppers, MITM — not the operator |
| At rest | SQLCipher (optional, see below) | Someone who steals the database file |
| Application | Invoice sealed to recipient key material | The operator, the mailbox server, everyone |

Application-layer confidentiality is the load-bearing one. IMAP has no native
content encryption; TLS only protects transport; SQLCipher only protects at
rest. True end-to-end confidentiality against a *live* operator comes solely
from the application layer.

## Key hierarchy (DK wrapper ladder)

One **data key (DK)** encrypts all of a user's mailbox data. DK is never stored
in the clear and never exposed to the server except transiently. It is wrapped
under multiple keys:

- **Master public key (asymmetric).** DK is wrapped under the user's master
  public key. A compatible client holds the master private key, unwraps DK
  locally, and decrypts locally — the server never sees the private key.
- **Per-share wrapping keys (symmetric).** DK is additionally wrapped under each
  of `n` independent share keys. These shares are the **app passwords**.

This is a KMK-style key hierarchy: shares are *not* copies of the master key and
are *not* derived from it — each is an independent random wrapper key.

### Shares as app passwords

- Default: `n = 8` shares, generated client-side at account setup.
- **Compatible client:** uses a share to unwrap DK locally and decrypt — fully
  server-blind.
- **Incompatible / standard mail client:** the user supplies a share in the
  password field, appending `:app` to the username to override the default
  password. The server uses the share **only to authenticate** (does it unlock
  any registered wrapper?) — it then serves ciphertext. The client decrypts
  locally; the server never decrypts.

### Revocation

A leaked or suspected share is revoked by **dropping its wrapper and re-wrapping
DK under the surviving shares**. DK never changes and no message data is
re-encrypted; the revoked share is permanently useless for future traffic.

Re-wrapping requires the server to transiently hold DK (unwrap from any
surviving wrapper, re-wrap under the rest). That brief window is the same trust
the server already has during an app-password request; DK must be zeroized
after the re-wrap.

### Threshold later

The wrapper design is naturally 1-of-n (any one share unlocks — inherent to the
app-password UX). Real threshold (e.g. 2-of-3 quorum custody) is a *different*
primitive and is deferred. The key hierarchy is modular so a threshold resolver
can be added without touching the protocol core. See the `KeyResolver` /
`ShareScheme` contracts in [`architecture.md`](architecture.md).

## What the server holds (and never holds)

The server may hold:

- User **public** keys (so senders can encrypt invoices to recipients).
- The registration attestation `R` (tamper-evident username↔pubkey binding).
- The per-user **keyring** (trusted sender public keys + trust labels).
- DK **wrappers** (ciphertext of DK).
- Messages (ciphertext).
- Optionally, an `ivk_commitment` (never the IVK itself).

The server never holds: private keys, the IVK (unless delegated inside the
`AddressProvider`), DK at rest, or any plaintext.

## Invoice confidentiality by mode

| | Transparent | Shielded |
|---|---|---|
| On-chain binding | `OP_RETURN H(invoice)` | shielded memo carries `K` |
| Invoice content | private, encrypted to recipient pubkey | sealed, encrypted with `K` |
| Recipient unlock | master key / share | IVK → `K` → decrypt |
| Server visibility | ciphertext only | ciphertext only |

Both modes are server-blind. Transparent invoices are **not public** — only a
hash of the invoice appears on-chain via `OP_RETURN`.

## Deniability

- **Content deniability.** Everything in the ZSMTP transcript is opaque without
  the recipient's key material. An interceptor with every key except the
  recipient's IVK cannot decrypt the invoice, link any on-chain tx to it, or
  prove a payment attempt.
- **Connection is observable.** The ECDH session makes the transcript deniable;
  the fact of connection (IP, timing, server logs) remains observable. Accepted
  scope reduction, not connection anonymity.

## Proof-of-integrity is delivery, not receipt

A server signing a *sealed* invoice proves "an invoice blob was delivered via
this server", not that the recipient read its contents. **Offline recipient XOR
non-repudiable receipt**: the sender's delivery is non-repudiable; the
recipient's awareness is not proven.

## Known accepted risks

- **App-password sessions** hand the server a share; the server authenticates
  with it but never decrypts. The share is a full key to the client-side DK.
- **A compromised *running* daemon** sees everything a user could fetch.
  SQLCipher protects at rest, not in memory; application-layer sealing protects
  against a live operator only when the user never shares key material.
- **Optional IVK delegation** enables dynamic addresses at the cost of letting
  the `AddressProvider` scan/detect payments to derived addresses. Opt-in per
  user; the IVK is isolated inside a swappable provider boundary.
- **Keyring trust is TOFU + attested bootstrap.** Pinning happens only after the
  client verifies the sender's server-attested key. A *malicious* sending server
  could attest a fake key at first contact (same trust model as recipient
  attestation); the keyring protects against subsequent key changes/DB edits.
- **DNS / indexer trust.** The daemon trusts its lightwalletd indexer and its
  DNS resolution; a compromised resolver or indexer can misdirect or misreport
  (see O1 in [`decisions.md`](decisions.md)).
