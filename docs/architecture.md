# Architecture

## Core model

- The daemon is a multi-user Zcash wallet that holds **viewing keys only**
  (non-custodial).
- It uses a **trusted lightwalletd indexer** as its view of chain truth. The
  indexer reports which block a transaction was received at; the daemon syncs
  continuously, so it knows all transactions and revealed nullifiers up to a
  given block height.
- The recipient daemon has an **inbox** holding delivered note data. It verifies
  client-side against the indexer that the commitment is a real, unspent note in
  the chain's commitment tree — only then does it surface as received money.
- Invalid inputs (forged / paid-to-someone-else / already-spent) are dropped to
  an **outbox** (dead-letter quarantine). No bounce is generated.
- **No acknowledgement** is sent back to the sender about successful receipt.
  Rejects go to the outbox.

### Security model

The mailbox is **server-blind end-to-end** (Model A): the server stores
ciphertext only and never holds keys that can decrypt user data at rest.
Invoices are sealed to the recipient's key material; the server decrypts only
during an explicit app-password request. See [`security.md`](security.md).

## Why verification is sound

The delivered note data is the same note data a wallet would obtain by scanning
the chain on its own: `pk_d`, `value`, `rho`, `rcm`, and the computed commitment
`cm`. The commitment `cm` is the chain-anchored link. Verification:

1. Forged note → `cm` not in tree → outbox.
2. Note paid to someone else → fails to decrypt under the user's ivk → outbox.
3. Real but already spent → nullifier already revealed → outbox.
4. Real and unspent → accepted, surfaces as received money.

Because the daemon re-syncs continuously, "spent later" just marks the note spent
like any wallet. The chain is the single source of truth; delivery is the
courier.

## Replay / message identity

Since there is no ack, the inbox requires a mandatory unique message id and
per-user dedup, otherwise replay either double-counts or DoSes the inbox.

## The daemon is a full scanning wallet

Because the daemon scans via lightwalletd anyway, a never-delivered note is still
found by the regular scan. The inbox protocol is an acceleration/notification
layer, not the only path to receipt. Delivery failure never loses money — it only
delays it.

## Key custody (decided)

- The daemon holds **viewing keys only**. It cannot spend on its own.
- The spending key stays with the user/caller.

## Modular design

Every pluggable decision is behind a Rust trait so mechanisms can be swapped
without touching the protocol core. Threshold custody, engines, and storage are
drop-in implementations.

| Concern | Trait | v1 impls | Swappable to |
|---|---|---|---|
| Mailbox storage | `MailStore` | `SqliteStore` (SQLCipher optional) | anything |
| Key unwrap / decryption | `KeyResolver` | `MasterKeyResolver`, `ShareResolver` | `ThresholdResolver` (2-of-3, later) |
| Share scheme | `ShareScheme` | `PerShareWrapper` (DK wrapped per share) | real threshold SSS |
| Message templating | `TemplateEngine` | `TeraEngine`, `LiquidEngine` | (deferred) |
| Attestation | `Attester` | `DomainKeyAttester` | keyserver / on-ledger |
| Address minting | `AddressProvider` | `PlaceholderAddressProvider` | `IvkAddressProvider` (owns IVK; may run on its own socket/port) |
| Sender trust | `Keyring` | `SqliteKeyring` | anything |

Key contracts:

- `KeyResolver::unwrap(data_key, credential) -> Option<Dk>` — client-side;
  the server never decrypts.
- `ShareScheme::wrap(dk, shares) -> WrappedDkSet` and
  `rewrap(survivors, dk) -> WrappedDkSet` — revocation = re-wrap under
  survivors; DK never changes.
- `AddressProvider::mint(mode) -> MintedAddress` — isolates the IVK so the
  daemon never touches it.
- `Keyring::state(user_id, sender_mailbox) -> TrustState` — `trusted` |
  `untrusted` | `unverified`, computed at delivery.

## Send path (decided architecture)

The daemon includes a local socket for sending transactions:

1. Caller asks the daemon to prepare a transaction.
2. Daemon prepares it (selects notes, computes nullifiers, gets merkle witness
   from lightwalletd) and hands the caller **data to sign**.
3. Caller (holder of the spending key) signs — **ultimate signing authority is
   the caller, always**.
4. Caller returns the signature.
5. Daemon computes the zk-proof, assembles the transaction, and broadcasts it to
   another server's account.

This works cryptographically because Zcash separates the spend key from the full
viewing key: the caller holds `ask` (only they can produce the SpendAuthSig), the
daemon holds `nsk` via the viewing key (can compute nullifiers and generate
proofs).

### Authentication is the signature

The spend auth signature over the transaction *is* the proof of identity. No
separate challenge-response round-trip is needed for send operations, and it
works with any wallet because it is just signing a transaction. **The signing key
is the account.**

### The signer must review

A compromised daemon could present a tx paying a different amount/recipient. The
signing payload must be human-reviewable (recipient, amount, fee, block height
lock) and the daemon must be able to prove the final assembled tx matches what
was signed. The exact format of the signed payload is open.

## Sockets

Three sockets:

- **secure_mailbox.sock** — local only; uses user authentication. The user/wallet
  interface (signing happens here; this socket's caller is a human or their
  software).
- **mailbox.sock** — the IMAP listener (hand-rolled IMAP4rev1 subset; IDLE push;
  IMAPS-first). Disabled by default. See [`imap.md`](imap.md). HTTP/2 on the
  mailbox was not hardline and is not a day-one requirement.
- **zsmtp.sock** — outbound delivery: prepares a transaction, prompts the caller
  to sign, then sends to another server's account. See [`zsmtp.md`](zsmtp.md).

## Delivery → mailbox pipeline

```
ZSMTP delivery (invoice: sealed | plaintext, both encrypted)
        │
        ▼
┌───────────────────────────────┐
│  Translation harness          │   (deferred: "when to template what")
│  TemplateEngine (trait)       │
│  config: engine + selection   │
└───────────────────────────────┘
        │  rendered MIME bytes (opaque here)
        ▼
┌───────────────────────────────┐
│  MailStore (SQLite + SQLCipher│
│  behind trait)                │
└───────────────────────────────┘
        │  store → broadcast
        ▼
┌───────────────────────────────┐
│  IMAP stack (hand-rolled)     │
│  IDLE push on new message     │
└───────────────────────────────┘
```

IMAP has zero rendering logic and the push layer has zero rendering logic; the
harness owns all presentation, and it is config-driven.
