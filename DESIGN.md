# Talk — Design Notes

A daemon service for SMTP-like P2P Zcash transactions, run by service managers
(systemd on Linux, launchd via brew on macOS).

Status: **brainstorming**. This file captures everything decided and open so far.

## Vision

A system to securely do P2P transactions between Zcash users — contacting a
server and sending a resident user Zcash without an intermediary. Modeled on
SMTP: handshake, DNS-based key/domain validation, secure delivery of a
transaction, and a Checks-Effects-Interactions style P2P consensus.

SMTP-like properties are intentional:

- **No end-to-end acknowledgment** (at-most-once, exactly like SMTP).
- Invalid inputs are silently dropped.

## Core model (as decided)

- Daemon is a multi-user Zcash wallet that holds **viewing keys only**
  (non-custodial).
- Uses a **trusted lightwalletd indexer** as its view of chain truth. The
  indexer reports which block a transaction was received at; the daemon syncs
  continuously, so it knows all transactions and revealed nullifiers up to a
  given block height.
- Recipient daemon has an **inbox** holding delivered note data. It verifies
  client-side against the indexer that the commitment is a real, unspent note in
  the chain's commitment tree — only then does it surface as received money.
- Invalid inputs (forged / paid-to-someone-else / already-spent) are dropped to
  an **outbox** (dead-letter quarantine). No bounce is generated.
- **No acknowledgement** is sent back to the sender about successful receipt.
  Rejects go to the outbox.

### Why verification is sound

The delivered note data is the same note data a wallet would obtain by scanning
the chain on its own: `pk_d`, `value`, `rho`, `rcm`, and the computed commitment
`cm`. The commitment `cm` is the chain-anchored link. Verification is:

1. Forged note → `cm` not in tree → outbox.
2. Note paid to someone else → fails to decrypt under the user's ivk → outbox.
3. Real but already spent → nullifier already revealed → outbox.
4. Real and unspent → accepted, surfaces as received money.

Because the daemon re-syncs continuously, "spent later" just marks the note spent
like any wallet. The chain is the single source of truth; delivery is the courier.

### Replay / message identity

Since there is no ack, the inbox requires a mandatory unique message id and
per-user dedup, otherwise replay either double-counts or DoSes the inbox.

### The daemon is a full scanning wallet

Because the daemon scans via lightwalletd anyway, a never-delivered note is still
found by the regular scan. The inbox protocol is an acceleration/notification
layer, not the only path to receipt. Delivery failure never loses money — it only
delays it.

## Key custody (decided)

- Daemon holds **viewing keys only**. It cannot spend on its own.
- Spending key stays with the user/caller.

## Send path (decided architecture)

Daemon includes a local socket for sending transactions:

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

Open: whether a standalone challenge-response for interactive login is wanted
(raw RedJubjub over a nonce, verified against `ak` derived from the FVK). Note:
only a custom client can produce it — no third-party Zcash wallet supports
shielded message signing today (ZIP 304 is a draft and undeployed; no Orchard or
UA equivalent exists).

### The signer must review

A compromised daemon could present a tx paying a different amount/recipient. The
signing payload must be human-reviewable (recipient, amount, fee, block height
lock) and the daemon must be able to prove the final assembled tx matches what
was signed. Open: exact format of the signed payload.

## Sockets (decided)

Three sockets:

- **secure_mailbox.sock** — local only; uses user authentication. The user/wallet
  interface (signing happens here; this socket's caller is a human or their
  software).
- **mailbox.sock** — disabled by default; used to expose via HTTP. Design
  deferred. Must be HTTP/2 compliant so consumers can interact with it like any
  HTTP port, and it can be exposed as an HTTP server via a reverse proxy.
- **zsmtp.sock** — outbound delivery: prepares a transaction, prompts the caller
  to sign, then sends to another server's account.

## SMTP reference (for ZSMTP design)

Session mechanics to mirror:

- Line-based request/reply session with 3-digit status codes:
  `2xx` success, `3xx` continue, `4xx` transient fail (retry later),
  `5xx` permanent fail (give up).
- Envelope: `MAIL FROM` / `RCPT TO`, distinct from the message body. Multiple
  `RCPT TO` = fan-out.
- `DATA` carries headers + body; dot-stuffing terminates the payload.
- `Message-ID`: globally-unique id from the sender, used for dedup across relays.
- `Received:` chain: each relay appends a header, creating an audit trail.
- DKIM/SPF: sending domain signs the message; the receiving MX validates via DNS.
- Routing via MX record lookup in DNS — the record tells you where to deliver.
- "250 OK queued" means "accepted by next hop", not "received by user".
- Queuing and retry with backoff on `4xx`; `5xx` is permanent. Bounces are
  separate messages, not in-band acks.
- Auth: classic server-to-server SMTP is unauthenticated (why SPF/DKIM/DMARC were
  bolted on later). User submission uses SMTP AUTH + TLS on port 587.

### SMTP → ZSMTP mapping

| SMTP concept | ZSMTP translation |
|---|---|
| `MAIL FROM` / `RCPT TO` envelope | Sender account → recipient account envelope |
| MX + DNS routing | DNS record → where to find recipient's daemon |
| `Message-ID` dedup | Mandatory unique message id |
| `250 OK queued` | "Accepted into inbox" — not "received by user" |
| No end-to-end ack | Same — already decided |
| 4xx vs 5xx | Transient (resend later) vs permanent (outbox quarantine) |
| DATA + headers/body | Note data payload |
| SPF/DKIM validation | DNS-key validation of the sending server |
| Session commands | State machine — greet, identify, deliver |

Things SMTP got wrong that we should not copy:

- No auth between servers → sending server should be cryptographically identified
  from the start (this is the DNS key validation).
- Bounce messages → rejects go to the outbox; no bounce generated.
- Email trusts the relay → here the recipient daemon verifies against the
  chain/indexer, so forgery is impossible anyway.

## Open questions

- **Indexer trust model**: whose full node / indexer, and what happens if it
  disagrees with the actual chain? (Assumption: lightwalletd connected to a
  trusted node; exact failure story TBD.)
- **In-band delivery**: encrypted note (as on-chain) vs decrypted note data.
  Encrypted delivery is what the chain does anyway and avoids leaking
  amount/memo to inbox message observers.
- **Pending state**: if the daemon's sync height is behind the block a delivered
  note claims, accept as "pending" and confirm on next refresh (recommended) vs
  reject until the daemon has seen that block.
- **HTTP/2 shape for mailbox.sock**: gRPC vs JSON REST; TLS vs h2c; auth model
  when reverse-proxied.
- **Third-party wallets as socket callers**: if supported, tx-signing-only auth
  is the ceiling; no fine-grained per-operation control.
- **Who is the socket caller** — our own client only, or arbitrary wallets?
- **Sender identity model**: SMTP's `MAIL FROM` is server identity; here the
  money is authorized by the user's signature. Likely two envelope fields:
  sending server (DNS-verified) and authorizing user (spend-auth signature). To
  confirm.
- **Getting the note plaintext to deliver**: the sender's client constructed the
  shielded output, so it has the note data. Needs confirming as part of the send
  path.

## Next steps

1. Design ZSMTP protocol (zsmtp.sock) — command set, envelope, status codes,
   message id, dedup, retry semantics.
2. Resolve open questions above.
3. Design secure_mailbox.sock (user-facing signing interface).
4. Design mailbox.sock (HTTP/2 exposure, reverse proxy).
