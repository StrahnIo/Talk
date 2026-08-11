# Talk

A daemon service for SMTP-like P2P Zcash transactions, run by service managers
(systemd on Linux, launchd via brew on macOS).

## Status

**Brainstorming.** All documents are working notes capturing what has been
decided and what remains open.

## Documents

| Document | Contents |
|---|---|
| [`architecture.md`](architecture.md) | Core model, inbox/outbox, key custody, send path, sockets |
| [`zsmtp.md`](zsmtp.md) | ZSMTP protocol: SMTP reference, handshake, invoice, deniability |
| [`decisions.md`](decisions.md) | Decision log and open questions |

## Vision

A system to securely do P2P transactions between Zcash users — contacting a
server and sending a resident user Zcash without an intermediary. Modeled on
SMTP: handshake, DNS-based key/domain validation, secure delivery of a
transaction, and a Checks-Effects-Interactions style P2P consensus.

Intentional SMTP-like properties:

- **No end-to-end acknowledgment** (at-most-once, exactly like SMTP).
- Invalid inputs are silently dropped.
