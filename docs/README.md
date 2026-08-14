# Talk

A daemon service for SMTP-like P2P Zcash transactions, run by service managers
(systemd on Linux, launchd via brew on macOS).

## Status

**Brainstorming.** All documents are working notes capturing what has been
decided and what remains open.

## Documents

| Document | Contents |
|---|---|
| [`architecture.md`](architecture.md) | Core model, inbox/outbox, key custody, send path, sockets, modular design |
| [`zsmtp.md`](zsmtp.md) | ZSMTP protocol: federated identity, handshake, sealed invoice, deniability |
| [`imap.md`](imap.md) | Hand-rolled IMAP mailbox server: subset, framing, schema, SQLCipher |
| [`security.md`](security.md) | Model A, DK wrapper ladder, app passwords, trust boundaries |
| [`attestation.md`](attestation.md) | Address + pubkey attestation flow |
| [`plugins.md`](plugins.md) | Layer-2 plugin ideas: proof-of-funds, loyalty proofs, and more |
| [`decisions.md`](decisions.md) | Decision log, open questions, grant/ZIP positioning |

## Vision

A system to securely do P2P transactions between Zcash users — contacting a
server and sending a resident user Zcash without an intermediary. Federated,
SMTP-like identity and delivery, tuned for shielded addresses where address
rotation and unlinkability are the norm (ENS-style central registries do not
apply). Modeled on SMTP: handshake, DNS domain-key validation, secure sealed
delivery of a transaction, and a Commit-Effect-Interact style P2P consensus.
Reading happens through a hand-rolled IMAP mailbox that is server-blind
end-to-end; a key-hierarchy "app password" scheme lets standard mail clients
unlock messages without ever trusting the server.

Intentional SMTP-like properties:

- **No end-to-end acknowledgment** (at-most-once, exactly like SMTP).
- Invalid inputs are silently dropped.
