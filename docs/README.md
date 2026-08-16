# Talk

A daemon service for SMTP-like P2P Zcash transactions, run by service managers
(systemd on Linux, launchd via brew on macOS).

## Status

**Early implementation.** Core daemon built: ZSMTP (Unix + TCP/TLS), IMAP
mailbox (real-client compatible), identity layer (registration, attestation,
sender keyring). Documents capture what is decided, built, and open.

## Documents

| Document | Contents |
|---|---|
| [`architecture.md`](architecture.md) | Core model, inbox/outbox, key custody, send path, sockets, modular design |
| [`zsmtp.md`](zsmtp.md) | ZSMTP protocol: command set, transports, handshake, sealed invoice, deniability |
| [`imap.md`](imap.md) | Hand-rolled IMAP mailbox server: subset, framing, schema, auth, testing |
| [`security.md`](security.md) | Model A, server-blind (no IVK), DK wrapper ladder, app passwords, trust boundaries |
| [`attestation.md`](attestation.md) | Registration/live attestation (R/L), dynamic addresses, sender keyring |
| [`ctl.md`](ctl.md) | `talkctl` CLI: accounts, shares, keyring, settings, config |
| [`plugins.md`](plugins.md) | Layer-2 plugin ideas: proof-of-funds, loyalty proofs, and more |
| [`decisions.md`](decisions.md) | Decision log (D1–D26), open questions, grant/ZIP positioning |

## Vision

A system to securely do P2P transactions between Zcash users — contacting a
server and sending a resident user Zcash without an intermediary. Federated,
SMTP-like identity and delivery, tuned for shielded addresses where address
rotation and unlinkability are the norm (ENS-style central registries do not
apply). ZSMTP (over Unix socket or TCP with implicit TLS) handles the
daemon-to-daemon exchange with domain-key authentication, sealed invoices, and
registration/live attestations; reading happens through a hand-rolled IMAP
mailbox that is server-blind end-to-end. A key-hierarchy "app password" scheme
lets standard mail clients authenticate without ever trusting the server.

Intentional SMTP-like properties:

- **No end-to-end acknowledgment** (at-most-once, exactly like SMTP).
- Invalid inputs are silently dropped.
