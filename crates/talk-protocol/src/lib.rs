//! ZSMTP protocol: envelope, status codes, framing, and handshake.
//!
//! ZSMTP is an SMTP-like line protocol spoken between daemons over
//! `zsmtp.sock`. Design decisions (see `docs/zsmtp.md`):
//! - Line-based commands with length-prefixed blobs (no dot-stuffing).
//! - SMTP-style status codes: `2xx` success, `4xx` transient, `5xx` permanent.
//! - A mandatory, globally-unique message id on every delivery (dedup).
//! - Server auth via DNS domain keys; the sending server is cryptographically
//!   identified from the start (unlike classic SMTP).

pub mod attestation;
pub mod client;
pub mod codec;
pub mod dns;
pub mod envelope;
pub mod framing;
pub mod handshake;
pub mod mailbox;
pub mod server;
pub mod session;
pub mod status;

pub use attestation::{Attestation, AttestationError, AttestationMode};
pub use client::{ClientError, ClientState, ZsmptClient, connect_tcp, connect_unix};
pub use dns::{DohDomainKeyResolver, DomainKeyResolver, ResolverError, StaticDomainKeyResolver};
pub use envelope::{Envelope, Payload, Recipient};
pub use handshake::{Challenge, ChallengeResponse, DomainKey, HandshakeError};
pub use mailbox::{AttestResult, RegisterResult, SecureMailboxClient, SecureMailboxHandler, SendResult};
pub use session::{DeliveryOutcome, DeliverySink, Reply, SessionState, ZsmptSession};
pub use status::{Status, StatusCode};
