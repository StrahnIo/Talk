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
pub mod emulate;
pub mod envelope;
pub mod framing;
pub mod handshake;
pub mod mailbox;
pub mod server;
pub mod session;
pub mod status;

pub use attestation::{
    AddressProvider, Attestation, AttestationError, AttestationMode, MintedAddress,
    PlaceholderAddressProvider, RegistrationAttestation,
};
pub use client::{
    ClientError, ClientState, SendInvoice, ZsmptClient, accept_any_cert_client_config, connect_tcp,
    connect_tcp_tls, connect_unix, send_invoice_over,
};
pub use dns::{
    COUNTERPARTY_DOMAIN, COUNTERPARTY_DOMAINKEY_HEX, COUNTERPARTY_PORT_SMTP,
    DohDomainKeyResolver, DohEndpointResolver, DomainKeyResolver, EndpointResolver, ResolverError,
    SRV_SERVICE, StaticDomainKeyResolver, StaticEndpointResolver, is_counterparty, parse_srv,
};
pub use emulate::EmulatePayload;
pub use envelope::{Envelope, Payload, Recipient};
pub use handshake::{Challenge, ChallengeResponse, DomainKey, HandshakeError};
pub use mailbox::{
    AsyncSecureMailboxHandler, AttestResult, EmulateResult, RegisterResult, SecureMailboxClient,
    SecureMailboxHandler, SendResult,
};
pub use session::{
    DeliveryOutcome, DeliverySink, Keyring, Reply, SessionState, TrustState, UserDirectory,
    ZsmptSession,
};
pub use status::{Status, StatusCode};
