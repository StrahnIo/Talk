//! Hand-rolled IMAP4rev1 mailbox server (subset).

pub mod capture;
pub mod parse;
pub mod response;
pub mod server;
pub mod session;
pub mod tls;

pub use session::AuthMode;
