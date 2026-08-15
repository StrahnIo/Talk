//! DK wrapper ladder: data keys, share wrapping, key resolvers.
//!
//! One data key (DK) encrypts a user's mailbox data. DK is never stored in the
//! clear. It is wrapped under the user's master public key (compatible clients
//! unwrap locally) and under `n` independent per-share wrapping keys (app
//! passwords). Shares are independent random keys, never derived from the
//! master key.

pub mod dk;
pub mod resolver;
pub mod share;

pub use dk::DataKey;
pub use resolver::{KeyResolver, MasterKeyResolver, ShareResolver, WrappedByMaster};
pub use share::{PerShareWrapper, Share, ShareScheme, WrappedDkSet};
