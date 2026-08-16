//! DK wrapper ladder: data keys, share wrapping, key resolvers.
//!
//! One data key (DK) encrypts a user's mailbox data. DK is never stored in the
//! clear. It is wrapped under the user's master public key (compatible clients
//! unwrap locally) and under `n` independent per-share wrapping keys (app
//! passwords). Shares are independent random keys, never derived from the
//! master key.

pub mod dk;
pub mod master;
pub mod resolver;
pub mod share;

pub use dk::DataKey;
pub use master::{
    MasterKeyPair, SealError, generate_master_pair, master_public_from_bytes, master_pubkey,
    open_envelope, seal_envelope,
};
pub use resolver::{Credential, KeyResolver, MasterKeyResolver, ShareResolver, WrappedByMaster};
pub use share::{PerShareWrapper, Share, ShareError, ShareScheme, WrappedByShare, WrappedDkSet};
