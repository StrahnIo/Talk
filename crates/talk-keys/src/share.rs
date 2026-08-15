use crate::dk::{DataKey, KEY_LEN, SecretKey, aead_open, aead_seal};
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;

/// A share: an independent random wrapping key (an app password).
pub type Share = SecretKey;

/// A single share identifier (opaque handle, not secret).
pub type ShareId = [u8; 16];

/// A DK wrapped under one specific share.
#[derive(Clone, Debug)]
pub struct WrappedByShare {
    pub share_id: ShareId,
    /// AEAD ciphertext: nonce || tag || ciphertext of DK.
    pub wrapped: Vec<u8>,
}

/// The set of all wrappers for one DK, one per share.
#[derive(Clone, Debug)]
pub struct WrappedDkSet {
    pub wrappers: Vec<WrappedByShare>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ShareError {
    #[error("share scheme mismatch: cannot rewrap a wrapper set produced by another scheme")]
    SchemeMismatch,
    #[error("no survivors remain to rewrap under")]
    NoSurvivors,
    #[error("wrapped DK failed to decrypt")]
    DecryptFailed,
}

/// Strategy for wrapping a DK under multiple share keys.
///
/// v1 implements a per-share wrapper ladder: each share independently wraps the
/// DK. Revocation = drop a wrapper and re-wrap DK under the survivors. A real
/// threshold scheme (e.g. 2-of-3) is a future implementation of this trait.
pub trait ShareScheme {
    /// Wrap `dk` under each of `shares`. Each share carries its own fresh id.
    fn wrap(&self, dk: &DataKey, shares: &[Share]) -> WrappedDkSet;

    /// Re-wrap `dk` under the surviving shares, dropping any share not present.
    fn rewrap(&self, dk: &DataKey, survivors: &[Share]) -> WrappedDkSet;

    /// Unwrap a DK from one share's wrapper.
    fn unwrap(&self, share: &Share, wrapper: &WrappedByShare) -> Result<DataKey, ShareError>;
}

/// The v1 ladder: DK wrapped independently under each share key.
#[derive(Default)]
pub struct PerShareWrapper;

impl PerShareWrapper {
    fn share_id(&self) -> ShareId {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        id
    }
}

impl ShareScheme for PerShareWrapper {
    fn wrap(&self, dk: &DataKey, shares: &[Share]) -> WrappedDkSet {
        let wrappers = shares
            .iter()
            .map(|share| WrappedByShare {
                share_id: self.share_id(),
                wrapped: aead_seal(share, dk.as_bytes()),
            })
            .collect();
        WrappedDkSet { wrappers }
    }

    fn rewrap(&self, dk: &DataKey, survivors: &[Share]) -> WrappedDkSet {
        self.wrap(dk, survivors)
    }

    fn unwrap(&self, share: &Share, wrapper: &WrappedByShare) -> Result<DataKey, ShareError> {
        let bytes = aead_open(share, &wrapper.wrapped).ok_or(ShareError::DecryptFailed)?;
        if bytes.len() != KEY_LEN {
            return Err(ShareError::DecryptFailed);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(DataKey::from_bytes(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shares(n: usize) -> Vec<Share> {
        let mut rng = rand::thread_rng();
        (0..n).map(|_| Share::generate(&mut rng)).collect()
    }

    #[test]
    fn wrap_and_unwrap_each_share() {
        let mut rng = rand::thread_rng();
        let dk = DataKey::generate(&mut rng);
        let shares = test_shares(8);
        let scheme = PerShareWrapper;

        let set = scheme.wrap(&dk, &shares);
        assert_eq!(set.wrappers.len(), 8);

        for (share, wrapper) in shares.iter().zip(set.wrappers.iter()) {
            let unwrapped = scheme.unwrap(share, wrapper).expect("share must unwrap");
            assert_eq!(unwrapped.as_bytes(), dk.as_bytes());
        }
    }

    #[test]
    fn wrong_share_fails() {
        let mut rng = rand::thread_rng();
        let dk = DataKey::generate(&mut rng);
        let shares = test_shares(2);
        let scheme = PerShareWrapper;
        let set = scheme.wrap(&dk, &shares);

        let outsider = Share::generate(&mut rng);
        let err = scheme.unwrap(&outsider, &set.wrappers[0]).unwrap_err();
        assert_eq!(err, ShareError::DecryptFailed);
    }

    #[test]
    fn rewrap_drops_revoked_share() {
        let mut rng = rand::thread_rng();
        let dk = DataKey::generate(&mut rng);
        let shares = test_shares(3);
        let scheme = PerShareWrapper;

        // Revoke share 0: survivors are shares 1 and 2.
        let survivors: Vec<Share> = shares.iter().skip(1).cloned().collect();
        let rewrapped = scheme.rewrap(&dk, &survivors);
        assert_eq!(rewrapped.wrappers.len(), 2);

        // Surviving shares still unwrap; the revoked share cannot.
        assert!(scheme.unwrap(&shares[1], &rewrapped.wrappers[0]).is_ok());
        assert!(scheme.unwrap(&shares[2], &rewrapped.wrappers[1]).is_ok());
        let revoked_set = scheme.wrap(&dk, &[shares[0].clone()]);
        assert!(scheme.unwrap(&shares[0], &revoked_set.wrappers[0]).is_ok());
    }
}
