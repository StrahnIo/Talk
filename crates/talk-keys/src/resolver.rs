use crate::dk::{DataKey, SecretKey, aead_open, aead_seal};
use crate::share::{Share, ShareScheme, WrappedDkSet};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// A DK wrapped under the user's master public key (ECIES over X25519).
///
/// Compatible clients hold the master private key, unwrap DK locally, and
/// decrypt locally — the server never sees the private key.
#[derive(Clone, Debug)]
pub struct WrappedByMaster {
    /// Ephemeral X25519 public key used for this wrap.
    pub ephemeral_pub: [u8; 32],
    /// AEAD ciphertext: nonce || tag || ciphertext of DK.
    pub wrapped: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("wrapped data key failed to decrypt")]
    DecryptFailed,
    #[error("share does not match any wrapper in the set")]
    ShareMismatch,
}

/// A credential that can unlock a user's data key.
#[derive(Clone, Debug)]
pub enum Credential {
    /// The user's master private key (compatible clients).
    Master(SecretKey),
    /// A single share (app password).
    Share(Share),
}

/// Resolves a credential into the user's data key.
///
/// Implementations must return DK in memory only; callers are responsible for
/// zeroizing after use.
pub trait KeyResolver {
    /// Unwrap the data key from its wrappers using `credential`.
    fn unwrap(&self, credential: &Credential) -> Result<DataKey, ResolverError>;
}

/// Resolves via the per-share wrapper ladder.
pub struct ShareResolver<'a> {
    scheme: &'a dyn ShareScheme,
    set: &'a WrappedDkSet,
}

impl<'a> ShareResolver<'a> {
    pub fn new(scheme: &'a dyn ShareScheme, set: &'a WrappedDkSet) -> Self {
        Self { scheme, set }
    }
}

impl KeyResolver for ShareResolver<'_> {
    fn unwrap(&self, credential: &Credential) -> Result<DataKey, ResolverError> {
        let Credential::Share(share) = credential else {
            return Err(ResolverError::ShareMismatch);
        };
        let mut last_err = ResolverError::ShareMismatch;
        for wrapper in &self.set.wrappers {
            match self.scheme.unwrap(share, wrapper) {
                Ok(dk) => return Ok(dk),
                Err(e) => last_err = e.into(),
            }
        }
        Err(last_err)
    }
}

/// Resolves via the master key (ECIES unwrap).
pub struct MasterKeyResolver;

impl MasterKeyResolver {
    /// Wrap `dk` under a master public key.
    pub fn wrap<R: RngCore + CryptoRng>(
        &self,
        dk: &DataKey,
        master_pub: &PublicKey,
        rng: &mut R,
    ) -> WrappedByMaster {
        let ephemeral = StaticSecret::random_from_rng(rng);
        let ephemeral_pub = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(master_pub);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrapped_key = [0u8; 32];
        hkdf.expand(b"talk/dk-wrap", &mut wrapped_key)
            .expect("hkdf expansion is infallible");
        let wrap_key = SecretKey::from_bytes(wrapped_key);
        wrapped_key.zeroize();
        let ciphertext = aead_seal(&wrap_key, dk.as_bytes());
        WrappedByMaster {
            ephemeral_pub: ephemeral_pub.to_bytes(),
            wrapped: ciphertext,
        }
    }

    /// Unwrap a DK wrapped under a master public key, using the master private key.
    pub fn unwrap(
        &self,
        master_priv: &SecretKey,
        wrapped: &WrappedByMaster,
    ) -> Result<DataKey, ResolverError> {
        let ephemeral_pub = PublicKey::from(wrapped.ephemeral_pub);
        let static_secret = StaticSecret::from(*master_priv.as_bytes());
        let shared = static_secret.diffie_hellman(&ephemeral_pub);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrapped_key = [0u8; 32];
        hkdf.expand(b"talk/dk-wrap", &mut wrapped_key)
            .expect("hkdf expansion is infallible");
        let wrap_key = SecretKey::from_bytes(wrapped_key);
        wrapped_key.zeroize();
        let bytes = aead_open(&wrap_key, &wrapped.wrapped).ok_or(ResolverError::DecryptFailed)?;
        if bytes.len() != 32 {
            return Err(ResolverError::DecryptFailed);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(DataKey::from_bytes(key))
    }
}

impl From<crate::share::ShareError> for ResolverError {
    fn from(_: crate::share::ShareError) -> Self {
        ResolverError::DecryptFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::PerShareWrapper;

    fn test_share_set() -> (Vec<Share>, WrappedDkSet) {
        let mut rng = rand::thread_rng();
        let dk = DataKey::generate(&mut rng);
        let shares: Vec<Share> = (0..4).map(|_| Share::generate(&mut rng)).collect();
        let scheme = PerShareWrapper;
        let set = scheme.wrap(&dk, &shares);
        (shares, set)
    }

    #[test]
    fn share_resolver_unlocks_with_any_share() {
        let (shares, set) = test_share_set();
        let scheme = PerShareWrapper;
        let resolver = ShareResolver::new(&scheme, &set);
        for share in &shares {
            let dk = resolver
                .unwrap(&Credential::Share(share.clone()))
                .expect("any share must unlock");
            assert!(dk.as_bytes().len() == 32);
        }
    }

    #[test]
    fn share_resolver_rejects_wrong_share() {
        let (_, set) = test_share_set();
        let scheme = PerShareWrapper;
        let resolver = ShareResolver::new(&scheme, &set);
        let outsider = Share::generate(&mut rand::thread_rng());
        assert!(resolver.unwrap(&Credential::Share(outsider)).is_err());
    }

    #[test]
    fn master_key_roundtrip() {
        let mut rng = rand::thread_rng();
        let dk = DataKey::generate(&mut rng);
        let master_secret = StaticSecret::random_from_rng(&mut rng);
        let master_pub = PublicKey::from(&master_secret);

        let resolver = MasterKeyResolver;
        let wrapped = resolver.wrap(&dk, &master_pub, &mut rng);

        let master_priv = SecretKey::from_bytes(master_secret.to_bytes());
        let unwrapped = resolver
            .unwrap(&master_priv, &wrapped)
            .expect("must unwrap");
        assert_eq!(unwrapped.as_bytes(), dk.as_bytes());
    }
}
