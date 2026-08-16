//! X25519 master keypair and ECIES file sealing.
//!
//! The master key is the user's asymmetric identity: the public half is what a
//! compatible client publishes (and what `talkctl user create --pubkey`
//! stores), the private half stays with the client and unwraps the data key
//! locally (see [`resolver::MasterKeyResolver`]).
//!
//! [`seal_envelope`] encrypts arbitrary data to a master *public* key via
//! ephemeral X25519 ECDH + HKDF-SHA256 + chacha20poly1305. [`open_envelope`]
//! decrypts with the master *private* key. The envelope is self-describing and
//! versioned so the format can evolve.

use crate::dk::{SecretKey, aead_open, aead_seal};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Envelope magic: `TKS1` (Talk Key Seal v1).
const MAGIC: &[u8; 4] = b"TKS1";
const VERSION: u8 = 1;
const EPHEMERAL_LEN: usize = 32;

/// HKDF info label, distinct from the DK-wrap label to prevent cross-protocol
/// key reuse.
const HKDF_INFO: &[u8] = b"talk/file-seal";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    #[error("not a sealed envelope (bad magic)")]
    BadMagic,
    #[error("unsupported envelope version {0}")]
    BadVersion(u8),
    #[error("envelope too short")]
    TooShort,
    #[error("failed to decrypt (wrong key or corrupted data)")]
    DecryptFailed,
}

/// A freshly generated X25519 master keypair.
pub struct MasterKeyPair {
    /// The master private key (zeroizes on drop).
    pub private: SecretKey,
    /// The master public key (publish this).
    pub public: PublicKey,
}

/// Generate a fresh X25519 master keypair.
pub fn generate_master_pair() -> MasterKeyPair {
    let mut rng = rand::rngs::OsRng;
    generate_master_pair_with(&mut rng)
}

/// Generate a fresh X25519 master keypair from a caller-provided RNG.
pub fn generate_master_pair_with<R: RngCore + CryptoRng>(rng: &mut R) -> MasterKeyPair {
    let static_secret = StaticSecret::random_from_rng(rng);
    let private = SecretKey::from_bytes(static_secret.to_bytes());
    let public = PublicKey::from(&static_secret);
    MasterKeyPair { private, public }
}

/// Derive the master public key from a master private key.
pub fn master_pubkey(private: &SecretKey) -> PublicKey {
    let static_secret = StaticSecret::from(*private.as_bytes());
    PublicKey::from(&static_secret)
}

/// Import a master public key from its 32 raw bytes.
pub fn master_public_from_bytes(bytes: [u8; 32]) -> PublicKey {
    PublicKey::from(bytes)
}

/// Encrypt `data` to a master public key (ECIES).
///
/// Uses an ephemeral X25519 keypair per call, so the same `data` and `pub`
/// produce a different envelope each time.
pub fn seal_envelope<R: RngCore + CryptoRng>(
    master_pub: &PublicKey,
    data: &[u8],
    rng: &mut R,
) -> Vec<u8> {
    let ephemeral = StaticSecret::random_from_rng(rng);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(master_pub);
    let wrap_key = derive_wrap_key(shared.as_bytes());

    let mut out = Vec::with_capacity(MAGIC.len() + 1 + EPHEMERAL_LEN + data.len() + 28);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&aead_seal(&wrap_key, data));
    out
}

/// Decrypt an envelope produced by [`seal_envelope`], using the master private
/// key.
pub fn open_envelope(private: &SecretKey, envelope: &[u8]) -> Result<Vec<u8>, SealError> {
    let head = MAGIC.len() + 1 + EPHEMERAL_LEN;
    if envelope.len() < head {
        return Err(SealError::TooShort);
    }
    if &envelope[..4] != MAGIC {
        return Err(SealError::BadMagic);
    }
    if envelope[4] != VERSION {
        return Err(SealError::BadVersion(envelope[4]));
    }
    let mut ephemeral_pub = [0u8; EPHEMERAL_LEN];
    ephemeral_pub.copy_from_slice(&envelope[5..head]);
    let ephemeral_pub = PublicKey::from(ephemeral_pub);

    let static_secret = StaticSecret::from(*private.as_bytes());
    let shared = static_secret.diffie_hellman(&ephemeral_pub);
    let wrap_key = derive_wrap_key(shared.as_bytes());

    aead_open(&wrap_key, &envelope[head..]).ok_or(SealError::DecryptFailed)
}

/// Derive the AEAD wrap key from an X25519 shared secret.
fn derive_wrap_key(shared_secret: &[u8]) -> SecretKey {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut wrapped_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut wrapped_key)
        .expect("hkdf expansion is infallible");
    let key = SecretKey::from_bytes(wrapped_key);
    wrapped_key.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_public_derives_from_private() {
        let pair = generate_master_pair();
        assert_eq!(master_pubkey(&pair.private), pair.public);
    }

    #[test]
    fn seal_open_roundtrip() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let data = b"hello, sealed world";
        let envelope = seal_envelope(&pair.public, data, &mut rng);
        let opened = open_envelope(&pair.private, &envelope).expect("open");
        assert_eq!(opened, data);
    }

    #[test]
    fn seal_open_roundtrip_binary() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..255u8).collect();
        let envelope = seal_envelope(&pair.public, &data, &mut rng);
        assert_eq!(open_envelope(&pair.private, &envelope).expect("open"), data);
    }

    #[test]
    fn wrong_key_fails() {
        let a = generate_master_pair();
        let b = generate_master_pair();
        let mut rng = rand::thread_rng();
        let envelope = seal_envelope(&a.public, b"data", &mut rng);
        assert_eq!(
            open_envelope(&b.private, &envelope),
            Err(SealError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let mut envelope = seal_envelope(&pair.public, b"data", &mut rng);
        let last = envelope.len() - 1;
        envelope[last] ^= 0xff;
        assert_eq!(
            open_envelope(&pair.private, &envelope),
            Err(SealError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_ephemeral_fails() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let mut envelope = seal_envelope(&pair.public, b"data", &mut rng);
        envelope[5] ^= 0xff; // flip a byte in the ephemeral public key
        assert_eq!(
            open_envelope(&pair.private, &envelope),
            Err(SealError::DecryptFailed)
        );
    }

    #[test]
    fn bad_magic_and_short_rejected() {
        let pair = generate_master_pair();
        assert_eq!(open_envelope(&pair.private, b"nope"), Err(SealError::TooShort));
        let mut rng = rand::thread_rng();
        let mut envelope = seal_envelope(&pair.public, b"data", &mut rng);
        envelope[0] = b'X';
        assert_eq!(
            open_envelope(&pair.private, &envelope),
            Err(SealError::BadMagic)
        );
    }

    #[test]
    fn bad_version_rejected() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let mut envelope = seal_envelope(&pair.public, b"data", &mut rng);
        envelope[4] = 99;
        assert_eq!(
            open_envelope(&pair.private, &envelope),
            Err(SealError::BadVersion(99))
        );
    }

    #[test]
    fn seal_is_nondeterministic() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let a = seal_envelope(&pair.public, b"data", &mut rng);
        let b = seal_envelope(&pair.public, b"data", &mut rng);
        assert_ne!(a, b, "fresh ephemeral + nonce per seal");
    }

    #[test]
    fn empty_data_roundtrip() {
        let pair = generate_master_pair();
        let mut rng = rand::thread_rng();
        let envelope = seal_envelope(&pair.public, b"", &mut rng);
        assert_eq!(open_envelope(&pair.private, &envelope).expect("open"), b"");
    }
}
