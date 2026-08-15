use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of a data key or wrapping key, in bytes.
pub const KEY_LEN: usize = 32;

/// A symmetric key that zeroizes itself on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; KEY_LEN]);

impl SecretKey {
    /// Generate a fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Import a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

/// The data key that encrypts a user's mailbox data.
pub type DataKey = SecretKey;

/// AEAD over a secret key with a random nonce.
pub(crate) fn aead_seal(key: &SecretKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    let tag = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("AEAD seal is infallible");
    out.extend_from_slice(&tag);
    out
}

/// AEAD open with the nonce embedded in `ciphertext[..12]`.
pub(crate) fn aead_open(key: &SecretKey, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 12 {
        return None;
    }
    let (nonce, body) = ciphertext.split_at(12);
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
    cipher.decrypt(Nonce::from_slice(nonce), body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let data = b"some mailbox data";
        let sealed = aead_seal(&key, data);
        assert_ne!(&sealed[12..], data);
        let opened = aead_open(&key, &sealed).expect("must open");
        assert_eq!(opened, data);
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let other = SecretKey::generate(&mut rng);
        let sealed = aead_seal(&key, b"data");
        assert!(aead_open(&other, &sealed).is_none());
    }
}
