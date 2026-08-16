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

    #[test]
    fn empty_plaintext_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let sealed = aead_seal(&key, b"");
        let opened = aead_open(&key, &sealed).expect("must open");
        assert!(opened.is_empty());
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 256) as u8).collect();
        let sealed = aead_seal(&key, &data);
        let opened = aead_open(&key, &sealed).expect("must open");
        assert_eq!(opened, data);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let sealed = aead_seal(&key, b"authentic data");
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(aead_open(&key, &tampered).is_none());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let sealed = aead_seal(&key, b"data");
        let truncated = &sealed[..sealed.len() - 1];
        assert!(aead_open(&key, truncated).is_none());
    }

    #[test]
    fn too_short_ciphertext_fails() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        assert!(aead_open(&key, &[0u8; 11]).is_none());
    }

    #[test]
    fn nonces_are_unique_across_seals() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let a = aead_seal(&key, b"x");
        let b = aead_seal(&key, b"x");
        assert_ne!(&a[..12], &b[..12], "fresh nonce per seal");
    }

    #[test]
    fn two_keys_generate_distinct_material() {
        let mut rng = rand::thread_rng();
        let a = SecretKey::generate(&mut rng);
        let b = SecretKey::generate(&mut rng);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn import_roundtrip_preserves_bytes() {
        let bytes = [7u8; 32];
        let key = SecretKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let debug = format!("{key:?}");
        assert!(!debug.contains("7"), "Debug must not print key bytes");
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn seal_is_not_identity_on_identical_input() {
        let mut rng = rand::thread_rng();
        let key = SecretKey::generate(&mut rng);
        let data = [0u8; 64];
        let sealed = aead_seal(&key, &data);
        // Ciphertext must never equal plaintext (nonce + tag prefix guarantees this).
        assert_ne!(&sealed[12..], &data[..]);
    }
}
