//! Address attestation: a domain-key-signed `(address, pubkey)` binding.
//!
//! Per `docs/attestation.md`, the server attests to both the shielded address
//! (where to pay) and the recipient's public encryption key (how to encrypt
//! the invoice) under one signature, preventing pubkey substitution.
//!
//! v1 uses a placeholder address/keypair: a fresh random x25519-style public
//! key serialized as a hex string. The attestation structure, signature, and
//! verification flow are the load-bearing parts; real shielded-address
//! derivation can swap in without protocol change.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("attestation domain mismatch")]
    DomainMismatch,
}

/// The issuance mode requested by the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    Ephemeral,
    Attested,
}

/// An attestation of a recipient's payment address + encryption pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The attesting server's domain.
    pub domain: String,
    /// The user being attested.
    pub user: String,
    pub mode: AttestationMode,
    /// The (placeholder) payment address.
    pub address: String,
    /// The public encryption key for this address (hex).
    pub pubkey: String,
    /// Domain-key signature over the canonical binding.
    pub signature: Vec<u8>,
}

impl Attestation {
    /// Build an attestation and sign it with the domain key.
    pub fn sign(
        domain: &str,
        user: &str,
        mode: AttestationMode,
        address: String,
        pubkey: String,
        domain_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let binding = Self {
            domain: domain.to_string(),
            user: user.to_string(),
            mode,
            address,
            pubkey,
            signature: Vec::new(),
        };
        let sig = domain_key.sign(&binding.canonical_digest());
        Self {
            signature: sig.to_bytes().to_vec(),
            ..binding
        }
    }

    /// The exact bytes that are signed — deterministic and canonical.
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zsmpt-attest-v1");
        hasher.update(self.domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.user.as_bytes());
        hasher.update([0u8]);
        let mode: &[u8] = match self.mode {
            AttestationMode::Ephemeral => b"ephemeral",
            AttestationMode::Attested => b"attested",
        };
        hasher.update(mode);
        hasher.update([0u8]);
        hasher.update(self.address.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.pubkey.as_bytes());
        hasher.finalize().into()
    }

    /// Verify the signature against the domain's public key.
    pub fn verify(
        &self,
        domain_key: &VerifyingKey,
        expected_domain: &str,
    ) -> Result<(), AttestationError> {
        if self.domain != expected_domain {
            return Err(AttestationError::DomainMismatch);
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| AttestationError::BadSignature)?;
        domain_key
            .verify(&self.canonical_digest(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| AttestationError::BadSignature)
    }

    /// Serialize for the wire (JSON).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("attestation serializes")
    }

    /// Parse from the wire (JSON).
    pub fn from_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|_| AttestationError::InvalidKey)
    }
}

/// A placeholder address keypair: generates a random pubkey on demand.
///
/// Ephemeral mode mints a fresh pubkey per request; attested mode returns a
/// stable one (a fixed placeholder for v1).
pub fn placeholder_pubkey(rng: &mut impl RngCore) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a placeholder address keypair for the given mode.
///
/// Both modes mint a random 32-byte value as a stand-in for the address and
/// the pubkey. Real shielded-address derivation replaces this. The two modes
/// differ only in whether the address is rotated per request (ephemeral) or
/// stable per user (attested); with a random placeholder, "stability" is left
/// to the caller's key management, so the minted pair is random in both modes.
pub fn mint_pair(_mode: AttestationMode) -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    (format!("taddr-{hex}"), hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn sign_and_verify() {
        let key = keypair();
        let att = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Ephemeral,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        assert!(att.verify(&key.verifying_key(), "example.org").is_ok());
    }

    #[test]
    fn verify_rejects_wrong_domain() {
        let key = keypair();
        let att = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Ephemeral,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        assert_eq!(
            att.verify(&key.verifying_key(), "evil.org"),
            Err(AttestationError::DomainMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_pubkey() {
        let key = keypair();
        let mut att = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Ephemeral,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        att.pubkey = "tampered".into();
        assert_eq!(
            att.verify(&key.verifying_key(), "example.org"),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key = keypair();
        let other = keypair();
        let att = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Ephemeral,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        assert_eq!(
            att.verify(&other.verifying_key(), "example.org"),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn digest_binds_all_fields() {
        let key = keypair();
        let base = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Ephemeral,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        let mut other = base.clone();
        other.user = "bob".into();
        assert_ne!(base.canonical_digest(), other.canonical_digest());
        let mut other2 = base.clone();
        other2.mode = AttestationMode::Attested;
        assert_ne!(base.canonical_digest(), other2.canonical_digest());
    }

    #[test]
    fn json_roundtrip() {
        let key = keypair();
        let att = Attestation::sign(
            "example.org",
            "alice",
            AttestationMode::Attested,
            "taddr-abc".into(),
            "def".into(),
            &key,
        );
        let json = att.to_json();
        let back = Attestation::from_json(&json).expect("parse");
        assert_eq!(att, back);
    }

    #[test]
    fn json_from_garbage_fails() {
        assert!(Attestation::from_json("not json").is_err());
    }

    #[test]
    fn placeholder_pubkey_is_hex() {
        let mut rng = OsRng;
        let pk = placeholder_pubkey(&mut rng);
        assert_eq!(pk.len(), 64, "32 bytes hex = 64 chars");
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn mint_pair_produces_distinct_ephemeral_addresses() {
        let (a, _) = mint_pair(AttestationMode::Ephemeral);
        let (b, _) = mint_pair(AttestationMode::Ephemeral);
        assert_ne!(a, b);
    }
}
