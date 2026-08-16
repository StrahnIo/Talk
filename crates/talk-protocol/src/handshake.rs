//! ZSMTP server authentication via DNS domain keys.
//!
//! Both servers authenticate as true to their DNS. The sending server issues a
//! random challenge; the receiving server signs it with its domain private key.
//! The sender verifies against the recipient's public domain key (published in
//! DNS, `_zsmtp._tcp.<domain>` TXT record — the DKIM analog).
//!
//! The challenge binds both parties' domains, a session nonce, and a timestamp
//! so it cannot be replayed or abused as a signing oracle (O10).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("challenge is stale (older than {0} seconds)")]
    Stale(i64),
    #[error("challenge nonce replayed")]
    Replay,
    #[error("challenge domain mismatch")]
    DomainMismatch,
    #[error("invalid key bytes")]
    InvalidKey,
}

/// A challenge issued by the sending server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The sender's domain (the challenger).
    pub sender_domain: String,
    /// The receiver's domain (the responder).
    pub receiver_domain: String,
    /// Random nonce, prevents replay.
    pub nonce: [u8; 16],
    /// Unix seconds at issue time.
    pub issued_at: i64,
}

impl Challenge {
    pub fn issue(sender_domain: &str, receiver_domain: &str) -> Self {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Self {
            sender_domain: sender_domain.to_string(),
            receiver_domain: receiver_domain.to_string(),
            nonce,
            issued_at: now_secs(),
        }
    }

    /// The exact bytes that get signed.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"zsmtp-v1");
        hasher.update(self.sender_domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.receiver_domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.nonce);
        hasher.update(self.issued_at.to_be_bytes());
        hasher.finalize().into()
    }

    /// Encode for the wire: `sender|receiver|nonce-hex|issued-at`.
    pub fn to_wire(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.sender_domain,
            self.receiver_domain,
            hex(&self.nonce),
            self.issued_at
        )
    }

    /// Parse from the wire encoding.
    pub fn from_wire(s: &str) -> Option<Self> {
        let mut parts = s.split('|');
        let sender_domain = parts.next()?.to_string();
        let receiver_domain = parts.next()?.to_string();
        let nonce_hex = parts.next()?;
        let issued_at = parts.next()?.parse().ok()?;
        if nonce_hex.len() != 32 || parts.next().is_some() {
            return None;
        }
        let nonce = unhex(nonce_hex)?;
        Some(Self {
            sender_domain,
            receiver_domain,
            nonce,
            issued_at,
        })
    }
}

/// A signed challenge response from the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub challenge: Challenge,
    /// ed25519 signature over `challenge.digest()`.
    pub signature: Vec<u8>,
}

impl ChallengeResponse {
    /// The receiver signs the challenge with their domain key.
    pub fn respond(challenge: &Challenge, domain_key: &SigningKey) -> Self {
        let signature = domain_key.sign(&challenge.digest());
        Self {
            challenge: challenge.clone(),
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// The sender verifies the response against the receiver's public key.
    pub fn verify(
        &self,
        receiver_pub: &VerifyingKey,
        max_age_secs: i64,
    ) -> Result<(), HandshakeError> {
        if self.challenge.sender_domain.is_empty() || self.challenge.receiver_domain.is_empty() {
            return Err(HandshakeError::DomainMismatch);
        }
        let age = now_secs() - self.challenge.issued_at;
        if age > max_age_secs || age < 0 {
            return Err(HandshakeError::Stale(max_age_secs));
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| HandshakeError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        receiver_pub
            .verify(&self.challenge.digest(), &signature)
            .map_err(|_| HandshakeError::BadSignature)
    }
}

/// A domain keypair bound to a domain.
pub struct DomainKey {
    pub domain: String,
    pub signing: SigningKey,
}

impl DomainKey {
    pub fn generate(domain: &str) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self {
            domain: domain.to_string(),
            signing,
        }
    }

    pub fn verifying(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs() as i64
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_AGE: i64 = 300;

    #[test]
    fn challenge_wire_roundtrip() {
        let c = Challenge::issue("sender.example.com", "receiver.example.org");
        let wire = c.to_wire();
        let back = Challenge::from_wire(&wire).expect("parse");
        assert_eq!(c, back);
    }

    #[test]
    fn challenge_wire_rejects_garbage() {
        assert!(Challenge::from_wire("").is_none());
        assert!(Challenge::from_wire("a|b|zzzz|1").is_none());
    }

    #[test]
    fn challenge_digest_is_deterministic() {
        let c = Challenge::issue("a.com", "b.org");
        assert_eq!(c.digest(), c.digest());
    }

    #[test]
    fn challenge_digest_binds_domains_and_nonce() {
        let c = Challenge::issue("a.com", "b.org");
        let mut other = c.clone();
        other.receiver_domain = "evil.org".to_string();
        assert_ne!(c.digest(), other.digest());
        let mut other2 = c.clone();
        other2.nonce[0] ^= 1;
        assert_ne!(c.digest(), other2.digest());
    }

    #[test]
    fn happy_path_respond_and_verify() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let challenge = Challenge::issue(&sender.domain, &receiver.domain);
        let response = ChallengeResponse::respond(&challenge, &receiver.signing);
        assert!(response.verify(&receiver.verifying(), MAX_AGE).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let attacker = DomainKey::generate("attacker.example.net");
        let challenge = Challenge::issue(&sender.domain, &receiver.domain);
        let response = ChallengeResponse::respond(&challenge, &attacker.signing);
        assert_eq!(
            response.verify(&receiver.verifying(), MAX_AGE),
            Err(HandshakeError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_domain() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let challenge = Challenge::issue(&sender.domain, &receiver.domain);
        let mut response = ChallengeResponse::respond(&challenge, &receiver.signing);
        // Mutate the domain after signing: signature no longer matches.
        response.challenge.receiver_domain = "evil.org".to_string();
        assert_eq!(
            response.verify(&receiver.verifying(), MAX_AGE),
            Err(HandshakeError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_stale_challenge() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let mut challenge = Challenge::issue(&sender.domain, &receiver.domain);
        challenge.issued_at = now_secs() - 3600; // 1 hour ago
        let response = ChallengeResponse::respond(&challenge, &receiver.signing);
        assert_eq!(
            response.verify(&receiver.verifying(), MAX_AGE),
            Err(HandshakeError::Stale(MAX_AGE))
        );
    }

    #[test]
    fn verify_rejects_future_challenge() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let mut challenge = Challenge::issue(&sender.domain, &receiver.domain);
        challenge.issued_at = now_secs() + 100; // clock skew the other way
        let response = ChallengeResponse::respond(&challenge, &receiver.signing);
        assert_eq!(
            response.verify(&receiver.verifying(), MAX_AGE),
            Err(HandshakeError::Stale(MAX_AGE))
        );
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let sender = DomainKey::generate("sender.example.com");
        let receiver = DomainKey::generate("receiver.example.org");
        let challenge = Challenge::issue(&sender.domain, &receiver.domain);
        let mut response = ChallengeResponse::respond(&challenge, &receiver.signing);
        response.signature.truncate(32);
        assert_eq!(
            response.verify(&receiver.verifying(), MAX_AGE),
            Err(HandshakeError::BadSignature)
        );
    }

    #[test]
    fn domain_keys_generate_distinct_verifying_keys() {
        let a = DomainKey::generate("a.com");
        let b = DomainKey::generate("b.com");
        assert_ne!(a.verifying().to_bytes(), b.verifying().to_bytes());
    }
}
