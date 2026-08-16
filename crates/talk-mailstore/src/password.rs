//! Argon2 password hashing and verification.

use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Hash a password with Argon2id, returning the PHC string to store.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::default();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// Verify a password against a stored PHC hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse").expect("hash");
        assert_ne!(hash, "correct horse");
        assert!(verify_password("correct horse", &hash).expect("verify"));
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct horse").expect("hash");
        assert!(!verify_password("wrong", &hash).expect("verify"));
    }

    #[test]
    fn hashes_are_salted() {
        let a = hash_password("same").expect("a");
        let b = hash_password("same").expect("b");
        assert_ne!(a, b, "salts must differ");
    }
}
