// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Crypto utilities module using aws-lc-rs
//!
//! This module provides cryptographic utilities using aws-lc-rs instead of Ring,
//! as part of the transition to pure PQC implementation.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::{aead, digest, hkdf, hmac};
use std::sync::Arc;

/// Errors from cryptographic operations
#[derive(Debug, Clone)]
pub struct CryptoUtilError {
    /// Error message describing the cryptographic operation failure
    pub message: String,
}

impl std::fmt::Display for CryptoUtilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crypto utility error: {}", self.message)
    }
}

impl std::error::Error for CryptoUtilError {}

impl From<aws_lc_rs::error::Unspecified> for CryptoUtilError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Self {
            message: "Unspecified cryptographic error".to_string(),
        }
    }
}

/// Result type for cryptographic operations
pub type CryptoUtilResult<T> = Result<T, CryptoUtilError>;

/// Compute SHA256 hash of data
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Compute SHA384 hash of data
pub fn sha384(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA384, data).as_ref().to_vec()
}

/// Compute SHA512 hash of data
pub fn sha512(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().to_vec()
}

/// HMAC-SHA256 wrapper
pub struct HmacSha256 {
    key: hmac::Key,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 key
    pub fn new(key_material: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key_material),
        }
    }

    /// Sign data with the HMAC key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        hmac::sign(&self.key, data).as_ref().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> CryptoUtilResult<()> {
        hmac::verify(&self.key, data, signature)?;
        Ok(())
    }
}

/// HKDF-SHA256 wrapper for key derivation
pub struct HkdfSha256;

impl HkdfSha256 {
    /// Extract and expand key material
    pub fn extract_and_expand(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> CryptoUtilResult<Vec<u8>> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);

        let mut output = vec![0u8; output_len];
        let info_parts = [info];
        let okm = prk.expand(&info_parts, hkdf::HKDF_SHA256)?;
        okm.fill(&mut output)?;

        Ok(output)
    }

    /// Extract phase only (returns PRK)
    pub fn extract(salt: &[u8], ikm: &[u8]) -> HkdfPrk {
        HkdfPrk {
            prk: Arc::new(hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm)),
        }
    }
}

/// HKDF Pseudo-Random Key wrapper
#[derive(Clone)]
pub struct HkdfPrk {
    prk: Arc<hkdf::Prk>,
}

impl HkdfPrk {
    /// Expand the PRK to derive output key material
    pub fn expand(&self, info: &[u8], output_len: usize) -> CryptoUtilResult<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let info_parts = [info];
        let okm = self.prk.expand(&info_parts, hkdf::HKDF_SHA256)?;
        okm.fill(&mut output)?;
        Ok(output)
    }
}

/// AES-256-GCM AEAD wrapper
pub struct Aes256Gcm {
    key: aead::LessSafeKey,
}

impl Aes256Gcm {
    /// Create a new AES-256-GCM key
    pub fn new(key_bytes: &[u8]) -> CryptoUtilResult<Self> {
        if key_bytes.len() != 32 {
            return Err(CryptoUtilError {
                message: format!("Invalid key length: expected 32, got {}", key_bytes.len()),
            });
        }

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound_key),
        })
    }

    /// Encrypt data in place with a nonce and additional data
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> CryptoUtilResult<()> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        self.key.seal_in_place_append_tag(nonce, aad, data)?;
        Ok(())
    }

    /// Decrypt data in place with a nonce and additional data
    pub fn decrypt_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> CryptoUtilResult<&'a [u8]> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        let plaintext = self.key.open_in_place(nonce, aad, ciphertext)?;
        Ok(plaintext)
    }

    /// Encrypt with separate tag output
    pub fn encrypt_separate_tag(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> CryptoUtilResult<[u8; 16]> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        let tag = self.key.seal_in_place_separate_tag(nonce, aad, plaintext)?;

        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_ref());
        Ok(tag_bytes)
    }
}

/// AES-128-GCM AEAD wrapper
pub struct Aes128Gcm {
    key: aead::LessSafeKey,
}

impl Aes128Gcm {
    /// Create a new AES-128-GCM key
    pub fn new(key_bytes: &[u8]) -> CryptoUtilResult<Self> {
        if key_bytes.len() != 16 {
            return Err(CryptoUtilError {
                message: format!("Invalid key length: expected 16, got {}", key_bytes.len()),
            });
        }

        let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound_key),
        })
    }

    /// Encrypt data in place with a nonce and additional data
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> CryptoUtilResult<()> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        self.key.seal_in_place_append_tag(nonce, aad, data)?;
        Ok(())
    }

    /// Decrypt data in place with a nonce and additional data
    pub fn decrypt_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> CryptoUtilResult<&'a [u8]> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        let plaintext = self.key.open_in_place(nonce, aad, ciphertext)?;
        Ok(plaintext)
    }
}

/// ChaCha20-Poly1305 AEAD wrapper
pub struct ChaCha20Poly1305 {
    key: aead::LessSafeKey,
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 key
    pub fn new(key_bytes: &[u8]) -> CryptoUtilResult<Self> {
        if key_bytes.len() != 32 {
            return Err(CryptoUtilError {
                message: format!("Invalid key length: expected 32, got {}", key_bytes.len()),
            });
        }

        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound_key),
        })
    }

    /// Encrypt data in place with a nonce and additional data
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> CryptoUtilResult<()> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        self.key.seal_in_place_append_tag(nonce, aad, data)?;
        Ok(())
    }

    /// Decrypt data in place with a nonce and additional data
    pub fn decrypt_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &'a mut [u8],
    ) -> CryptoUtilResult<&'a [u8]> {
        let nonce = aead::Nonce::assume_unique_for_key(*nonce);
        let aad = aead::Aad::from(aad);
        let plaintext = self.key.open_in_place(nonce, aad, ciphertext)?;
        Ok(plaintext)
    }
}

/// Secure random number generator
pub struct SecureRng {
    rng: SystemRandom,
}

impl SecureRng {
    /// Create a new secure RNG
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Fill a buffer with random bytes
    pub fn fill(&self, buf: &mut [u8]) -> CryptoUtilResult<()> {
        self.rng.fill(buf)?;
        Ok(())
    }

    /// Generate a random array of fixed size
    pub fn generate<const N: usize>(&self) -> CryptoUtilResult<[u8; N]> {
        let mut bytes = [0u8; N];
        self.fill(&mut bytes)?;
        Ok(bytes)
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Hello, PQC World!";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);

        // Test deterministic
        let hash2 = sha256(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret-key";
        let data = b"message to sign";

        let hmac = HmacSha256::new(key);
        let signature = hmac.sign(data);
        assert_eq!(signature.len(), 32);

        // Verify should succeed
        assert!(hmac.verify(data, &signature).is_ok());

        // Wrong data should fail
        assert!(hmac.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_hkdf_sha256() {
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";

        // Test with 32 bytes (SHA256 output size)
        let output = HkdfSha256::extract_and_expand(salt, ikm, info, 32).unwrap();
        assert_eq!(output.len(), 32);

        // Test extract and expand separately
        let prk = HkdfSha256::extract(salt, ikm);
        let output2 = prk.expand(info, 32).unwrap();
        assert_eq!(output, output2);

        // Test deterministic output
        let output3 = HkdfSha256::extract_and_expand(salt, ikm, info, 32).unwrap();
        assert_eq!(output, output3);
    }

    #[test]
    fn test_aes_256_gcm() {
        let rng = SecureRng::new();
        let key = rng.generate::<32>().unwrap();
        let nonce = rng.generate::<12>().unwrap();
        let aad = b"additional data";

        let aes = Aes256Gcm::new(&key).unwrap();

        let plaintext = b"secret message";
        let mut data = plaintext.to_vec();

        // Encrypt
        aes.encrypt_in_place(&nonce, aad, &mut data).unwrap();
        assert_ne!(&data[..plaintext.len()], plaintext);

        // Decrypt
        let decrypted = aes.decrypt_in_place(&nonce, aad, &mut data).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secure_rng() {
        let rng = SecureRng::new();

        let bytes1 = rng.generate::<32>().unwrap();
        let bytes2 = rng.generate::<32>().unwrap();

        // Should be different
        assert_ne!(bytes1, bytes2);

        // Should not be all zeros
        assert_ne!(bytes1, [0u8; 32]);
        assert_ne!(bytes2, [0u8; 32]);
    }
}
