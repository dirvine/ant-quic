//! Tests for crypto utilities using aws-lc-rs instead of Ring
//!
//! These tests ensure that our crypto utilities work correctly with aws-lc-rs
//! as we transition away from Ring to pure PQC implementation.

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    use aws_lc_rs::{aead, digest, hkdf, hmac};

    #[test]
    fn test_sha256_hashing() {
        // Test SHA256 hashing with aws-lc-rs
        let data = b"Hello, Post-Quantum World!";
        let hash = digest::digest(&digest::SHA256, data);

        // Verify hash has correct length
        assert_eq!(hash.as_ref().len(), 32);

        // Test with empty input
        let empty_hash = digest::digest(&digest::SHA256, b"");
        assert_eq!(empty_hash.as_ref().len(), 32);

        // Test deterministic property
        let hash2 = digest::digest(&digest::SHA256, data);
        assert_eq!(hash.as_ref(), hash2.as_ref());
    }

    #[test]
    fn test_sha384_hashing() {
        let data = b"SHA-384 test data";
        let hash = digest::digest(&digest::SHA384, data);
        assert_eq!(hash.as_ref().len(), 48);
    }

    #[test]
    fn test_sha512_hashing() {
        let data = b"SHA-512 test data";
        let hash = digest::digest(&digest::SHA512, data);
        assert_eq!(hash.as_ref().len(), 64);
    }

    #[test]
    fn test_hmac_operations() {
        // Test HMAC-SHA256
        let key_material = b"my-secret-key-for-hmac";
        let data = b"Message to authenticate";

        let key = hmac::Key::new(hmac::HMAC_SHA256, key_material);
        let tag = hmac::sign(&key, data);

        // Verify tag length
        assert_eq!(tag.as_ref().len(), 32); // SHA256 output

        // Test verification
        assert!(hmac::verify(&key, data, tag.as_ref()).is_ok());

        // Test with wrong data fails
        let wrong_data = b"Wrong message";
        assert!(hmac::verify(&key, wrong_data, tag.as_ref()).is_err());
    }

    #[test]
    fn test_hkdf_operations() {
        // Test HKDF with SHA256
        let salt = b"salt-value";
        let ikm = b"input-key-material";
        let info = b"context-info";

        // Extract phase
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);

        // Expand phase - derive 64 bytes
        let mut okm = [0u8; 64];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .expect("HKDF expand failed")
            .fill(&mut okm)
            .expect("HKDF fill failed");

        assert_eq!(okm.len(), 64);

        // Verify deterministic
        let mut okm2 = [0u8; 64];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .expect("HKDF expand failed")
            .fill(&mut okm2)
            .expect("HKDF fill failed");

        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_aead_aes_256_gcm() {
        // Test AES-256-GCM encryption/decryption
        let rng = SystemRandom::new();

        // Generate key
        let mut key_bytes = [0u8; 32]; // 256 bits
        rng.fill(&mut key_bytes).expect("Failed to generate key");

        let unbound_key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).expect("Failed to create key");
        let key = aead::LessSafeKey::new(unbound_key);

        // Create nonce
        let mut nonce_bytes = [0u8; 12]; // 96 bits for GCM
        rng.fill(&mut nonce_bytes)
            .expect("Failed to generate nonce");
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Encrypt
        let plaintext = b"Secret PQC message";
        let aad = b"Additional authenticated data";
        let mut ciphertext = plaintext.to_vec();

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut ciphertext)
            .expect("Encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..], plaintext);

        // Decrypt
        let nonce2 = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut decrypted = ciphertext.clone();
        decrypted.extend_from_slice(tag.as_ref());

        let unbound_key2 =
            aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).expect("Failed to create key");
        let key2 = aead::LessSafeKey::new(unbound_key2);

        let plaintext_result = key2
            .open_in_place(nonce2, aead::Aad::from(aad), &mut decrypted)
            .expect("Decryption failed");

        assert_eq!(plaintext_result, plaintext);
    }

    #[test]
    fn test_aead_aes_128_gcm() {
        // Test AES-128-GCM as alternative
        let rng = SystemRandom::new();

        let mut key_bytes = [0u8; 16]; // 128 bits
        rng.fill(&mut key_bytes).expect("Failed to generate key");

        let unbound_key =
            aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes).expect("Failed to create key");
        let key = aead::LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .expect("Failed to generate nonce");
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let plaintext = b"Test message";
        let mut ciphertext = plaintext.to_vec();

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut ciphertext)
            .expect("Encryption failed");

        assert_eq!(tag.as_ref().len(), 16); // GCM tag is 128 bits
    }

    #[test]
    fn test_secure_random() {
        // Test secure random number generation
        let rng = SystemRandom::new();

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng.fill(&mut bytes1).expect("RNG failed");
        rng.fill(&mut bytes2).expect("RNG failed");

        // Should be different (extremely high probability)
        assert_ne!(bytes1, bytes2);

        // Should not be all zeros
        assert_ne!(bytes1, [0u8; 32]);
        assert_ne!(bytes2, [0u8; 32]);
    }

    #[test]
    fn test_key_derivation_chain() {
        // Test a complete key derivation chain as might be used in TLS
        let rng = SystemRandom::new();

        // Generate random salt
        let mut salt = [0u8; 32];
        rng.fill(&mut salt).expect("Failed to generate salt");

        // Initial key material (could be from ECDHE/ML-KEM)
        let ikm = b"initial-key-material-from-key-exchange";

        // Derive keys using HKDF
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(ikm);

        // Derive multiple keys
        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        let mut client_iv = [0u8; 12];
        let mut server_iv = [0u8; 12];

        prk.expand(&[b"client key"], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut client_key)
            .unwrap();

        prk.expand(&[b"server key"], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut server_key)
            .unwrap();

        prk.expand(&[b"client iv"], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut client_iv)
            .unwrap();

        prk.expand(&[b"server iv"], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut server_iv)
            .unwrap();

        // Verify all derived values are different
        assert_ne!(client_key, server_key);
        assert_ne!(client_iv, server_iv);
    }
}
