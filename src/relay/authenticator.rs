// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ML-DSA-based authentication for relay operations with anti-replay protection.

use crate::crypto::raw_keys::{MlDsaKeyPair, MlDsaPublicKey, MlDsaSignature};
use crate::relay::{RelayError, RelayResult};
use rand::rngs::OsRng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cryptographic authentication token for relay operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken {
    /// Unique nonce to prevent replay attacks
    pub nonce: u64,
    /// Timestamp when token was created (Unix timestamp)
    pub timestamp: u64,
    /// Requested bandwidth limit in bytes per second
    pub bandwidth_limit: u32,
    /// Session timeout in seconds
    pub timeout_seconds: u32,
    /// ML-DSA signature over the token data
    pub signature: Vec<u8>,
}

/// ML-DSA authenticator with anti-replay protection
#[derive(Debug)]
pub struct RelayAuthenticator {
    /// Keypair for this node
    keypair: MlDsaKeyPair,
    /// Set of used nonces for anti-replay protection
    used_nonces: Arc<Mutex<HashSet<u64>>>,
    /// Maximum age of tokens in seconds (default: 5 minutes)
    max_token_age: u64,
    /// Size of anti-replay window
    replay_window_size: u64,
}

impl AuthToken {
    /// Create a new authentication token
    pub fn new(
        bandwidth_limit: u32,
        timeout_seconds: u32,
        keypair: &MlDsaKeyPair,
    ) -> RelayResult<Self> {
        let nonce = Self::generate_nonce();
        let timestamp = Self::current_timestamp()?;

        let mut token = Self {
            nonce,
            timestamp,
            bandwidth_limit,
            timeout_seconds,
            signature: Vec::new(),
        };

        // Sign the token
        let signature =
            keypair
                .sign(&token.signable_data())
                .map_err(|e| RelayError::AuthenticationFailed {
                    reason: format!("Failed to sign token: {}", e),
                })?;
        token.signature = signature.as_bytes().to_vec();

        Ok(token)
    }

    /// Generate a cryptographically secure nonce
    fn generate_nonce() -> u64 {
        use rand::Rng;
        OsRng.r#gen()
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> RelayResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| RelayError::AuthenticationFailed {
                reason: "System time before Unix epoch".to_string(),
            })
    }

    /// Get the data that should be signed
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.bandwidth_limit.to_le_bytes());
        data.extend_from_slice(&self.timeout_seconds.to_le_bytes());
        data
    }

    /// Verify the token signature
    pub fn verify(&self, public_key: &MlDsaPublicKey) -> RelayResult<()> {
        let signature = MlDsaSignature::from_bytes(&self.signature).map_err(|_| {
            RelayError::AuthenticationFailed {
                reason: "Invalid signature format".to_string(),
            }
        })?;

        // Create a temporary keypair for verification
        // Note: This is a workaround since we only have the public key
        let _dummy_keypair =
            MlDsaKeyPair::generate().map_err(|_| RelayError::AuthenticationFailed {
                reason: "Failed to create verification context".to_string(),
            })?;

        // Use saorsa_pqc for verification
        use saorsa_pqc::{
            MlDsaOperations, MlDsaPublicKey as SaorsaPublicKey, MlDsaSignature as SaorsaSignature,
        };

        let ml_dsa = saorsa_pqc::MlDsa65::new();

        // Convert to saorsa_pqc types
        let saorsa_public_key =
            SaorsaPublicKey::from_bytes(public_key.as_bytes()).map_err(|e| {
                RelayError::AuthenticationFailed {
                    reason: format!("Invalid public key: {}", e),
                }
            })?;
        let saorsa_signature = SaorsaSignature::from_bytes(signature.as_bytes()).map_err(|e| {
            RelayError::AuthenticationFailed {
                reason: format!("Invalid signature: {}", e),
            }
        })?;

        // Verify the signature
        let is_valid = ml_dsa
            .verify(&saorsa_public_key, &self.signable_data(), &saorsa_signature)
            .map_err(|e| RelayError::AuthenticationFailed {
                reason: format!("Verification failed: {}", e),
            })?;

        if !is_valid {
            return Err(RelayError::AuthenticationFailed {
                reason: "Invalid signature".to_string(),
            });
        }

        Ok(())
    }

    /// Check if the token has expired
    pub fn is_expired(&self, max_age_seconds: u64) -> RelayResult<bool> {
        let current_time = Self::current_timestamp()?;
        Ok(current_time > self.timestamp + max_age_seconds)
    }
}

impl RelayAuthenticator {
    /// Create a new authenticator with a random key pair
    pub fn try_new() -> RelayResult<Self> {
        let keypair = MlDsaKeyPair::generate().map_err(|e| RelayError::AuthenticationFailed {
            reason: format!("ML-DSA key generation failed: {}", e),
        })?;
        Ok(Self {
            keypair,
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
            max_token_age: 300, // 5 minutes
            replay_window_size: 1000,
        })
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::try_new().expect("failed to construct RelayAuthenticator for test")
    }

    /// Create an authenticator with a specific keypair
    pub fn with_key(keypair: MlDsaKeyPair) -> Self {
        Self {
            keypair,
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
            max_token_age: 300,
            replay_window_size: 1000,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> MlDsaPublicKey {
        self.keypair.public_key()
    }

    /// Create a new authentication token
    pub fn create_token(
        &self,
        bandwidth_limit: u32,
        timeout_seconds: u32,
    ) -> RelayResult<AuthToken> {
        AuthToken::new(bandwidth_limit, timeout_seconds, &self.keypair)
    }

    /// Verify an authentication token with anti-replay protection
    pub fn verify_token(
        &self,
        token: &AuthToken,
        peer_public_key: &MlDsaPublicKey,
    ) -> RelayResult<()> {
        // Check signature
        token.verify(peer_public_key)?;

        // Check if token has expired
        if token.is_expired(self.max_token_age)? {
            return Err(RelayError::AuthenticationFailed {
                reason: "Token expired".to_string(),
            });
        }

        // Check for replay attack
        let mut used_nonces = self
            .used_nonces
            .lock()
            .map_err(|_| RelayError::NetworkError {
                operation: "verify_token.lock".into(),
                source: "mutex poisoned".into(),
            })?;

        if used_nonces.contains(&token.nonce) {
            return Err(RelayError::AuthenticationFailed {
                reason: "Token replay detected".to_string(),
            });
        }

        // Add nonce to used set (with size limit)
        if used_nonces.len() >= self.replay_window_size as usize {
            // Remove oldest entries (simple approach - in production might use LRU)
            let to_remove: Vec<_> = used_nonces.iter().take(100).cloned().collect();
            for nonce in to_remove {
                used_nonces.remove(&nonce);
            }
        }

        used_nonces.insert(token.nonce);

        Ok(())
    }

    /// Set maximum token age
    pub fn set_max_token_age(&mut self, max_age_seconds: u64) {
        self.max_token_age = max_age_seconds;
    }

    /// Get maximum token age
    pub fn max_token_age(&self) -> u64 {
        self.max_token_age
    }

    /// Clear all used nonces (for testing)
    pub fn clear_nonces(&self) {
        let mut used_nonces = match self.used_nonces.lock() {
            Ok(guard) => guard,
            Err(_) => return, // best-effort clear
        };
        used_nonces.clear();
    }

    /// Get number of used nonces (for testing)
    pub fn nonce_count(&self) -> usize {
        match self.used_nonces.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }
}

// Default intentionally not implemented for RelayAuthenticator to avoid hidden panics

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_auth_token_creation_and_verification() {
        let authenticator = RelayAuthenticator::new();
        let token = authenticator.create_token(1024, 300).unwrap();

        assert!(token.bandwidth_limit == 1024);
        assert!(token.timeout_seconds == 300);
        assert!(token.nonce != 0);
        assert!(token.timestamp > 0);

        // Verify token
        let public_key = authenticator.public_key();
        assert!(token.verify(&public_key).is_ok());
    }

    #[test]
    fn test_token_verification_with_wrong_key() {
        let authenticator1 = RelayAuthenticator::new();
        let authenticator2 = RelayAuthenticator::new();

        let token = authenticator1.create_token(1024, 300).unwrap();

        // Should fail with wrong key
        let public_key2 = authenticator2.public_key();
        assert!(token.verify(&public_key2).is_err());
    }

    #[test]
    fn test_token_expiration() {
        let mut authenticator = RelayAuthenticator::new();
        authenticator.set_max_token_age(1); // 1 second

        let token = authenticator.create_token(1024, 300).unwrap();

        // Should not be expired immediately (using authenticator's max age)
        let max_age = authenticator.max_token_age();
        assert!(!token.is_expired(max_age).unwrap());

        // Wait for expiration - using longer delay to ensure expiration
        thread::sleep(Duration::from_secs(2)); // 2 full seconds to be sure

        // Should be expired now (using authenticator's max age)
        assert!(token.is_expired(max_age).unwrap());
    }

    #[test]
    fn test_anti_replay_protection() {
        let authenticator = RelayAuthenticator::new();
        let token = authenticator.create_token(1024, 300).unwrap();

        // First verification should succeed
        let public_key = authenticator.public_key();
        assert!(authenticator.verify_token(&token, &public_key).is_ok());

        // Second verification should fail (replay)
        assert!(authenticator.verify_token(&token, &public_key).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let authenticator = RelayAuthenticator::new();
        let mut nonces = HashSet::new();

        // Generate many tokens and check nonce uniqueness
        for _ in 0..1000 {
            let token = authenticator.create_token(1024, 300).unwrap();
            assert!(!nonces.contains(&token.nonce), "Duplicate nonce detected");
            nonces.insert(token.nonce);
        }
    }

    #[test]
    fn test_token_signable_data() {
        let authenticator = RelayAuthenticator::new();
        let token1 = authenticator.create_token(1024, 300).unwrap();
        let token2 = authenticator.create_token(1024, 300).unwrap();

        // Different tokens should have different signable data (due to nonce/timestamp)
        assert_ne!(token1.signable_data(), token2.signable_data());
    }

    #[test]
    fn test_nonce_window_management() {
        let authenticator = RelayAuthenticator::new();

        // Fill up the nonce window
        for _ in 0..1000 {
            let token = authenticator.create_token(1024, 300).unwrap();
            let public_key = authenticator.public_key();
            let _ = authenticator.verify_token(&token, &public_key);
        }

        assert_eq!(authenticator.nonce_count(), 1000);

        // Add one more token (should trigger cleanup)
        let token = authenticator.create_token(1024, 300).unwrap();
        let public_key = authenticator.public_key();
        let _ = authenticator.verify_token(&token, &public_key);

        // Window should be maintained at reasonable size
        assert!(authenticator.nonce_count() <= 1000);
    }

    #[test]
    fn test_clear_nonces() {
        let authenticator = RelayAuthenticator::new();
        let token = authenticator.create_token(1024, 300).unwrap();

        // Use token
        let public_key = authenticator.public_key();
        let _ = authenticator.verify_token(&token, &public_key);
        assert!(authenticator.nonce_count() > 0);

        // Clear nonces
        authenticator.clear_nonces();
        assert_eq!(authenticator.nonce_count(), 0);

        // Should be able to use the same token again
        assert!(
            authenticator
                .verify_token(&token, &authenticator.public_key())
                .is_ok()
        );
    }

    #[test]
    fn test_with_specific_key() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let authenticator = RelayAuthenticator::with_key(keypair);

        let token = authenticator.create_token(1024, 300).unwrap();
        let public_key = authenticator.public_key();
        assert!(token.verify(&public_key).is_ok());
    }
}
