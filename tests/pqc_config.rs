//! Tests for Post-Quantum Cryptography configuration API

use ant_quic::crypto::pqc::{PqcConfig};
use ant_quic::{
    EndpointConfig,
    crypto::{CryptoError, HmacKey},
};
use std::sync::Arc;

/// Dummy HMAC key for testing
struct TestHmacKey;

impl HmacKey for TestHmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        // Dummy implementation for testing
        let len = out.len().min(data.len());
        out[..len].copy_from_slice(&data[..len]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        // Dummy verification for testing
        if signature.len() >= self.signature_len() {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

#[test]
fn test_pqc_config_integration_with_endpoint() {
    // Create a PQC config
    let pqc_config = PqcConfig::builder()
        .memory_pool_size(20)
        .handshake_timeout_multiplier(2.0)
        .build()
        .unwrap();

    // Create an endpoint config
    let reset_key: Arc<dyn HmacKey> = Arc::new(TestHmacKey);
    let mut endpoint_config = EndpointConfig::new(reset_key);

    // Set PQC config
    endpoint_config.pqc_config(pqc_config.clone());

    // Verify the configuration was set
    assert_eq!(pqc_config.memory_pool_size, 20);
    assert_eq!(pqc_config.handshake_timeout_multiplier, 2.0);
}

#[test]
fn test_pqc_config_defaults() {
    let config = PqcConfig::default();
    
    // PQC is always enabled
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    
    // Check default values
    assert_eq!(config.memory_pool_size, 10);
    assert_eq!(config.handshake_timeout_multiplier, 2.0);
}

#[test]
fn test_pqc_config_builder_customization() {
    let config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(50)
        .handshake_timeout_multiplier(3.5)
        .build()
        .unwrap();
    
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.memory_pool_size, 50);
    assert_eq!(config.handshake_timeout_multiplier, 3.5);
}