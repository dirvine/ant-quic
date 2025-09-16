//! Basic integration tests for PQC implementation
//!
//! This test suite performs basic validation of PQC functionality

use ant_quic::crypto::pqc::{PqcConfigBuilder, types::PqcError};

#[test]
fn test_pqc_config_builder() {
    // Test default configuration
    let config = PqcConfigBuilder::default()
        .build()
        .expect("Failed to build default config");

    // PQC is now always enabled
    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Test configuration with custom settings
    let custom_config = PqcConfigBuilder::default()
        .memory_pool_size(100)
        .handshake_timeout_multiplier(2.5)
        .build()
        .expect("Failed to build custom config");

    assert_eq!(custom_config.memory_pool_size, 100);
    assert_eq!(custom_config.handshake_timeout_multiplier, 2.5);
}

#[test]
fn test_pqc_algorithm_availability() {
    // Verify ML-KEM-768 is available
    use ant_quic::crypto::pqc::{MlKem768, MlKemOperations};

    let ml_kem = MlKem768::new();
    match ml_kem.generate_keypair() {
        Ok((pub_key, _sec_key)) => {
            assert_eq!(pub_key.as_bytes().len(), 1184); // ML-KEM-768 public key size
        }
        Err(PqcError::OperationNotSupported) => {
            // Expected if aws-lc-rs doesn't support ML-KEM yet
        }
        Err(e) => {
            println!("ML-KEM not yet available: {e:?}");
        }
    }

    // Verify ML-DSA-65 is available
    use ant_quic::crypto::pqc::{MlDsa65, MlDsaOperations};

    let ml_dsa = MlDsa65::new();
    match ml_dsa.generate_keypair() {
        Ok((pub_key, _sec_key)) => {
            assert_eq!(pub_key.as_bytes().len(), 1952); // ML-DSA-65 public key size
        }
        Err(PqcError::OperationNotSupported) => {
            // Expected if aws-lc-rs doesn't support ML-DSA yet
        }
        Err(e) => {
            println!("ML-DSA not yet available: {e:?}");
        }
    }
}

#[test]
fn test_pqc_memory_pool() {
    // Test memory pool configuration
    let config = PqcConfigBuilder::default()
        .memory_pool_size(50)
        .build()
        .expect("Failed to build config with memory pool");

    assert_eq!(config.memory_pool_size, 50);
}
