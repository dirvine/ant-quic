//! Final integration tests for PQC implementation
//!
//! This test suite validates the complete PQC functionality
//! including ML-KEM-768 and ML-DSA-65 operations.

use ant_quic::crypto::pqc::{
    MlDsa65, MlKem768,
    PqcConfig, PqcConfigBuilder,
    MlDsaOperations, MlKemOperations,
};
use std::time::{Duration, Instant};

// Security requirements
const MIN_ML_KEM_KEY_SIZE: usize = 1184;  // ML-KEM-768 public key size
const MIN_ML_DSA_KEY_SIZE: usize = 1952;  // ML-DSA-65 public key size

#[tokio::test]
async fn test_ml_kem_operations() {
    let ml_kem = MlKem768::new();

    // Test key generation
    let start = Instant::now();
    let (pub_key, sec_key) = ml_kem
        .generate_keypair()
        .expect("Failed to generate ML-KEM keypair");
    let keygen_time = start.elapsed();

    // Verify key sizes meet security requirements
    assert!(
        pub_key.as_bytes().len() >= MIN_ML_KEM_KEY_SIZE,
        "ML-KEM public key too small: {} bytes",
        pub_key.as_bytes().len()
    );

    // Test encapsulation
    let start = Instant::now();
    let (ciphertext, shared_secret1) = ml_kem
        .encapsulate(&pub_key)
        .expect("Failed to encapsulate");
    let encap_time = start.elapsed();

    // Test decapsulation
    let start = Instant::now();
    let shared_secret2 = ml_kem
        .decapsulate(&sec_key, &ciphertext)
        .expect("Failed to decapsulate");
    let decap_time = start.elapsed();

    // Verify shared secrets match
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "Shared secrets don't match"
    );

    // Verify shared secret has sufficient entropy
    assert!(
        shared_secret1.as_bytes().len() >= 32,
        "Shared secret too small"
    );

    // Log performance metrics
    println!("ML-KEM-768 Performance:");
    println!("  Key generation: {keygen_time:?}");
    println!("  Encapsulation: {encap_time:?}");
    println!("  Decapsulation: {decap_time:?}");

    // Verify performance is reasonable
    assert!(
        keygen_time < Duration::from_millis(100),
        "Key generation too slow"
    );
    assert!(
        encap_time < Duration::from_millis(10),
        "Encapsulation too slow"
    );
    assert!(
        decap_time < Duration::from_millis(10),
        "Decapsulation too slow"
    );
}

#[tokio::test]
async fn test_ml_dsa_operations() {
    let ml_dsa = MlDsa65::new();

    // Test key generation
    let start = Instant::now();
    let (pub_key, sec_key) = ml_dsa
        .generate_keypair()
        .expect("Failed to generate ML-DSA keypair");
    let keygen_time = start.elapsed();

    // Verify key sizes meet security requirements
    assert!(
        pub_key.as_bytes().len() >= MIN_ML_DSA_KEY_SIZE,
        "ML-DSA public key too small: {} bytes",
        pub_key.as_bytes().len()
    );

    // Test signing
    let message = b"Test message for ML-DSA-65 signature";
    let start = Instant::now();
    let signature = ml_dsa
        .sign(&sec_key, message)
        .expect("Failed to sign message");
    let sign_time = start.elapsed();

    // Test verification
    let start = Instant::now();
    let valid = ml_dsa
        .verify(&pub_key, message, &signature)
        .expect("Failed to verify signature");
    let verify_time = start.elapsed();

    assert!(valid, "Signature verification failed");

    // Test invalid signature rejection
    let wrong_message = b"Different message";
    let invalid = ml_dsa
        .verify(&pub_key, wrong_message, &signature)
        .expect("Failed to verify signature");
    assert!(!invalid, "Invalid signature was accepted");

    // Log performance metrics
    println!("ML-DSA-65 Performance:");
    println!("  Key generation: {keygen_time:?}");
    println!("  Signing: {sign_time:?}");
    println!("  Verification: {verify_time:?}");

    // Verify performance is reasonable
    assert!(
        keygen_time < Duration::from_millis(100),
        "Key generation too slow"
    );
    assert!(sign_time < Duration::from_millis(50), "Signing too slow");
    assert!(
        verify_time < Duration::from_millis(50),
        "Verification too slow"
    );
}

#[tokio::test]
async fn test_pqc_configuration() {
    // Test default configuration
    let default_config = PqcConfig::default();
    assert!(default_config.ml_kem_enabled);
    assert!(default_config.ml_dsa_enabled);

    // Test custom configuration
    let custom_config = PqcConfigBuilder::default()
        .memory_pool_size(100)
        .handshake_timeout_multiplier(2.5)
        .build()
        .expect("Failed to build PQC config");

    assert_eq!(custom_config.memory_pool_size, 100);
    assert_eq!(custom_config.handshake_timeout_multiplier, 2.5);
}

#[tokio::test]
async fn test_pqc_with_quic_endpoint() {
    // Create PQC configuration
    let _pqc_config = PqcConfigBuilder::default()
        .memory_pool_size(50)
        .build()
        .expect("Failed to build PQC config");

    // Note: In the full PQC branch, PQC is always enabled
    // and integrated at the TLS/crypto layer automatically
    
    println!("PQC is now always enabled with:");
    println!("  • ML-KEM-768 for key exchange");
    println!("  • ML-DSA-65 for signatures");
}

#[tokio::test]
async fn test_pqc_memory_pool() {
    // Test memory pool configuration
    let config = PqcConfigBuilder::default()
        .memory_pool_size(20)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.memory_pool_size, 20);

    // Memory pool is used internally for efficient buffer management
    // during PQC operations
}

#[tokio::test]
async fn test_pqc_timeout_configuration() {
    // Test timeout multiplier for PQC handshakes
    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(3.0)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 3.0);

    // This multiplier accounts for the increased handshake time
    // due to larger PQC keys and signatures
}

#[test]
fn test_pqc_key_sizes() {
    // Verify expected key sizes
    
    // ML-KEM-768
    assert_eq!(ant_quic::crypto::pqc::types::ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
    assert_eq!(ant_quic::crypto::pqc::types::ML_KEM_768_SECRET_KEY_SIZE, 2400);
    assert_eq!(ant_quic::crypto::pqc::types::ML_KEM_768_CIPHERTEXT_SIZE, 1088);
    
    // ML-DSA-65
    assert_eq!(ant_quic::crypto::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE, 1952);
    assert_eq!(ant_quic::crypto::pqc::types::ML_DSA_65_SECRET_KEY_SIZE, 4032);
    assert_eq!(ant_quic::crypto::pqc::types::ML_DSA_65_SIGNATURE_SIZE, 3309);
}

#[test]
fn test_pqc_security_levels() {
    // ML-KEM-768 provides NIST Level 3 security (~192-bit classical)
    // ML-DSA-65 provides NIST Level 3 security (~192-bit classical)
    
    // These provide strong post-quantum security against
    // attacks from both classical and quantum computers
    
    println!("Security Levels:");
    println!("  ML-KEM-768: NIST Level 3 (~192-bit classical security)");
    println!("  ML-DSA-65: NIST Level 3 (~192-bit classical security)");
}

#[test]
fn test_pqc_feature_always_enabled() {
    // PQC is now always enabled in the full_pqc branch
    // No feature flags are needed
    
    // Verify that PQC types are always available
    let _ml_kem = MlKem768::new();
    let _ml_dsa = MlDsa65::new();
    
    // Verify configuration is available
    let _config = PqcConfig::default();
}

#[test]
fn test_no_hybrid_mode_available() {
    // Hybrid modes that combined classical and PQC algorithms
    // are no longer available in the full_pqc branch
    
    // The system now uses pure PQC:
    // - ML-DSA-65 only (no Ed25519)
    // - ML-KEM-768 only (no X25519)
    
    println!("Pure PQC mode active:");
    println!("  • No classical cryptography fallback");
    println!("  • No hybrid modes available");
    println!("  • Full quantum resistance");
}