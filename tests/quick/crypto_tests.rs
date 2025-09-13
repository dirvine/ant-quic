//! Quick cryptography tests

use std::time::Duration;

#[test]
fn test_basic_crypto_operations() {
    super::utils::assert_duration(Duration::from_millis(100), || {
        // Basic crypto operations are tested in unit tests
        // This is a placeholder for quick crypto tests
        // Placeholder test - implementation pending
    });
}

#[test]
fn test_key_generation_speed() {
    super::utils::assert_duration(Duration::from_millis(200), || {
        // Test that key generation is reasonably fast
        use ant_quic::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;
        let _keypair = generate_ml_dsa_keypair();
        // Test completed - key generated successfully
    });
}
