//! Example demonstrating Post-Quantum Cryptography configuration in ant-quic
//!
//! This example shows the available configuration options for PQC.
//! Note: PQC is now always enabled - no hybrid modes are available.

use ant_quic::crypto::pqc::{PqcConfig, PqcConfigBuilder};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== ant-quic PQC Configuration Demo ===\n");

    println!("ant-quic has transitioned to full post-quantum cryptography.");
    println!("PQC is always enabled with ML-DSA-65 and ML-KEM-768.\n");

    // Example 1: Default configuration
    default_config()?;

    // Example 2: Custom memory pool configuration
    custom_memory_pool()?;

    // Example 3: Custom timeout configuration
    custom_timeout()?;

    // Example 4: Production configuration
    production_config()?;

    println!("\n✅ All PQC configurations demonstrated successfully!");
    Ok(())
}

fn default_config() -> Result<(), Box<dyn Error>> {
    println!("📋 Example 1: Default PQC Configuration");
    println!("----------------------------------------");

    let pqc_config = PqcConfig::default();

    println!("Configuration:");
    println!("   ML-KEM-768: {}", pqc_config.ml_kem_enabled);
    println!("   ML-DSA-65: {}", pqc_config.ml_dsa_enabled);
    println!(
        "   Memory Pool Size: {} buffers",
        pqc_config.memory_pool_size
    );
    println!(
        "   Handshake Timeout Multiplier: {:.1}x",
        pqc_config.handshake_timeout_multiplier
    );
    println!();

    Ok(())
}

fn custom_memory_pool() -> Result<(), Box<dyn Error>> {
    println!("📋 Example 2: Custom Memory Pool Configuration");
    println!("-----------------------------------------------");

    let pqc_config = PqcConfigBuilder::default().memory_pool_size(100).build()?;

    println!("Configuration:");
    println!(
        "   Memory Pool Size: {} buffers",
        pqc_config.memory_pool_size
    );
    println!("   (Useful for high-connection servers)");
    println!();

    Ok(())
}

fn custom_timeout() -> Result<(), Box<dyn Error>> {
    println!("📋 Example 3: Custom Timeout Configuration");
    println!("-------------------------------------------");

    let pqc_config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(3.0)
        .build()?;

    println!("Configuration:");
    println!(
        "   Handshake Timeout Multiplier: {:.1}x",
        pqc_config.handshake_timeout_multiplier
    );
    println!("   (Useful for high-latency networks)");
    println!();

    Ok(())
}

fn production_config() -> Result<(), Box<dyn Error>> {
    println!("📋 Example 4: Production Configuration");
    println!("---------------------------------------");

    let pqc_config = PqcConfigBuilder::default()
        .memory_pool_size(500) // Large pool for many connections
        .handshake_timeout_multiplier(2.5) // Moderate timeout increase
        .build()?;

    println!("Configuration:");
    println!("   ML-KEM-768: {}", pqc_config.ml_kem_enabled);
    println!("   ML-DSA-65: {}", pqc_config.ml_dsa_enabled);
    println!(
        "   Memory Pool Size: {} buffers",
        pqc_config.memory_pool_size
    );
    println!(
        "   Handshake Timeout Multiplier: {:.1}x",
        pqc_config.handshake_timeout_multiplier
    );
    println!();

    println!("📝 Notes:");
    println!("   • PQC is always enabled (no classical-only mode)");
    println!("   • ML-DSA-65 public keys: 1952 bytes");
    println!("   • ML-DSA-65 signatures: 3309 bytes");
    println!("   • ML-KEM-768 public keys: 1184 bytes");
    println!("   • ML-KEM-768 ciphertexts: 1088 bytes");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_examples() {
        assert!(default_config().is_ok());
        assert!(custom_memory_pool().is_ok());
        assert!(custom_timeout().is_ok());
        assert!(production_config().is_ok());
    }
}
