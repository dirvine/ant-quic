//! Example showing the migration to full PQC
//!
//! ant-quic has completed the migration to full post-quantum cryptography.
//! This example documents the transition for users upgrading from earlier versions.

fn main() {
    println!("=== Migration to Full PQC Complete ===\n");
    
    println!("ant-quic has migrated from hybrid to full post-quantum cryptography.\n");
    
    println!("Previous (Hybrid) Architecture:");
    println!("  • Ed25519 + ML-DSA-65 for signatures");
    println!("  • X25519 + ML-KEM-768 for key exchange");
    println!("  • Configurable hybrid preferences");
    println!();
    
    println!("Current (Full PQC) Architecture:");
    println!("  • ML-DSA-65 only for signatures");
    println!("  • ML-KEM-768 only for key exchange");
    println!("  • No hybrid modes available");
    println!();
    
    println!("Migration Notes:");
    println!("  • The 'pqc' feature flag is no longer needed (PQC is always enabled)");
    println!("  • HybridPreference and PqcMode enums have been removed");
    println!("  • All Ed25519/X25519 functionality has been removed");
    println!("  • Key sizes have increased:");
    println!("    - Public keys: 32 bytes → 1952 bytes (ML-DSA-65)");
    println!("    - Signatures: 64 bytes → 3309 bytes (ML-DSA-65)");
    println!();
    
    println!("For updated examples, see:");
    println!("  • examples/ml_kem_usage.rs");
    println!("  • examples/ml_dsa_usage.rs");
    println!("  • examples/pqc_basic.rs");
}