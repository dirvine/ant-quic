//! Example demonstrating that hybrid mode is no longer available
//!
//! The ant-quic library has transitioned to full post-quantum cryptography.
//! Hybrid modes that combined classical and PQC algorithms are no longer supported.

fn main() {
    println!("=== Hybrid Mode Deprecated ===\n");
    
    println!("ant-quic has transitioned to full post-quantum cryptography.");
    println!("Hybrid modes (combining classical and PQC) are no longer available.\n");
    
    println!("The library now uses:");
    println!("  • ML-DSA-65 for signatures (replacing Ed25519)");
    println!("  • ML-KEM-768 for key exchange (replacing X25519)");
    println!();
    
    println!("For examples of using the pure PQC implementation, see:");
    println!("  • examples/ml_kem_usage.rs - ML-KEM key exchange");
    println!("  • examples/ml_dsa_usage.rs - ML-DSA signatures");
    println!("  • examples/pqc_basic.rs - Basic PQC usage");
}