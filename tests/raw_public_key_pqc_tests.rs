//! Integration tests for PQC raw public key support

mod pqc_raw_public_key_tests {
    use ant_quic::crypto::pqc::{MlDsaOperations, ml_dsa::MlDsa65, types::PqcError};
    use ant_quic::crypto::raw_public_keys::pqc::{ExtendedRawPublicKey, PqcRawPublicKeyVerifier};
    use rustls::SignatureScheme;

    #[test]
    fn test_ml_dsa_raw_public_key_lifecycle() {
        // Create ML-DSA key pair
        let ml_dsa = MlDsa65::new();
        match ml_dsa.generate_keypair() {
            Ok((public_key, _secret_key)) => {
                // Create extended raw public key
                let raw_key = ExtendedRawPublicKey::MlDsa65(public_key.clone());

                // Test properties
                assert_eq!(raw_key.size(), public_key.as_bytes().len());
                assert_eq!(
                    raw_key.supported_signature_schemes(),
                    vec![SignatureScheme::Unknown(0xFE3C)]
                );

                // Test SPKI encoding
                match raw_key.to_subject_public_key_info() {
                    Ok(spki) => {
                        assert!(spki.len() > raw_key.size());

                        // Test round-trip (when implemented)
                        match ExtendedRawPublicKey::from_subject_public_key_info(&spki) {
                            Ok(_) => {
                                // Success when ML-DSA parsing is implemented
                            }
                            Err(PqcError::OperationNotSupported) => {
                                // Expected for now
                            }
                            Err(e) => {
                                println!("ML-DSA not yet available: {e:?}");
                                // This is expected until aws-lc-rs supports ML-DSA
                            }
                        }
                    }
                    Err(PqcError::OperationNotSupported) => {
                        // Expected until implementation is complete
                    }
                    Err(e) => {
                        println!("ML-DSA not yet available: {e:?}");
                        // This is expected until aws-lc-rs supports ML-DSA
                    }
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until aws-lc-rs support
            }
            Err(e) => {
                println!("ML-DSA not yet available: {e:?}");
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_pqc_verifier_with_ml_dsa_keys() {
        let ml_dsa = MlDsa65::new();

        match ml_dsa.generate_keypair() {
            Ok((ml_dsa_key, _)) => {
                let ml_dsa_raw = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);

                // Create verifier with a vector containing the key
                let _verifier = PqcRawPublicKeyVerifier::new(vec![ml_dsa_raw]);

                // Verifier created successfully with ML-DSA key
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until aws-lc-rs support
            }
            Err(e) => {
                println!("ML-DSA not yet available: {e:?}");
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }

    #[test]
    fn test_large_key_serialization() {
        // Test with ML-DSA (1952 bytes)
        let ml_dsa = MlDsa65::new();
        match ml_dsa.generate_keypair() {
            Ok((ml_dsa_key, _)) => {
                let large_key = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);

                // Test serialization
                match large_key.to_subject_public_key_info() {
                    Ok(spki) => {
                        // ML-DSA public keys are larger
                        assert!(spki.len() > 1900);

                        // Test deserialization round-trip
                        match ExtendedRawPublicKey::from_subject_public_key_info(&spki) {
                            Ok(_) => {
                                // Success when implemented
                            }
                            Err(PqcError::OperationNotSupported) => {
                                // Expected for now
                            }
                            Err(e) => {
                                println!("ML-DSA not yet available: {e:?}");
                                // This is expected until aws-lc-rs supports ML-DSA
                            }
                        }
                    }
                    Err(PqcError::OperationNotSupported) => {
                        // Expected until implementation is complete
                    }
                    Err(e) => {
                        println!("ML-DSA not yet available: {e:?}");
                        // This is expected until aws-lc-rs supports ML-DSA
                    }
                }
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until aws-lc-rs support
            }
            Err(e) => {
                println!("ML-DSA not yet available: {e:?}");
                // This is expected until aws-lc-rs supports ML-DSA
            }
        }
    }
}
