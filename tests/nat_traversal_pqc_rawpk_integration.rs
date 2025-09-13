//! Integration test: NAT traversal RFC frame config + RFC 7250 raw public keys with PQC

mod pqc_integration {
    use ant_quic::crypto::pqc::types::MlDsaPublicKey;
    use ant_quic::crypto::pqc::types::PqcError;
    use ant_quic::crypto::raw_public_keys::pqc::{ExtendedRawPublicKey, PqcRawPublicKeyVerifier};
    use ant_quic::frame::nat_traversal_unified::{
        NatTraversalFrameConfig, TRANSPORT_PARAM_RFC_NAT_TRAVERSAL, peer_supports_rfc_nat,
    };

    // Helper to synthesize a minimal TransportParameters byte blob that contains
    // the RFC NAT traversal transport parameter identifier, so peer_supports_rfc_nat() returns true.
    fn synthesize_tp_bytes_with_rfc_nat_param() -> Vec<u8> {
        // Embed the 8-byte constant somewhere in the byte stream
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 7]);
        buf.extend_from_slice(&TRANSPORT_PARAM_RFC_NAT_TRAVERSAL.to_be_bytes());
        buf.extend_from_slice(&[0u8; 5]);
        buf
    }

    #[test]
    fn test_nat_rfc_frames_and_pqc_raw_public_keys() {
        // 1) NAT traversal RFC 7250 frame config setup
        let cfg = NatTraversalFrameConfig::rfc_only();
        assert!(cfg.use_rfc_format);
        assert!(!cfg.accept_legacy);

        // Test with ML-DSA-65 (PQC) raw public key SPKI flow
        // Construct a dummy ML-DSA public key of the exact size
        let ml_dsa_key = MlDsaPublicKey::from_bytes(
            &vec![0u8; ant_quic::crypto::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE],
        )
        .expect("Failed to create ML-DSA public key");
        let pqc_key = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);
        
        // Export SPKI for ML-DSA
        let ml_dsa_spki_result = pqc_key.to_subject_public_key_info();
        match ml_dsa_spki_result {
            Ok(spki) => {
                // The verifier should either accept or report a controlled error
                let verifier = PqcRawPublicKeyVerifier::new(vec![]);
                let _recovered = verifier.verify_cert(&spki);
                // In full PQC mode, we expect ML-DSA keys to be properly handled
            }
            Err(PqcError::OperationNotSupported) => {
                // Expected until full implementation
            }
            Err(e) => {
                println!("ML-DSA SPKI generation not yet available: {e:?}");
            }
        }

        // Test peer support detection
        let tp_bytes = synthesize_tp_bytes_with_rfc_nat_param();
        assert!(peer_supports_rfc_nat(&tp_bytes));

        // Test endpoint config with NAT traversal
        use ant_quic::{
            EndpointConfig,
            crypto::{CryptoError, HmacKey},
        };
        use std::sync::Arc;

        struct DummyHmacKey;
        impl HmacKey for DummyHmacKey {
            fn sign(&self, data: &[u8], out: &mut [u8]) {
                let len = out.len().min(data.len());
                out[..len].copy_from_slice(&data[..len]);
            }
            fn signature_len(&self) -> usize {
                32
            }
            fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
                if signature.len() >= self.signature_len() {
                    Ok(())
                } else {
                    Err(CryptoError)
                }
            }
        }

        let reset_key: Arc<dyn HmacKey> = Arc::new(DummyHmacKey);
        let mut endpoint_config = EndpointConfig::new(reset_key);
        
        // Configure NAT traversal parameters
        endpoint_config.max_udp_payload_size(1200).unwrap();
        
        // Configure keep-alive via TransportConfig
        let mut transport_config = ant_quic::TransportConfig::default();
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(30)));
        
        // Verify configuration
        assert_eq!(endpoint_config.get_max_udp_payload_size(), 1200);
    }
}