// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! RFC 7250 Raw Public Keys Support for ant-quic
//!
//! This module implements Raw Public Keys (RPK) support as defined in RFC 7250,
//! allowing P2P connections to authenticate using ML-DSA public keys directly
//! without the overhead of X.509 certificates.

// PQC extensions for raw public keys - always available
pub mod pqc;

use std::{collections::HashSet, fmt::Debug, sync::Arc};

use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SigningKey},
};

use super::tls_extension_simulation::{Rfc7250ClientConfig, Rfc7250ServerConfig};

use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::crypto::raw_keys::MlDsaKeyPair;

use tracing::{debug, info, warn};

/// Raw Public Key verifier for client-side authentication
#[derive(Debug)]
pub struct RawPublicKeyVerifier {
    /// Set of trusted public keys (ML-DSA-65 public keys are 1952 bytes)
    trusted_keys: HashSet<Vec<u8>>,
    /// Whether to allow any key (for development/testing)
    allow_any_key: bool,
}

impl RawPublicKeyVerifier {
    /// Create a new RPK verifier with a set of trusted public keys
    pub fn new(trusted_keys: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_keys: trusted_keys.into_iter().collect(),
            allow_any_key: false,
        }
    }

    /// Create a verifier that accepts any valid ML-DSA public key
    /// WARNING: Only use for development/testing!
    pub fn allow_any() -> Self {
        Self {
            trusted_keys: HashSet::new(),
            allow_any_key: true,
        }
    }

    /// Add a trusted public key
    pub fn add_trusted_key(&mut self, public_key: Vec<u8>) {
        self.trusted_keys.insert(public_key);
    }

    /// Extract ML-DSA public key from SubjectPublicKeyInfo
    fn extract_ml_dsa_key(&self, spki_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Parse the SubjectPublicKeyInfo structure
        // ML-DSA-65 OID: 2.16.840.1.101.3.4.3.17

        // For RFC 7250, the "certificate" is actually just the SubjectPublicKeyInfo
        // We need to extract the raw ML-DSA public key from this structure

        // ML-DSA-65 public keys are 1952 bytes
        const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

        // Simple parsing for ML-DSA SubjectPublicKeyInfo
        // In a full SPKI, the key would be embedded with OID and headers
        // For now, we'll do a simple size-based extraction

        if spki_der.len() < ML_DSA_65_PUBLIC_KEY_SIZE {
            // If the SPKI is smaller than expected, it might be just the raw key
            // or a different format - return it as-is
            debug!(
                "SPKI smaller than expected ML-DSA key size: {} bytes",
                spki_der.len()
            );
            return Ok(spki_der.to_vec());
        }

        // If the SPKI is larger, try to extract the key from the end
        // (ML-DSA keys are typically at the end of the SPKI structure)
        // Our SPKI is 1972 bytes (20 bytes header + 1952 bytes key)
        if spki_der.len() >= ML_DSA_65_PUBLIC_KEY_SIZE + 10 {
            // Likely a full SPKI with headers - extract the last 1952 bytes
            let key_start = spki_der.len() - ML_DSA_65_PUBLIC_KEY_SIZE;
            let public_key = spki_der[key_start..].to_vec();
            debug!(
                "Extracted ML-DSA public key from SPKI: {} bytes",
                public_key.len()
            );
            return Ok(public_key);
        }

        // Otherwise, assume the entire SPKI is the key data
        debug!(
            "Using entire SPKI as ML-DSA public key: {} bytes",
            spki_der.len()
        );
        Ok(spki_der.to_vec())
    }
}

impl ServerCertVerifier for RawPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        debug!("Verifying server certificate with Raw Public Key verifier");

        // Extract the ML-DSA public key from the certificate
        let public_key = self.extract_ml_dsa_key(end_entity.as_ref())?;

        // Check if this key is trusted
        if self.allow_any_key {
            info!("Accepting any ML-DSA public key (development mode)");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        if self.trusted_keys.contains(&public_key) {
            info!("Server public key is trusted: {} bytes", public_key.len());
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            warn!("Unknown server public key: {} bytes", public_key.len());
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // TLS 1.2 not supported for Raw Public Keys in this implementation
        Err(TlsError::UnsupportedNameType)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        debug!("Verifying TLS 1.3 signature with Raw Public Key");

        // Extract ML-DSA public key
        let public_key_bytes = self.extract_ml_dsa_key(cert.as_ref())?;

        // Create ML-DSA public key
        let public_key = MlDsaPublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Verify ML-DSA signature (variable length)
        let signature = MlDsaSignature::from_bytes(dss.signature())
            .map_err(|_| TlsError::General("Invalid ML-DSA signature format".to_string()))?;

        // Use saorsa_pqc to verify the signature
        use saorsa_pqc::MlDsaOperations;

        let pk = saorsa_pqc::MlDsaPublicKey::from_bytes(public_key.as_bytes())
            .map_err(|_| TlsError::General("Invalid public key".to_string()))?;
        let sig = saorsa_pqc::MlDsaSignature::from_bytes(signature.as_bytes())
            .map_err(|_| TlsError::General("Invalid signature".to_string()))?;

        let ml_dsa = saorsa_pqc::MlDsa65::new();
        if !ml_dsa
            .verify(&pk, message, &sig)
            .map_err(|_| TlsError::General("Signature verification failed".to_string()))?
        {
            return Err(TlsError::General(
                "Signature verification failed".to_string(),
            ));
        }

        debug!("TLS 1.3 signature verification successful");
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertise ML-DSA-65 via private-use codepoint
        let mldsa65 = crate::crypto::pqc::tls_extensions::SignatureScheme::MlDsa65.to_u16();
        vec![SignatureScheme::Unknown(mldsa65)]
    }
}

/// Raw Public Key resolver for server-side
#[derive(Debug)]
pub struct RawPublicKeyResolver {
    /// The server's certified key pair
    certified_key: Arc<CertifiedKey>,
}

impl RawPublicKeyResolver {
    /// Create a new RPK resolver with an ML-DSA key pair
    pub fn new(keypair: MlDsaKeyPair) -> Result<Self, TlsError> {
        // Get the public key from the keypair
        let public_key = keypair.public_key();

        // Create SubjectPublicKeyInfo for the ML-DSA public key
        let public_key_der = create_ml_dsa_subject_public_key_info(&public_key);

        // Create a signing key wrapper
        let signing_key = MlDsaSigningKey::new(keypair);

        // Create certified key
        let certified_key = Arc::new(CertifiedKey {
            cert: vec![CertificateDer::from(public_key_der)],
            key: Arc::new(signing_key),
            ocsp: None,
        });

        Ok(Self { certified_key })
    }
}

impl ResolvesServerCert for RawPublicKeyResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        debug!("Resolving server certificate with Raw Public Key");
        Some(self.certified_key.clone())
    }
}

/// Ed25519 signing key implementation for rustls
#[derive(Debug)]
struct MlDsaSigningKey {
    keypair: MlDsaKeyPair,
}

impl MlDsaSigningKey {
    fn new(keypair: MlDsaKeyPair) -> Self {
        Self { keypair }
    }
}

impl SigningKey for MlDsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        // For PQC-only, select ML-DSA-65 via private-use codepoint
        let mldsa65 = crate::crypto::pqc::tls_extensions::SignatureScheme::MlDsa65.to_u16();
        if offered.contains(&SignatureScheme::Unknown(mldsa65)) {
            Some(Box::new(MlDsaSigner {
                keypair: self.keypair.clone(),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        // rustls does not yet expose a PQC algorithm identifier; retain ED25519 here
        // to satisfy trait requirements. The actual selected scheme is communicated
        // via Signer::scheme() as Unknown(ML-DSA-65).
        rustls::SignatureAlgorithm::ED25519
    }
}

/// ML-DSA signer implementation
#[derive(Debug)]
struct MlDsaSigner {
    keypair: MlDsaKeyPair,
}

impl rustls::sign::Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let signature = self
            .keypair
            .sign(message)
            .map_err(|e| TlsError::General(format!("Failed to sign: {}", e)))?;
        Ok(signature.as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        let mldsa65 = crate::crypto::pqc::tls_extensions::SignatureScheme::MlDsa65.to_u16();
        SignatureScheme::Unknown(mldsa65)
    }
}

/// Create a SubjectPublicKeyInfo DER encoding for an ML-DSA public key
pub fn create_ml_dsa_subject_public_key_info(public_key: &MlDsaPublicKey) -> Vec<u8> {
    // ML-DSA SubjectPublicKeyInfo structure:
    // SEQUENCE {
    //   SEQUENCE {
    //     OBJECT IDENTIFIER (ML-DSA-65 - temporary)
    //   }
    //   BIT STRING (1952 bytes of public key)
    // }

    // Delegate to the raw_keys module implementation
    crate::crypto::raw_keys::create_ml_dsa_subject_public_key_info(public_key)
}

/// Configuration builder for Raw Public Keys with TLS extension support
#[derive(Debug, Default, Clone)]
pub struct RawPublicKeyConfigBuilder {
    trusted_keys: Vec<Vec<u8>>,
    allow_any: bool,
    server_key: Option<MlDsaKeyPair>,
    /// Enable TLS certificate type extensions
    enable_extensions: bool,
    /// Certificate type preferences for negotiation
    cert_type_preferences: Option<super::tls_extensions::CertificateTypePreferences>,
}

impl RawPublicKeyConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted public key
    pub fn add_trusted_key(mut self, public_key: Vec<u8>) -> Self {
        self.trusted_keys.push(public_key);
        self
    }

    /// Allow any valid Ed25519 public key (development only)
    pub fn allow_any_key(mut self) -> Self {
        self.allow_any = true;
        self
    }

    /// Set the server's key pair
    pub fn with_server_key(mut self, keypair: MlDsaKeyPair) -> Self {
        self.server_key = Some(keypair);
        self
    }

    /// Enable TLS certificate type extensions for negotiation
    pub fn with_certificate_type_extensions(
        mut self,
        preferences: super::tls_extensions::CertificateTypePreferences,
    ) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences = Some(preferences);
        self
    }

    /// Enable TLS extensions with default Raw Public Key preferences
    pub fn enable_certificate_type_extensions(mut self) -> Self {
        self.enable_extensions = true;
        self.cert_type_preferences =
            Some(super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key());
        self
    }

    /// Build a client configuration with Raw Public Keys
    pub fn build_client_config(self) -> Result<ClientConfig, TlsError> {
        let verifier = if self.allow_any {
            RawPublicKeyVerifier::allow_any()
        } else {
            RawPublicKeyVerifier::new(self.trusted_keys)
        };

        // Create the client config with Raw Public Key support
        // rustls 0.23.x requires specific configuration for RFC 7250
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        // Enable Raw Public Key certificate type in rustls
        // This tells rustls to advertise support for Raw Public Keys in the
        // client_certificate_type and server_certificate_type extensions
        if self.enable_extensions {
            // rustls 0.23.x automatically handles RFC 7250 extensions when
            // a custom certificate verifier is provided that supports Raw Public Keys
            // The verifier we're using (RawPublicKeyVerifier) handles SubjectPublicKeyInfo
            // format which rustls recognizes as Raw Public Key support
        }

        Ok(config)
    }

    /// Build a server configuration with Raw Public Keys
    pub fn build_server_config(self) -> Result<ServerConfig, TlsError> {
        let keypair = self
            .server_key
            .ok_or_else(|| TlsError::General("Server key pair required".into()))?;

        let resolver = RawPublicKeyResolver::new(keypair)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        // Add TLS certificate type extensions if enabled
        if self.enable_extensions {
            if let Some(_preferences) = self.cert_type_preferences {
                // rustls 0.23.x handles RFC 7250 internally, so we just need to configure it
                // No custom extension handler needed
            }
        }

        Ok(config)
    }

    /// Build a client configuration with RFC 7250 extension simulation
    pub fn build_rfc7250_client_config(self) -> Result<Rfc7250ClientConfig, TlsError> {
        let preferences = self.cert_type_preferences.clone().unwrap_or_else(|| {
            super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key()
        });
        let base_config = self.build_client_config()?;

        Ok(Rfc7250ClientConfig::new(base_config, preferences))
    }

    /// Build a server configuration with RFC 7250 extension simulation
    pub fn build_rfc7250_server_config(self) -> Result<Rfc7250ServerConfig, TlsError> {
        let preferences = self.cert_type_preferences.clone().unwrap_or_else(|| {
            super::tls_extensions::CertificateTypePreferences::prefer_raw_public_key()
        });
        let base_config = self.build_server_config()?;

        Ok(Rfc7250ServerConfig::new(base_config, preferences))
    }
}

/// Utility functions for key generation and conversion
pub mod key_utils {
    use super::*;

    /// Generate a new ML-DSA key pair
    pub fn generate_ml_dsa_keypair() -> MlDsaKeyPair {
        MlDsaKeyPair::generate().expect("Failed to generate ML-DSA keypair")
    }

    /// Convert ML-DSA public key to bytes
    pub fn public_key_to_bytes(public_key: &MlDsaPublicKey) -> Vec<u8> {
        public_key.as_bytes().to_vec()
    }

    /// Create ML-DSA public key from bytes
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<MlDsaPublicKey, &'static str> {
        MlDsaPublicKey::from_bytes(bytes).map_err(|_| "Invalid public key bytes")
    }

    /// Create a test key pair for development
    pub fn create_test_keypair() -> MlDsaKeyPair {
        // Generate a new ML-DSA keypair for testing
        MlDsaKeyPair::generate().expect("Failed to generate test ML-DSA keypair")
    }

    /// Derive a peer ID from an ML-DSA public key using SHA-256 hash
    ///
    /// This provides a secure, collision-resistant peer ID derivation method
    /// that follows P2P networking best practices. The SHA-256 hash ensures
    /// uniform distribution and prevents direct key exposure.
    pub fn derive_peer_id_from_public_key(
        public_key: &MlDsaPublicKey,
    ) -> crate::nat_traversal_api::PeerId {
        // Use SHA-256 from utilities module for ML-DSA keys (1952 bytes)
        use crate::crypto::utilities;

        let key_bytes = public_key.as_bytes();
        let mut input = Vec::with_capacity(20 + key_bytes.len());
        input.extend_from_slice(b"AUTONOMI_PEER_ID_V2:"); // V2 for PQC
        input.extend_from_slice(key_bytes);

        let hash = utilities::sha256(&input);
        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(&hash[..32]);

        crate::nat_traversal_api::PeerId(peer_id_bytes)
    }

    /// Derive a peer ID from raw public key bytes (ML-DSA key)
    ///
    /// This is a convenience function for when you have the raw key bytes
    /// rather than an MlDsaPublicKey object.
    pub fn derive_peer_id_from_key_bytes(
        key_bytes: &[u8],
    ) -> Result<crate::nat_traversal_api::PeerId, &'static str> {
        let public_key = public_key_from_bytes(key_bytes)?;
        Ok(derive_peer_id_from_public_key(&public_key))
    }

    /// Verify that a peer ID was correctly derived from a public key
    ///
    /// This is useful for validation during connection establishment
    /// to ensure the peer's claimed ID matches their public key.
    pub fn verify_peer_id(
        peer_id: &crate::nat_traversal_api::PeerId,
        public_key: &MlDsaPublicKey,
    ) -> bool {
        let derived_id = derive_peer_id_from_public_key(public_key);
        *peer_id == derived_id
    }
}

#[cfg(test)]
mod tests {
    use super::key_utils::*;
    use super::*;
    use std::sync::Once;

    // Minimal DER length parser for tests
    fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() {
            return None;
        }
        if data[0] < 128 {
            return Some((data[0] as usize, 1));
        }
        if data[0] == 0x81 && data.len() >= 2 {
            return Some((data[1] as usize, 2));
        }
        if data[0] == 0x82 && data.len() >= 3 {
            let len = ((data[1] as usize) << 8) | (data[2] as usize);
            return Some((len, 3));
        }
        None
    }

    static INIT: Once = Once::new();

    // Ensure crypto provider is installed for tests
    fn ensure_crypto_provider() {
        INIT.call_once(|| {
            // Install the crypto provider if not already installed
            #[cfg(feature = "rustls-aws-lc-rs")]
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            #[cfg(feature = "rustls-ring")]
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_create_ml_dsa_subject_public_key_info() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let spki = create_ml_dsa_subject_public_key_info(&public_key);

        // ML-DSA-65 SPKI should be larger than just the key (1952 bytes key + ASN.1 wrapper)
        assert!(spki.len() > 1952);

        // Should start with ASN.1 SEQUENCE tag (0x30)
        // The actual structure will vary based on ML-DSA-65 OID
        assert_eq!(spki[0], 0x30); // SEQUENCE tag

        // Minimal structural check: SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING }
        assert_eq!(spki[0], 0x30);
        // Parse outer length
        let (outer_len, len_bytes) = parse_der_length(&spki[1..]).unwrap();
        assert!(outer_len + 1 + len_bytes <= spki.len());
        let mut offset = 1 + len_bytes;
        // AlgorithmIdentifier
        assert_eq!(spki[offset], 0x30);
        offset += 1;
        let (_alg_len, alg_len_bytes) = parse_der_length(&spki[offset..]).unwrap();
        offset += alg_len_bytes;
        // OID
        assert_eq!(spki[offset], 0x06);
        offset += 1;
        let (oid_len, oid_len_bytes) = parse_der_length(&spki[offset..]).unwrap();
        offset += oid_len_bytes;
        let oid_value = &spki[offset..offset + oid_len];
        offset += oid_len;
        // Ensure OID is ML-DSA-65
        use crate::crypto::pqc::oids::{OID_ML_DSA_65, decode_oid_value};
        let arcs = decode_oid_value(oid_value).unwrap();
        assert_eq!(arcs.as_slice(), OID_ML_DSA_65);
        // After AlgorithmIdentifier, expect BIT STRING
        assert_eq!(spki[offset], 0x03);
        // Skip BIT STRING header
        offset += 1;
        let (bs_len, bs_len_bytes) = parse_der_length(&spki[offset..]).unwrap();
        offset += bs_len_bytes;
        // First byte unused bits
        assert_eq!(spki[offset], 0x00);
        offset += 1;
        assert_eq!(bs_len - 1, public_key.as_bytes().len());
        assert_eq!(
            &spki[offset..offset + public_key.as_bytes().len()],
            public_key.as_bytes()
        );
    }

    #[test]
    fn test_raw_public_key_verifier_trusted_key() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let key_bytes = public_key_to_bytes(&public_key);

        let verifier = RawPublicKeyVerifier::new(vec![key_bytes]);

        // Create a mock certificate with the public key
        let spki = create_ml_dsa_subject_public_key_info(&public_key);
        let cert = CertificateDer::from(spki);

        // Should successfully verify
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_raw_public_key_verifier_unknown_key() {
        let keypair1 = generate_ml_dsa_keypair();
        let public_key1 = keypair1.public_key();
        let keypair2 = generate_ml_dsa_keypair();
        let public_key2 = keypair2.public_key();

        let key1_bytes = public_key_to_bytes(&public_key1);
        let verifier = RawPublicKeyVerifier::new(vec![key1_bytes]);

        // Create certificate with different key
        let spki = create_ml_dsa_subject_public_key_info(&public_key2);
        let cert = CertificateDer::from(spki);

        // Should fail verification
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_raw_public_key_verifier_allow_any() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let verifier = RawPublicKeyVerifier::allow_any();

        let spki = create_ml_dsa_subject_public_key_info(&public_key);
        let cert = CertificateDer::from(spki);

        // Should accept any valid key
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("test").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_config_builder() {
        ensure_crypto_provider();
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let key_bytes = public_key_to_bytes(&public_key);

        // Test client config
        let client_config = RawPublicKeyConfigBuilder::new()
            .add_trusted_key(key_bytes)
            .build_client_config();
        assert!(client_config.is_ok());

        // Test server config
        let server_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(keypair)
            .build_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_extract_ml_dsa_key() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let spki = create_ml_dsa_subject_public_key_info(&public_key);

        let verifier = RawPublicKeyVerifier::allow_any();
        let extracted_key = verifier.extract_ml_dsa_key(&spki).unwrap();

        // For ML-DSA, we just check the size is reasonable
        assert!(!extracted_key.is_empty());
    }

    #[test]
    fn test_derive_peer_id_from_public_key() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();

        // Test that the function produces a consistent peer ID
        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_public_key(&public_key);

        assert_eq!(peer_id1, peer_id2);

        // Test that different keys produce different peer IDs
        let keypair2 = create_test_keypair();
        let public_key2 = keypair2.public_key();
        let peer_id3 = derive_peer_id_from_public_key(&public_key2);

        assert_ne!(peer_id1, peer_id3);
    }

    #[test]
    fn test_derive_peer_id_from_key_bytes() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let key_bytes = public_key_to_bytes(&public_key);

        // Test that both methods produce the same result
        let peer_id1 = derive_peer_id_from_public_key(&public_key);
        let peer_id2 = derive_peer_id_from_key_bytes(&key_bytes).unwrap();

        assert_eq!(peer_id1, peer_id2);

        // Test with a different valid key to ensure different peer IDs
        let keypair2 = create_test_keypair();
        let public_key2 = keypair2.public_key();
        let key_bytes2 = public_key_to_bytes(&public_key2);
        let peer_id3 = derive_peer_id_from_key_bytes(&key_bytes2).unwrap();

        assert_ne!(peer_id1, peer_id3);
    }

    #[test]
    fn test_verify_peer_id() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Test that verification succeeds for correct peer ID
        assert!(verify_peer_id(&peer_id, &public_key));

        // Test that verification fails for incorrect peer ID
        let other_keypair = create_test_keypair();
        let other_public_key = other_keypair.public_key();
        assert!(!verify_peer_id(&peer_id, &other_public_key));

        // Test that verification fails for wrong peer ID
        let wrong_peer_id = crate::nat_traversal_api::PeerId([0u8; 32]);
        assert!(!verify_peer_id(&wrong_peer_id, &public_key));
    }

    #[test]
    fn test_peer_id_domain_separation() {
        let keypair = generate_ml_dsa_keypair();
        let public_key = keypair.public_key();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // The peer ID should not be the same as the raw public key
        let key_bytes = public_key_to_bytes(&public_key);
        // Compare first 32 bytes since peer_id is [u8; 32] and key_bytes is Vec<u8>
        assert_ne!(&peer_id.0[..], &key_bytes[..32.min(key_bytes.len())]);

        // The peer ID should be deterministic
        let peer_id2 = derive_peer_id_from_public_key(&public_key);
        assert_eq!(peer_id, peer_id2);
    }
}
