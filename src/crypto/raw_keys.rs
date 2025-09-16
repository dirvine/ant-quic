// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Raw Public Key Support - PQC Only Implementation
//!
//! This module implements support for ML-DSA-65 keys in SubjectPublicKeyInfo format
//! as specified in RFC 7250, adapted for post-quantum cryptography.
//! It provides functionality for key generation, encoding, and verification
//! with a focus on quantum resistance.

// ML-DSA verification is done via saorsa_pqc directly
use crate::crypto::utilities;
use thiserror::Error;

/// Errors that can occur during raw public key operations
#[derive(Debug, Error)]
pub enum RawKeyError {
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("PQC error: {0}")]
    PqcError(String),
}

/// ML-DSA-65 key pair for authentication (PQC-only)
pub struct MlDsaKeyPair {
    public_key: crate::crypto::pqc::types::MlDsaPublicKey,
    secret_key: crate::crypto::pqc::types::MlDsaSecretKey,
}

impl Clone for MlDsaKeyPair {
    fn clone(&self) -> Self {
        // We need to re-generate from the secret key bytes
        Self::from_secret_key_bytes(self.secret_key.as_bytes())
            .expect("Cloning from valid secret key should not fail")
    }
}

impl std::fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("public_key", &"<ML-DSA-65 public key>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl MlDsaKeyPair {
    /// Generate a new random ML-DSA-65 key pair
    pub fn generate() -> Result<Self, RawKeyError> {
        use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey};
        use saorsa_pqc::MlDsaOperations;

        let ml_dsa = saorsa_pqc::MlDsa65::new();
        let (saorsa_pub_key, saorsa_sec_key) = ml_dsa
            .generate_keypair()
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        // Convert saorsa_pqc types to our wrapper types
        let public_key = MlDsaPublicKey::from_bytes(saorsa_pub_key.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;
        let secret_key = MlDsaSecretKey::from_bytes(saorsa_sec_key.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Create a key pair from existing secret key bytes
    pub fn from_secret_key_bytes(secret_key_bytes: &[u8]) -> Result<Self, RawKeyError> {
        let secret_key = crate::crypto::pqc::types::MlDsaSecretKey::from_bytes(secret_key_bytes)
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;
        // For ML-DSA-65, the secret key format includes the public key
        // The first 1952 bytes after the 32-byte seed are the public key
        if secret_key_bytes.len() < 1952 + 32 {
            return Err(RawKeyError::InvalidFormat(
                "Secret key too short".to_string(),
            ));
        }
        // Extract public key from the secret key bytes (after 32-byte seed)
        let public_key_bytes = &secret_key_bytes[32..32 + 1952];
        let public_key = crate::crypto::pqc::types::MlDsaPublicKey::from_bytes(public_key_bytes)
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key in SubjectPublicKeyInfo format
    pub fn public_key_spki(&self) -> Vec<u8> {
        create_ml_dsa_subject_public_key_info(&self.public_key)
    }

    /// Get the raw public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> crate::crypto::pqc::types::MlDsaPublicKey {
        self.public_key.clone()
    }

    /// Sign data with the private key
    pub fn sign(
        &self,
        data: &[u8],
    ) -> Result<crate::crypto::pqc::types::MlDsaSignature, RawKeyError> {
        use crate::crypto::pqc::types::MlDsaSignature;
        use saorsa_pqc::{MlDsaOperations, MlDsaSecretKey as SaorsaSecretKey};

        let ml_dsa = saorsa_pqc::MlDsa65::new();

        // Convert our wrapper type to saorsa_pqc type
        let saorsa_secret_key = SaorsaSecretKey::from_bytes(self.secret_key.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        // Sign with saorsa_pqc
        let saorsa_signature = ml_dsa
            .sign(&saorsa_secret_key, data)
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        // Convert back to our wrapper type
        MlDsaSignature::from_bytes(saorsa_signature.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))
    }

    /// Verify a signature with the public key
    pub fn verify(
        &self,
        data: &[u8],
        signature: &crate::crypto::pqc::types::MlDsaSignature,
    ) -> Result<(), RawKeyError> {
        use saorsa_pqc::{
            MlDsaOperations, MlDsaPublicKey as SaorsaPublicKey, MlDsaSignature as SaorsaSignature,
        };

        let ml_dsa = saorsa_pqc::MlDsa65::new();

        // Convert our wrapper types to saorsa_pqc types
        let saorsa_public_key = SaorsaPublicKey::from_bytes(self.public_key.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;
        let saorsa_signature = SaorsaSignature::from_bytes(signature.as_bytes())
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        // Verify with saorsa_pqc
        let is_valid = ml_dsa
            .verify(&saorsa_public_key, data, &saorsa_signature)
            .map_err(|e| RawKeyError::PqcError(e.to_string()))?;

        if is_valid {
            Ok(())
        } else {
            Err(RawKeyError::VerificationFailed)
        }
    }
}

/// Create a SubjectPublicKeyInfo DER encoding for an ML-DSA-65 public key
///
/// This function creates a minimal DER encoding of the SubjectPublicKeyInfo
/// structure containing an ML-DSA-65 public key as specified in RFC 5280,
/// adapted for post-quantum algorithms.
pub fn create_ml_dsa_subject_public_key_info(
    public_key: &crate::crypto::pqc::types::MlDsaPublicKey,
) -> Vec<u8> {
    // ML-DSA-65 SubjectPublicKeyInfo structure (RFC 5280 + LAMPS drafts):
    // SEQUENCE {
    //   algorithm AlgorithmIdentifier {
    //       algorithm OBJECT IDENTIFIER (id-ml-dsa-65 = 2.16.840.1.101.3.4.3.18)
    //       parameters ABSENT
    //   }
    //   subjectPublicKey BIT STRING (1952 bytes, unused bits = 0)
    // }

    use crate::crypto::pqc::oids::{OID_ML_DSA_65, encode_oid_value};

    let key_bytes = public_key.as_bytes();
    let key_len = key_bytes.len();

    // Build AlgorithmIdentifier = SEQUENCE { OID, (no params) }
    let oid_value = encode_oid_value(OID_ML_DSA_65);
    let mut alg_id = Vec::new();
    // OID
    alg_id.push(0x06);
    encode_der_length(&mut alg_id, oid_value.len());
    alg_id.extend_from_slice(&oid_value);

    // Wrap AlgorithmIdentifier in SEQUENCE
    let mut alg_seq = Vec::new();
    alg_seq.push(0x30);
    encode_der_length(&mut alg_seq, alg_id.len());
    alg_seq.extend_from_slice(&alg_id);

    // subjectPublicKey BIT STRING: 0 unused bits + key
    let bit_string_len = key_len + 1; // +1 unused bits byte

    // Assemble SPKI
    let mut spki = Vec::new();
    spki.push(0x30);
    let total_inner_len = alg_seq.len() + 1 /*tag*/ + der_length_len(bit_string_len)
        + bit_string_len;
    encode_der_length(&mut spki, total_inner_len);
    spki.extend_from_slice(&alg_seq);
    spki.push(0x03); // BIT STRING
    encode_der_length(&mut spki, bit_string_len);
    spki.push(0x00); // unused bits
    spki.extend_from_slice(key_bytes);
    spki
}

/// Helper function to encode DER length
fn encode_der_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(length as u8);
    } else if length < 256 {
        output.push(0x81);
        output.push(length as u8);
    } else {
        output.push(0x82);
        output.push((length >> 8) as u8);
        output.push((length & 0xff) as u8);
    }
}

fn der_length_len(length: usize) -> usize {
    if length < 128 {
        1
    } else if length < 256 {
        2
    } else {
        3
    }
}

/// Extract an ML-DSA-65 public key from SubjectPublicKeyInfo format
///
/// This function extracts the raw ML-DSA-65 public key from a
/// SubjectPublicKeyInfo structure.
pub fn extract_ml_dsa_key_from_spki(spki_der: &[u8]) -> Result<Vec<u8>, RawKeyError> {
    // Basic validation
    if spki_der.len() < 20 {
        return Err(RawKeyError::InvalidFormat("SPKI too short".to_string()));
    }

    // Check for SEQUENCE tag
    if spki_der[0] != 0x30 {
        return Err(RawKeyError::InvalidFormat(
            "Invalid SPKI format: missing SEQUENCE tag".to_string(),
        ));
    }

    // Parse length and find the BIT STRING containing the key
    let mut offset = 1;
    let (_total_len, len_bytes) = parse_der_length(&spki_der[offset..])
        .ok_or_else(|| RawKeyError::InvalidFormat("Invalid DER length".to_string()))?;
    offset += len_bytes;

    // Parse the algorithm identifier SEQUENCE
    if spki_der[offset] != 0x30 {
        return Err(RawKeyError::InvalidFormat(
            "Invalid algorithm identifier".to_string(),
        ));
    }
    offset += 1;
    let (algo_len, len_bytes) = parse_der_length(&spki_der[offset..])
        .ok_or_else(|| RawKeyError::InvalidFormat("Invalid algorithm length".to_string()))?;
    let alg_start = offset + len_bytes;
    let alg_end = alg_start + algo_len;
    // Parse OID inside AlgorithmIdentifier
    if spki_der.get(alg_start) != Some(&0x06) {
        return Err(RawKeyError::InvalidFormat(
            "AlgorithmIdentifier missing OID".to_string(),
        ));
    }
    let (oid_len, oid_len_bytes) = parse_der_length(&spki_der[alg_start + 1..])
        .ok_or_else(|| RawKeyError::InvalidFormat("Invalid OID length".to_string()))?;
    let oid_start = alg_start + 1 + oid_len_bytes;
    let oid_end = oid_start + oid_len;
    if oid_end > alg_end {
        return Err(RawKeyError::InvalidFormat("Truncated OID".to_string()));
    }
    let oid_value = &spki_der[oid_start..oid_end];
    // Check OID matches ML-DSA-65
    use crate::crypto::pqc::oids::{OID_ML_DSA_65, decode_oid_value};
    let arcs = decode_oid_value(oid_value)
        .ok_or_else(|| RawKeyError::InvalidFormat("Invalid OID".to_string()))?;
    if arcs.as_slice() != OID_ML_DSA_65 {
        return Err(RawKeyError::InvalidFormat(format!(
            "Unexpected OID for ML-DSA-65: {:?}",
            arcs
        )));
    }
    offset = alg_end;

    // Parse the BIT STRING
    if spki_der[offset] != 0x03 {
        return Err(RawKeyError::InvalidFormat(
            "Invalid SPKI format: missing BIT STRING tag".to_string(),
        ));
    }
    offset += 1;
    let (bit_string_len, len_bytes) = parse_der_length(&spki_der[offset..])
        .ok_or_else(|| RawKeyError::InvalidFormat("Invalid BIT STRING length".to_string()))?;
    offset += len_bytes;

    // Skip unused bits byte
    if spki_der[offset] != 0x00 {
        return Err(RawKeyError::InvalidFormat(
            "Unexpected unused bits in BIT STRING".to_string(),
        ));
    }
    offset += 1;

    // Extract the public key
    let key_len = bit_string_len - 1; // -1 for unused bits byte
    if offset + key_len > spki_der.len() {
        return Err(RawKeyError::InvalidFormat("SPKI truncated".to_string()));
    }

    Ok(spki_der[offset..offset + key_len].to_vec())
}

/// Helper function to parse DER length
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    if data[0] < 128 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 && data.len() >= 2 {
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 && data.len() >= 3 {
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Some((len, 3))
    } else {
        None
    }
}

/// Create a public key from SubjectPublicKeyInfo format
pub fn ml_dsa_key_from_spki(
    spki_der: &[u8],
) -> Result<crate::crypto::pqc::types::MlDsaPublicKey, RawKeyError> {
    let key_bytes = extract_ml_dsa_key_from_spki(spki_der)?;
    crate::crypto::pqc::types::MlDsaPublicKey::from_bytes(&key_bytes)
        .map_err(|e| RawKeyError::InvalidFormat(format!("Invalid ML-DSA-65 public key: {e}")))
}

/// Derive a peer ID from a public key
///
/// This function creates a deterministic peer ID from an ML-DSA-65 public key
/// using a secure hash function to ensure uniform distribution and prevent
/// direct key exposure.
pub fn derive_peer_id_from_public_key(
    public_key: &crate::crypto::pqc::types::MlDsaPublicKey,
) -> [u8; 32] {
    let key_bytes = public_key.as_bytes();

    // Create the input data with domain separator
    let mut input = Vec::with_capacity(20 + key_bytes.len());
    input.extend_from_slice(b"AUTONOMI_PEER_ID_V2:"); // V2 for PQC
    input.extend_from_slice(key_bytes);

    // Use SHA-256 from utilities module
    let hash = utilities::sha256(&input);

    let mut peer_id_bytes = [0u8; 32];
    peer_id_bytes.copy_from_slice(&hash[..32]);
    peer_id_bytes
}

/// Verify that a peer ID was correctly derived from a public key
pub fn verify_peer_id(
    peer_id: &[u8; 32],
    public_key: &crate::crypto::pqc::types::MlDsaPublicKey,
) -> bool {
    let derived_id = derive_peer_id_from_public_key(public_key);
    peer_id == &derived_id
}

/// Generate a new ML-DSA-65 key pair (convenience function)
pub fn generate_ml_dsa_keypair() -> Result<MlDsaKeyPair, RawKeyError> {
    MlDsaKeyPair::generate()
}

// Re-export PQC types for public use
pub use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

pub fn public_key_to_bytes(public_key: &crate::crypto::pqc::types::MlDsaPublicKey) -> Vec<u8> {
    public_key.as_bytes().to_vec()
}

pub fn verifying_key_from_spki(
    spki_der: &[u8],
) -> Result<crate::crypto::pqc::types::MlDsaPublicKey, RawKeyError> {
    ml_dsa_key_from_spki(spki_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let signature = keypair.sign(b"test message").unwrap();
        assert!(keypair.verify(b"test message", &signature).is_ok());
        assert!(keypair.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_spki_encoding_decoding() {
        let keypair = MlDsaKeyPair::generate().unwrap();
        let spki = keypair.public_key_spki();

        // Verify SPKI format starts with SEQUENCE
        assert_eq!(spki[0], 0x30);

        // Extract key from SPKI
        let extracted_key = extract_ml_dsa_key_from_spki(&spki).unwrap();
        assert_eq!(extracted_key, keypair.public_key_bytes());

        // Create public key from SPKI
        let public_key = ml_dsa_key_from_spki(&spki).unwrap();
        assert_eq!(public_key.as_bytes(), keypair.public_key().as_bytes());
    }

    #[test]
    fn test_peer_id_derivation() {
        let keypair1 = MlDsaKeyPair::generate().unwrap();
        let keypair2 = MlDsaKeyPair::generate().unwrap();

        let peer_id1 = derive_peer_id_from_public_key(&keypair1.public_key());
        let peer_id2 = derive_peer_id_from_public_key(&keypair1.public_key());
        let peer_id3 = derive_peer_id_from_public_key(&keypair2.public_key());

        // Same key should produce same peer ID
        assert_eq!(peer_id1, peer_id2);

        // Different keys should produce different peer IDs
        assert_ne!(peer_id1, peer_id3);

        // Verify peer ID
        assert!(verify_peer_id(&peer_id1, &keypair1.public_key()));
        assert!(!verify_peer_id(&peer_id1, &keypair2.public_key()));
    }

    #[test]
    fn test_invalid_spki() {
        // Too short
        let result = extract_ml_dsa_key_from_spki(&[0; 10]);
        assert!(result.is_err());

        // Wrong tag
        let invalid_spki = vec![0xFF; 100];
        let result = extract_ml_dsa_key_from_spki(&invalid_spki);
        assert!(result.is_err());

        // Wrong OID
        let keypair = MlDsaKeyPair::generate().unwrap();
        let mut spki = keypair.public_key_spki();
        // Mutate OID value bytes (find first OID tag 0x06 and flip a value byte)
        if let Some(pos) = spki.iter().position(|b| *b == 0x06) {
            if pos + 3 < spki.len() {
                spki[pos + 3] ^= 0x40; // flip a bit within OID value
            }
        }
        let result = extract_ml_dsa_key_from_spki(&spki);
        assert!(result.is_err());
    }
}
