// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Post-Quantum Cryptography extensions for Raw Public Keys
//!
//! This module extends the raw public key infrastructure to support
//! ML-DSA keys and hybrid combinations for post-quantum authentication.

use std::fmt::{self, Debug};

use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::crypto::pqc::{
    MlDsaOperations,
    ml_dsa::MlDsa65,
    types::{MlDsaPublicKey as MlDsa65PublicKey, MlDsaSignature as MlDsa65Signature, PqcError},
};

// Pure PQC implementation - no Ed25519 support

/// Extended Raw Public Key types - PQC only
#[derive(Clone, Debug)]
pub enum ExtendedRawPublicKey {
    /// Post-quantum ML-DSA-65 key
    MlDsa65(MlDsa65PublicKey),
}

impl ExtendedRawPublicKey {
    /// Create SubjectPublicKeyInfo DER encoding for the key
    pub fn to_subject_public_key_info(&self) -> Result<Vec<u8>, PqcError> {
        match self {
            Self::MlDsa65(key) => {
                // Create ML-DSA SPKI encoding
                create_ml_dsa_subject_public_key_info(key)
            }
        }
    }

    /// Extract public key from SubjectPublicKeyInfo
    pub fn from_subject_public_key_info(spki: &[u8]) -> Result<Self, PqcError> {
        // Try ML-DSA
        if let Ok(key) = extract_ml_dsa_from_spki(spki) {
            return Ok(Self::MlDsa65(key));
        }

        Err(PqcError::InvalidPublicKey)
    }

    /// Verify a signature using this public key
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        scheme: SignatureScheme,
    ) -> Result<(), PqcError> {
        match self {
            Self::MlDsa65(key) => verify_ml_dsa_signature(key, message, signature, scheme),
        }
    }

    /// Get the signature schemes supported by this key type
    pub fn supported_signature_schemes(&self) -> Vec<SignatureScheme> {
        match self {
            Self::MlDsa65(_) => vec![
                // ML-DSA-65 scheme (private use codepoint)
                SignatureScheme::Unknown(0xFE3C),
            ],
        }
    }

    /// Get the size of this public key in bytes
    pub fn size(&self) -> usize {
        match self {
            Self::MlDsa65(key) => key.as_bytes().len(),
        }
    }
}

/// Create SubjectPublicKeyInfo for ML-DSA public key
fn create_ml_dsa_subject_public_key_info(
    public_key: &MlDsa65PublicKey,
) -> Result<Vec<u8>, PqcError> {
    use crate::crypto::pqc::oids::{OID_ML_DSA_65, encode_oid_value};
    let key_bytes = public_key.as_bytes();
    let key_len = key_bytes.len();

    // Build AlgorithmIdentifier with OID id-ml-dsa-65 and absent parameters
    let oid_value = encode_oid_value(OID_ML_DSA_65);
    let mut alg_id = Vec::new();
    alg_id.push(0x06);
    encode_length(&mut alg_id, oid_value.len());
    alg_id.extend_from_slice(&oid_value);

    let mut alg_seq = Vec::new();
    alg_seq.push(0x30);
    encode_length(&mut alg_seq, alg_id.len());
    alg_seq.extend_from_slice(&alg_id);

    let bit_string_len = 1 + key_len; // unused bits + key

    let mut spki = Vec::new();
    spki.push(0x30);
    let total_inner_len = alg_seq.len() + 1 + der_len_len(bit_string_len) + bit_string_len;
    encode_length(&mut spki, total_inner_len);
    spki.extend_from_slice(&alg_seq);
    spki.push(0x03);
    encode_length(&mut spki, bit_string_len);
    spki.push(0x00);
    spki.extend_from_slice(key_bytes);
    Ok(spki)
}

/// Extract ML-DSA key from SPKI
fn extract_ml_dsa_from_spki(spki: &[u8]) -> Result<MlDsa65PublicKey, PqcError> {
    // Basic validation
    if spki.len() < 20 {
        return Err(PqcError::InvalidPublicKey);
    }

    // Check for SEQUENCE tag
    if spki[0] != 0x30 {
        return Err(PqcError::InvalidPublicKey);
    }

    // Parse length and find the BIT STRING containing the key
    let mut offset = 1;
    let (_total_len, len_bytes) =
        parse_der_length(&spki[offset..]).ok_or(PqcError::InvalidPublicKey)?;
    offset += len_bytes;

    // Parse the algorithm identifier SEQUENCE
    if spki[offset] != 0x30 {
        return Err(PqcError::InvalidPublicKey);
    }
    offset += 1;
    let (algo_len, len_bytes) =
        parse_der_length(&spki[offset..]).ok_or(PqcError::InvalidPublicKey)?;
    let alg_start = offset + len_bytes;
    let alg_end = alg_start + algo_len;
    if spki.get(alg_start) != Some(&0x06) {
        return Err(PqcError::InvalidPublicKey);
    }
    let (oid_len, oid_len_bytes) =
        parse_der_length(&spki[alg_start + 1..]).ok_or(PqcError::InvalidPublicKey)?;
    let oid_start = alg_start + 1 + oid_len_bytes;
    let oid_end = oid_start + oid_len;
    if oid_end > alg_end {
        return Err(PqcError::InvalidPublicKey);
    }
    use crate::crypto::pqc::oids::{OID_ML_DSA_65, decode_oid_value};
    let arcs = decode_oid_value(&spki[oid_start..oid_end]).ok_or(PqcError::InvalidPublicKey)?;
    if arcs.as_slice() != OID_ML_DSA_65 {
        return Err(PqcError::InvalidPublicKey);
    }
    offset = alg_end;

    // Parse the BIT STRING
    if spki[offset] != 0x03 {
        return Err(PqcError::InvalidPublicKey);
    }
    offset += 1;
    let (bit_string_len, len_bytes) =
        parse_der_length(&spki[offset..]).ok_or(PqcError::InvalidPublicKey)?;
    offset += len_bytes;

    // Skip unused bits byte
    if spki[offset] != 0x00 {
        return Err(PqcError::InvalidPublicKey);
    }
    offset += 1;

    // Extract the public key
    let key_len = bit_string_len - 1; // -1 for unused bits byte
    if offset + key_len > spki.len() {
        return Err(PqcError::InvalidPublicKey);
    }

    MlDsa65PublicKey::from_bytes(&spki[offset..offset + key_len])
}

/// Parse DER length
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

/// Verify ML-DSA signature (placeholder)
fn verify_ml_dsa_signature(
    key: &MlDsa65PublicKey,
    message: &[u8],
    signature: &[u8],
    scheme: SignatureScheme,
) -> Result<(), PqcError> {
    // Check for ML-DSA scheme
    if scheme != SignatureScheme::Unknown(0xFE3C) {
        return Err(PqcError::InvalidSignature);
    }

    // Parse signature bytes into ML-DSA signature
    let sig = MlDsa65Signature::from_bytes(signature)?;

    // Use the ML-DSA verifier
    let verifier = MlDsa65::new();
    match verifier.verify(key, message, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err(PqcError::InvalidSignature),
        Err(e) => Err(e),
    }
}

/// Encode ASN.1 length
fn encode_length(output: &mut Vec<u8>, len: usize) {
    if len < 128 {
        output.push(len as u8);
    } else if len < 256 {
        output.push(0x81);
        output.push(len as u8);
    } else {
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push((len & 0xFF) as u8);
    }
}

fn der_len_len(len: usize) -> usize {
    if len < 128 {
        1
    } else if len < 256 {
        2
    } else {
        3
    }
}

/// PQC-aware Raw Public Key Verifier
#[derive(Debug)]
pub struct PqcRawPublicKeyVerifier {
    /// Set of trusted public keys
    trusted_keys: Vec<ExtendedRawPublicKey>,
    /// Whether to allow any valid key
    allow_any_key: bool,
}

impl PqcRawPublicKeyVerifier {
    /// Create a new verifier with trusted keys
    pub fn new(trusted_keys: Vec<ExtendedRawPublicKey>) -> Self {
        Self {
            trusted_keys,
            allow_any_key: false,
        }
    }

    /// Create a verifier that accepts any valid key (development only)
    pub fn allow_any() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_any_key: true,
        }
    }

    /// Add a trusted key
    pub fn add_trusted_key(&mut self, key: ExtendedRawPublicKey) {
        self.trusted_keys.push(key);
    }

    /// Verify a certificate (SPKI) against trusted keys
    pub fn verify_cert(&self, cert: &[u8]) -> Result<ExtendedRawPublicKey, TlsError> {
        // Extract key from SPKI
        let key = ExtendedRawPublicKey::from_subject_public_key_info(cert)
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Check if trusted
        if self.allow_any_key {
            return Ok(key);
        }

        // Check against trusted keys
        for trusted in &self.trusted_keys {
            if self.keys_match(&key, trusted) {
                return Ok(key);
            }
        }

        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ))
    }

    /// Check if two keys match
    fn keys_match(&self, a: &ExtendedRawPublicKey, b: &ExtendedRawPublicKey) -> bool {
        match (a, b) {
            (ExtendedRawPublicKey::MlDsa65(a), ExtendedRawPublicKey::MlDsa65(b)) => {
                a.as_bytes() == b.as_bytes()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_spki_encoding() {
        // Create a dummy ML-DSA public key
        let ml_dsa_key = MlDsa65PublicKey::from_bytes(&vec![0u8; 1952]).unwrap();
        let extended_key = ExtendedRawPublicKey::MlDsa65(ml_dsa_key);

        // Test SPKI encoding
        let spki = extended_key.to_subject_public_key_info().unwrap();
        // Should have proper ASN.1 structure
        assert!(spki.starts_with(&[0x30])); // SEQUENCE tag
        assert!(spki.len() > 1952); // Larger than key due to ASN.1

        // Test size
        assert_eq!(extended_key.size(), 1952);

        // Test supported schemes
        assert_eq!(
            extended_key.supported_signature_schemes(),
            vec![SignatureScheme::Unknown(0xFE3C)]
        );
    }

    #[test]
    fn test_pqc_verifier() {
        // Create test ML-DSA keys
        let key1_bytes = vec![1u8; 1952];
        let key2_bytes = vec![2u8; 1952];

        let ml_dsa1 = MlDsa65PublicKey::from_bytes(&key1_bytes).unwrap();
        let ml_dsa2 = MlDsa65PublicKey::from_bytes(&key2_bytes).unwrap();

        let key1 = ExtendedRawPublicKey::MlDsa65(ml_dsa1);
        let key2 = ExtendedRawPublicKey::MlDsa65(ml_dsa2);

        // Create verifier with trusted key
        let verifier = PqcRawPublicKeyVerifier::new(vec![key1.clone()]);

        // Test verification with trusted key
        let spki1 = key1.to_subject_public_key_info().unwrap();
        assert!(verifier.verify_cert(&spki1).is_ok());

        // Test verification with untrusted key
        let spki2 = key2.to_subject_public_key_info().unwrap();
        assert!(verifier.verify_cert(&spki2).is_err());

        // Test allow_any mode
        let any_verifier = PqcRawPublicKeyVerifier::allow_any();
        assert!(any_verifier.verify_cert(&spki2).is_ok());
    }

    #[test]
    fn test_asn1_length_encoding() {
        let mut buf = Vec::new();

        // Short form (< 128)
        encode_length(&mut buf, 50);
        assert_eq!(buf, vec![50]);

        // Long form (128-255)
        buf.clear();
        encode_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        // Long form (256+)
        buf.clear();
        encode_length(&mut buf, 1000);
        assert_eq!(buf, vec![0x82, 0x03, 0xE8]);
    }
}
