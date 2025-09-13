// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! TLS integration for post-quantum cryptography
//!
//! This module provides TLS extensions helpers for PQC (PQC-only in this branch).

use crate::crypto::pqc::tls_extensions::{NamedGroup, SignatureScheme};
use crate::crypto::pqc::types::*;

/// TLS extension handler for PQC negotiation
pub struct PqcTlsExtension {
    /// Supported named groups in preference order
    pub supported_groups: Vec<NamedGroup>,

    /// Supported signature schemes in preference order
    pub supported_signatures: Vec<SignatureScheme>,

    /// Whether to prefer PQC algorithms
    pub prefer_pqc: bool,
}

impl PqcTlsExtension {
    /// Create a new PQC TLS extension handler (PQC-only)
    pub fn new() -> Self {
        Self {
            supported_groups: vec![NamedGroup::MlKem768, NamedGroup::MlKem1024],
            supported_signatures: vec![SignatureScheme::MlDsa65, SignatureScheme::MlDsa87],
            prefer_pqc: true,
        }
    }

    /// Create a classical-only configuration
    pub fn classical_only() -> Self { Self::new() }

    /// Create a PQC-only configuration (no fallback)
    pub fn pqc_only() -> Self { Self::new() }

    /// Get supported named groups for TLS negotiation
    pub fn supported_groups(&self) -> &[NamedGroup] {
        &self.supported_groups
    }

    /// Get supported signature schemes for TLS negotiation
    pub fn supported_signatures(&self) -> &[SignatureScheme] {
        &self.supported_signatures
    }

    /// Select the best named group from peer's list
    pub fn select_group(&self, peer_groups: &[NamedGroup]) -> Option<NamedGroup> {
        // Find first match in our preference order
        self.supported_groups
            .iter()
            .find(|&&our_group| peer_groups.contains(&our_group))
            .copied()
    }

    /// Select the best signature scheme from peer's list
    pub fn select_signature(&self, peer_schemes: &[SignatureScheme]) -> Option<SignatureScheme> {
        // Find first match in our preference order
        self.supported_signatures
            .iter()
            .find(|&&our_scheme| peer_schemes.contains(&our_scheme))
            .copied()
    }

    /// Check if a named group is supported
    pub fn supports_group(&self, group: NamedGroup) -> bool {
        self.supported_groups.contains(&group)
    }

    /// Check if a signature scheme is supported
    pub fn supports_signature(&self, scheme: SignatureScheme) -> bool {
        self.supported_signatures.contains(&scheme)
    }

    /// Perform group selection (PQC-only). Returns Selected on match, otherwise Failed.
    pub fn negotiate_group(&self, peer_groups: &[NamedGroup]) -> NegotiationResult<NamedGroup> {
        let pqc_groups: Vec<NamedGroup> = peer_groups.iter().copied().filter(|g| g.is_pqc()).collect();
        if let Some(group) = self.select_group(&pqc_groups) { return NegotiationResult::Selected(group); }
        NegotiationResult::Failed
    }

    /// Perform signature selection (PQC-only). Returns Selected on match, otherwise Failed.
    pub fn negotiate_signature(
        &self,
        peer_schemes: &[SignatureScheme],
    ) -> NegotiationResult<SignatureScheme> {
        let pqc_schemes: Vec<SignatureScheme> = peer_schemes.iter().copied().filter(|s| s.is_pqc()).collect();
        if let Some(scheme) = self.select_signature(&pqc_schemes) { return NegotiationResult::Selected(scheme); }
        NegotiationResult::Failed
    }
}

/// Result of algorithm negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationResult<T> {
    /// Successfully selected preferred algorithm
    Selected(T),
    /// No common algorithms found
    Failed,
}

impl<T> NegotiationResult<T> {
    /// Check if negotiation succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Selected(_))
    }

    /// Check if we had to downgrade
    pub fn is_downgraded(&self) -> bool {
        false
    }

    /// Get the selected value if any
    pub fn value(&self) -> Option<&T> {
        match self { Self::Selected(v) => Some(v), Self::Failed => None }
    }
}

impl Default for PqcTlsExtension {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert between TLS wire format and internal types
pub mod wire_format {
    use super::*;

    /// Encode supported groups extension
    pub fn encode_supported_groups(groups: &[NamedGroup]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + groups.len() * 2);

        // Length prefix (2 bytes)
        let len = (groups.len() * 2) as u16;
        encoded.extend_from_slice(&len.to_be_bytes());

        // Group codepoints
        for group in groups {
            encoded.extend_from_slice(&group.to_bytes());
        }

        encoded
    }

    /// Decode supported groups extension
    pub fn decode_supported_groups(data: &[u8]) -> Result<Vec<NamedGroup>, PqcError> {
        if data.len() < 2 {
            return Err(PqcError::InvalidKeySize {
                expected: 2,
                actual: data.len(),
            });
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != 2 + len {
            return Err(PqcError::InvalidKeySize {
                expected: 2 + len,
                actual: data.len(),
            });
        }

        let mut groups = Vec::new();
        let mut offset = 2;

        while offset + 2 <= data.len() {
            match NamedGroup::from_bytes(&data[offset..offset + 2]) {
                Ok(group) => groups.push(group),
                Err(_) => {} // Skip unknown groups silently (per TLS spec)
            }
            offset += 2;
        }

        Ok(groups)
    }

    /// Encode signature algorithms extension
    pub fn encode_signature_schemes(schemes: &[SignatureScheme]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + schemes.len() * 2);

        // Length prefix (2 bytes)
        let len = (schemes.len() * 2) as u16;
        encoded.extend_from_slice(&len.to_be_bytes());

        // Scheme codepoints
        for scheme in schemes {
            encoded.extend_from_slice(&scheme.to_bytes());
        }

        encoded
    }

    /// Decode signature algorithms extension
    pub fn decode_signature_schemes(data: &[u8]) -> Result<Vec<SignatureScheme>, PqcError> {
        if data.len() < 2 {
            return Err(PqcError::InvalidSignatureSize {
                expected: 2,
                actual: data.len(),
            });
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != 2 + len {
            return Err(PqcError::InvalidSignatureSize {
                expected: 2 + len,
                actual: data.len(),
            });
        }

        let mut schemes = Vec::new();
        let mut offset = 2;

        while offset + 2 <= data.len() {
            match SignatureScheme::from_bytes(&data[offset..offset + 2]) {
                Ok(scheme) => schemes.push(scheme),
                Err(_) => {} // Skip unknown schemes silently (per TLS spec)
            }
            offset += 2;
        }

        Ok(schemes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_consistency_pqc_only_offers() {
        let ext = PqcTlsExtension::new();
        for g in ext.supported_groups() {
            assert!(g.is_pqc() && !g.is_hybrid(), "group {:?} must be pure PQC", g);
        }
        for s in ext.supported_signatures() {
            assert!(s.is_pqc() && !s.is_hybrid(), "sig {:?} must be pure PQC", s);
        }
    }

    #[test]
    fn test_pqc_extension_classical_only_is_alias() {
        let ext = PqcTlsExtension::classical_only();
        // Alias to PQC-only in this branch
        for g in ext.supported_groups() { assert!(g.is_pqc()); }
        for s in ext.supported_signatures() { assert!(s.is_pqc()); }
    }

    #[test]
    fn test_pqc_extension_pqc_only() {
        let ext = PqcTlsExtension::pqc_only();

        // Should support PQC only
        assert!(ext.supports_group(NamedGroup::MlKem768));
        assert!(ext.supports_signature(SignatureScheme::MlDsa65));
        assert!(!ext.supports_group(NamedGroup::X25519));
        assert!(!ext.supports_signature(SignatureScheme::Ed25519));
    }

    #[test]
    fn test_negotiation_both_support_pqc() {
        let ext = PqcTlsExtension::new();

        // Peer supports PQC
        let peer_groups = vec![NamedGroup::MlKem768, NamedGroup::MlKem1024];

        let result = ext.negotiate_group(&peer_groups);
        assert!(result.is_success());
        assert_eq!(result.value(), Some(&NamedGroup::MlKem768));
    }

    #[test]
    fn test_negotiation_downgrade() {
        // In PQC-only, if no common PQC, negotiation fails
        let mut ext = PqcTlsExtension::new();
        ext.supported_groups = vec![NamedGroup::MlKem768];
        let peer_groups = vec![NamedGroup::MlKem1024];
        let result = ext.negotiate_group(&peer_groups);
        assert!(!result.is_success());
        assert!(result.value().is_none());
    }

    #[test]
    fn test_wire_format_encoding() {
        use wire_format::*;

        let groups = vec![NamedGroup::MlKem768, NamedGroup::MlKem1024];

        let encoded = encode_supported_groups(&groups);
        assert_eq!(encoded.len(), 2 + 4); // Length + 2 groups

        let decoded = decode_supported_groups(&encoded).unwrap();
        assert_eq!(decoded, groups);
    }
}
