// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! OID assignments for ML-DSA and ML-KEM as specified by IETF LAMPS drafts.
//!
//! Sources (as of 2024-11; confirmed 2025-09):
//! - ML-DSA certificates: id-ml-dsa-44/65/87 are under
//!   2.16.840.1.101.3.4.3.{17,18,19}. Parameters MUST be absent.
//! - ML-KEM certificates: id-ml-kem-512/768/1024 are under
//!   2.16.840.1.101.3.4.4.{1,2,3}. Parameters MUST be absent.
//!
//! See LAMPS drafts for details.

/// ML-DSA-44 OID arcs: 2.16.840.1.101.3.4.3.17
pub const OID_ML_DSA_44: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
/// ML-DSA-65 OID arcs: 2.16.840.1.101.3.4.3.18
pub const OID_ML_DSA_65: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
/// ML-DSA-87 OID arcs: 2.16.840.1.101.3.4.3.19
pub const OID_ML_DSA_87: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

/// ML-KEM-512 OID arcs: 2.16.840.1.101.3.4.4.1
pub const OID_ML_KEM_512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 1];
/// ML-KEM-768 OID arcs: 2.16.840.1.101.3.4.4.2
pub const OID_ML_KEM_768: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 2];
/// ML-KEM-1024 OID arcs: 2.16.840.1.101.3.4.4.3
pub const OID_ML_KEM_1024: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 3];

/// Encode dotted OID arcs into DER value bytes (without tag/length)
pub fn encode_oid_value(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "OID must have at least two arcs");
    let mut out = Vec::new();
    // First two arcs are encoded as (40 * arc0 + arc1)
    out.push((40 * arcs[0] + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        // base-128 varint, MSB set on all but last
        let mut stack = [0u8; 5];
        let mut i = stack.len();
        let mut v = arc;
        loop {
            i -= 1;
            stack[i] = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 { break; }
        }
        for j in i..stack.len() {
            let is_last = j == stack.len() - 1;
            out.push(if is_last { stack[j] } else { stack[j] | 0x80 });
        }
    }
    out
}

/// Decode DER value bytes into dotted OID arcs (without tag/length)
pub fn decode_oid_value(mut bytes: &[u8]) -> Option<Vec<u32>> {
    if bytes.is_empty() { return None; }
    let first = bytes[0];
    let arc0 = (first / 40) as u32;
    let arc1 = (first % 40) as u32;
    let mut arcs = vec![arc0, arc1];
    bytes = &bytes[1..];
    while !bytes.is_empty() {
        let mut v: u32 = 0;
        let mut i = 0;
        loop {
            if bytes.is_empty() || i == 5 { return None; }
            let b = bytes[0];
            bytes = &bytes[1..];
            v = (v << 7) | (b & 0x7f) as u32;
            i += 1;
            if b & 0x80 == 0 { break; }
        }
        arcs.push(v);
    }
    Some(arcs)
}

