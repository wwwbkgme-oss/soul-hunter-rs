//! # Hash Module
//!
//! Provides cryptographic hashing functionality for the evidence chain.
//!
//! ## Features
//!
//! - **SHA-256**: Industry-standard SHA-256 hashing via the `sha2` crate
//! - **Ring Integration**: Alternative SHA-256 implementation via the `ring` crate
//! - **Hex Encoding**: Convenient hex encoding/decoding of hash values
//!
//! ## Example
//!
//! ```rust
//! use sh_evidence::hash::{Hasher, Sha256Hasher};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let hasher = Sha256Hasher::new();
//! let hash = hasher.hash(b"Hello, World!");
//! println!("Hash: {}", hash);
//! # Ok(())
//! # }
//! ```

use sha2::{Sha256, Digest};

/// Trait for hash implementations
pub trait Hasher: Send + Sync {
    /// Compute hash of input data
    fn hash(&self, data: &[u8]) -> String;

    /// Compute hash of multiple data chunks
    fn hash_chunks(&self, chunks: &[&[u8]]) -> String;

    /// Verify that data matches a given hash
    fn verify(&self, data: &[u8], expected_hash: &str) -> bool;
}

/// SHA-256 hasher implementation using the `sha2` crate
#[derive(Debug, Clone, Default)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self
    }

    /// Hash a JSON value
    pub fn hash_json(&self, value: &serde_json::Value) -> crate::Result<String> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| crate::EvidenceError::Serialization(e.to_string()))?;
        Ok(self.hash(&bytes))
    }

    /// Hash two hashes together (for Merkle tree operations)
    pub fn hash_pair(&self, left: &str, right: &str) -> String {
        let combined = format!("{}{}", left, right);
        self.hash(combined.as_bytes())
    }
}

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn hash_chunks(&self, chunks: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn verify(&self, data: &[u8], expected_hash: &str) -> bool {
        let computed = self.hash(data);
        computed == expected_hash
    }
}

/// Ring-based SHA-256 hasher (alternative implementation)
#[derive(Debug, Clone, Default)]
pub struct RingSha256Hasher;

impl RingSha256Hasher {
    /// Create a new Ring SHA-256 hasher
    pub fn new() -> Self {
        Self
    }
}

impl Hasher for RingSha256Hasher {
    fn hash(&self, data: &[u8]) -> String {
        use ring::digest::{Context, SHA256};
        let mut context = Context::new(&SHA256);
        context.update(data);
        let digest = context.finish();
        hex::encode(digest.as_ref())
    }

    fn hash_chunks(&self, chunks: &[&[u8]]) -> String {
        use ring::digest::{Context, SHA256};
        let mut context = Context::new(&SHA256);
        for chunk in chunks {
            context.update(chunk);
        }
        let digest = context.finish();
        hex::encode(digest.as_ref())
    }

    fn verify(&self, data: &[u8], expected_hash: &str) -> bool {
        let computed = self.hash(data);
        computed == expected_hash
    }
}

/// Compute Merkle root from a list of hashes
pub fn compute_merkle_root(hashes: &[String]) -> Option<String> {
    if hashes.is_empty() {
        return None;
    }

    let hasher = Sha256Hasher::new();
    let mut current_layer: Vec<String> = hashes.to_vec();

    while current_layer.len() > 1 {
        let mut next_layer = Vec::new();

        for chunk in current_layer.chunks(2) {
            if chunk.len() == 2 {
                // Hash two nodes together
                let combined = hasher.hash_pair(&chunk[0], &chunk[1]);
                next_layer.push(combined);
            } else {
                // Odd node out - promote to next level
                next_layer.push(chunk[0].clone());
            }
        }

        current_layer = next_layer;
    }

    current_layer.first().cloned()
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    leaf_hash: &str,
    proof: &[String],
    root: &str,
    index: usize,
) -> bool {
    let hasher = Sha256Hasher::new();
    let mut current_hash = leaf_hash.to_string();
    let mut current_index = index;

    for sibling_hash in proof {
        current_hash = if current_index % 2 == 0 {
            // Current node is on the left
            hasher.hash_pair(&current_hash, sibling_hash)
        } else {
            // Current node is on the right
            hasher.hash_pair(sibling_hash, &current_hash)
        };
        current_index /= 2;
    }

    current_hash == root
}

/// Generate a Merkle proof for a leaf at the given index
pub fn generate_merkle_proof(hashes: &[String], index: usize) -> Option<Vec<String>> {
    if hashes.is_empty() || index >= hashes.len() {
        return None;
    }

    let hasher = Sha256Hasher::new();
    let mut proof = Vec::new();
    let mut current_layer: Vec<String> = hashes.to_vec();
    let mut current_index = index;

    while current_layer.len() > 1 {
        let mut next_layer = Vec::new();

        for (i, chunk) in current_layer.chunks(2).enumerate() {
            if chunk.len() == 2 {
                if i == current_index / 2 {
                    // This chunk contains our target node
                    if current_index % 2 == 0 {
                        // Target is on the left, sibling is on the right
                        proof.push(chunk[1].clone());
                    } else {
                        // Target is on the right, sibling is on the left
                        proof.push(chunk[0].clone());
                    }
                }
                let combined = hasher.hash_pair(&chunk[0], &chunk[1]);
                next_layer.push(combined);
            } else {
                // Odd node out - promote to next level
                next_layer.push(chunk[0].clone());
            }
        }

        current_layer = next_layer;
        current_index /= 2;
    }

    Some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher() {
        let hasher = Sha256Hasher::new();
        let hash = hasher.hash(b"Hello, World!");
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_consistency() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"test data");
        let hash2 = hasher.hash(b"test data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_uniqueness() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"data1");
        let hash2 = hasher.hash(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_chunks() {
        let hasher = Sha256Hasher::new();
        let hash = hasher.hash_chunks(&[b"Hello, ", b"World!"]);
        let expected = hasher.hash(b"Hello, World!");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_verify() {
        let hasher = Sha256Hasher::new();
        let data = b"test data";
        let hash = hasher.hash(data);
        assert!(hasher.verify(data, &hash));
        assert!(!hasher.verify(b"wrong data", &hash));
    }

    #[test]
    fn test_hash_json() {
        let hasher = Sha256Hasher::new();
        let json = serde_json::json!({ "key": "value", "number": 42 });
        let hash = hasher.hash_json(&json).expect("Failed to hash JSON");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_pair() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"left");
        let hash2 = hasher.hash(b"right");
        let combined = hasher.hash_pair(&hash1, &hash2);
        assert_eq!(combined.len(), 64);
    }

    #[test]
    fn test_ring_sha256_hasher() {
        let hasher = RingSha256Hasher::new();
        let hash = hasher.hash(b"Hello, World!");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_ring_and_sha2_compatibility() {
        let sha2_hasher = Sha256Hasher::new();
        let ring_hasher = RingSha256Hasher::new();

        let data = b"test data for compatibility";
        let sha2_hash = sha2_hasher.hash(data);
        let ring_hash = ring_hasher.hash(data);

        assert_eq!(sha2_hash, ring_hash);
    }

    #[test]
    fn test_merkle_root_single() {
        let hashes = vec![
            "abc123".to_string(),
        ];
        let root = compute_merkle_root(&hashes);
        assert_eq!(root, Some("abc123".to_string()));
    }

    #[test]
    fn test_merkle_root_two() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"data1");
        let hash2 = hasher.hash(b"data2");
        let hashes = vec![hash1.clone(), hash2.clone()];
        let root = compute_merkle_root(&hashes);
        let expected = hasher.hash_pair(&hash1, &hash2);
        assert_eq!(root, Some(expected));
    }

    #[test]
    fn test_merkle_root_three() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"data1");
        let hash2 = hasher.hash(b"data2");
        let hash3 = hasher.hash(b"data3");
        let hashes = vec![hash1, hash2, hash3];
        let root = compute_merkle_root(&hashes);
        assert!(root.is_some());
        assert_eq!(root.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn test_merkle_root_empty() {
        let hashes: Vec<String> = vec![];
        let root = compute_merkle_root(&hashes);
        assert_eq!(root, None);
    }

    #[test]
    fn test_merkle_proof() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"data1");
        let hash2 = hasher.hash(b"data2");
        let hash3 = hasher.hash(b"data3");
        let hash4 = hasher.hash(b"data4");
        let hashes = vec![hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];

        let root = compute_merkle_root(&hashes).expect("Failed to compute root");

        // Generate proof for index 0
        let proof = generate_merkle_proof(&hashes, 0).expect("Failed to generate proof");
        assert!(!proof.is_empty());

        // Verify the proof
        assert!(verify_merkle_proof(&hash1, &proof, &root, 0));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"data1");
        let hash2 = hasher.hash(b"data2");
        let hash3 = hasher.hash(b"data3");
        let hash4 = hasher.hash(b"data4");
        let hashes = vec![hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];

        let root = compute_merkle_root(&hashes).expect("Failed to compute root");

        // Generate proof for index 0
        let proof = generate_merkle_proof(&hashes, 0).expect("Failed to generate proof");

        // Verify with wrong hash
        let wrong_hash = hasher.hash(b"wrong data");
        assert!(!verify_merkle_proof(&wrong_hash, &proof, &root, 0));
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let hashes = vec!["hash1".to_string()];
        let proof = generate_merkle_proof(&hashes, 5);
        assert_eq!(proof, None);
    }
}
