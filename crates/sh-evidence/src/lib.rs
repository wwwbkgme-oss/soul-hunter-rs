//! # sh-evidence - Cryptographic Evidence Chain
//!
//! A production-ready evidence chain implementation for the Soul Hunter security analysis platform.
//!
//! ## Features
//!
//! - **Cryptographic Chain**: Each evidence entry is cryptographically linked to the previous entry
//! - **SHA-256 Hashing**: All evidence is hashed using SHA-256 for integrity verification
//! - **Ed25519 Signatures**: Optional Ed25519 signatures for non-repudiation
//! - **Merkle Trees**: Efficient tamper detection through Merkle tree roots
//! - **Chain Verification**: Full chain integrity verification with detailed error reporting
//!
//! ## Example
//!
//! ```rust
//! use sh_evidence::{EvidenceChain, EvidenceEntry};
//! use sh_types::FindingId;
//! use uuid::Uuid;
//! use std::collections::HashMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new evidence chain
//! let chain = EvidenceChain::new();
//!
//! // Add evidence to the chain
//! let finding_id = Uuid::new_v4();
//! let evidence_id = chain.add_evidence(
//!     finding_id,
//!     "security-scanner",
//!     "1.0.0",
//!     serde_json::json!({ "finding": "SQL injection" }),
//!     HashMap::new(),
//! )?;
//!
//! // Verify the chain integrity
//! let verification = chain.verify_chain(finding_id)?;
//! assert!(verification.is_valid);
//! # Ok(())
//! # }
//! ```

pub mod chain;
pub mod hash;
pub mod signature;

// Re-export main types
pub use chain::{EvidenceChain, EvidenceEntry, ChainVerification, EvidenceId};
pub use hash::{Hasher, Sha256Hasher};
pub use signature::{SignatureManager, KeyPair};

/// Error types for evidence operations
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("Hash computation failed: {0}")]
    HashFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Finding not found: {0}")]
    FindingNotFound(sh_types::FindingId),

    #[error("Entry not found: {0}")]
    EntryNotFound(EvidenceId),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Chain verification failed")]
    VerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Merkle tree computation failed: {0}")]
    MerkleTreeFailed(String),
}

/// Result type for evidence operations
pub type Result<T> = std::result::Result<T, EvidenceError>;

/// Version of the evidence chain format
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::FindingId;
    use uuid::Uuid;
    use std::collections::HashMap;

    #[test]
    fn test_evidence_chain_creation() {
        let chain = EvidenceChain::new();
        assert!(chain.merkle_root().is_none());
    }

    #[test]
    fn test_evidence_chain_with_signing() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let chain = EvidenceChain::new_with_signing(keypair);
        assert!(chain.merkle_root().is_none());
    }

    #[test]
    fn test_add_evidence() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        let evidence_id = chain.add_evidence(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let evidence = chain.get_evidence(finding_id);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].id, evidence_id);
    }

    #[test]
    fn test_chain_verification() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        chain.add_evidence(
            finding_id,
            "tool2",
            "1.0.0",
            serde_json::json!({ "step": 2 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let verification = chain.verify_chain(finding_id).expect("Failed to verify chain");
        assert!(verification.is_valid);
        assert_eq!(verification.entries.len(), 2);
    }

    #[test]
    fn test_tamper_detection() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        let evidence_id = chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        // Tamper with the evidence
        chain.tamper_with_evidence_for_testing(evidence_id, serde_json::json!({ "step": 999 }));

        let verification = chain.verify_chain(finding_id).expect("Failed to verify chain");
        assert!(!verification.is_valid);
        assert!(verification.broken_link.is_some());
    }

    #[test]
    fn test_signed_evidence() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let chain = EvidenceChain::new_with_signing(keypair);
        let finding_id = Uuid::new_v4();

        let evidence_id = chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let evidence = chain.get_entry(evidence_id).expect("Failed to get evidence");
        assert!(evidence.signature.is_some());

        let verification = chain.verify_chain(finding_id).expect("Failed to verify chain");
        assert!(verification.is_valid);
    }

    #[test]
    fn test_merkle_root_computation() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        assert!(chain.merkle_root().is_some());
    }

    #[test]
    fn test_export_chain() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let export = chain.export_chain(finding_id).expect("Failed to export chain");
        assert!(export.get("finding_id").is_some());
        assert!(export.get("merkle_root").is_some());
        assert!(export.get("entries").is_some());
    }

    #[test]
    fn test_clear_chain() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        chain.clear();
        assert!(chain.get_evidence(finding_id).is_empty());
        assert!(chain.merkle_root().is_none());
    }
}
