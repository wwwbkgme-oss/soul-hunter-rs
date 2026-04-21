//! # Chain Module
//!
//! Core evidence chain implementation with cryptographic integrity.
//!
//! ## Features
//!
//! - **Linked Entries**: Each entry links to the previous entry via hash
//! - **Merkle Trees**: Efficient verification of the entire chain
//! - **Signatures**: Optional Ed25519 signatures for non-repudiation
//! - **Verification**: Full chain integrity verification
//! - **Export/Import**: JSON serialization for persistence
//!
//! ## Architecture
//!
//! The evidence chain is organized by finding ID. Each finding can have multiple
//! evidence entries forming a chain. The chain is stored in a concurrent hash map
//! for thread-safe access.
//!
//! ```
//! Finding A: Entry 1 -> Entry 2 -> Entry 3 (chain tip)
//! Finding B: Entry 4 -> Entry 5 (chain tip)
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sh_types::FindingId;

use crate::hash::{compute_merkle_root, Sha256Hasher};
use crate::signature::KeyPair;
use crate::{EvidenceError, Result};

/// Unique identifier for evidence entries
pub type EvidenceId = Uuid;

/// Evidence chain entry
///
/// Each entry represents a piece of evidence linked to a finding.
/// Entries are cryptographically chained via the `previous_hash` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Unique identifier for this entry
    pub id: EvidenceId,

    /// ID of the finding this evidence belongs to
    pub finding_id: FindingId,

    /// SHA-256 hash of the evidence data
    pub evidence_hash: String,

    /// Hash of the previous entry in the chain (None for first entry)
    pub previous_hash: Option<String>,

    /// Timestamp when this entry was created
    pub timestamp: DateTime<Utc>,

    /// Name of the tool that generated this evidence
    pub tool_name: String,

    /// Version of the tool
    pub tool_version: String,

    /// Raw evidence data (JSON)
    pub raw_evidence: serde_json::Value,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Ed25519 signature (hex-encoded, optional)
    pub signature: Option<String>,
}

impl EvidenceEntry {
    /// Create a new evidence entry
    pub fn new(
        finding_id: FindingId,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
        raw_evidence: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            finding_id,
            evidence_hash: String::new(),
            previous_hash: None,
            timestamp: Utc::now(),
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            raw_evidence,
            metadata: HashMap::new(),
            signature: None,
        }
    }

    /// Add metadata to the entry
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set the evidence hash
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.evidence_hash = hash.into();
        self
    }

    /// Set the previous hash
    pub fn with_previous_hash(mut self, hash: impl Into<String>) -> Self {
        self.previous_hash = Some(hash.into());
        self
    }

    /// Set the signature
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// Compute the hash of this entry's data
    pub fn compute_hash(&self, previous_hash: Option<&str>) -> Result<String> {
        let hasher = Sha256Hasher::new();

        // Create a canonical representation for hashing
        let hash_data = serde_json::json!({
            "finding_id": self.finding_id,
            "raw_evidence": self.raw_evidence,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "metadata": self.metadata,
            "previous_hash": previous_hash,
        });

        hasher.hash_json(&hash_data)
    }

    /// Verify the integrity of this entry
    pub fn verify(&self, previous_hash: Option<&str>) -> Result<bool> {
        let computed_hash = self.compute_hash(previous_hash)?;
        Ok(computed_hash == self.evidence_hash)
    }
}

/// Evidence chain manager
///
/// Manages evidence chains for multiple findings. Each finding has its own
/// chain of evidence entries. The chain provides cryptographic integrity
/// through hashing and optional digital signatures.
#[derive(Debug)]
pub struct EvidenceChain {
    /// All evidence entries indexed by ID
    entries: DashMap<EvidenceId, EvidenceEntry>,

    /// Maps finding ID to its chain tip (most recent entry)
    chain_tips: DashMap<FindingId, EvidenceId>,

    /// Current Merkle root of all entries
    merkle_root: Arc<dashmap::DashMap<(), String>>,

    /// Optional signing key pair
    signing_key: Option<KeyPair>,

    /// Hasher for computing hashes
    hasher: Sha256Hasher,
}

impl Default for EvidenceChain {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceChain {
    /// Create a new evidence chain without signing
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            chain_tips: DashMap::new(),
            merkle_root: Arc::new(DashMap::new()),
            signing_key: None,
            hasher: Sha256Hasher::new(),
        }
    }

    /// Create a new evidence chain with signing capability
    pub fn new_with_signing(keypair: KeyPair) -> Self {
        Self {
            entries: DashMap::new(),
            chain_tips: DashMap::new(),
            merkle_root: Arc::new(DashMap::new()),
            signing_key: Some(keypair),
            hasher: Sha256Hasher::new(),
        }
    }

    /// Add evidence to the chain for a finding
    ///
    /// # Arguments
    ///
    /// * `finding_id` - The ID of the finding this evidence belongs to
    /// * `tool_name` - Name of the tool that generated the evidence
    /// * `tool_version` - Version of the tool
    /// * `raw_evidence` - The raw evidence data
    /// * `metadata` - Additional metadata
    ///
    /// # Returns
    ///
    /// The ID of the newly created evidence entry
    pub fn add_evidence(
        &self,
        finding_id: FindingId,
        tool_name: &str,
        tool_version: &str,
        raw_evidence: serde_json::Value,
        metadata: HashMap<String, String>,
    ) -> Result<EvidenceId> {
        // Get the previous hash for this finding's chain
        let previous_hash = self.chain_tips.get(&finding_id).and_then(|tip_id| {
            self.entries.get(&*tip_id).map(|entry| entry.evidence_hash.clone())
        });

        // Create the entry
        let mut entry = EvidenceEntry::new(
            finding_id,
            tool_name,
            tool_version,
            raw_evidence,
        );
        entry.metadata = metadata;
        entry.previous_hash = previous_hash.clone();

        // Compute the hash
        let evidence_hash = entry.compute_hash(previous_hash.as_deref())?;
        entry.evidence_hash = evidence_hash.clone();

        // Sign if we have a signing key
        if let Some(keypair) = &self.signing_key {
            let signature = keypair.sign(evidence_hash.as_bytes())
                .map_err(|e| EvidenceError::InvalidSignature(e.to_string()))?;
            entry.signature = Some(signature);
        }

        let entry_id = entry.id;

        // Store the entry
        self.entries.insert(entry_id, entry);

        // Update the chain tip
        self.chain_tips.insert(finding_id, entry_id);

        // Recompute the Merkle root
        self.recompute_merkle_root()?;

        Ok(entry_id)
    }

    /// Get an entry by ID
    pub fn get_entry(&self, entry_id: EvidenceId) -> Option<EvidenceEntry> {
        self.entries.get(&entry_id).map(|e| e.clone())
    }

    /// Get all evidence for a finding
    ///
    /// Returns the evidence entries in reverse chronological order
    /// (most recent first).
    pub fn get_evidence(&self, finding_id: FindingId) -> Vec<EvidenceEntry> {
        let mut evidence = Vec::new();
        let mut current_id = self.chain_tips.get(&finding_id).map(|t| *t);

        while let Some(id) = current_id {
            if let Some(entry) = self.entries.get(&id) {
                let entry_clone = entry.clone();
                current_id = entry_clone
                    .previous_hash
                    .as_ref()
                    .and_then(|hash| self.find_entry_by_hash(hash));
                evidence.push(entry_clone);
            } else {
                break;
            }
        }

        evidence
    }

    /// Find an entry by its hash
    fn find_entry_by_hash(&self, hash: &str) -> Option<EvidenceId> {
        self.entries.iter().find(|e| e.evidence_hash == hash).map(|e| e.id)
    }

    /// Verify the integrity of a finding's evidence chain
    ///
    /// Walks the entire chain from tip to root, verifying:
    /// - Each entry's hash matches its content
    /// - Each entry's previous_hash points to a valid entry
    /// - Each signature is valid (if present)
    pub fn verify_chain(&self, finding_id: FindingId) -> Result<ChainVerification> {
        let tip_id = self.chain_tips
            .get(&finding_id)
            .ok_or_else(|| EvidenceError::FindingNotFound(finding_id))?;

        let mut entries = Vec::new();
        let mut is_valid = true;
        let mut broken_link: Option<EvidenceId> = None;
        let mut current_id = Some(*tip_id);
        let mut previous_hash: Option<String> = None;

        while let Some(id) = current_id {
            let entry = self.entries
                .get(&id)
                .ok_or_else(|| EvidenceError::EntryNotFound(id))?;

            // Verify the entry's hash
            if !entry.verify(previous_hash.as_deref())? {
                is_valid = false;
                broken_link = Some(id);
                break;
            }

            // Verify signature if present and we have a verifying key
            if let (Some(sig), Some(keypair)) = (&entry.signature, &self.signing_key) {
                let is_sig_valid = keypair
                    .verify(entry.evidence_hash.as_bytes(), sig)
                    .map_err(|e| EvidenceError::InvalidSignature(e.to_string()))?;

                if !is_sig_valid {
                    is_valid = false;
                    broken_link = Some(id);
                    break;
                }
            }

            previous_hash = Some(entry.evidence_hash.clone());
            current_id = entry.previous_hash.as_ref().and_then(|h| self.find_entry_by_hash(h));
            entries.push(entry.clone());
        }

        // Get the Merkle root
        let merkle_root = self.merkle_root.get(&()).map(|r| r.clone());

        Ok(ChainVerification {
            finding_id,
            is_valid,
            entries,
            broken_link,
            merkle_root,
        })
    }

    /// Recompute the Merkle root of all entries
    fn recompute_merkle_root(&self) -> Result<()> {
        let mut hashes: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.evidence_hash.clone())
            .collect();

        if hashes.is_empty() {
            self.merkle_root.clear();
            return Ok(());
        }

        // Sort for deterministic ordering
        hashes.sort();

        let root = compute_merkle_root(&hashes)
            .ok_or_else(|| EvidenceError::MerkleTreeFailed("Empty hash list".to_string()))?;

        self.merkle_root.insert((), root);
        Ok(())
    }

    /// Get the current Merkle root
    pub fn merkle_root(&self) -> Option<String> {
        self.merkle_root.get(&()).map(|r| r.clone())
    }

    /// Export a finding's evidence chain as JSON
    pub fn export_chain(&self, finding_id: FindingId) -> Result<serde_json::Value> {
        let evidence = self.get_evidence(finding_id);
        let merkle_root = self.merkle_root();

        Ok(serde_json::json!({
            "finding_id": finding_id,
            "merkle_root": merkle_root,
            "total_entries": evidence.len(),
            "export_timestamp": Utc::now(),
            "entries": evidence,
        }))
    }

    /// Clear all evidence
    pub fn clear(&self) {
        self.entries.clear();
        self.chain_tips.clear();
        self.merkle_root.clear();
    }

    /// Get the number of entries in the chain
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of findings with evidence
    pub fn finding_count(&self) -> usize {
        self.chain_tips.len()
    }

    /// Check if a finding has evidence
    pub fn has_evidence(&self, finding_id: FindingId) -> bool {
        self.chain_tips.contains_key(&finding_id)
    }

    /// Get all finding IDs with evidence
    pub fn finding_ids(&self) -> Vec<FindingId> {
        self.chain_tips.iter().map(|e| *e.key()).collect()
    }

    /// Tamper with evidence (for testing only)
    #[cfg(test)]
    pub fn tamper_with_evidence_for_testing(
        &self,
        entry_id: EvidenceId,
        new_evidence: serde_json::Value,
    ) {
        if let Some(mut entry) = self.entries.get_mut(&entry_id) {
            entry.raw_evidence = new_evidence;
        }
    }
}

/// Chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    /// The finding ID that was verified
    pub finding_id: FindingId,

    /// Whether the chain is valid
    pub is_valid: bool,

    /// All entries in the chain (in reverse chronological order)
    pub entries: Vec<EvidenceEntry>,

    /// The first broken link (if any)
    pub broken_link: Option<EvidenceId>,

    /// The Merkle root at the time of verification
    pub merkle_root: Option<String>,
}

impl ChainVerification {
    /// Get the number of valid entries
    pub fn valid_entry_count(&self) -> usize {
        if self.is_valid {
            self.entries.len()
        } else if let Some(broken) = self.broken_link {
            self.entries.iter().position(|e| e.id == broken).unwrap_or(0)
        } else {
            0
        }
    }

    /// Get a summary of the verification
    pub fn summary(&self) -> String {
        if self.is_valid {
            format!(
                "Chain for finding {} is valid with {} entries",
                self.finding_id, self.entries.len()
            )
        } else if let Some(broken) = self.broken_link {
            format!(
                "Chain for finding {} is INVALID. Broken link at entry {}",
                self.finding_id, broken
            )
        } else {
            format!("Chain for finding {} verification failed", self.finding_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_evidence_entry_creation() {
        let finding_id = Uuid::new_v4();
        let entry = EvidenceEntry::new(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
        );

        assert_eq!(entry.finding_id, finding_id);
        assert_eq!(entry.tool_name, "test-tool");
        assert_eq!(entry.tool_version, "1.0.0");
        assert!(entry.signature.is_none());
    }

    #[test]
    fn test_evidence_entry_builder() {
        let finding_id = Uuid::new_v4();
        let entry = EvidenceEntry::new(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
        )
        .with_metadata("key", "value")
        .with_hash("abc123")
        .with_signature("sig456");

        assert_eq!(entry.metadata.get("key"), Some(&"value".to_string()));
        assert_eq!(entry.evidence_hash, "abc123");
        assert_eq!(entry.signature, Some("sig456".to_string()));
    }

    #[test]
    fn test_evidence_entry_hash() {
        let finding_id = Uuid::new_v4();
        let entry = EvidenceEntry::new(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
        );

        let hash = entry.compute_hash(None).expect("Failed to compute hash");
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars

        // Same data should produce same hash
        let hash2 = entry.compute_hash(None).expect("Failed to compute hash");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_evidence_entry_hash_with_previous() {
        let finding_id = Uuid::new_v4();
        let entry = EvidenceEntry::new(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
        );

        let hash1 = entry.compute_hash(None).expect("Failed to compute hash");
        let hash2 = entry.compute_hash(Some("previous_hash")).expect("Failed to compute hash");

        // Different previous hash should produce different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_evidence_entry_verify() {
        let finding_id = Uuid::new_v4();
        let mut entry = EvidenceEntry::new(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
        );

        let hash = entry.compute_hash(None).expect("Failed to compute hash");
        entry.evidence_hash = hash.clone();

        assert!(entry.verify(None).expect("Failed to verify"));

        // Tamper with data
        entry.raw_evidence = serde_json::json!({ "test": "tampered" });
        assert!(!entry.verify(None).expect("Failed to verify"));
    }

    #[test]
    fn test_chain_creation() {
        let chain = EvidenceChain::new();
        assert_eq!(chain.entry_count(), 0);
        assert_eq!(chain.finding_count(), 0);
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

        assert_eq!(chain.entry_count(), 1);
        assert_eq!(chain.finding_count(), 1);
        assert!(chain.has_evidence(finding_id));

        let entry = chain.get_entry(evidence_id).expect("Failed to get entry");
        assert_eq!(entry.finding_id, finding_id);
        assert_eq!(entry.tool_name, "test-tool");
    }

    #[test]
    fn test_chain_linking() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        let id1 = chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let id2 = chain.add_evidence(
            finding_id,
            "tool2",
            "1.0.0",
            serde_json::json!({ "step": 2 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let entry2 = chain.get_entry(id2).expect("Failed to get entry");
        let entry1 = chain.get_entry(id1).expect("Failed to get entry");

        assert_eq!(entry2.previous_hash, Some(entry1.evidence_hash.clone()));
    }

    #[test]
    fn test_get_evidence() {
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

        let evidence = chain.get_evidence(finding_id);
        assert_eq!(evidence.len(), 2);

        // Should be in reverse chronological order (most recent first)
        assert_eq!(evidence[0].tool_name, "tool2");
        assert_eq!(evidence[1].tool_name, "tool1");
    }

    #[test]
    fn test_verify_valid_chain() {
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

        let verification = chain.verify_chain(finding_id).expect("Failed to verify");
        assert!(verification.is_valid);
        assert_eq!(verification.entries.len(), 2);
        assert!(verification.broken_link.is_none());
    }

    #[test]
    fn test_verify_tampered_chain() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        let id1 = chain.add_evidence(
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

        // Tamper with the first entry
        chain.tamper_with_evidence_for_testing(id1, serde_json::json!({ "step": 999 }));

        let verification = chain.verify_chain(finding_id).expect("Failed to verify");
        assert!(!verification.is_valid);
        assert!(verification.broken_link.is_some());
    }

    #[test]
    fn test_verify_nonexistent_finding() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        let result = chain.verify_chain(finding_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_root() {
        let chain = EvidenceChain::new();
        let finding_id = Uuid::new_v4();

        assert!(chain.merkle_root().is_none());

        chain.add_evidence(
            finding_id,
            "tool1",
            "1.0.0",
            serde_json::json!({ "step": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let root = chain.merkle_root().expect("No Merkle root");
        assert_eq!(root.len(), 64);

        // Add more evidence
        chain.add_evidence(
            finding_id,
            "tool2",
            "1.0.0",
            serde_json::json!({ "step": 2 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let root2 = chain.merkle_root().expect("No Merkle root");
        // Root should change when entries are added
        assert_ne!(root, root2);
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

        let export = chain.export_chain(finding_id).expect("Failed to export");
        assert_eq!(export["finding_id"], finding_id.to_string());
        assert!(export["merkle_root"].is_string());
        assert_eq!(export["total_entries"], 1);
        assert!(export["entries"].is_array());
    }

    #[test]
    fn test_clear() {
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

        assert_eq!(chain.entry_count(), 0);
        assert_eq!(chain.finding_count(), 0);
        assert!(chain.merkle_root().is_none());
        assert!(!chain.has_evidence(finding_id));
    }

    #[test]
    fn test_multiple_findings() {
        let chain = EvidenceChain::new();
        let finding_id1 = Uuid::new_v4();
        let finding_id2 = Uuid::new_v4();

        chain.add_evidence(
            finding_id1,
            "tool1",
            "1.0.0",
            serde_json::json!({ "finding": 1 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        chain.add_evidence(
            finding_id2,
            "tool2",
            "1.0.0",
            serde_json::json!({ "finding": 2 }),
            HashMap::new(),
        ).expect("Failed to add evidence");

        assert_eq!(chain.entry_count(), 2);
        assert_eq!(chain.finding_count(), 2);

        let evidence1 = chain.get_evidence(finding_id1);
        let evidence2 = chain.get_evidence(finding_id2);

        assert_eq!(evidence1.len(), 1);
        assert_eq!(evidence2.len(), 1);
        assert_eq!(evidence1[0].tool_name, "tool1");
        assert_eq!(evidence2[0].tool_name, "tool2");
    }

    #[test]
    fn test_finding_ids() {
        let chain = EvidenceChain::new();
        let finding_id1 = Uuid::new_v4();
        let finding_id2 = Uuid::new_v4();

        chain.add_evidence(
            finding_id1,
            "tool1",
            "1.0.0",
            serde_json::json!({}),
            HashMap::new(),
        ).expect("Failed to add evidence");

        chain.add_evidence(
            finding_id2,
            "tool2",
            "1.0.0",
            serde_json::json!({}),
            HashMap::new(),
        ).expect("Failed to add evidence");

        let ids = chain.finding_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&finding_id1));
        assert!(ids.contains(&finding_id2));
    }

    #[test]
    fn test_chain_verification_summary() {
        let valid = ChainVerification {
            finding_id: Uuid::new_v4(),
            is_valid: true,
            entries: vec![EvidenceEntry::new(
                Uuid::new_v4(),
                "tool",
                "1.0.0",
                serde_json::json!({}),
            )],
            broken_link: None,
            merkle_root: None,
        };

        assert!(valid.summary().contains("is valid"));

        let invalid = ChainVerification {
            finding_id: Uuid::new_v4(),
            is_valid: false,
            entries: vec![],
            broken_link: Some(Uuid::new_v4()),
            merkle_root: None,
        };

        assert!(invalid.summary().contains("INVALID"));
    }

    #[test]
    fn test_valid_entry_count() {
        let valid = ChainVerification {
            finding_id: Uuid::new_v4(),
            is_valid: true,
            entries: vec![
                EvidenceEntry::new(Uuid::new_v4(), "tool", "1.0.0", serde_json::json!({})),
                EvidenceEntry::new(Uuid::new_v4(), "tool", "1.0.0", serde_json::json!({})),
            ],
            broken_link: None,
            merkle_root: None,
        };

        assert_eq!(valid.valid_entry_count(), 2);
    }
}
