//! Finding Deduplication Engine
//!
//! Removes duplicate findings based on configurable similarity thresholds.
//! Supports multiple deduplication strategies and maintains evidence chains.

use std::collections::{HashMap, HashSet};

use tracing::{debug, info, instrument, warn};

use sh_types::{Confidence, Finding, FindingId, Severity};

use crate::{FindingError, Result};

/// Configuration for deduplication operations
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Similarity threshold for deduplication (0.0 - 1.0)
    pub similarity_threshold: f64,
    /// Require exact file path match
    pub require_exact_path: bool,
    /// Require exact line number match
    pub require_exact_line: bool,
    /// Require CWE match
    pub require_cwe_match: bool,
    /// Maximum line distance for fuzzy matching
    pub max_line_distance: u32,
    /// Strategy for selecting the primary finding
    pub primary_selection: PrimarySelectionStrategy,
    /// Merge evidence from duplicates
    pub merge_evidence: bool,
    /// Keep duplicate findings as references
    pub keep_references: bool,
}

impl DeduplicationConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.85,
            require_exact_path: true,
            require_exact_line: false,
            require_cwe_match: false,
            max_line_distance: 5,
            primary_selection: PrimarySelectionStrategy::HighestSeverity,
            merge_evidence: true,
            keep_references: true,
        }
    }
    
    /// Set similarity threshold
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
        self
    }
    
    /// Set exact path requirement
    pub fn with_require_exact_path(mut self, require: bool) -> Self {
        self.require_exact_path = require;
        self
    }
    
    /// Set exact line requirement
    pub fn with_require_exact_line(mut self, require: bool) -> Self {
        self.require_exact_line = require;
        self
    }
    
    /// Set CWE match requirement
    pub fn with_require_cwe_match(mut self, require: bool) -> Self {
        self.require_cwe_match = require;
        self
    }
    
    /// Set maximum line distance
    pub fn with_max_line_distance(mut self, distance: u32) -> Self {
        self.max_line_distance = distance;
        self
    }
    
    /// Set primary selection strategy
    pub fn with_primary_selection(mut self, strategy: PrimarySelectionStrategy) -> Self {
        self.primary_selection = strategy;
        self
    }
    
    /// Set evidence merging
    pub fn with_merge_evidence(mut self, merge: bool) -> Self {
        self.merge_evidence = merge;
        self
    }
    
    /// Set reference keeping
    pub fn with_keep_references(mut self, keep: bool) -> Self {
        self.keep_references = keep;
        self
    }
    
    /// Create strict configuration (exact matches only)
    pub fn strict() -> Self {
        Self::new()
            .with_similarity_threshold(1.0)
            .with_require_exact_path(true)
            .with_require_exact_line(true)
    }
    
    /// Create lenient configuration (fuzzy matching)
    pub fn lenient() -> Self {
        Self::new()
            .with_similarity_threshold(0.7)
            .with_require_exact_path(false)
            .with_require_exact_line(false)
            .with_max_line_distance(20)
    }
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Strategy for selecting the primary finding in a duplicate group
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimarySelectionStrategy {
    /// Select the finding with highest severity
    HighestSeverity,
    /// Select the finding with highest confidence
    HighestConfidence,
    /// Select the finding with most evidence
    MostEvidence,
    /// Select the first finding encountered
    FirstSeen,
    /// Select the finding from the most reputable tool
    ToolReputation,
}

/// A group of duplicate findings
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Primary finding (the one kept)
    pub primary: Finding,
    /// Duplicate findings
    pub duplicates: Vec<Finding>,
    /// Similarity scores for each duplicate
    pub similarity_scores: HashMap<FindingId, f64>,
}

impl DuplicateGroup {
    /// Create a new duplicate group with a primary finding
    pub fn new(primary: Finding) -> Self {
        Self {
            primary,
            duplicates: Vec::new(),
            similarity_scores: HashMap::new(),
        }
    }
    
    /// Add a duplicate finding
    pub fn add_duplicate(&mut self, finding: Finding, similarity: f64) {
        self.similarity_scores.insert(finding.id, similarity);
        self.duplicates.push(finding);
    }
    
    /// Get the count of duplicates
    pub fn duplicate_count(&self) -> usize {
        self.duplicates.len()
    }
    
    /// Get total count (primary + duplicates)
    pub fn total_count(&self) -> usize {
        self.duplicates.len() + 1
    }
    
    /// Get all finding IDs in the group
    pub fn all_ids(&self) -> Vec<FindingId> {
        let mut ids = vec![self.primary.id];
        ids.extend(self.duplicates.iter().map(|f| f.id));
        ids
    }
    
    /// Get merged evidence from all findings
    pub fn merged_evidence(&self) -> Vec<sh_types::Evidence> {
        let mut evidence = self.primary.evidence.clone();
        for dup in &self.duplicates {
            for ev in &dup.evidence {
                if !evidence.iter().any(|e| e.id == ev.id) {
                    evidence.push(ev.clone());
                }
            }
        }
        evidence
    }
}

/// Deduplication engine for removing duplicate findings
#[derive(Debug, Clone)]
pub struct DeduplicationEngine {
    config: DeduplicationConfig,
    seen_hashes: HashSet<String>,
}

impl DeduplicationEngine {
    /// Create a new deduplication engine
    pub fn new(config: DeduplicationConfig) -> Self {
        Self {
            config,
            seen_hashes: HashSet::new(),
        }
    }
    
    /// Calculate similarity between two findings for deduplication
    #[instrument(skip(self, a, b), fields(finding_a = %a.id, finding_b = %b.id))]
    pub fn calculate_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;
        
        // Type must match for deduplication
        if a.finding_type != b.finding_type {
            return 0.0;
        }
        score += 0.3;
        weights += 0.3;
        
        // Location comparison
        let location_sim = self.location_similarity(&a, &b);
        if self.config.require_exact_path && location_sim < 1.0 {
            return 0.0;
        }
        score += location_sim * 0.35;
        weights += 0.35;
        
        // CWE comparison
        let cwe_sim = if self.config.require_cwe_match {
            if a.cwe_id != b.cwe_id {
                return 0.0;
            }
            1.0
        } else {
            match (&a.cwe_id, &b.cwe_id) {
                (Some(cwe_a), Some(cwe_b)) if cwe_a == cwe_b => 1.0,
                (None, None) => 1.0,
                _ => 0.0,
            }
        };
        score += cwe_sim * 0.15;
        weights += 0.15;
        
        // Title similarity
        let title_sim = self.text_similarity(&a.title, &b.title);
        score += title_sim * 0.1;
        weights += 0.1;
        
        // Description similarity
        let desc_sim = self.text_similarity(&a.description, &b.description);
        score += desc_sim * 0.1;
        weights += 0.1;
        
        if weights > 0.0 {
            score / weights
        } else {
            0.0
        }
    }
    
    /// Check if two findings are duplicates
    pub fn is_duplicate(&self, a: &Finding, b: &Finding) -> bool {
        let similarity = self.calculate_similarity(a, b);
        similarity >= self.config.similarity_threshold
    }
    
    /// Find a duplicate for a finding in a collection
    #[instrument(skip(self, finding, candidates), fields(finding_id = %finding.id))]
    pub async fn find_duplicate(&self, finding: &Finding, candidates: &[Finding]) -> Option<FindingId> {
        for candidate in candidates {
            if candidate.id == finding.id {
                continue;
            }
            
            if self.is_duplicate(finding, candidate) {
                debug!(
                    "Found duplicate: {} is duplicate of {} (similarity: {:.2})",
                    finding.id,
                    candidate.id,
                    self.calculate_similarity(finding, candidate)
                );
                return Some(candidate.id);
            }
        }
        
        None
    }
    
    /// Deduplicate a batch of findings
    #[instrument(skip(self, findings), fields(batch_size = findings.len()))]
    pub async fn deduplicate_batch(&self, findings: Vec<Finding>) -> Vec<Finding> {
        if findings.len() < 2 {
            return findings;
        }
        
        info!("Deduplicating batch of {} findings", findings.len());
        
        let mut groups: Vec<DuplicateGroup> = Vec::new();
        let mut processed = HashSet::new();
        
        for finding in &findings {
            if processed.contains(&finding.id) {
                continue;
            }
            
            // Try to find an existing group
            let mut found_group = false;
            for group in &mut groups {
                if self.is_duplicate(finding, &group.primary) {
                    let similarity = self.calculate_similarity(finding, &group.primary);
                    group.add_duplicate(finding.clone(), similarity);
                    processed.insert(finding.id);
                    found_group = true;
                    break;
                }
            }
            
            if !found_group {
                // Create new group
                groups.push(DuplicateGroup::new(finding.clone()));
                processed.insert(finding.id);
            }
        }
        
        // Merge groups and create final findings
        let mut result = Vec::with_capacity(groups.len());
        
        for mut group in groups {
            if !group.duplicates.is_empty() {
                info!(
                    "Merged {} findings into group with primary {}",
                    group.total_count(),
                    group.primary.id
                );
                
                // Merge the group
                let merged = self.merge_group(&mut group);
                result.push(merged);
            } else {
                result.push(group.primary);
            }
        }
        
        info!("Deduplication complete: {} -> {} findings", findings.len(), result.len());
        result
    }
    
    /// Find and group all duplicates
    #[instrument(skip(self, findings), fields(batch_size = findings.len()))]
    pub async fn find_duplicate_groups(&self, findings: &[Finding]) -> Vec<DuplicateGroup> {
        let mut groups: Vec<DuplicateGroup> = Vec::new();
        let mut processed = HashSet::new();
        
        for finding in findings {
            if processed.contains(&finding.id) {
                continue;
            }
            
            let mut group = DuplicateGroup::new(finding.clone());
            processed.insert(finding.id);
            
            for other in findings {
                if other.id == finding.id || processed.contains(&other.id) {
                    continue;
                }
                
                if self.is_duplicate(finding, other) {
                    let similarity = self.calculate_similarity(finding, other);
                    group.add_duplicate(other.clone(), similarity);
                    processed.insert(other.id);
                }
            }
            
            if !group.duplicates.is_empty() {
                groups.push(group);
            }
        }
        
        groups
    }
    
    /// Compute a hash for a finding
    pub fn compute_hash(&self, finding: &Finding) -> String {
        let mut components = vec![
            finding.finding_type.clone(),
            finding.title.clone(),
        ];
        
        if let Some(ref path) = finding.location.file_path {
            components.push(path.clone());
        }
        
        if let Some(line) = finding.location.line_number {
            components.push(line.to_string());
        }
        
        if let Some(ref cwe) = finding.cwe_id {
            components.push(cwe.clone());
        }
        
        // Simple hash
        format!("{:x}", components.join("|").as_bytes().iter().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(*b as u64)
        }))
    }
    
    /// Check if a finding hash has been seen
    pub fn has_seen(&self, hash: &str) -> bool {
        self.seen_hashes.contains(hash)
    }
    
    /// Mark a hash as seen
    pub fn mark_seen(&mut self, hash: String) {
        self.seen_hashes.insert(hash);
    }
    
    /// Clear seen hashes
    pub fn clear_seen(&mut self) {
        self.seen_hashes.clear();
    }
    
    /// Get the configuration
    pub fn config(&self) -> &DeduplicationConfig {
        &self.config
    }
    
    /// Location similarity calculation
    fn location_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let path_sim = match (&a.location.file_path, &b.location.file_path) {
            (Some(path_a), Some(path_b)) => {
                if path_a == path_b {
                    1.0
                } else if path_a.contains(path_b) || path_b.contains(path_a) {
                    0.5
                } else {
                    0.0
                }
            }
            (None, None) => 1.0,
            _ => 0.0,
        };
        
        if path_sim < 1.0 {
            return path_sim;
        }
        
        // Check line distance
        let line_sim = match (a.location.line_number, b.location.line_number) {
            (Some(line_a), Some(line_b)) => {
                if self.config.require_exact_line {
                    if line_a == line_b {
                        1.0
                    } else {
                        0.0
                    }
                } else {
                    let distance = if line_a > line_b {
                        line_a - line_b
                    } else {
                        line_b - line_a
                    };
                    
                    if distance == 0 {
                        1.0
                    } else if distance <= self.config.max_line_distance {
                        1.0 - (distance as f64 / self.config.max_line_distance as f64)
                    } else {
                        0.0
                    }
                }
            }
            (None, None) => 1.0,
            _ => 0.5, // One has line, one doesn't
        };
        
        path_sim * 0.6 + line_sim * 0.4
    }
    
    /// Text similarity using word overlap
    fn text_similarity(&self, a: &str, b: &str) -> f64 {
        if a == b {
            return 1.0;
        }
        
        let a_words: HashSet<String> = a.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        let b_words: HashSet<String> = b.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        if a_words.is_empty() && b_words.is_empty() {
            return 1.0;
        }
        
        if a_words.is_empty() || b_words.is_empty() {
            return 0.0;
        }
        
        let intersection: HashSet<_> = a_words.intersection(&b_words).collect();
        let union: HashSet<_> = a_words.union(&b_words).collect();
        
        intersection.len() as f64 / union.len() as f64
    }
    
    /// Merge a duplicate group into a single finding
    fn merge_group(&self, group: &mut DuplicateGroup) -> Finding {
        // Select primary based on strategy
        let primary = self.select_primary(&group.primary, &group.duplicates);
        let mut merged = primary.clone();
        
        // Mark duplicates
        for dup in &group.duplicates {
            if dup.id != primary.id {
                merged.correlated_ids.push(dup.id);
            }
        }
        
        // Merge evidence
        if self.config.merge_evidence {
            let all_evidence = group.merged_evidence();
            merged.evidence = all_evidence;
        }
        
        // Take highest severity
        let max_severity = group.duplicates.iter()
            .map(|f| f.severity)
            .chain(std::iter::once(group.primary.severity))
            .max()
            .unwrap_or(Severity::Info);
        merged.severity = max_severity;
        
        // Take highest confidence
        let max_confidence = group.duplicates.iter()
            .map(|f| f.confidence)
            .chain(std::iter::once(group.primary.confidence))
            .max_by_key(|c| match c {
                Confidence::Confirmed => 2,
                Confidence::Probable => 1,
                Confidence::Tentative => 0,
            })
            .unwrap_or(Confidence::Tentative);
        merged.confidence = max_confidence;
        
        // Update description
        if group.duplicate_count() > 0 {
            merged.description = format!(
                "{}\n\n(Merged from {} similar findings)",
                merged.description,
                group.total_count()
            );
        }
        
        merged
    }
    
    /// Select the primary finding from a group
    fn select_primary(&self, primary: &Finding, duplicates: &[Finding]) -> &Finding {
        match self.config.primary_selection {
            PrimarySelectionStrategy::FirstSeen => primary,
            PrimarySelectionStrategy::HighestSeverity => {
                duplicates.iter().chain(std::iter::once(primary))
                    .max_by_key(|f| f.severity)
                    .unwrap_or(primary)
            }
            PrimarySelectionStrategy::HighestConfidence => {
                duplicates.iter().chain(std::iter::once(primary))
                    .max_by_key(|f| match f.confidence {
                        Confidence::Confirmed => 2,
                        Confidence::Probable => 1,
                        Confidence::Tentative => 0,
                    })
                    .unwrap_or(primary)
            }
            PrimarySelectionStrategy::MostEvidence => {
                duplicates.iter().chain(std::iter::once(primary))
                    .max_by_key(|f| f.evidence.len())
                    .unwrap_or(primary)
            }
            PrimarySelectionStrategy::ToolReputation => {
                // Simplified - would use actual tool reputation scores
                primary
            }
        }
    }
}

impl Default for DeduplicationEngine {
    fn default() -> Self {
        Self::new(DeduplicationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Confidence, Location};

    fn create_test_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(title, "Test description")
            .with_severity(severity)
            .with_type("security")
    }

    #[test]
    fn test_deduplication_config() {
        let config = DeduplicationConfig::new()
            .with_similarity_threshold(0.9)
            .with_require_exact_line(true)
            .with_primary_selection(PrimarySelectionStrategy::MostEvidence);
        
        assert_eq!(config.similarity_threshold, 0.9);
        assert!(config.require_exact_line);
        assert_eq!(config.primary_selection, PrimarySelectionStrategy::MostEvidence);
    }

    #[test]
    fn test_strict_config() {
        let config = DeduplicationConfig::strict();
        assert_eq!(config.similarity_threshold, 1.0);
        assert!(config.require_exact_path);
        assert!(config.require_exact_line);
    }

    #[test]
    fn test_lenient_config() {
        let config = DeduplicationConfig::lenient();
        assert_eq!(config.similarity_threshold, 0.7);
        assert!(!config.require_exact_path);
        assert!(!config.require_exact_line);
    }

    #[test]
    fn test_similarity_calculation() {
        let engine = DeduplicationEngine::default();
        
        let a = create_test_finding("Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(42))
            .with_cwe("CWE-798");
        
        let b = create_test_finding("Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(42))
            .with_cwe("CWE-798");
        
        let c = create_test_finding("SQL Injection", Severity::Critical)
            .with_location(Location::new().with_file("query.java").with_line(100))
            .with_cwe("CWE-89");
        
        let sim_ab = engine.calculate_similarity(&a, &b);
        let sim_ac = engine.calculate_similarity(&a, &c);
        
        assert!(sim_ab > sim_ac);
        assert_eq!(sim_ab, 1.0); // Exact match
        assert!(sim_ac < 0.5); // Different type
    }

    #[test]
    fn test_is_duplicate() {
        let engine = DeduplicationEngine::default();
        
        let a = create_test_finding("Same Issue", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(42));
        
        let b = create_test_finding("Same Issue", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(42));
        
        let c = create_test_finding("Same Issue", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(100));
        
        assert!(engine.is_duplicate(&a, &b));
        assert!(!engine.is_duplicate(&a, &c)); // Different line
    }

    #[tokio::test]
    async fn test_deduplicate_batch() {
        let engine = DeduplicationEngine::default();
        
        let findings = vec![
            create_test_finding("Finding 1", Severity::High)
                .with_location(Location::new().with_file("file1.java").with_line(10)),
            create_test_finding("Finding 1", Severity::High)
                .with_location(Location::new().with_file("file1.java").with_line(10)),
            create_test_finding("Finding 2", Severity::Medium)
                .with_location(Location::new().with_file("file2.java").with_line(20)),
        ];
        
        let result = engine.deduplicate_batch(findings).await;
        
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_find_duplicate_groups() {
        let engine = DeduplicationEngine::default();
        
        let findings = vec![
            create_test_finding("Finding 1", Severity::High)
                .with_location(Location::new().with_file("file1.java").with_line(10)),
            create_test_finding("Finding 1", Severity::Medium)
                .with_location(Location::new().with_file("file1.java").with_line(10)),
            create_test_finding("Finding 2", Severity::Critical)
                .with_location(Location::new().with_file("file2.java").with_line(20)),
        ];
        
        let groups = engine.find_duplicate_groups(&findings).await;
        
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].total_count(), 2);
    }

    #[test]
    fn test_duplicate_group() {
        let primary = create_test_finding("Primary", Severity::High);
        let mut group = DuplicateGroup::new(primary.clone());
        
        let dup1 = create_test_finding("Dup1", Severity::Medium);
        let dup2 = create_test_finding("Dup2", Severity::Low);
        
        group.add_duplicate(dup1, 0.95);
        group.add_duplicate(dup2, 0.90);
        
        assert_eq!(group.duplicate_count(), 2);
        assert_eq!(group.total_count(), 3);
        assert_eq!(group.all_ids().len(), 3);
    }

    #[test]
    fn test_compute_hash() {
        let engine = DeduplicationEngine::default();
        
        let finding = create_test_finding("Test", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(42))
            .with_cwe("CWE-798");
        
        let hash = engine.compute_hash(&finding);
        assert!(!hash.is_empty());
        
        // Same finding should produce same hash
        let hash2 = engine.compute_hash(&finding);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_location_similarity() {
        let engine = DeduplicationEngine::default();
        
        let a = create_test_finding("Test", Severity::High)
            .with_location(Location::new().with_file("file.java").with_line(42));
        
        let b = create_test_finding("Test", Severity::High)
            .with_location(Location::new().with_file("file.java").with_line(42));
        
        let c = create_test_finding("Test", Severity::High)
            .with_location(Location::new().with_file("file.java").with_line(50));
        
        let sim_ab = engine.location_similarity(&a, &b);
        let sim_ac = engine.location_similarity(&a, &c);
        
        assert_eq!(sim_ab, 1.0);
        assert!(sim_ac < 1.0);
        assert!(sim_ac > 0.0);
    }

    #[test]
    fn test_text_similarity() {
        let engine = DeduplicationEngine::default();
        
        assert_eq!(engine.text_similarity("exact match", "exact match"), 1.0);
        assert!(engine.text_similarity("hardcoded password", "password hardcoded") > 0.5);
        assert!(engine.text_similarity("completely different", "nothing alike") < 0.3);
    }
}
