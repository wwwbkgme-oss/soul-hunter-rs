//! Finding Normalizer - Production Ready
//! 
//! Deduplicates and merges findings from multiple tools
//! Based on tracker-brain-rs implementation

use std::collections::HashMap;

use tracing::{debug, info, warn};

use sh_types::prelude::*;
use sh_types::{Confidence, Finding, FindingId, Location, Severity};

/// Finding normalizer for deduplication
#[derive(Debug, Clone)]
pub struct FindingNormalizer {
    similarity_threshold: f64,
}

impl FindingNormalizer {
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.85,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            similarity_threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Normalize a single finding
    pub fn normalize(&self, finding: &Finding) -> NormalizedFinding {
        NormalizedFinding {
            finding: finding.clone(),
            confidence: self.calculate_confidence(finding),
            hash: self.compute_hash(finding),
        }
    }

    /// Normalize batch of findings with deduplication
    pub fn normalize_batch(&self, findings: &[Finding]) -> Vec<Finding> {
        if findings.is_empty() {
            return Vec::new();
        }

        info!("Normalizing {} findings", findings.len());

        // Group findings by type and location
        let mut groups: HashMap<String, Vec<Finding>> = HashMap::new();

        for finding in findings {
            let key = self.grouping_key(finding);
            groups.entry(key).or_default().push(finding.clone());
        }

        debug!("Grouped into {} buckets", groups.len());

        // Merge findings in each group
        let mut normalized: Vec<Finding> = Vec::new();

        for (key, group) in groups {
            if group.len() == 1 {
                normalized.push(group[0].clone());
            } else {
                debug!("Merging {} findings in group {}", group.len(), key);
                let merged = self.merge_group(&group);
                normalized.push(merged);
            }
        }

        info!("After normalization: {} findings", normalized.len());
        normalized
    }

    /// Calculate confidence score for finding
    fn calculate_confidence(&self, finding: &Finding) -> f64 {
        let base_confidence = match finding.confidence {
            Confidence::Confirmed => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Tentative => 0.4,
        };

        // Adjust based on evidence
        let evidence_bonus = (finding.evidence.len() as f64 * 0.1).min(0.2);
        
        // Adjust based on tool reputation (simplified)
        let tool_factor = 0.9; // Would be configurable

        (base_confidence + evidence_bonus) * tool_factor
    }

    /// Compute hash for finding comparison
    fn compute_hash(&self, finding: &Finding) -> String {
        let mut components = vec![
            finding.finding_type.clone(),
            finding.title.clone(),
        ];

        if let Some(ref path) = finding.location.file_path {
            components.push(path.clone());
        }

        if let Some(ref cwe) = finding.cwe_id {
            components.push(cwe.clone());
        }

        // Simple hash - in production would use proper hashing
        format!("{:x}", components.join("|").as_bytes().iter().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(*b as u64)
        }))
    }

    /// Generate grouping key for deduplication
    fn grouping_key(&self, finding: &Finding) -> String {
        let location_key = finding.location.file_path.as_ref()
            .map(|p| p.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let line_key = finding.location.line_number
            .map(|l| format!(":{}", l))
            .unwrap_or_default();

        format!("{}|{}{}", finding.finding_type, location_key, line_key)
    }

    /// Merge findings in a group
    fn merge_group(&self, findings: &[Finding]) -> Finding {
        if findings.is_empty() {
            panic!("Cannot merge empty group");
        }

        if findings.len() == 1 {
            return findings[0].clone();
        }

        // Use the first finding as base
        let mut base = findings[0].clone();

        // Merge evidence from all findings
        let mut all_evidence = base.evidence.clone();
        for finding in &findings[1..] {
            all_evidence.extend(finding.evidence.clone());
        }
        base.evidence = all_evidence;

        // Take highest severity
        let max_severity = findings.iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        base.severity = max_severity;

        // Take highest confidence
        let max_confidence = findings.iter()
            .map(|f| f.confidence)
            .max_by_key(|c| match c {
                Confidence::Confirmed => 2,
                Confidence::Probable => 1,
                Confidence::Tentative => 0,
            })
            .unwrap_or(Confidence::Tentative);
        base.confidence = max_confidence;

        // Merge correlated IDs
        for finding in &findings[1..] {
            base.correlated_ids.push(finding.id);
        }

        // Update description to indicate merge
        base.description = format!(
            "{}\n\n(Merged from {} similar findings)",
            base.description,
            findings.len()
        );

        base
    }

    /// Calculate similarity between two findings (0.0 - 1.0)
    pub fn similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // Type similarity (high weight)
        if a.finding_type == b.finding_type {
            score += 0.4;
        }
        weights += 0.4;

        // Location similarity
        if let (Some(ref path_a), Some(ref path_b)) = (&a.location.file_path, &b.location.file_path) {
            if path_a == path_b {
                score += 0.3;
            } else if path_a.contains(path_b) || path_b.contains(path_a) {
                score += 0.15;
            }
        }
        weights += 0.3;

        // CWE similarity
        if let (Some(ref cwe_a), Some(ref cwe_b)) = (&a.cwe_id, &b.cwe_id) {
            if cwe_a == cwe_b {
                score += 0.2;
            }
        }
        weights += 0.2;

        // Title similarity (simplified)
        let title_sim = self.text_similarity(&a.title, &b.title);
        score += title_sim * 0.1;
        weights += 0.1;

        if weights > 0.0 {
            score / weights
        } else {
            0.0
        }
    }

    /// Simple text similarity (Jaccard-like)
    fn text_similarity(&self, a: &str, b: &str) -> f64 {
        let a_words: std::collections::HashSet<String> = a.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        let b_words: std::collections::HashSet<String> = b.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if a_words.is_empty() && b_words.is_empty() {
            return 1.0;
        }

        let intersection: std::collections::HashSet<_> = a_words.intersection(&b_words).collect();
        let union: std::collections::HashSet<_> = a_words.union(&b_words).collect();

        intersection.len() as f64 / union.len() as f64
    }

    /// Check if two findings are duplicates
    pub fn is_duplicate(&self, a: &Finding, b: &Finding) -> bool {
        self.similarity(a, b) >= self.similarity_threshold
    }
}

impl Default for FindingNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalized finding with metadata
#[derive(Debug, Clone)]
pub struct NormalizedFinding {
    pub finding: Finding,
    pub confidence: f64,
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(title, "Test description")
            .with_severity(severity)
            .with_type("test_type")
            .with_location(Location::new().with_file("test.java").with_line(42))
    }

    #[test]
    fn test_normalize_single() {
        let normalizer = FindingNormalizer::new();
        let finding = create_test_finding("Test Finding", Severity::High);
        
        let normalized = normalizer.normalize(&finding);
        assert_eq!(normalized.finding.title, "Test Finding");
        assert!(normalized.confidence > 0.0);
        assert!(!normalized.hash.is_empty());
    }

    #[test]
    fn test_normalize_batch() {
        let normalizer = FindingNormalizer::new();
        
        let findings = vec![
            create_test_finding("Finding 1", Severity::High),
            create_test_finding("Finding 2", Severity::Medium),
            create_test_finding("Finding 1", Severity::Low), // Duplicate
        ];

        let normalized = normalizer.normalize_batch(&findings);
        // Should merge the two similar findings
        assert!(normalized.len() <= 2);
    }

    #[test]
    fn test_similarity() {
        let normalizer = FindingNormalizer::new();
        
        let a = create_test_finding("Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(10));
        
        let b = create_test_finding("Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(10));
        
        let c = create_test_finding("Different Issue", Severity::Low)
            .with_location(Location::new().with_file("other.java").with_line(50));

        let sim_ab = normalizer.similarity(&a, &b);
        let sim_ac = normalizer.similarity(&a, &c);

        assert!(sim_ab > sim_ac);
        assert!(sim_ab > 0.8);
        assert!(sim_ac < 0.5);
    }

    #[test]
    fn test_is_duplicate() {
        let normalizer = FindingNormalizer::new();
        
        let a = create_test_finding("Same Issue", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(42));
        
        let b = create_test_finding("Same Issue", Severity::High)
            .with_location(Location::new().with_file("test.java").with_line(42));

        assert!(normalizer.is_duplicate(&a, &b));
    }
}
