//! Finding Correlation Skill
//!
//! Correlates findings across different analysis types:
//! - Duplicate detection
//! - Related finding chains
//! - Attack path construction
//! - Finding clusters
//! - Cross-skill correlation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, FindingId, Location, Platform, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Correlation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    Duplicate,      // Same issue found by multiple tools
    Related,        // Related findings
    Chain,          // Part of an attack chain
    Cluster,        // Part of a finding cluster
    Supersedes,     // One finding supersedes another
}

/// Correlation between findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCorrelation {
    pub source_id: FindingId,
    pub target_id: FindingId,
    pub correlation_type: CorrelationType,
    pub confidence: f64, // 0.0 to 1.0
    pub reason: String,
}

/// Configuration for correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    pub detect_duplicates: bool,
    pub detect_chains: bool,
    pub detect_clusters: bool,
    pub similarity_threshold: f64,
    pub max_correlations_per_finding: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            detect_duplicates: true,
            detect_chains: true,
            detect_clusters: true,
            similarity_threshold: 0.8,
            max_correlations_per_finding: 10,
        }
    }
}

/// Correlation skill
#[derive(Debug)]
pub struct CorrelationSkill {
    id: SkillId,
    config: CorrelationConfig,
}

impl CorrelationSkill {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            config: CorrelationConfig::default(),
        }
    }

    pub fn with_config(mut self, config: CorrelationConfig) -> Self {
        self.config = config;
        self
    }

    /// Find duplicate findings
    fn find_duplicates(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut processed = HashSet::new();

        for (i, finding1) in findings.iter().enumerate() {
            if processed.contains(&finding1.id) {
                continue;
            }

            for finding2 in findings.iter().skip(i + 1) {
                if processed.contains(&finding2.id) {
                    continue;
                }

                let similarity = self.calculate_similarity(finding1, finding2);
                if similarity >= self.config.similarity_threshold {
                    correlations.push(FindingCorrelation {
                        source_id: finding1.id,
                        target_id: finding2.id,
                        correlation_type: CorrelationType::Duplicate,
                        confidence: similarity,
                        reason: format!("Similarity score: {:.2}", similarity),
                    });
                    processed.insert(finding2.id);
                }
            }
        }

        correlations
    }

    /// Calculate similarity between two findings (0.0 to 1.0)
    fn calculate_similarity(&self, f1: &Finding, f2: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // Title similarity (weight: 0.3)
        let title_sim = self.string_similarity(&f1.title, &f2.title);
        score += title_sim * 0.3;
        weights += 0.3;

        // Description similarity (weight: 0.2)
        let desc_sim = self.string_similarity(&f1.description, &f2.description);
        score += desc_sim * 0.2;
        weights += 0.2;

        // Location similarity (weight: 0.3)
        let loc_sim = self.location_similarity(&f1.location, &f2.location);
        score += loc_sim * 0.3;
        weights += 0.3;

        // CWE similarity (weight: 0.1)
        if f1.cwe_id == f2.cwe_id && f1.cwe_id.is_some() {
            score += 1.0 * 0.1;
        }
        weights += 0.1;

        // Finding type similarity (weight: 0.1)
        if f1.finding_type == f2.finding_type {
            score += 1.0 * 0.1;
        }
        weights += 0.1;

        if weights > 0.0 {
            score / weights
        } else {
 0.0
        }
    }

    /// Simple string similarity using Jaccard index on words
    fn string_similarity(&self, s1: &str, s2: &str) -> f64 {
        let words1: HashSet<String> = s1.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let words2: HashSet<String> = s2.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if words1.is_empty() && words2.is_empty() {
            return 1.0;
        }
        if words1.is_empty() || words2.is_empty() {
            return 0.0;
        }

        let intersection: HashSet<_> = words1.intersection(&words2).collect();
        let union: HashSet<_> = words1.union(&words2).collect();

        intersection.len() as f64 / union.len() as f64
    }

    /// Calculate location similarity
    fn location_similarity(&self, l1: &Location, l2: &Location) -> f64 {
        let mut matches = 0;
        let mut total = 0;

        if let (Some(f1), Some(f2)) = (&l1.file_path, &l2.file_path) {
            total += 1;
            if f1 == f2 {
                matches += 1;
            }
        }

        if let (Some(n1), Some(n2)) = (&l1.line_number, &l2.line_number) {
            total += 1;
            // Lines within 5 lines are considered similar
            if (*n1 as i32 - *n2 as i32).abs() <= 5 {
                matches += 1;
            }
        }

        if let (Some(f1), Some(f2)) = (&l1.function_name, &l2.function_name) {
            total += 1;
            if f1 == f2 {
                matches += 1;
            }
        }

        if total > 0 {
            matches as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Find related findings (different but related issues)
    fn find_related(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();

        for (i, finding1) in findings.iter().enumerate() {
            for finding2 in findings.iter().skip(i + 1) {
                // Check if findings are in the same file and related by CWE
                if let (Some(cwe1), Some(cwe2)) = (&finding1.cwe_id, &finding2.cwe_id) {
                    if cwe1 == cwe2 && self.same_file(&finding1.location, &finding2.location) {
                        correlations.push(FindingCorrelation {
                            source_id: finding1.id,
                            target_id: finding2.id,
                            correlation_type: CorrelationType::Related,
                            confidence: 0.7,
                            reason: format!("Same CWE ({}) in same file", cwe1),
                        });
                    }
                }

                // Check for attack chains (e.g., exported component + implicit intent)
                if self.forms_attack_chain(finding1, finding2) {
                    correlations.push(FindingCorrelation {
                        source_id: finding1.id,
                        target_id: finding2.id,
                        correlation_type: CorrelationType::Chain,
                        confidence: 0.8,
                        reason: "Forms potential attack chain".to_string(),
                    });
                }
            }
        }

        correlations
    }

    fn same_file(&self, l1: &Location, l2: &Location) -> bool {
        match (&l1.file_path, &l2.file_path) {
            (Some(f1), Some(f2)) => f1 == f2,
            _ => false,
        }
    }

    /// Check if two findings form an attack chain
    fn forms_attack_chain(&self, f1: &Finding, f2: &Finding) -> bool {
        // Example: exported component + implicit intent could form a chain
        let chain_patterns = vec![
            ("exported_component", "implicit_intent"),
            ("debuggable", "hardcoded_secret"),
            ("cleartext_traffic", "network_listener"),
        ];

        for (type1, type2) in &chain_patterns {
            if (f1.finding_type.contains(type1) && f2.finding_type.contains(type2))
                || (f1.finding_type.contains(type2) && f2.finding_type.contains(type1))
            {
                return true;
            }
        }

        false
    }

    /// Group findings into clusters
    fn cluster_findings(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut clusters: HashMap<String, Vec<FindingId>> = HashMap::new();

        // Group by file
        for finding in findings {
            if let Some(ref file) = finding.location.file_path {
                clusters.entry(file.clone()).or_default().push(finding.id);
            }
        }

        // Create cluster correlations
        for (file, ids) in clusters {
            if ids.len() > 1 {
                for (i, id1) in ids.iter().enumerate() {
                    for id2 in ids.iter().skip(i + 1) {
                        correlations.push(FindingCorrelation {
                            source_id: *id1,
                            target_id: *id2,
                            correlation_type: CorrelationType::Cluster,
                            confidence: 0.6,
                            reason: format!("In same file: {}", file),
                        });
                    }
                }
            }
        }

        correlations
    }

    /// Apply correlations to findings (mark duplicates, etc.)
    fn apply_correlations(&self, findings: &mut [Finding], correlations: &[FindingCorrelation]) {
        for corr in correlations {
            match corr.correlation_type {
                CorrelationType::Duplicate => {
                    // Mark the target as duplicate of source
                    if let Some(target) = findings.iter_mut().find(|f| f.id == corr.target_id) {
                        target.duplicate_of = Some(corr.source_id);
                    }
                }
                CorrelationType::Related | CorrelationType::Chain | CorrelationType::Cluster => {
                    // Add correlation to both findings
                    if let Some(source) = findings.iter_mut().find(|f| f.id == corr.source_id) {
                        source.correlated_ids.push(corr.target_id);
                    }
                    if let Some(target) = findings.iter_mut().find(|f| f.id == corr.target_id) {
                        target.correlated_ids.push(corr.source_id);
                    }
                }
                _ => {}
            }
        }
    }
}

#[async_trait]
impl SecuritySkill for CorrelationSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "correlation"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web, Platform::Iot, Platform::Network]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing finding correlation");

        // Get findings from context
        let mut findings: Vec<Finding> = ctx.config.options.get("findings")
            .and_then(|v| serde_json::from_value::<Vec<Finding>>(v.clone()).ok())
            .unwrap_or_default();

        if findings.is_empty() {
            return Ok(SkillResult::new(self.id, ctx.task_id));
        }

        let mut all_correlations = Vec::new();

        // Detect duplicates
        if self.config.detect_duplicates {
            let duplicates = self.find_duplicates(&findings);
            all_correlations.extend(duplicates);
        }

        // Find related findings
        let related = self.find_related(&findings);
        all_correlations.extend(related);

        // Cluster findings
        if self.config.detect_clusters {
            let clusters = self.cluster_findings(&findings);
            all_correlations.extend(clusters);
        }

        // Apply correlations to findings
        self.apply_correlations(&mut findings, &all_correlations);

        // Create correlation summary finding
        let summary = Finding::new(
            "Finding Correlation Analysis",
            format!("Found {} correlations across {} findings", all_correlations.len(), findings.len()),
        )
        .with_severity(Severity::Info)
        .with_type("correlation");

        let mut result_findings = vec![summary];
        result_findings.extend(findings);

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(result_findings)
            .with_metadata("skill_type", serde_json::json!("correlation"))
            .with_metadata("correlation_count", serde_json::json!(all_correlations.len()))
            .with_metadata("correlations", serde_json::to_value(&all_correlations).unwrap_or_default());

        Ok(result)
    }
}

impl Default for CorrelationSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_skill_creation() {
        let skill = CorrelationSkill::new();
        assert_eq!(skill.name(), "correlation");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_string_similarity() {
        let skill = CorrelationSkill::new();
        
        let sim1 = skill.string_similarity("Hardcoded Password", "Hardcoded Password");
        assert_eq!(sim1, 1.0);

        let sim2 = skill.string_similarity("Hardcoded Password", "Hardcoded API Key");
        assert!(sim2 > 0.3 && sim2 < 1.0);

        let sim3 = skill.string_similarity("Completely Different", "Nothing Alike");
        assert!(sim3 < 0.3);
    }

    #[test]
    fn test_location_similarity() {
        let skill = CorrelationSkill::new();
        
        let loc1 = Location::new().with_file("test.java").with_line(10);
        let loc2 = Location::new().with_file("test.java").with_line(12);
        
        let sim = skill.location_similarity(&loc1, &loc2);
        assert!(sim > 0.5);
    }
}
