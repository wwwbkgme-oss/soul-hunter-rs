//! Finding Correlation Engine
//!
//! Correlates related findings from multiple sources using configurable
//! similarity strategies. Supports multiple correlation algorithms including
//! location-based, CWE-based, and semantic similarity.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use tracing::{debug, instrument, warn};

use sh_types::{Finding, FindingId, Location, Severity};

use crate::{FindingError, Result};

/// Configuration for correlation operations
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Similarity threshold for correlation (0.0 - 1.0)
    pub similarity_threshold: f64,
    /// Maximum distance in lines for location-based correlation
    pub max_line_distance: u32,
    /// Consider file path in similarity calculation
    pub consider_location: bool,
    /// Consider CWE ID in similarity calculation
    pub consider_cwe: bool,
    /// Consider finding type in similarity calculation
    pub consider_type: bool,
    /// Consider title similarity
    pub consider_title: bool,
    /// Weight for location similarity
    pub location_weight: f64,
    /// Weight for CWE similarity
    pub cwe_weight: f64,
    /// Weight for type similarity
    pub type_weight: f64,
    /// Weight for title similarity
    pub title_weight: f64,
    /// Maximum number of correlations per finding
    pub max_correlations: usize,
}

impl CorrelationConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.75,
            max_line_distance: 50,
            consider_location: true,
            consider_cwe: true,
            consider_type: true,
            consider_title: true,
            location_weight: 0.35,
            cwe_weight: 0.25,
            type_weight: 0.25,
            title_weight: 0.15,
            max_correlations: 10,
        }
    }
    
    /// Set similarity threshold
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
        self
    }
    
    /// Set maximum line distance
    pub fn with_max_line_distance(mut self, distance: u32) -> Self {
        self.max_line_distance = distance;
        self
    }
    
    /// Set location consideration
    pub fn with_consider_location(mut self, consider: bool) -> Self {
        self.consider_location = consider;
        self
    }
    
    /// Set CWE consideration
    pub fn with_consider_cwe(mut self, consider: bool) -> Self {
        self.consider_cwe = consider;
        self
    }
    
    /// Set type consideration
    pub fn with_consider_type(mut self, consider: bool) -> Self {
        self.consider_type = consider;
        self
    }
    
    /// Set title consideration
    pub fn with_consider_title(mut self, consider: bool) -> Self {
        self.consider_title = consider;
        self
    }
    
    /// Set weights for similarity components
    pub fn with_weights(mut self, location: f64, cwe: f64, type_w: f64, title: f64) -> Self {
        let total = location + cwe + type_w + title;
        if total > 0.0 {
            self.location_weight = location / total;
            self.cwe_weight = cwe / total;
            self.type_weight = type_w / total;
            self.title_weight = title / total;
        }
        self
    }
    
    /// Set maximum correlations
    pub fn with_max_correlations(mut self, max: usize) -> Self {
        self.max_correlations = max.max(1);
        self
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Similarity calculation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityStrategy {
    /// Exact matching
    Exact,
    /// Jaccard similarity for text
    Jaccard,
    /// Levenshtein distance for text
    Levenshtein,
    /// Combined strategy
    Combined,
}

/// A group of correlated findings
#[derive(Debug, Clone)]
pub struct CorrelationGroup {
    /// Primary finding ID
    pub primary_id: FindingId,
    /// IDs of correlated findings
    pub correlated_ids: Vec<FindingId>,
    /// Average similarity score
    pub avg_similarity: f64,
    /// Common CWE ID if any
    pub common_cwe: Option<String>,
    /// Common file path if any
    pub common_path: Option<String>,
}

impl CorrelationGroup {
    /// Create a new correlation group
    pub fn new(primary_id: FindingId) -> Self {
        Self {
            primary_id,
            correlated_ids: Vec::new(),
            avg_similarity: 0.0,
            common_cwe: None,
            common_path: None,
        }
    }
    
    /// Add a correlated finding
    pub fn add_correlation(&mut self, finding_id: FindingId, similarity: f64) {
        self.correlated_ids.push(finding_id);
        
        // Update average
        let n = self.correlated_ids.len() as f64;
        self.avg_similarity = (self.avg_similarity * (n - 1.0) + similarity) / n;
    }
    
    /// Get the size of the group
    pub fn size(&self) -> usize {
        self.correlated_ids.len() + 1 // +1 for primary
    }
}

/// Correlation engine for finding relationships
#[derive(Debug, Clone)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
    strategy: SimilarityStrategy,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            config,
            strategy: SimilarityStrategy::Combined,
        }
    }
    
    /// Create with a specific strategy
    pub fn with_strategy(config: CorrelationConfig, strategy: SimilarityStrategy) -> Self {
        Self { config, strategy }
    }
    
    /// Calculate similarity between two findings
    #[instrument(skip(self, a, b), fields(finding_a = %a.id, finding_b = %b.id))]
    pub fn calculate_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        match self.strategy {
            SimilarityStrategy::Exact => self.exact_similarity(a, b),
            SimilarityStrategy::Jaccard => self.jaccard_similarity(a, b),
            SimilarityStrategy::Levenshtein => self.levenshtein_similarity(a, b),
            SimilarityStrategy::Combined => self.combined_similarity(a, b),
        }
    }
    
    /// Check if two findings should be correlated
    pub fn should_correlate(&self, a: &Finding, b: &Finding) -> bool {
        let similarity = self.calculate_similarity(a, b);
        similarity >= self.config.similarity_threshold
    }
    
    /// Find correlations for a finding in a collection
    #[instrument(skip(self, finding, candidates), fields(finding_id = %finding.id))]
    pub async fn find_correlations(&self, finding: &Finding, candidates: &[Finding]) -> Vec<FindingId> {
        let mut correlations = Vec::new();
        
        for candidate in candidates {
            if candidate.id == finding.id {
                continue;
            }
            
            if self.should_correlate(finding, candidate) {
                debug!(
                    "Found correlation between {} and {} (similarity: {:.2})",
                    finding.id,
                    candidate.id,
                    self.calculate_similarity(finding, candidate)
                );
                correlations.push(candidate.id);
                
                if correlations.len() >= self.config.max_correlations {
                    break;
                }
            }
        }
        
        correlations
    }
    
    /// Correlate a batch of findings and return correlation groups
    #[instrument(skip(self, findings), fields(batch_size = findings.len()))]
    pub async fn correlate_batch(&self, findings: &[Finding]) -> Vec<CorrelationGroup> {
        if findings.len() < 2 {
            return Vec::new();
        }
        
        let mut groups: HashMap<FindingId, CorrelationGroup> = HashMap::new();
        let mut processed = HashSet::new();
        
        for (i, finding) in findings.iter().enumerate() {
            if processed.contains(&finding.id) {
                continue;
            }
            
            let mut group = CorrelationGroup::new(finding.id);
            let mut common_cwe = finding.cwe_id.clone();
            let mut common_path = finding.location.file_path.clone();
            
            for other in &findings[i + 1..] {
                if processed.contains(&other.id) {
                    continue;
                }
                
                let similarity = self.calculate_similarity(finding, other);
                
                if similarity >= self.config.similarity_threshold {
                    group.add_correlation(other.id, similarity);
                    processed.insert(other.id);
                    
                    // Update common attributes
                    if common_cwe != other.cwe_id {
                        common_cwe = None;
                    }
                    if common_path != other.location.file_path {
                        common_path = None;
                    }
                }
            }
            
            if !group.correlated_ids.is_empty() {
                group.common_cwe = common_cwe;
                group.common_path = common_path;
                groups.insert(finding.id, group);
            }
            
            processed.insert(finding.id);
        }
        
        groups.into_values().collect()
    }
    
    /// Exact matching similarity
    fn exact_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;
        
        if self.config.consider_type {
            if a.finding_type == b.finding_type {
                score += self.config.type_weight;
            }
            weights += self.config.type_weight;
        }
        
        if self.config.consider_cwe {
            if let (Some(ref cwe_a), Some(ref cwe_b)) = (&a.cwe_id, &b.cwe_id) {
                if cwe_a == cwe_b {
                    score += self.config.cwe_weight;
                }
            }
            weights += self.config.cwe_weight;
        }
        
        if self.config.consider_location {
            if let (Some(ref path_a), Some(ref path_b)) = (&a.location.file_path, &b.location.file_path) {
                if path_a == path_b {
                    score += self.config.location_weight;
                    
                    // Bonus for close line numbers
                    if let (Some(line_a), Some(line_b)) = (a.location.line_number, b.location.line_number) {
                        let distance = if line_a > line_b {
                            line_a - line_b
                        } else {
                            line_b - line_a
                        };
                        
                        if distance <= self.config.max_line_distance {
                            score += self.config.location_weight * 0.5;
                        }
                    }
                }
            }
            weights += self.config.location_weight;
        }
        
        if weights > 0.0 {
            score / weights
        } else {
            0.0
        }
    }
    
    /// Jaccard similarity for text
    fn jaccard_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let base_sim = self.exact_similarity(a, b);
        
        let title_sim = if self.config.consider_title {
            self.text_jaccard(&a.title, &b.title)
        } else {
            0.0
        };
        
        let desc_sim = self.text_jaccard(&a.description, &b.description);
        
        base_sim * 0.6 + title_sim * 0.2 + desc_sim * 0.2
    }
    
    /// Calculate Jaccard similarity between two strings
    fn text_jaccard(&self, a: &str, b: &str) -> f64 {
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
    
    /// Levenshtein-based similarity
    fn levenshtein_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let base_sim = self.exact_similarity(a, b);
        
        let title_sim = if self.config.consider_title {
            1.0 - (self.levenshtein_distance(&a.title, &b.title) as f64
                / a.title.len().max(b.title.len()) as f64)
        } else {
            0.0
        };
        
        base_sim * 0.7 + title_sim * 0.3
    }
    
    /// Calculate Levenshtein distance
    fn levenshtein_distance(&self, a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        
        let m = a_chars.len();
        let n = b_chars.len();
        
        if m == 0 {
            return n;
        }
        if n == 0 {
            return m;
        }
        
        let mut matrix = vec![vec![0; n + 1]; m + 1];
        
        for i in 0..=m {
            matrix[i][0] = i;
        }
        for j in 0..=n {
            matrix[0][j] = j;
        }
        
        for i in 1..=m {
            for j in 1..=n {
                let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }
        
        matrix[m][n]
    }
    
    /// Combined similarity using multiple strategies
    fn combined_similarity(&self, a: &Finding, b: &Finding) -> f64 {
        let exact = self.exact_similarity(a, b);
        let jaccard = self.jaccard_similarity(a, b);
        
        // Weight exact matches higher
        exact * 0.6 + jaccard * 0.4
    }
    
    /// Get the configuration
    pub fn config(&self) -> &CorrelationConfig {
        &self.config
    }
    
    /// Get the strategy
    pub fn strategy(&self) -> SimilarityStrategy {
        self.strategy
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Confidence, Location};

    fn create_test_finding(id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(title, "Test description")
            .with_severity(severity)
            .with_type("security")
    }

    #[test]
    fn test_correlation_config() {
        let config = CorrelationConfig::new()
            .with_similarity_threshold(0.8)
            .with_max_line_distance(100)
            .with_consider_cwe(false);
        
        assert_eq!(config.similarity_threshold, 0.8);
        assert_eq!(config.max_line_distance, 100);
        assert!(!config.consider_cwe);
    }

    #[test]
    fn test_similarity_calculation() {
        let engine = CorrelationEngine::default();
        
        let a = create_test_finding("1", "Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(42))
            .with_cwe("CWE-798");
        
        let b = create_test_finding("2", "Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(42))
            .with_cwe("CWE-798");
        
        let c = create_test_finding("3", "SQL Injection", Severity::Critical)
            .with_location(Location::new().with_file("query.java").with_line(100))
            .with_cwe("CWE-89");
        
        let sim_ab = engine.calculate_similarity(&a, &b);
        let sim_ac = engine.calculate_similarity(&a, &c);
        
        assert!(sim_ab > sim_ac);
        assert!(sim_ab > 0.8);
    }

    #[tokio::test]
    async fn test_find_correlations() {
        let engine = CorrelationEngine::default();
        
        let base = create_test_finding("1", "Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(42))
            .with_cwe("CWE-798");
        
        let similar = create_test_finding("2", "Hardcoded Password", Severity::High)
            .with_location(Location::new().with_file("config.java").with_line(45))
            .with_cwe("CWE-798");
        
        let different = create_test_finding("3", "SQL Injection", Severity::Critical)
            .with_location(Location::new().with_file("other.java").with_line(100))
            .with_cwe("CWE-89");
        
        let candidates = vec![similar.clone(), different];
        let correlations = engine.find_correlations(&base, &candidates).await;
        
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0], similar.id);
    }

    #[tokio::test]
    async fn test_correlate_batch() {
        let engine = CorrelationEngine::default();
        
        let findings = vec![
            create_test_finding("1", "Hardcoded Password", Severity::High)
                .with_location(Location::new().with_file("config.java").with_line(42))
                .with_cwe("CWE-798"),
            create_test_finding("2", "Hardcoded Password", Severity::Medium)
                .with_location(Location::new().with_file("config.java").with_line(45))
                .with_cwe("CWE-798"),
            create_test_finding("3", "SQL Injection", Severity::Critical)
                .with_location(Location::new().with_file("query.java").with_line(100))
                .with_cwe("CWE-89"),
        ];
        
        let groups = engine.correlate_batch(&findings).await;
        
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].size(), 2);
    }

    #[test]
    fn test_text_jaccard() {
        let engine = CorrelationEngine::default();
        
        let sim1 = engine.text_jaccard("hardcoded password", "hardcoded password");
        assert_eq!(sim1, 1.0);
        
        let sim2 = engine.text_jaccard("hardcoded password", "password hardcoded");
        assert!(sim2 > 0.5);
        
        let sim3 = engine.text_jaccard("hardcoded password", "sql injection");
        assert!(sim3 < 0.5);
    }

    #[test]
    fn test_levenshtein_distance() {
        let engine = CorrelationEngine::default();
        
        assert_eq!(engine.levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(engine.levenshtein_distance("", "abc"), 3);
        assert_eq!(engine.levenshtein_distance("abc", "abc"), 0);
    }

    #[test]
    fn test_correlation_group() {
        let mut group = CorrelationGroup::new(uuid::Uuid::new_v4());
        
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        
        group.add_correlation(id1, 0.9);
        group.add_correlation(id2, 0.8);
        
        assert_eq!(group.size(), 3);
        assert_eq!(group.correlated_ids.len(), 2);
        assert!((group.avg_similarity - 0.85).abs() < 0.01);
    }
}
