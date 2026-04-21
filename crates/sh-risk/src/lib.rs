//! # sh-risk - Risk Scoring Engine
//!
//! Production-ready risk scoring engine for Soul Hunter RS.
//! Merges implementations from tracker-brain-rs and zero-hero-rs.
//!
//! ## Features
//!
//! - **CVSS v3.1 Calculation**: Full CVSS v3.1 base, temporal, and environmental score calculation
//! - **ML-Based Scoring**: Machine learning enhanced risk scoring with confidence weighting
//! - **Business Context**: Asset criticality, data sensitivity, and compliance framework support
//! - **Overall Risk Calculation**: Aggregate risk scoring for assessments and finding collections
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_risk::{CvssCalculator, RiskEngine, BusinessContext, RiskFactors};
//! use sh_types::risk::{CvssScore, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Impact};
//!
//! // Calculate CVSS v3.1 score
//! let cvss = CvssScore {
//!     base_score: 0.0, // Will be calculated
//!     temporal_score: None,
//!     environmental_score: None,
//!     attack_vector: AttackVector::Network,
//!     attack_complexity: AttackComplexity::Low,
//!     privileges_required: PrivilegesRequired::None,
//!     user_interaction: UserInteraction::None,
//!     scope: Scope::Unchanged,
//!     confidentiality_impact: Impact::High,
//!     integrity_impact: Impact::High,
//!     availability_impact: Impact::High,
//!     exploit_code_maturity: None,
//!     remediation_level: None,
//!     report_confidence: None,
//! };
//!
//! let base_score = CvssCalculator::calculate_base_score(&cvss);
//! ```

pub mod cvss;
pub mod engine;
pub mod ml_scoring;

pub use cvss::CvssCalculator;
pub use engine::{RiskEngine, RiskFactors, BusinessContext, ExposureLevel, DataSensitivity, AssetCriticality};
pub use ml_scoring::{MlRiskScorer, MlFeatures, ModelWeights};

use thiserror::Error;

/// Risk engine error types
#[derive(Error, Debug)]
pub enum RiskError {
    #[error("Invalid CVSS metrics: {0}")]
    InvalidCvssMetrics(String),

    #[error("Calculation error: {0}")]
    CalculationError(String),

    #[error("Invalid risk factors: weights must sum to 1.0, got {0}")]
    InvalidRiskFactors(f64),

    #[error("ML model error: {0}")]
    MlModelError(String),

    #[error("Invalid score value: {0}, must be between 0.0 and 10.0")]
    InvalidScore(f64),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, RiskError>;

/// Risk score with detailed breakdown
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RiskScore {
    /// Overall risk score (0.0 - 10.0)
    pub overall: f64,
    /// CVSS component contribution
    pub cvss_component: f64,
    /// Business impact component
    pub business_impact: f64,
    /// Threat level component
    pub threat_level: f64,
    /// ML confidence score (0.0 - 1.0)
    pub ml_confidence: Option<f64>,
    /// Severity rating
    pub severity: sh_types::Severity,
}

impl RiskScore {
    /// Create a new risk score
    pub fn new(overall: f64) -> Self {
        let overall = overall.clamp(0.0, 10.0);
        Self {
            overall,
            cvss_component: 0.0,
            business_impact: 0.0,
            threat_level: 0.0,
            ml_confidence: None,
            severity: Self::calculate_severity(overall),
        }
    }

    /// Create with CVSS component
    pub fn with_cvss(mut self, cvss: f64) -> Self {
        self.cvss_component = cvss.clamp(0.0, 10.0);
        self
    }

    /// Create with business impact
    pub fn with_business_impact(mut self, impact: f64) -> Self {
        self.business_impact = impact.clamp(0.0, 10.0);
        self
    }

    /// Create with threat level
    pub fn with_threat_level(mut self, threat: f64) -> Self {
        self.threat_level = threat.clamp(0.0, 10.0);
        self
    }

    /// Create with ML confidence
    pub fn with_ml_confidence(mut self, confidence: f64) -> Self {
        self.ml_confidence = Some(confidence.clamp(0.0, 1.0));
        self
    }

    /// Calculate severity from score
    fn calculate_severity(score: f64) -> sh_types::Severity {
        match score {
            s if s >= 9.0 => sh_types::Severity::Critical,
            s if s >= 7.0 => sh_types::Severity::High,
            s if s >= 4.0 => sh_types::Severity::Medium,
            s if s >= 0.1 => sh_types::Severity::Low,
            _ => sh_types::Severity::Info,
        }
    }

    /// Get risk level as string
    pub fn risk_level(&self) -> &'static str {
        match self.overall {
            s if s >= 9.0 => "critical",
            s if s >= 7.0 => "high",
            s if s >= 4.0 => "medium",
            s if s >= 0.1 => "low",
            _ => "info",
        }
    }

    /// Check if score is critical
    pub fn is_critical(&self) -> bool {
        self.overall >= 9.0
    }

    /// Check if score is high or above
    pub fn is_high_or_above(&self) -> bool {
        self.overall >= 7.0
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        Self::new(0.0)
    }
}

/// Aggregate risk statistics for collections
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RiskStatistics {
    /// Average risk score
    pub average: f64,
    /// Maximum risk score
    pub maximum: f64,
    /// Minimum risk score
    pub minimum: f64,
    /// Median risk score
    pub median: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Count by severity
    pub by_severity: std::collections::HashMap<sh_types::Severity, usize>,
}

impl RiskStatistics {
    /// Calculate statistics from a collection of scores
    pub fn from_scores(scores: &[RiskScore]) -> Self {
        if scores.is_empty() {
            return Self::default();
        }

        let mut values: Vec<f64> = scores.iter().map(|s| s.overall).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let count = values.len() as f64;
        let sum: f64 = values.iter().sum();
        let average = sum / count;

        let min = values.first().copied().unwrap_or(0.0);
        let max = values.last().copied().unwrap_or(0.0);

        let median = if values.len() % 2 == 0 {
            let mid = values.len() / 2;
            (values[mid - 1] + values[mid]) / 2.0
        } else {
            values[values.len() / 2]
        };

        let variance: f64 = values.iter().map(|v| (v - average).powi(2)).sum::<f64>() / count;
        let std_dev = variance.sqrt();

        let mut by_severity: std::collections::HashMap<sh_types::Severity, usize> =
            std::collections::HashMap::new();
        for score in scores {
            *by_severity.entry(score.severity).or_insert(0) += 1;
        }

        Self {
            average,
            maximum: max,
            minimum: min,
            median,
            std_dev,
            by_severity,
        }
    }

    /// Get total count
    pub fn total_count(&self) -> usize {
        self.by_severity.values().sum()
    }

    /// Get critical count
    pub fn critical_count(&self) -> usize {
        self.by_severity.get(&sh_types::Severity::Critical).copied().unwrap_or(0)
    }

    /// Get high count
    pub fn high_count(&self) -> usize {
        self.by_severity.get(&sh_types::Severity::High).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_creation() {
        let score = RiskScore::new(7.5)
            .with_cvss(8.0)
            .with_business_impact(6.0)
            .with_threat_level(7.0);

        assert_eq!(score.overall, 7.5);
        assert_eq!(score.cvss_component, 8.0);
        assert_eq!(score.business_impact, 6.0);
        assert_eq!(score.threat_level, 7.0);
        assert_eq!(score.severity, sh_types::Severity::High);
    }

    #[test]
    fn test_risk_score_clamping() {
        let score = RiskScore::new(15.0);
        assert_eq!(score.overall, 10.0);

        let score = RiskScore::new(-5.0);
        assert_eq!(score.overall, 0.0);
    }

    #[test]
    fn test_risk_score_severity() {
        assert_eq!(RiskScore::new(9.5).severity, sh_types::Severity::Critical);
        assert_eq!(RiskScore::new(7.5).severity, sh_types::Severity::High);
        assert_eq!(RiskScore::new(5.5).severity, sh_types::Severity::Medium);
        assert_eq!(RiskScore::new(2.5).severity, sh_types::Severity::Low);
        assert_eq!(RiskScore::new(0.0).severity, sh_types::Severity::Info);
    }

    #[test]
    fn test_risk_statistics() {
        let scores = vec![
            RiskScore::new(3.0),
            RiskScore::new(5.0),
            RiskScore::new(7.0),
            RiskScore::new(9.0),
        ];

        let stats = RiskStatistics::from_scores(&scores);

        assert_eq!(stats.average, 6.0);
        assert_eq!(stats.minimum, 3.0);
        assert_eq!(stats.maximum, 9.0);
        assert_eq!(stats.median, 6.0);
        assert!(stats.std_dev > 0.0);
        assert_eq!(stats.total_count(), 4);
    }

    #[test]
    fn test_risk_statistics_empty() {
        let stats = RiskStatistics::from_scores(&[]);
        assert_eq!(stats.average, 0.0);
        assert_eq!(stats.total_count(), 0);
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(RiskScore::new(9.5).risk_level(), "critical");
        assert_eq!(RiskScore::new(7.5).risk_level(), "high");
        assert_eq!(RiskScore::new(5.5).risk_level(), "medium");
        assert_eq!(RiskScore::new(2.5).risk_level(), "low");
        assert_eq!(RiskScore::new(0.0).risk_level(), "info");
    }
}
