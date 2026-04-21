//! Assessment types for security analysis sessions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AnalysisTarget, FindingCollection, JobId, Platform};

/// Unique identifier for assessments
pub type AssessmentId = Uuid;

/// Assessment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Created,
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl Default for AssessmentStatus {
    fn default() -> Self {
        AssessmentStatus::Created
    }
}

/// A security assessment session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub id: AssessmentId,
    pub name: String,
    pub description: Option<String>,
    pub target: AnalysisTarget,
    pub status: AssessmentStatus,
    
    // Timing
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub timeout_secs: Option<u64>,
    
    // Configuration
    pub config: AssessmentConfig,
    
    // Jobs
    pub job_ids: Vec<JobId>,
    
    // Results
    pub findings: Option<FindingCollection>,
    pub risk_score: Option<RiskScore>,
    pub error: Option<String>,
    
    // Metadata
    pub tags: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl Assessment {
    pub fn new(name: impl Into<String>, target: AnalysisTarget) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            target,
            status: AssessmentStatus::Created,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            timeout_secs: None,
            config: AssessmentConfig::default(),
            job_ids: Vec::new(),
            findings: None,
            risk_score: None,
            error: None,
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }

    pub fn with_config(mut self, config: AssessmentConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_job(mut self, job_id: JobId) -> Self {
        self.job_ids.push(job_id);
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn mark_started(&mut self) {
        self.status = AssessmentStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn mark_completed(&mut self, findings: FindingCollection) {
        self.status = AssessmentStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.findings = Some(findings);
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = AssessmentStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error.into());
    }

    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            _ => None,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.status, AssessmentStatus::Completed | AssessmentStatus::Failed | AssessmentStatus::Cancelled)
    }
}

/// Assessment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentConfig {
    pub enable_static_analysis: bool,
    pub enable_dynamic_analysis: bool,
    pub enable_network_analysis: bool,
    pub enable_crypto_analysis: bool,
    pub enable_intent_analysis: bool,
    pub enable_owasp_mapping: bool,
    pub enable_risk_scoring: bool,
    pub enable_evidence_chain: bool,
    pub enable_attack_graph: bool,
    pub enable_correlation: bool,
    pub output_format: crate::job::OutputFormat,
    pub max_workers: u32,
    pub tool_configs: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for AssessmentConfig {
    fn default() -> Self {
        Self {
            enable_static_analysis: true,
            enable_dynamic_analysis: false,
            enable_network_analysis: true,
            enable_crypto_analysis: true,
            enable_intent_analysis: true,
            enable_owasp_mapping: true,
            enable_risk_scoring: true,
            enable_evidence_chain: false,
            enable_attack_graph: false,
            enable_correlation: true,
            output_format: crate::job::OutputFormat::Json,
            max_workers: 4,
            tool_configs: std::collections::HashMap::new(),
        }
    }
}

impl AssessmentConfig {
    pub fn with_static_analysis(mut self, enable: bool) -> Self {
        self.enable_static_analysis = enable;
        self
    }

    pub fn with_dynamic_analysis(mut self, enable: bool) -> Self {
        self.enable_dynamic_analysis = enable;
        self
    }

    pub fn with_network_analysis(mut self, enable: bool) -> Self {
        self.enable_network_analysis = enable;
        self
    }

    pub fn with_crypto_analysis(mut self, enable: bool) -> Self {
        self.enable_crypto_analysis = enable;
        self
    }

    pub fn with_intent_analysis(mut self, enable: bool) -> Self {
        self.enable_intent_analysis = enable;
        self
    }

    pub fn with_owasp_mapping(mut self, enable: bool) -> Self {
        self.enable_owasp_mapping = enable;
        self
    }

    pub fn with_risk_scoring(mut self, enable: bool) -> Self {
        self.enable_risk_scoring = enable;
        self
    }

    pub fn with_evidence_chain(mut self, enable: bool) -> Self {
        self.enable_evidence_chain = enable;
        self
    }

    pub fn with_attack_graph(mut self, enable: bool) -> Self {
        self.enable_attack_graph = enable;
        self
    }

    pub fn with_correlation(mut self, enable: bool) -> Self {
        self.enable_correlation = enable;
        self
    }

    pub fn with_max_workers(mut self, max_workers: u32) -> Self {
        self.max_workers = max_workers;
        self
    }

    pub fn add_tool_config(mut self, tool: impl Into<String>, config: serde_json::Value) -> Self {
        self.tool_configs.insert(tool.into(), config);
        self
    }
}

/// Risk score for an assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall_score: f64,
    pub business_impact: f64,
    pub threat_level: f64,
    pub factors: RiskFactors,
}

impl RiskScore {
    pub fn new(overall_score: f64) -> Self {
        Self {
            overall_score,
            business_impact: 0.0,
            threat_level: 0.0,
            factors: RiskFactors::default(),
        }
    }

    pub fn with_business_impact(mut self, impact: f64) -> Self {
        self.business_impact = impact;
        self
    }

    pub fn with_threat_level(mut self, level: f64) -> Self {
        self.threat_level = level;
        self
    }

    pub fn with_factors(mut self, factors: RiskFactors) -> Self {
        self.factors = factors;
        self
    }
}

/// Risk factor weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    pub cvss: f64,
    pub asset_criticality: f64,
    pub exploitability: f64,
    pub exposure: f64,
    pub data_sensitivity: f64,
    pub compliance: f64,
    pub confidence: f64,
}

impl Default for RiskFactors {
    fn default() -> Self {
        Self {
            cvss: 0.25,
            asset_criticality: 0.20,
            exploitability: 0.20,
            exposure: 0.15,
            data_sensitivity: 0.10,
            compliance: 0.05,
            confidence: 0.05,
        }
    }
}

/// Assessment summary for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub id: AssessmentId,
    pub name: String,
    pub status: AssessmentStatus,
    pub target_path: String,
    pub platform: Platform,
    pub created_at: DateTime<Utc>,
    pub duration_secs: Option<u64>,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub risk_score: Option<f64>,
}

impl From<&Assessment> for AssessmentSummary {
    fn from(assessment: &Assessment) -> Self {
        let (findings_count, critical_count, high_count) = match &assessment.findings {
            Some(findings) => (
                findings.total_count,
                findings.critical().len(),
                findings.high().len(),
            ),
            None => (0, 0, 0),
        };

        Self {
            id: assessment.id,
            name: assessment.name.clone(),
            status: assessment.status,
            target_path: assessment.target.path.clone(),
            platform: assessment.target.platform,
            created_at: assessment.created_at,
            duration_secs: assessment.duration().map(|d| d.num_seconds() as u64),
            findings_count,
            critical_count,
            high_count,
            risk_score: assessment.risk_score.as_ref().map(|r| r.overall_score),
        }
    }
}

/// Assessment filter for querying
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssessmentFilter {
    pub status: Option<AssessmentStatus>,
    pub platform: Option<Platform>,
    pub tags: Vec<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub has_findings: Option<bool>,
}

impl AssessmentFilter {
    pub fn with_status(mut self, status: AssessmentStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_has_findings(mut self, has_findings: bool) -> Self {
        self.has_findings = Some(has_findings);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assessment_builder() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let assessment = Assessment::new("Security Scan", target)
            .with_description("Full security assessment")
            .with_timeout(3600)
            .add_tag("production");

        assert_eq!(assessment.name, "Security Scan");
        assert_eq!(assessment.description, Some("Full security assessment".to_string()));
        assert_eq!(assessment.timeout_secs, Some(3600));
        assert!(assessment.tags.contains(&"production".to_string()));
    }

    #[test]
    fn test_assessment_lifecycle() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let mut assessment = Assessment::new("Test", target);

        assert_eq!(assessment.status, AssessmentStatus::Created);
        
        assessment.mark_started();
        assert_eq!(assessment.status, AssessmentStatus::Running);
        
        let findings = FindingCollection::default();
        assessment.mark_completed(findings);
        assert_eq!(assessment.status, AssessmentStatus::Completed);
        assert!(assessment.is_complete());
    }

    #[test]
    fn test_assessment_config() {
        let config = AssessmentConfig::default()
            .with_static_analysis(true)
            .with_dynamic_analysis(false)
            .with_max_workers(8);

        assert!(config.enable_static_analysis);
        assert!(!config.enable_dynamic_analysis);
        assert_eq!(config.max_workers, 8);
    }

    #[test]
    fn test_risk_score() {
        let score = RiskScore::new(8.5)
            .with_business_impact(7.0)
            .with_threat_level(6.5);

        assert_eq!(score.overall_score, 8.5);
        assert_eq!(score.business_impact, 7.0);
        assert_eq!(score.threat_level, 6.5);
    }
}
