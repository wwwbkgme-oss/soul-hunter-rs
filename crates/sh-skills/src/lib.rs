//! # Soul Hunter Skills
//!
//! Production-ready security analysis skills for the Soul Hunter platform.
//!
//! ## Architecture
//!
//! Each skill implements the `SecuritySkill` trait, providing a consistent interface
//! for security analysis operations. Skills are:
//!
//! - **Self-contained**: Each skill manages its own configuration and state
//! - **Async-capable**: All skills use async/await for non-blocking execution
//! - **Composable**: Skills can be chained and combined for complex analysis
//! - **Finding-centric**: All skills return standardized `Finding` results
//!
//! ## Available Skills
//!
//! - `AttackSurfaceSkill`: Maps application attack surface
//! - `StaticAnalysisSkill`: Pattern-based static code analysis
//! - `NetworkAnalysisSkill`: Network security configuration analysis
//! - `CryptoAnalysisSkill`: Cryptographic implementation review
//! - `IntentAnalysisSkill`: Android Intent/IPC analysis
//! - `OwaspTop10Skill`: OWASP categorization and mapping
//! - `CorrelationSkill`: Cross-finding correlation engine
//! - `RiskContextSkill`: Contextual risk scoring

pub mod attack_surface;
pub mod correlation;
pub mod crypto_analysis;
pub mod dynamic_analysis;
pub mod error;
pub mod intent_analysis;
pub mod network_analysis;
pub mod owasp_top10;
pub mod risk_context;
pub mod static_analysis;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Finding, FindingCollection, Platform, Severity};

pub use error::{Result, SkillError};

/// Unique identifier for skills
pub type SkillId = Uuid;

/// Configuration for skill execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillConfig {
    pub timeout_secs: u64,
    pub max_findings: usize,
    pub min_severity: Severity,
    pub options: HashMap<String, serde_json::Value>,
}

impl Default for SkillConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300,
            max_findings: 1000,
            min_severity: Severity::Info,
            options: HashMap::new(),
        }
    }
}

impl SkillConfig {
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = max;
        self
    }

    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    pub fn with_option(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.options.insert(key.into(), value);
        self
    }
}

/// Context for skill execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillContext {
    pub skill_id: SkillId,
    pub task_id: Uuid,
    pub target: AnalysisTarget,
    pub config: SkillConfig,
    pub started_at: DateTime<Utc>,
}

impl SkillContext {
    pub fn new(task_id: Uuid, target: AnalysisTarget) -> Self {
        Self {
            skill_id: Uuid::new_v4(),
            task_id,
            target,
            config: SkillConfig::default(),
            started_at: Utc::now(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }
}

/// Result of skill execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResult {
    pub skill_id: SkillId,
    pub task_id: Uuid,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub execution_time_ms: u64,
    pub completed_at: DateTime<Utc>,
}

impl SkillResult {
    pub fn new(skill_id: SkillId, task_id: Uuid) -> Self {
        Self {
            skill_id,
            task_id,
            findings: Vec::new(),
            metadata: HashMap::new(),
            execution_time_ms: 0,
            completed_at: Utc::now(),
        }
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn with_execution_time(mut self, ms: u64) -> Self {
        self.execution_time_ms = ms;
        self
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn collection(&self) -> FindingCollection {
        FindingCollection::new(self.findings.clone())
    }
}

/// Core trait for all security analysis skills
#[async_trait]
pub trait SecuritySkill: Send + Sync {
    /// Get the skill's unique identifier
    fn id(&self) -> SkillId;

    /// Get the skill's name
    fn name(&self) -> &str;

    /// Get the skill's version
    fn version(&self) -> &str;

    /// Get supported platforms
    fn supported_platforms(&self) -> Vec<Platform>;

    /// Check if the skill supports a specific platform
    fn supports_platform(&self, platform: &Platform) -> bool {
        self.supported_platforms().contains(platform)
    }

    /// Execute the skill with the given context
    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult>;

    /// Validate the skill's configuration
    fn validate_config(&self, config: &SkillConfig) -> Result<()> {
        if config.timeout_secs == 0 {
            return Err(SkillError::InvalidConfig(
                "Timeout must be greater than 0".to_string(),
            ));
        }
        if config.max_findings == 0 {
            return Err(SkillError::InvalidConfig(
                "Max findings must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Skill execution utilities
pub mod utils {
    use super::*;
    use std::time::Instant;

    /// Execute a skill with timeout
    pub async fn execute_with_timeout<F, Fut>(
        f: F,
        timeout: Duration,
    ) -> Result<SkillResult>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<SkillResult>>,
    {
        let start = Instant::now();

        match tokio::time::timeout(timeout, f()).await {
            Ok(result) => {
                let elapsed = start.elapsed().as_millis() as u64;
                debug!("Skill executed in {}ms", elapsed);
                result.map(|mut r| {
                    r.execution_time_ms = elapsed;
                    r
                })
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Skill timed out after {}ms", elapsed);
                Err(SkillError::Timeout(format!(
                    "Skill exceeded timeout of {:?}",
                    timeout
                )))
            }
        }
    }

    /// Filter findings by minimum severity
    pub fn filter_by_severity(findings: Vec<Finding>, min_severity: Severity) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Limit the number of findings
    pub fn limit_findings(findings: Vec<Finding>, max: usize) -> Vec<Finding> {
        findings.into_iter().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_config_default() {
        let config = SkillConfig::default();
        assert_eq!(config.timeout_secs, 300);
        assert_eq!(config.max_findings, 1000);
        assert_eq!(config.min_severity, Severity::Info);
    }

    #[test]
    fn test_skill_config_builder() {
        let config = SkillConfig::default()
            .with_timeout(600)
            .with_max_findings(500)
            .with_min_severity(Severity::High);

        assert_eq!(config.timeout_secs, 600);
        assert_eq!(config.max_findings, 500);
        assert_eq!(config.min_severity, Severity::High);
    }

    #[test]
    fn test_skill_context_creation() {
        let task_id = Uuid::new_v4();
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let ctx = SkillContext::new(task_id, target);

        assert_eq!(ctx.task_id, task_id);
        assert_eq!(ctx.target.platform, Platform::Android);
    }

    #[test]
    fn test_skill_result_builder() {
        let skill_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let result = SkillResult::new(skill_id, task_id)
            .with_metadata("key", serde_json::json!("value"))
            .with_execution_time(1000);

        assert_eq!(result.skill_id, skill_id);
        assert_eq!(result.task_id, task_id);
        assert_eq!(result.execution_time_ms, 1000);
        assert_eq!(result.metadata.get("key").unwrap(), "value");
    }
}
