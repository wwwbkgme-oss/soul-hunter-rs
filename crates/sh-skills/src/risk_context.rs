//! Risk Context Scoring Skill
//!
//! Provides contextual risk scoring based on:
//! - Environment (production vs development)
//! - Asset criticality
//! - Threat landscape
//! - Exploitability
//! - Business impact
//! - Compliance requirements

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Risk context factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    pub environment: Environment,
    pub asset_criticality: AssetCriticality,
    pub exposure: ExposureLevel,
    pub data_sensitivity: DataSensitivity,
    pub compliance_requirements: Vec<ComplianceFramework>,
}

impl Default for RiskContext {
    fn default() -> Self {
        Self {
            environment: Environment::Production,
            asset_criticality: AssetCriticality::Medium,
            exposure: ExposureLevel::Internal,
            data_sensitivity: DataSensitivity::Internal,
            compliance_requirements: Vec::new(),
        }
    }
}

/// Deployment environment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            Environment::Development => 0.5,
            Environment::Staging => 0.8,
            Environment::Production => 1.0,
        }
    }
}

/// Asset criticality level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetCriticality {
    Low,
    Medium,
    High,
    Critical,
}

impl AssetCriticality {
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            AssetCriticality::Low => 0.7,
            AssetCriticality::Medium => 1.0,
            AssetCriticality::High => 1.3,
            AssetCriticality::Critical => 1.5,
        }
    }
}

/// Exposure level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExposureLevel {
    Internal,
    Partner,
    Public,
}

impl ExposureLevel {
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            ExposureLevel::Internal => 0.8,
            ExposureLevel::Partner => 1.0,
            ExposureLevel::Public => 1.3,
        }
    }
}

/// Data sensitivity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataSensitivity {
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            DataSensitivity::Public => 0.7,
            DataSensitivity::Internal => 1.0,
            DataSensitivity::Confidential => 1.3,
            DataSensitivity::Restricted => 1.5,
        }
    }
}

/// Compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    PciDss,
    Hipaa,
    Soc2,
    Gdpr,
    Ccpa,
    Nist,
    Iso27001,
}

impl ComplianceFramework {
    pub fn name(&self) -> &'static str {
        match self {
            ComplianceFramework::PciDss => "PCI DSS",
            ComplianceFramework::Hipaa => "HIPAA",
            ComplianceFramework::Soc2 => "SOC 2",
            ComplianceFramework::Gdpr => "GDPR",
            ComplianceFramework::Ccpa => "CCPA",
            ComplianceFramework::Nist => "NIST",
            ComplianceFramework::Iso27001 => "ISO 27001",
        }
    }
}

/// Risk score with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualRiskScore {
    pub base_severity: Severity,
    pub contextual_score: f64, // 0.0 to 10.0
    pub risk_level: RiskLevel,
    pub factors: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Negligible => write!(f, "negligible"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Configuration for risk context scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContextConfig {
    pub context: RiskContext,
    pub adjust_severity: bool,
    pub generate_recommendations: bool,
}

impl Default for RiskContextConfig {
    fn default() -> Self {
        Self {
            context: RiskContext::default(),
            adjust_severity: true,
            generate_recommendations: true,
        }
    }
}

/// Risk context scoring skill
#[derive(Debug)]
pub struct RiskContextSkill {
    id: SkillId,
    config: RiskContextConfig,
}

impl RiskContextSkill {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            config: RiskContextConfig::default(),
        }
    }

    pub fn with_config(mut self, config: RiskContextConfig) -> Self {
        self.config = config;
        self
    }

    /// Calculate contextual risk score for a finding
    pub fn calculate_risk(&self, finding: &Finding) -> ContextualRiskScore {
        let base_score = self.severity_to_score(&finding.severity);
        let context = &self.config.context;

        // Calculate multipliers
        let env_mult = context.environment.risk_multiplier();
        let asset_mult = context.asset_criticality.risk_multiplier();
        let exposure_mult = context.exposure.risk_multiplier();
        let data_mult = context.data_sensitivity.risk_multiplier();

        // Calculate contextual score
        let contextual_score = base_score * env_mult * asset_mult * exposure_mult * data_mult;
        let clamped_score = contextual_score.min(10.0);

        // Determine risk level
        let risk_level = self.score_to_risk_level(clamped_score);

        // Build factors list
        let mut factors = Vec::new();
        factors.push(format!("Environment: {:?}", context.environment));
        factors.push(format!("Asset Criticality: {:?}", context.asset_criticality));
        factors.push(format!("Exposure: {:?}", context.exposure));
        factors.push(format!("Data Sensitivity: {:?}", context.data_sensitivity));

        // Generate recommendations
        let recommendations = if self.config.generate_recommendations {
            self.generate_recommendations(finding, &risk_level)
        } else {
            Vec::new()
        };

        ContextualRiskScore {
            base_severity: finding.severity.clone(),
            contextual_score: clamped_score,
            risk_level,
            factors,
            recommendations,
        }
    }

    fn severity_to_score(&self, severity: &Severity) -> f64 {
        match severity {
            Severity::Info => 1.0,
            Severity::Low => 3.0,
            Severity::Medium => 5.0,
            Severity::High => 7.5,
            Severity::Critical => 9.0,
        }
    }

    fn score_to_risk_level(&self, score: f64) -> RiskLevel {
        match score {
            s if s < 2.0 => RiskLevel::Negligible,
            s if s < 4.0 => RiskLevel::Low,
            s if s < 6.0 => RiskLevel::Medium,
            s if s < 8.0 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    fn generate_recommendations(&self, finding: &Finding, risk_level: &RiskLevel) -> Vec<String> {
        let mut recommendations = Vec::new();

        match risk_level {
            RiskLevel::Critical => {
                recommendations.push("Immediate remediation required".to_string());
                recommendations.push("Consider taking the application offline".to_string());
            }
            RiskLevel::High => {
                recommendations.push("Prioritize remediation within 7 days".to_string());
            }
            RiskLevel::Medium => {
                recommendations.push("Schedule remediation within 30 days".to_string());
            }
            _ => {}
        }

        // Add compliance-specific recommendations
        for framework in &self.config.context.compliance_requirements {
            match framework {
                ComplianceFramework::PciDss => {
                    recommendations.push("Review PCI DSS compliance requirements".to_string());
                }
                ComplianceFramework::Hipaa => {
                    recommendations.push("Ensure HIPAA safeguards are maintained".to_string());
                }
                ComplianceFramework::Gdpr => {
                    recommendations.push("Review GDPR data protection requirements".to_string());
                }
                _ => {}
            }
        }

        recommendations
    }

    /// Adjust finding severity based on context
    pub fn adjust_finding(&self, mut finding: Finding) -> Finding {
        let risk_score = self.calculate_risk(&finding);

        // Adjust severity if enabled
        if self.config.adjust_severity {
            let new_severity = self.risk_level_to_severity(&risk_score.risk_level);
            if new_severity > finding.severity {
                finding.severity = new_severity;
            }
        }

        // Add risk context metadata
        let metadata = serde_json::json!({
            "contextual_risk_score": risk_score.contextual_score,
            "risk_level": risk_score.risk_level.to_string(),
            "risk_factors": risk_score.factors,
            "recommendations": risk_score.recommendations,
        });

        finding.with_metadata(metadata)
    }

    fn risk_level_to_severity(&self, risk_level: &RiskLevel) -> Severity {
        match risk_level {
            RiskLevel::Negligible => Severity::Info,
            RiskLevel::Low => Severity::Low,
            RiskLevel::Medium => Severity::Medium,
            RiskLevel::High => Severity::High,
            RiskLevel::Critical => Severity::Critical,
        }
    }

    /// Generate risk summary report
    pub fn generate_report(&self, findings: &[Finding]) -> RiskSummaryReport {
        let mut total_score = 0.0;
        let mut risk_distribution: HashMap<RiskLevel, usize> = HashMap::new();
        let mut severity_changes = Vec::new();

        for finding in findings {
            let risk = self.calculate_risk(finding);
            total_score += risk.contextual_score;
            *risk_distribution.entry(risk.risk_level).or_insert(0) += 1;

            if risk.risk_level != self.severity_to_risk_level(&finding.severity) {
                severity_changes.push((finding.id, finding.severity.clone(), risk.risk_level));
            }
        }

        let avg_score = if !findings.is_empty() {
            total_score / findings.len() as f64
        } else {
            0.0
        };

        RiskSummaryReport {
            total_findings: findings.len(),
            average_risk_score: avg_score,
            overall_risk_level: self.score_to_risk_level(avg_score),
            risk_distribution,
            severity_changes,
            context: self.config.context.clone(),
        }
    }

    fn severity_to_risk_level(&self, severity: &Severity) -> RiskLevel {
        match severity {
            Severity::Info => RiskLevel::Negligible,
            Severity::Low => RiskLevel::Low,
            Severity::Medium => RiskLevel::Medium,
            Severity::High => RiskLevel::High,
            Severity::Critical => RiskLevel::Critical,
        }
    }
}

#[async_trait]
impl SecuritySkill for RiskContextSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "risk_context"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web, Platform::Iot, Platform::Network]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing risk context scoring");

        // Get findings from context
        let findings: Vec<Finding> = ctx.config.options.get("findings")
            .and_then(|v| serde_json::from_value::<Vec<Finding>>(v.clone()).ok())
            .unwrap_or_default();

        if findings.is_empty() {
            return Ok(SkillResult::new(self.id, ctx.task_id));
        }

        // Adjust findings with risk context
        let adjusted_findings: Vec<Finding> = findings
            .into_iter()
            .map(|f| self.adjust_finding(f))
            .collect();

        // Generate report
        let report = self.generate_report(&adjusted_findings);

        // Create summary finding
        let summary = Finding::new(
            "Risk Context Analysis",
            format!(
                "Analyzed {} findings. Overall risk level: {} (avg score: {:.2})",
                report.total_findings, report.overall_risk_level, report.average_risk_score
            ),
        )
        .with_severity(Severity::from(report.overall_risk_level))
        .with_type("risk_context");

        let mut result_findings = vec![summary];
        result_findings.extend(adjusted_findings);

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(result_findings)
            .with_metadata("skill_type", serde_json::json!("risk_context"))
            .with_metadata("report", serde_json::to_value(&report).unwrap_or_default());

        Ok(result)
    }
}

/// Risk summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummaryReport {
    pub total_findings: usize,
    pub average_risk_score: f64,
    pub overall_risk_level: RiskLevel,
    pub risk_distribution: HashMap<RiskLevel, usize>,
    pub severity_changes: Vec<(Uuid, Severity, RiskLevel)>,
    pub context: RiskContext,
}

impl From<RiskLevel> for Severity {
    fn from(level: RiskLevel) -> Self {
        match level {
            RiskLevel::Negligible => Severity::Info,
            RiskLevel::Low => Severity::Low,
            RiskLevel::Medium => Severity::Medium,
            RiskLevel::High => Severity::High,
            RiskLevel::Critical => Severity::Critical,
        }
    }
}

impl Default for RiskContextSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_context_skill_creation() {
        let skill = RiskContextSkill::new();
        assert_eq!(skill.name(), "risk_context");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_calculate_risk() {
        let skill = RiskContextSkill::new();
        let finding = Finding::new("Test", "Test").with_severity(Severity::High);

        let risk = skill.calculate_risk(&finding);
        assert!(risk.contextual_score > 0.0);
        assert!(risk.contextual_score <= 10.0);
    }

    #[test]
    fn test_risk_multipliers() {
        assert_eq!(Environment::Production.risk_multiplier(), 1.0);
        assert_eq!(Environment::Development.risk_multiplier(), 0.5);
        
        assert_eq!(AssetCriticality::Critical.risk_multiplier(), 1.5);
        assert_eq!(AssetCriticality::Low.risk_multiplier(), 0.7);
    }

    #[test]
    fn test_score_to_risk_level() {
        let skill = RiskContextSkill::new();
        
        assert!(matches!(skill.score_to_risk_level(1.0), RiskLevel::Negligible));
        assert!(matches!(skill.score_to_risk_level(3.0), RiskLevel::Low));
        assert!(matches!(skill.score_to_risk_level(5.0), RiskLevel::Medium));
        assert!(matches!(skill.score_to_risk_level(7.0), RiskLevel::High));
        assert!(matches!(skill.score_to_risk_level(9.0), RiskLevel::Critical));
    }
}
