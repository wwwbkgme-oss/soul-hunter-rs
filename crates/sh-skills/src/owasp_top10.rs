//! OWASP Top 10 Mapping Skill
//!
//! Maps findings to OWASP Mobile Top 10 categories:
//! - M1: Improper Platform Usage
//! - M2: Insecure Data Storage
//! - M3: Insecure Communication
//! - M4: Insecure Authentication
//! - M5: Insufficient Cryptography
//! - M6: Insecure Authorization
//! - M7: Client Code Quality
//! - M8: Code Tampering
//! - M9: Reverse Engineering
//! - M10: Extraneous Functionality

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// OWASP Mobile Top 10 categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    M1, // Improper Platform Usage
    M2, // Insecure Data Storage
    M3, // Insecure Communication
    M4, // Insecure Authentication
    M5, // Insufficient Cryptography
    M6, // Insecure Authorization
    M7, // Client Code Quality
    M8, // Code Tampering
    M9, // Reverse Engineering
    M10, // Extraneous Functionality
}

impl OwaspCategory {
    pub fn name(&self) -> &'static str {
        match self {
            OwaspCategory::M1 => "Improper Platform Usage",
            OwaspCategory::M2 => "Insecure Data Storage",
            OwaspCategory::M3 => "Insecure Communication",
            OwaspCategory::M4 => "Insecure Authentication",
            OwaspCategory::M5 => "Insufficient Cryptography",
            OwaspCategory::M6 => "Insecure Authorization",
            OwaspCategory::M7 => "Client Code Quality",
            OwaspCategory::M8 => "Code Tampering",
            OwaspCategory::M9 => "Reverse Engineering",
            OwaspCategory::M10 => "Extraneous Functionality",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            OwaspCategory::M1 => "M1",
            OwaspCategory::M2 => "M2",
            OwaspCategory::M3 => "M3",
            OwaspCategory::M4 => "M4",
            OwaspCategory::M5 => "M5",
            OwaspCategory::M6 => "M6",
            OwaspCategory::M7 => "M7",
            OwaspCategory::M8 => "M8",
            OwaspCategory::M9 => "M9",
            OwaspCategory::M10 => "M10",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            OwaspCategory::M1 => "Misuse of platform features or failure to use platform security controls",
            OwaspCategory::M2 => "Insecure storage of sensitive data in device storage",
            OwaspCategory::M3 => "Insufficient protection of data in transit",
            OwaspCategory::M4 => "Weak or improper authentication mechanisms",
            OwaspCategory::M5 => "Use of weak or improper cryptographic algorithms",
            OwaspCategory::M6 => "Poor or missing authorization checks",
            OwaspCategory::M7 => "Poor code quality leading to security issues",
            OwaspCategory::M8 => "Lack of code integrity protections",
            OwaspCategory::M9 => "Lack of code obfuscation or anti-tampering measures",
            OwaspCategory::M10 => "Debug features, test code, or hidden functionality in production",
        }
    }
}

impl std::fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.name())
    }
}

/// Mapping rules for categorizing findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspMappingRule {
    pub finding_type: String,
    pub category: OwaspCategory,
    pub severity_adjustment: i32, // Can adjust severity based on category
}

/// Configuration for OWASP mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspMappingConfig {
    pub generate_summary: bool,
    pub adjust_severity: bool,
    pub custom_rules: Vec<OwaspMappingRule>,
}

impl Default for OwaspMappingConfig {
    fn default() -> Self {
        Self {
            generate_summary: true,
            adjust_severity: false,
            custom_rules: Vec::new(),
        }
    }
}

/// OWASP Top 10 mapping skill
#[derive(Debug)]
pub struct OwaspTop10Skill {
    id: SkillId,
    config: OwaspMappingConfig,
    default_rules: Vec<OwaspMappingRule>,
}

impl OwaspTop10Skill {
    pub fn new() -> Self {
        let mut skill = Self {
            id: Uuid::new_v4(),
            config: OwaspMappingConfig::default(),
            default_rules: Vec::new(),
        };
        skill.initialize_default_rules();
        skill
    }

    pub fn with_config(mut self, config: OwaspMappingConfig) -> Self {
        self.config = config;
        self
    }

    fn initialize_default_rules(&mut self) {
        self.default_rules = vec![
            // M1: Improper Platform Usage
            OwaspMappingRule {
                finding_type: "intent_analysis".to_string(),
                category: OwaspCategory::M1,
                severity_adjustment: 0,
            },
            OwaspMappingRule {
                finding_type: "exported_component".to_string(),
                category: OwaspCategory::M1,
                severity_adjustment: 0,
            },
            // M2: Insecure Data Storage
            OwaspMappingRule {
                finding_type: "hardcoded_secret".to_string(),
                category: OwaspCategory::M2,
                severity_adjustment: 1,
            },
            OwaspMappingRule {
                finding_type: "external_storage".to_string(),
                category: OwaspCategory::M2,
                severity_adjustment: 0,
            },
            // M3: Insecure Communication
            OwaspMappingRule {
                finding_type: "network_security".to_string(),
                category: OwaspCategory::M3,
                severity_adjustment: 0,
            },
            OwaspMappingRule {
                finding_type: "cleartext_traffic".to_string(),
                category: OwaspCategory::M3,
                severity_adjustment: 1,
            },
            // M4: Insecure Authentication
            OwaspMappingRule {
                finding_type: "weak_auth".to_string(),
                category: OwaspCategory::M4,
                severity_adjustment: 0,
            },
            // M5: Insufficient Cryptography
            OwaspMappingRule {
                finding_type: "crypto_analysis".to_string(),
                category: OwaspCategory::M5,
                severity_adjustment: 0,
            },
            OwaspMappingRule {
                finding_type: "weak_crypto".to_string(),
                category: OwaspCategory::M5,
                severity_adjustment: 1,
            },
            // M6: Insecure Authorization
            OwaspMappingRule {
                finding_type: "permission".to_string(),
                category: OwaspCategory::M6,
                severity_adjustment: 0,
            },
            // M7: Client Code Quality
            OwaspMappingRule {
                finding_type: "static_analysis".to_string(),
                category: OwaspCategory::M7,
                severity_adjustment: 0,
            },
            OwaspMappingRule {
                finding_type: "sql_injection".to_string(),
                category: OwaspCategory::M7,
                severity_adjustment: 1,
            },
            // M8: Code Tampering
            OwaspMappingRule {
                finding_type: "debuggable".to_string(),
                category: OwaspCategory::M8,
                severity_adjustment: 0,
            },
            // M9: Reverse Engineering
            OwaspMappingRule {
                finding_type: "obfuscation".to_string(),
                category: OwaspCategory::M9,
                severity_adjustment: 0,
            },
            // M10: Extraneous Functionality
            OwaspMappingRule {
                finding_type: "debug_code".to_string(),
                category: OwaspCategory::M10,
                severity_adjustment: 0,
            },
            OwaspMappingRule {
                finding_type: "test_code".to_string(),
                category: OwaspCategory::M10,
                severity_adjustment: 0,
            },
        ];
    }

    /// Categorize findings by OWASP Mobile Top 10
    pub fn categorize_findings(&self, findings: &[Finding]) -> HashMap<OwaspCategory, Vec<Finding>> {
        let mut categorized: HashMap<OwaspCategory, Vec<Finding>> = HashMap::new();

        for finding in findings {
            let category = self.determine_category(finding);
            categorized.entry(category).or_default().push(finding.clone());
        }

        categorized
    }

    fn determine_category(&self, finding: &Finding) -> OwaspCategory {
        // Check custom rules first
        for rule in &self.config.custom_rules {
            if finding.finding_type.contains(&rule.finding_type) {
                return rule.category;
            }
        }

        // Check default rules
        for rule in &self.default_rules {
            if finding.finding_type.contains(&rule.finding_type) {
                return rule.category;
            }
        }

        // Check OWASP category already set
        if let Some(ref owasp) = finding.owasp_category {
            return self.parse_owasp_category(owasp);
        }

        // Default to M7 for unknown findings
        OwaspCategory::M7
    }

    fn parse_owasp_category(&self, category: &str) -> OwaspCategory {
        match category {
            s if s.contains("M1") => OwaspCategory::M1,
            s if s.contains("M2") => OwaspCategory::M2,
            s if s.contains("M3") => OwaspCategory::M3,
            s if s.contains("M4") => OwaspCategory::M4,
            s if s.contains("M5") => OwaspCategory::M5,
            s if s.contains("M6") => OwaspCategory::M6,
            s if s.contains("M7") => OwaspCategory::M7,
            s if s.contains("M8") => OwaspCategory::M8,
            s if s.contains("M9") => OwaspCategory::M9,
            s if s.contains("M10") => OwaspCategory::M10,
            _ => OwaspCategory::M7,
        }
    }

    /// Generate OWASP compliance report
    pub fn generate_report(
        &self,
        categorized: &HashMap<OwaspCategory, Vec<Finding>>,
    ) -> OwaspComplianceReport {
        let mut category_summaries = HashMap::new();

        for category in [
            OwaspCategory::M1,
            OwaspCategory::M2,
            OwaspCategory::M3,
            OwaspCategory::M4,
            OwaspCategory::M5,
            OwaspCategory::M6,
            OwaspCategory::M7,
            OwaspCategory::M8,
            OwaspCategory::M9,
            OwaspCategory::M10,
        ] {
            let findings = categorized.get(&category).cloned().unwrap_or_default();
            let summary = CategorySummary {
                category,
                finding_count: findings.len(),
                critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
                medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            };
            category_summaries.insert(category, summary);
        }

        OwaspComplianceReport {
            category_summaries,
            total_findings: categorized.values().map(|v| v.len()).sum(),
        }
    }
}

#[async_trait]
impl SecuritySkill for OwaspTop10Skill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "owasp_top10"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web, Platform::Iot]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing OWASP Top 10 mapping");

        // This skill works on existing findings, so we expect them in the context
        let findings: Vec<Finding> = ctx.config.options.get("findings")
            .and_then(|v| serde_json::from_value::<Vec<Finding>>(v.clone()).ok())
            .unwrap_or_default();

        let categorized = self.categorize_findings(&findings);
        let report = self.generate_report(&categorized);

        // Create a summary finding
        let summary_finding = Finding::new(
            "OWASP Mobile Top 10 Compliance Report",
            format!("Analysis found {} findings across {} OWASP categories", 
                report.total_findings, report.category_summaries.len()),
        )
        .with_severity(Severity::Info)
        .with_type("owasp_compliance");

        let mut result_findings = vec![summary_finding];
        result_findings.extend(findings);

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(result_findings)
            .with_metadata("skill_type", serde_json::json!("owasp_top10"))
            .with_metadata("categorized", serde_json::to_value(&categorized).unwrap_or_default())
            .with_metadata("report", serde_json::to_value(&report).unwrap_or_default());

        Ok(result)
    }
}

/// Summary of findings for an OWASP category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: OwaspCategory,
    pub finding_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// OWASP compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspComplianceReport {
    pub category_summaries: HashMap<OwaspCategory, CategorySummary>,
    pub total_findings: usize,
}

impl Default for OwaspTop10Skill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owasp_category_display() {
        assert_eq!(OwaspCategory::M1.to_string(), "M1: Improper Platform Usage");
        assert_eq!(OwaspCategory::M5.to_string(), "M5: Insufficient Cryptography");
    }

    #[test]
    fn test_owasp_skill_creation() {
        let skill = OwaspTop10Skill::new();
        assert_eq!(skill.name(), "owasp_top10");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_categorize_findings() {
        let skill = OwaspTop10Skill::new();
        let findings = vec![
            Finding::new("Test", "Test").with_type("crypto_analysis"),
            Finding::new("Test2", "Test2").with_type("network_security"),
        ];

        let categorized = skill.categorize_findings(&findings);
        assert!(categorized.contains_key(&OwaspCategory::M5)); // crypto -> M5
        assert!(categorized.contains_key(&OwaspCategory::M3)); // network -> M3
    }
}
