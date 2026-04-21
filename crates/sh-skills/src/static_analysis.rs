//! Static Analysis Skill
//!
//! Performs pattern-based static code analysis to identify:
//! - Hardcoded secrets and credentials
//! - Insecure API usage
//! - SQL injection vulnerabilities
//! - Path traversal issues
//! - Insecure random number generation
//! - Weak cryptographic algorithms

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Static analysis finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StaticAnalysisType {
    HardcodedSecret,
    InsecureApiUsage,
    SqlInjection,
    PathTraversal,
    InsecureRandom,
    WeakCrypto,
    DebugCode,
    CommentedCode,
    SuspiciousPermission,
}

impl std::fmt::Display for StaticAnalysisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StaticAnalysisType::HardcodedSecret => write!(f, "hardcoded_secret"),
            StaticAnalysisType::InsecureApiUsage => write!(f, "insecure_api_usage"),
            StaticAnalysisType::SqlInjection => write!(f, "sql_injection"),
            StaticAnalysisType::PathTraversal => write!(f, "path_traversal"),
            StaticAnalysisType::InsecureRandom => write!(f, "insecure_random"),
            StaticAnalysisType::WeakCrypto => write!(f, "weak_crypto"),
            StaticAnalysisType::DebugCode => write!(f, "debug_code"),
            StaticAnalysisType::CommentedCode => write!(f, "commented_code"),
            StaticAnalysisType::SuspiciousPermission => write!(f, "suspicious_permission"),
        }
    }
}

/// Configuration for static analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisConfig {
    pub check_secrets: bool,
    pub check_insecure_apis: bool,
    pub check_sql_injection: bool,
    pub check_path_traversal: bool,
    pub check_weak_crypto: bool,
    pub file_extensions: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

impl Default for StaticAnalysisConfig {
    fn default() -> Self {
        Self {
            check_secrets: true,
            check_insecure_apis: true,
            check_sql_injection: true,
            check_path_traversal: true,
            check_weak_crypto: true,
            file_extensions: vec![
                "java".to_string(),
                "kt".to_string(),
                "xml".to_string(),
                "swift".to_string(),
                "m".to_string(),
                "mm".to_string(),
            ],
            exclude_patterns: vec![
                "test".to_string(),
                "Test".to_string(),
                "build".to_string(),
            ],
        }
    }
}

/// Static analysis skill
#[derive(Debug)]
pub struct StaticAnalysisSkill {
    id: SkillId,
    config: StaticAnalysisConfig,
    patterns: HashMap<StaticAnalysisType, Vec<Regex>>,
}

impl StaticAnalysisSkill {
    pub fn new() -> Self {
        let mut skill = Self {
            id: Uuid::new_v4(),
            config: StaticAnalysisConfig::default(),
            patterns: HashMap::new(),
        };
        skill.compile_patterns();
        skill
    }

    pub fn with_config(mut self, config: StaticAnalysisConfig) -> Self {
        self.config = config;
        self
    }

    fn compile_patterns(&mut self) {
        // Hardcoded secrets patterns
        let secret_patterns = vec![
            Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']"#).unwrap(),
            Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)(auth[_-]?token|authtoken)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)private[_-]?key\s*[=:]\s*["'][^"']{20,}["']"#).unwrap(),
        ];
        self.patterns.insert(StaticAnalysisType::HardcodedSecret, secret_patterns);

        // Insecure API patterns
        let insecure_api_patterns = vec![
            Regex::new(r#"(?i)Runtime\.getRuntime\(\)\.exec"#).unwrap(),
            Regex::new(r#"(?i)ProcessBuilder"#).unwrap(),
            Regex::new(r#"(?i)setJavaScriptEnabled\(true\)"#).unwrap(),
            Regex::new(r#"(?i)addJavascriptInterface"#).unwrap(),
        ];
        self.patterns.insert(StaticAnalysisType::InsecureApiUsage, insecure_api_patterns);

        // SQL injection patterns
        let sql_patterns = vec![
            Regex::new(r#"(?i)rawQuery\s*\(\s*["'].*\+"#).unwrap(),
            Regex::new(r#"(?i)execSQL\s*\(\s*["'].*\+"#).unwrap(),
            Regex::new(r#"(?i)query\s*\(\s*[^,]*\+"#).unwrap(),
        ];
        self.patterns.insert(StaticAnalysisType::SqlInjection, sql_patterns);

        // Path traversal patterns
        let path_patterns = vec![
            Regex::new(r#"(?i)new\s+File\s*\([^)]*\+"#).unwrap(),
            Regex::new(r#"(?i)getExternalFilesDir"#).unwrap(),
            Regex::new(r#"(?i)Environment\.getExternalStorage"#).unwrap(),
        ];
        self.patterns.insert(StaticAnalysisType::PathTraversal, path_patterns);

        // Weak crypto patterns
        let crypto_patterns = vec![
            Regex::new(r#"(?i)DES\s*\.\s*getInstance"#).unwrap(),
            Regex::new(r#"(?i)RC4\s*\.\s*getInstance"#).unwrap(),
            Regex::new(r#"(?i)ECB\s*\.\s*getInstance"#).unwrap(),
            Regex::new(r#"(?i)MD5\s*\.\s*getInstance"#).unwrap(),
            Regex::new(r#"(?i)SHA-?1\s*\.\s*getInstance"#).unwrap(),
            Regex::new(r#"(?i)Random\(\)"#).unwrap(),
        ];
        self.patterns.insert(StaticAnalysisType::WeakCrypto, crypto_patterns);
    }

    async fn analyze_directory(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut entries = tokio::fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let path_str = path.to_string_lossy();

            // Skip excluded patterns
            if self.should_exclude(&path_str) {
                continue;
            }

            if path.is_dir() {
                // Recursively analyze subdirectories
                let sub_findings = self.analyze_directory(&path_str).await?;
                findings.extend(sub_findings);
            } else if path.is_file() {
                // Check if file extension is in our list
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_string();
                    if self.config.file_extensions.contains(&ext_str) {
                        let file_findings = self.analyze_file(&path_str).await?;
                        findings.extend(file_findings);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn should_exclude(&self, path: &str) -> bool {
        self.config.exclude_patterns.iter().any(|p| path.contains(p))
    }

    async fn analyze_file(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return Ok(findings), // Skip binary files
        };

        let lines: Vec<&str> = content.lines().collect();

        // Check each pattern type
        if self.config.check_secrets {
            findings.extend(self.check_patterns(path, &lines, &StaticAnalysisType::HardcodedSecret, Severity::Critical));
        }

        if self.config.check_insecure_apis {
            findings.extend(self.check_patterns(path, &lines, &StaticAnalysisType::InsecureApiUsage, Severity::High));
        }

        if self.config.check_sql_injection {
            findings.extend(self.check_patterns(path, &lines, &StaticAnalysisType::SqlInjection, Severity::High));
        }

        if self.config.check_path_traversal {
            findings.extend(self.check_patterns(path, &lines, &StaticAnalysisType::PathTraversal, Severity::Medium));
        }

        if self.config.check_weak_crypto {
            findings.extend(self.check_patterns(path, &lines, &StaticAnalysisType::WeakCrypto, Severity::High));
        }

        Ok(findings)
    }

    fn check_patterns(
        &self,
        file_path: &str,
        lines: &[&str],
        pattern_type: &StaticAnalysisType,
        severity: Severity,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(patterns) = self.patterns.get(pattern_type) {
            for (line_num, line) in lines.iter().enumerate() {
                for pattern in patterns {
                    if pattern.is_match(line) {
                        let finding = Finding::new(
                            format!("{:?} Detected", pattern_type),
                            format!("Potential {} found in code", pattern_type),
                        )
                        .with_severity(severity.clone())
                        .with_confidence(Confidence::Probable)
                        .with_type("static_analysis")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_line((line_num + 1) as u32)
                                .with_snippet(line.to_string()),
                        );

                        findings.push(finding);
                        break; // Only report once per line
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl SecuritySkill for StaticAnalysisSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "static_analysis"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing static analysis for: {}", ctx.target.path);

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        let findings = self.analyze_directory(&ctx.target.path).await?;

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(findings)
            .with_metadata("skill_type", serde_json::json!("static_analysis"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()));

        Ok(result)
    }
}

impl Default for StaticAnalysisSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_analysis_skill_creation() {
        let skill = StaticAnalysisSkill::new();
        assert_eq!(skill.name(), "static_analysis");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_should_exclude() {
        let skill = StaticAnalysisSkill::new();
        assert!(skill.should_exclude("/path/to/test/file.java"));
        assert!(!skill.should_exclude("/path/to/src/file.java"));
    }
}
