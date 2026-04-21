//! Crypto Analysis Skill
//!
//! Identifies cryptographic issues and misconfigurations:
//! - Weak algorithms (DES, RC4, MD5, SHA1)
//! - Insecure modes (ECB)
//! - Weak keys
//! - Hardcoded keys
//! - Insecure random number generation
//! - Improper IV usage

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Cryptographic finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoFindingType {
    WeakAlgorithm,
    InsecureMode,
    WeakKey,
    HardcodedKey,
    InsecureRandom,
    StaticIv,
    PredictableIv,
    WeakPadding,
    DeprecatedApi,
}

impl std::fmt::Display for CryptoFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoFindingType::WeakAlgorithm => write!(f, "weak_algorithm"),
            CryptoFindingType::InsecureMode => write!(f, "insecure_mode"),
            CryptoFindingType::WeakKey => write!(f, "weak_key"),
            CryptoFindingType::HardcodedKey => write!(f, "hardcoded_key"),
            CryptoFindingType::InsecureRandom => write!(f, "insecure_random"),
            CryptoFindingType::StaticIv => write!(f, "static_iv"),
            CryptoFindingType::PredictableIv => write!(f, "predictable_iv"),
            CryptoFindingType::WeakPadding => write!(f, "weak_padding"),
            CryptoFindingType::DeprecatedApi => write!(f, "deprecated_api"),
        }
    }
}

/// Configuration for crypto analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAnalysisConfig {
    pub check_weak_algorithms: bool,
    pub check_insecure_modes: bool,
    pub check_hardcoded_keys: bool,
    pub check_insecure_random: bool,
    pub check_iv_usage: bool,
}

impl Default for CryptoAnalysisConfig {
    fn default() -> Self {
        Self {
            check_weak_algorithms: true,
            check_insecure_modes: true,
            check_hardcoded_keys: true,
            check_insecure_random: true,
            check_iv_usage: true,
        }
    }
}

/// Crypto analysis skill
#[derive(Debug)]
pub struct CryptoAnalysisSkill {
    id: SkillId,
    config: CryptoAnalysisConfig,
    patterns: HashMap<CryptoFindingType, Vec<Regex>>,
}

impl CryptoAnalysisSkill {
    pub fn new() -> Self {
        let mut skill = Self {
            id: Uuid::new_v4(),
            config: CryptoAnalysisConfig::default(),
            patterns: HashMap::new(),
        };
        skill.compile_patterns();
        skill
    }

    pub fn with_config(mut self, config: CryptoAnalysisConfig) -> Self {
        self.config = config;
        self
    }

    fn compile_patterns(&mut self) {
        // Weak algorithm patterns
        let weak_algo_patterns = vec![
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["']DES[^"']*["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["']DESede[^"']*["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["']RC4[^"']*["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["']ARC4[^"']*["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)"#).unwrap(),
        ];
        self.patterns.insert(CryptoFindingType::WeakAlgorithm, weak_algo_patterns);

        // Insecure mode patterns (ECB mode)
        let insecure_mode_patterns = vec![
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["'][^"']*/ECB[^"']*["']\s*\)"#).unwrap(),
            Regex::new(r#"(?i)Cipher\.getInstance\s*\(\s*["']AES/ECB[^"']*["']\s*\)"#).unwrap(),
        ];
        self.patterns.insert(CryptoFindingType::InsecureMode, insecure_mode_patterns);

        // Hardcoded key patterns
        let hardcoded_key_patterns = vec![
            Regex::new(r#"(?i)(secret[_-]?key|private[_-]?key|aes[_-]?key)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)new\s+SecretKeySpec\s*\(\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)SecretKeySpec\s*\(\s*"[^"]+"\.getBytes\(\)"#).unwrap(),
        ];
        self.patterns.insert(CryptoFindingType::HardcodedKey, hardcoded_key_patterns);

        // Insecure random patterns
        let insecure_random_patterns = vec![
            Regex::new(r#"(?i)new\s+Random\(\)"#).unwrap(),
            Regex::new(r#"(?i)Random\s+\w+\s*=\s*new\s+Random\(\)"#).unwrap(),
            Regex::new(r#"(?i)Math\.random\(\)"#).unwrap(),
        ];
        self.patterns.insert(CryptoFindingType::InsecureRandom, insecure_random_patterns);

        // Static IV patterns
        let static_iv_patterns = vec![
            Regex::new(r#"(?i)IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{\s*0"#).unwrap(),
            Regex::new(r#"(?i)IvParameterSpec\s*\(\s*["'][^"']{8,}["']"#).unwrap(),
            Regex::new(r#"(?i)GCMParameterSpec\s*\([^,]+,\s*new\s+byte"#).unwrap(),
        ];
        self.patterns.insert(CryptoFindingType::StaticIv, static_iv_patterns);
    }

    async fn analyze_directory(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut entries = tokio::fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let path_str = path.to_string_lossy();

            if path.is_dir() {
                let sub_findings = self.analyze_directory(&path_str).await?;
                findings.extend(sub_findings);
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if ext_str == "java" || ext_str == "kt" {
                        let file_findings = self.analyze_file(&path_str).await?;
                        findings.extend(file_findings);
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_file(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return Ok(findings),
        };

        let lines: Vec<&str> = content.lines().collect();

        if self.config.check_weak_algorithms {
            findings.extend(self.check_patterns(
                path, &lines, &CryptoFindingType::WeakAlgorithm,
                "Weak Cryptographic Algorithm",
                "Use of weak cryptographic algorithm detected",
                Severity::High, "CWE-327"
            ));
        }

        if self.config.check_insecure_modes {
            findings.extend(self.check_patterns(
                path, &lines, &CryptoFindingType::InsecureMode,
                "Insecure Cipher Mode",
                "ECB mode does not provide semantic security and should not be used",
                Severity::High, "CWE-327"
            ));
        }

        if self.config.check_hardcoded_keys {
            findings.extend(self.check_patterns(
                path, &lines, &CryptoFindingType::HardcodedKey,
                "Hardcoded Cryptographic Key",
                "Cryptographic keys should not be hardcoded in source code",
                Severity::Critical, "CWE-798"
            ));
        }

        if self.config.check_insecure_random {
            findings.extend(self.check_patterns(
                path, &lines, &CryptoFindingType::InsecureRandom,
                "Insecure Random Number Generation",
                "Use SecureRandom instead of Random for cryptographic operations",
                Severity::Medium, "CWE-338"
            ));
        }

        if self.config.check_iv_usage {
            findings.extend(self.check_patterns(
                path, &lines, &CryptoFindingType::StaticIv,
                "Static Initialization Vector",
                "IV should be randomly generated for each encryption operation",
                Severity::High, "CWE-329"
            ));
        }

        Ok(findings)
    }

    fn check_patterns(
        &self,
        file_path: &str,
        lines: &[&str],
        pattern_type: &CryptoFindingType,
        title: &str,
        description: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(patterns) = self.patterns.get(pattern_type) {
            for (line_num, line) in lines.iter().enumerate() {
                for pattern in patterns {
                    if pattern.is_match(line) {
                        let finding = Finding::new(title, description)
                            .with_severity(severity.clone())
                            .with_confidence(Confidence::Probable)
                            .with_type("crypto_analysis")
                            .with_cwe(cwe)
                            .with_owasp("M5: Insufficient Cryptography")
                            .with_location(
                                Location::new()
                                    .with_file(file_path)
                                    .with_line((line_num + 1) as u32)
                                    .with_snippet(line.to_string()),
                            );

                        findings.push(finding);
                        break;
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl SecuritySkill for CryptoAnalysisSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "crypto_analysis"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing crypto analysis for: {}", ctx.target.path);

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        let findings = self.analyze_directory(&ctx.target.path).await?;

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(findings)
            .with_metadata("skill_type", serde_json::json!("crypto_analysis"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()));

        Ok(result)
    }
}

impl Default for CryptoAnalysisSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_analysis_skill_creation() {
        let skill = CryptoAnalysisSkill::new();
        assert_eq!(skill.name(), "crypto_analysis");
        assert_eq!(skill.version(), "1.0.0");
    }
}
