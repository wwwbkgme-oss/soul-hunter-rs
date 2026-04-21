//! Intent Analysis Skill
//!
//! Analyzes Android Intent and IPC security:
//! - Implicit intents
//! - Pending intents
//! - Intent interception
//! - Broadcast theft
//! - URI exposure
//! - Clipboard exposure

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Intent security finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentFindingType {
    ImplicitIntent,
    PendingIntent,
    IntentInterception,
    BroadcastTheft,
    UriExposure,
    ClipboardExposure,
    StickyBroadcast,
    OrderedBroadcast,
    ResultReceiver,
}

impl std::fmt::Display for IntentFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentFindingType::ImplicitIntent => write!(f, "implicit_intent"),
            IntentFindingType::PendingIntent => write!(f, "pending_intent"),
            IntentFindingType::IntentInterception => write!(f, "intent_interception"),
            IntentFindingType::BroadcastTheft => write!(f, "broadcast_theft"),
            IntentFindingType::UriExposure => write!(f, "uri_exposure"),
            IntentFindingType::ClipboardExposure => write!(f, "clipboard_exposure"),
            IntentFindingType::StickyBroadcast => write!(f, "sticky_broadcast"),
            IntentFindingType::OrderedBroadcast => write!(f, "ordered_broadcast"),
            IntentFindingType::ResultReceiver => write!(f, "result_receiver"),
        }
    }
}

/// Configuration for intent analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAnalysisConfig {
    pub check_implicit_intents: bool,
    pub check_pending_intents: bool,
    pub check_broadcasts: bool,
    pub check_uri_exposure: bool,
    pub check_clipboard: bool,
}

impl Default for IntentAnalysisConfig {
    fn default() -> Self {
        Self {
            check_implicit_intents: true,
            check_pending_intents: true,
            check_broadcasts: true,
            check_uri_exposure: true,
            check_clipboard: true,
        }
    }
}

/// Intent analysis skill
#[derive(Debug)]
pub struct IntentAnalysisSkill {
    id: SkillId,
    config: IntentAnalysisConfig,
    patterns: HashMap<IntentFindingType, Vec<Regex>>,
}

impl IntentAnalysisSkill {
    pub fn new() -> Self {
        let mut skill = Self {
            id: Uuid::new_v4(),
            config: IntentAnalysisConfig::default(),
            patterns: HashMap::new(),
        };
        skill.compile_patterns();
        skill
    }

    pub fn with_config(mut self, config: IntentAnalysisConfig) -> Self {
        self.config = config;
        self
    }

    fn compile_patterns(&mut self) {
        // Implicit intent patterns
        let implicit_patterns = vec![
            Regex::new(r#"(?i)new\s+Intent\s*\(\s*\)"#).unwrap(),
            Regex::new(r#"(?i)setAction\s*\("#).unwrap(),
            Regex::new(r#"(?i)startActivity\s*\(\s*new\s+Intent"#).unwrap(),
        ];
        self.patterns.insert(IntentFindingType::ImplicitIntent, implicit_patterns);

        // Pending intent patterns
        let pending_patterns = vec![
            Regex::new(r#"(?i)PendingIntent\.getActivity"#).unwrap(),
            Regex::new(r#"(?i)PendingIntent\.getService"#).unwrap(),
            Regex::new(r#"(?i)PendingIntent\.getBroadcast"#).unwrap(),
        ];
        self.patterns.insert(IntentFindingType::PendingIntent, pending_patterns);

        // Sticky broadcast patterns
        let sticky_patterns = vec![
            Regex::new(r#"(?i)sendStickyBroadcast"#).unwrap(),
            Regex::new(r#"(?i)sendStickyOrderedBroadcast"#).unwrap(),
        ];
        self.patterns.insert(IntentFindingType::StickyBroadcast, sticky_patterns);

        // URI exposure patterns
        let uri_patterns = vec![
            Regex::new(r#"(?i)grantUriPermission"#).unwrap(),
            Regex::new(r#"(?i)FLAG_GRANT_READ_URI_PERMISSION"#).unwrap(),
            Regex::new(r#"(?i)FLAG_GRANT_WRITE_URI_PERMISSION"#).unwrap(),
        ];
        self.patterns.insert(IntentFindingType::UriExposure, uri_patterns);

        // Clipboard patterns
        let clipboard_patterns = vec![
            Regex::new(r#"(?i)ClipboardManager"#).unwrap(),
            Regex::new(r#"(?i)setPrimaryClip"#).unwrap(),
            Regex::new(r#"(?i)getPrimaryClip"#).unwrap(),
        ];
        self.patterns.insert(IntentFindingType::ClipboardExposure, clipboard_patterns);
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

        if self.config.check_implicit_intents {
            findings.extend(self.check_patterns(
                path, &lines, &IntentFindingType::ImplicitIntent,
                "Implicit Intent Usage",
                "Implicit intents can be intercepted by malicious apps. Consider using explicit intents.",
                Severity::Medium, "CWE-927"
            ));
        }

        if self.config.check_pending_intents {
            findings.extend(self.check_patterns(
                path, &lines, &IntentFindingType::PendingIntent,
                "Pending Intent Usage",
                "PendingIntents can be hijacked if not properly secured. Ensure proper flags are set.",
                Severity::Medium, "CWE-927"
            ));
        }

        if self.config.check_broadcasts {
            findings.extend(self.check_patterns(
                path, &lines, &IntentFindingType::StickyBroadcast,
                "Sticky Broadcast Usage",
                "Sticky broadcasts are deprecated and can leak sensitive information to any receiver",
                Severity::High, "CWE-927"
            ));
        }

        if self.config.check_uri_exposure {
            findings.extend(self.check_patterns(
                path, &lines, &IntentFindingType::UriExposure,
                "URI Permission Grant",
                "Granting URI permissions can expose file contents to other apps",
                Severity::Medium, "CWE-276"
            ));
        }

        if self.config.check_clipboard {
            findings.extend(self.check_patterns(
                path, &lines, &IntentFindingType::ClipboardExposure,
                "Clipboard Usage",
                "Clipboard data is accessible to any app. Avoid copying sensitive data.",
                Severity::Low, "CWE-200"
            ));
        }

        Ok(findings)
    }

    fn check_patterns(
        &self,
        file_path: &str,
        lines: &[&str],
        pattern_type: &IntentFindingType,
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
                            .with_type("intent_analysis")
                            .with_cwe(cwe)
                            .with_owasp("M1: Improper Platform Usage")
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
impl SecuritySkill for IntentAnalysisSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "intent_analysis"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing intent analysis for: {}", ctx.target.path);

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        let findings = self.analyze_directory(&ctx.target.path).await?;

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(findings)
            .with_metadata("skill_type", serde_json::json!("intent_analysis"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()));

        Ok(result)
    }
}

impl Default for IntentAnalysisSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_analysis_skill_creation() {
        let skill = IntentAnalysisSkill::new();
        assert_eq!(skill.name(), "intent_analysis");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_supported_platforms() {
        let skill = IntentAnalysisSkill::new();
        let platforms = skill.supported_platforms();
        assert!(platforms.contains(&Platform::Android));
        assert!(!platforms.contains(&Platform::Ios));
    }
}
