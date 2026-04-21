//! # Static Analysis Agent
//!
//! Performs static analysis on code, binaries, and configuration files without execution.
//! Capabilities include:
//! - APK manifest analysis
//! - Secret detection in source code
//! - Permission analysis
//! - Component analysis (activities, services, receivers, providers)
//! - Pattern matching for known vulnerabilities

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentStatus, AgentType, AnalysisTarget,
    Confidence, Finding, FindingCollection, Location, Platform, Remediation, RemediationEffort,
    Severity,
};
use sh_tools::apk::{ApkParser, ManifestAnalyzer};
use sh_tools::secrets::SecretDetector;

/// Static analysis agent for code and binary analysis
pub struct StaticAgent {
    base: AgentBase,
    secret_patterns: Vec<Regex>,
    vulnerability_patterns: Vec<(Regex, String, Severity)>, // (pattern, description, severity)
}

impl StaticAgent {
    /// Create a new static analysis agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Static)
            .with_capabilities(vec![
                AgentCapability::StaticAnalysis,
                AgentCapability::ManifestParsing,
                AgentCapability::SecretDetection,
                AgentCapability::PermissionAnalysis,
                AgentCapability::ComponentAnalysis,
            ])
            .with_platform(Platform::Android);

        let mut agent = Self {
            base,
            secret_patterns: Self::init_secret_patterns(),
            vulnerability_patterns: Self::init_vulnerability_patterns(),
        };

        // Set initial heartbeat
        agent.update_heartbeat();
        agent
    }

    /// Initialize secret detection patterns
    fn init_secret_patterns() -> Vec<Regex> {
        vec![
            // API keys
            Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]"#).unwrap(),
            // AWS keys
            Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
            // Private keys
            Regex::new(r#"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"#).unwrap(),
            // Passwords in code
            Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]"#).unwrap(),
            // Tokens
            Regex::new(r#"(?i)(token|secret)\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]"#).unwrap(),
            // URLs with credentials
            Regex::new(r#"https?://[^:]+:[^@]+@[a-zA-Z0-9.-]+"#).unwrap(),
        ]
    }

    /// Initialize vulnerability detection patterns
    fn init_vulnerability_patterns() -> Vec<(Regex, String, Severity)> {
        vec![
            // Hardcoded credentials
            (
                Regex::new(r#"(?i)(admin|root|test)\s*[=:]\s*['"]([^'"]+)['"]"#).unwrap(),
                "Hardcoded credentials detected".to_string(),
                Severity::Critical,
            ),
            // Debug mode enabled
            (
                Regex::new(r#"android:debuggable\s*=\s*['"]true['"]"#).unwrap(),
                "Debug mode enabled in manifest".to_string(),
                Severity::High,
            ),
            // Backup enabled
            (
                Regex::new(r#"android:allowBackup\s*=\s*['"]true['"]"#).unwrap(),
                "Application data backup enabled".to_string(),
                Severity::Medium,
            ),
            // HTTP (not HTTPS)
            (
                Regex::new(r#"http://[^\s\"]+"#).unwrap(),
                "Insecure HTTP URL found".to_string(),
                Severity::Medium,
            ),
            // SQL injection patterns
            (
                Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*"#).unwrap(),
                "Potential SQL injection vulnerability".to_string(),
                Severity::High,
            ),
            // Command injection
            (
                Regex::new(r#"(?i)(Runtime\.getRuntime\(\)|exec\s*\(|system\s*\()"#).unwrap(),
                "Potential command injection".to_string(),
                Severity::High,
            ),
        ]
    }

    /// Analyze an APK file
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn analyze_apk(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Starting APK analysis for: {}", target.path);

        let path = Path::new(&target.path);
        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "APK file not found: {}",
                target.path
            )));
        }

        let mut findings = Vec::new();

        // Parse APK structure
        let apk_parser = ApkParser::new(&target.path)
            .map_err(|e| AgentError::Tool(format!("Failed to parse APK: {}", e)))?;

        // Analyze manifest
        let manifest_analyzer = ManifestAnalyzer::new(&apk_parser);
        findings.extend(self.analyze_manifest(&manifest_analyzer).await?);

        // Analyze for secrets
        findings.extend(self.analyze_secrets(&apk_parser).await?);

        // Analyze components
        findings.extend(self.analyze_components(&manifest_analyzer).await?);

        // Analyze for vulnerabilities
        findings.extend(self.analyze_vulnerabilities(&apk_parser).await?);

        info!(
            "APK analysis completed. Found {} findings",
            findings.len()
        );

        Ok(FindingCollection::new(findings))
    }

    /// Analyze AndroidManifest.xml
    #[instrument(skip(self, analyzer))]
    async fn analyze_manifest(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for debug mode
        if let Some(debuggable) = analyzer.is_debuggable() {
            if debuggable {
                findings.push(
                    Finding::new(
                        "Debug Mode Enabled",
                        "The application has debug mode enabled, which can expose sensitive information and allow debugging access in production builds.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("manifest_config")
                    .with_cwe("CWE-489")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Set android:debuggable=\"false\" in the application tag of AndroidManifest.xml for production builds.")
                            .with_effort(RemediationEffort::Trivial)
                            .add_reference("https://developer.android.com/guide/topics/manifest/application-element#debug"),
                    )
                    .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        // Check for backup
        if let Some(allow_backup) = analyzer.allows_backup() {
            if allow_backup {
                findings.push(
                    Finding::new(
                        "Application Backup Enabled",
                        "The application allows data backup, which may expose sensitive user data through backup mechanisms.",
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("manifest_config")
                    .with_cwe("CWE-530")
                    .with_owasp("M2: Insecure Data Storage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Set android:allowBackup=\"false\" in the application tag if the app contains sensitive data that should not be backed up.")
                            .with_effort(RemediationEffort::Low)
                            .add_reference("https://developer.android.com/guide/topics/manifest/application-element#allowbackup"),
                    )
                    .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        // Check for exported components
        findings.extend(self.check_exported_components(analyzer).await?);

        // Check permissions
        findings.extend(self.analyze_permissions(analyzer).await?);

        Ok(findings)
    }

    /// Check for exported components
    #[instrument(skip(self, analyzer))]
    async fn check_exported_components(
        &self,
        analyzer: &ManifestAnalyzer,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check exported activities
        for activity in analyzer.get_exported_activities() {
            findings.push(
                Finding::new(
                    format!("Exported Activity: {}", activity),
                    "This activity is exported and can be accessed by other applications. Ensure proper permission checks are in place.",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Confirmed)
                .with_type("exported_component")
                .with_cwe("CWE-926")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(
                    Location::new()
                        .with_file("AndroidManifest.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Review if this component needs to be exported. If not, set android:exported=\"false\". If it must be exported, implement proper permission checks.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("StaticAgent", "0.1.0"),
            );
        }

        // Check exported services
        for service in analyzer.get_exported_services() {
            findings.push(
                Finding::new(
                    format!("Exported Service: {}", service),
                    "This service is exported and can be accessed by other applications. Ensure proper permission checks are in place.",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Confirmed)
                .with_type("exported_component")
                .with_cwe("CWE-926")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(
                    Location::new()
                        .with_file("AndroidManifest.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Review if this component needs to be exported. If not, set android:exported=\"false\". If it must be exported, implement proper permission checks.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("StaticAgent", "0.1.0"),
            );
        }

        // Check exported receivers
        for receiver in analyzer.get_exported_receivers() {
            findings.push(
                Finding::new(
                    format!("Exported BroadcastReceiver: {}", receiver),
                    "This broadcast receiver is exported and can receive broadcasts from any application. Ensure proper permission checks are in place.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("exported_component")
                .with_cwe("CWE-926")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(
                    Location::new()
                        .with_file("AndroidManifest.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Review if this component needs to be exported. If not, set android:exported=\"false\". If it must be exported, implement proper permission checks and validate intent data.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("StaticAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze permissions
    #[instrument(skip(self, analyzer))]
    async fn analyze_permissions(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let dangerous_permissions = vec![
            ("android.permission.READ_EXTERNAL_STORAGE", "External Storage Read", Severity::Medium),
            ("android.permission.WRITE_EXTERNAL_STORAGE", "External Storage Write", Severity::Medium),
            ("android.permission.READ_CONTACTS", "Contacts Read", Severity::High),
            ("android.permission.WRITE_CONTACTS", "Contacts Write", Severity::High),
            ("android.permission.READ_SMS", "SMS Read", Severity::High),
            ("android.permission.SEND_SMS", "SMS Send", Severity::Critical),
            ("android.permission.CALL_PHONE", "Phone Call", Severity::High),
            ("android.permission.READ_PHONE_STATE", "Phone State Read", Severity::High),
            ("android.permission.ACCESS_FINE_LOCATION", "Precise Location", Severity::High),
            ("android.permission.ACCESS_COARSE_LOCATION", "Approximate Location", Severity::Medium),
            ("android.permission.CAMERA", "Camera Access", Severity::Medium),
            ("android.permission.RECORD_AUDIO", "Audio Recording", Severity::High),
            ("android.permission.INTERNET", "Internet Access", Severity::Low),
        ];

        let permissions = analyzer.get_permissions();

        for (perm, desc, severity) in dangerous_permissions {
            if permissions.contains(&perm.to_string()) {
                findings.push(
                    Finding::new(
                        format!("Dangerous Permission: {}", desc),
                        format!("The application requests the {} permission ({}). Ensure this permission is necessary and properly justified.", desc, perm),
                    )
                    .with_severity(severity)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("dangerous_permission")
                    .with_cwe("CWE-250")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Review if this permission is necessary. If not, remove it. If required, ensure proper justification and user consent mechanisms are in place.")
                            .with_effort(RemediationEffort::Low),
                    )
                    .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Analyze for secrets
    #[instrument(skip(self, parser))]
    async fn analyze_secrets(&self, parser: &ApkParser) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get all text files from APK
        let text_files = parser
            .get_text_files()
            .map_err(|e| AgentError::Tool(format!("Failed to get text files: {}", e)))?;

        for (file_path, content) in text_files {
            for pattern in &self.secret_patterns {
                for mat in pattern.find_iter(&content) {
                    let finding = Finding::new(
                        "Potential Secret/Credential Exposed",
                        format!(
                            "A potential secret or credential was found in the application. Pattern matched: {}",
                            mat.as_str().chars().take(50).collect::<String>()
                        ),
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Probable)
                    .with_type("secret_exposure")
                    .with_cwe("CWE-798")
                    .with_owasp("M2: Insecure Data Storage")
                    .with_location(
                        Location::new()
                            .with_file(&file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Remove hardcoded secrets from the codebase. Use secure storage mechanisms like Android Keystore or environment variables.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05d-Testing-Data-Storage")
                            .add_reference("https://developer.android.com/training/articles/keystore"),
                    )
                    .with_tool("StaticAgent", "0.1.0");

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Analyze components
    #[instrument(skip(self, analyzer))]
    async fn analyze_components(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze content providers
        for provider in analyzer.get_content_providers() {
            if provider.exported && provider.read_permission.is_none() && provider.write_permission.is_none() {
                findings.push(
                    Finding::new(
                        format!("Unprotected ContentProvider: {}", provider.name),
                        "This content provider is exported without read/write permissions, potentially exposing sensitive data to other applications.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("unprotected_provider")
                    .with_cwe("CWE-284")
                    .with_owasp("M2: Insecure Data Storage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Add android:readPermission and/or android:writePermission attributes to protect this content provider, or set android:exported=\"false\" if it doesn't need to be accessed externally.")
                            .with_effort(RemediationEffort::Medium),
                    )
                    .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Analyze for vulnerabilities
    #[instrument(skip(self, parser))]
    async fn analyze_vulnerabilities(&self, parser: &ApkParser) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get all text files from APK
        let text_files = parser
            .get_text_files()
            .map_err(|e| AgentError::Tool(format!("Failed to get text files: {}", e)))?;

        for (file_path, content) in text_files {
            for (pattern, description, severity) in &self.vulnerability_patterns {
                for mat in pattern.find_iter(&content) {
                    let finding = Finding::new(
                        "Potential Vulnerability",
                        description.clone(),
                    )
                    .with_severity(*severity)
                    .with_confidence(Confidence::Probable)
                    .with_type("code_vulnerability")
                    .with_location(
                        Location::new()
                            .with_file(&file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Review this code pattern and implement secure alternatives. Consider using security libraries and following secure coding practices.")
                            .with_effort(RemediationEffort::Medium),
                    )
                    .with_tool("StaticAgent", "0.1.0");

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Analyze source code files
    #[instrument(skip(self, target))]
    async fn analyze_source(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        let path = Path::new(&target.path);
        let mut findings = Vec::new();

        if path.is_dir() {
            // Walk directory and analyze files
            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let file_path = entry.path();
                    if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                        findings.extend(self.scan_content(&content, file_path.to_str().unwrap_or("")).await?);
                    }
                }
            }
        } else if path.is_file() {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                findings.extend(self.scan_content(&content, &target.path).await?);
            }
        }

        Ok(FindingCollection::new(findings))
    }

    /// Scan content for issues
    async fn scan_content(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for secrets
        for pattern in &self.secret_patterns {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential Secret/Credential Exposed",
                        "A potential secret or credential was found in the source code.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Probable)
                    .with_type("secret_exposure")
                    .with_cwe("CWE-798")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Unknown)
                            .with_snippet(mat.as_str()),
                    )
                    .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        // Check for vulnerabilities
        for (pattern, description, severity) in &self.vulnerability_patterns {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new("Potential Vulnerability", description.clone())
                        .with_severity(*severity)
                        .with_confidence(Confidence::Probable)
                        .with_type("code_vulnerability")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_platform(Platform::Unknown)
                                .with_snippet(mat.as_str()),
                        )
                        .with_tool("StaticAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }
}

#[async_trait]
impl SecurityAgent for StaticAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Static
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        // This is a bit of a workaround - in practice, we'd want to avoid this
        unsafe {
            &*(self.base.config.read().unwrap() as *const AgentConfig)
        }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing StaticAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("StaticAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "StaticAgent executing task: {} on target: {}",
            context.task_id, context.target.path
        );

        self.base.set_status(AgentStatus::Busy);
        self.base.update_heartbeat();

        // Validate target
        if !Path::new(&context.target.path).exists() {
            self.base.increment_failed();
            self.base.set_status(AgentStatus::Idle);
            return Ok(AgentResult::failed(
                context.task_id,
                self.base.id,
                format!("Target not found: {}", context.target.path),
            ));
        }

        // Perform analysis based on target type
        let result = match context.target.platform {
            Platform::Android => self.analyze_apk(&context.target).await,
            _ => self.analyze_source(&context.target).await,
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(findings) => {
                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "StaticAgent completed task: {} with {} findings in {}ms",
                    context.task_id,
                    findings.total_count,
                    execution_time_ms
                );

                Ok(AgentResult::success(
                    context.task_id,
                    self.base.id,
                    findings,
                    execution_time_ms,
                ))
            }
            Err(e) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!("StaticAgent failed task: {} with error: {}", context.task_id, e);

                Ok(AgentResult::failed(context.task_id, self.base.id, e.to_string()))
            }
        }
    }

    async fn health(&self) -> AgentHealth {
        self.base.get_health()
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down StaticAgent: {}", self.base.name);
        self.base.set_status(AgentStatus::Offline);
        Ok(())
    }

    fn update_heartbeat(&self) {
        self.base.update_heartbeat();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_agent_creation() {
        let agent = StaticAgent::new("Test Static Agent");

        assert_eq!(agent.name(), "Test Static Agent");
        assert_eq!(agent.agent_type(), AgentType::Static);
        assert!(agent.has_capability(&AgentCapability::StaticAnalysis));
        assert!(agent.has_capability(&AgentCapability::SecretDetection));
        assert!(agent.has_capability(&AgentCapability::ManifestParsing));
    }

    #[test]
    fn test_secret_patterns_initialized() {
        let agent = StaticAgent::new("Test Agent");
        assert!(!agent.secret_patterns.is_empty());
    }

    #[test]
    fn test_vulnerability_patterns_initialized() {
        let agent = StaticAgent::new("Test Agent");
        assert!(!agent.vulnerability_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_static_agent_initialization() {
        let mut agent = StaticAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_static_agent_health() {
        let agent = StaticAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }
}
