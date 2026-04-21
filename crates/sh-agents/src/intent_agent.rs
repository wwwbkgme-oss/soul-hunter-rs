//! # Intent Analysis Agent
//!
//! Performs comprehensive Intent and IPC security analysis for Android applications.
//! Capabilities include:
//! - Exported activities without permissions
//! - Exported services without permissions
//! - Exported broadcast receivers without permissions
//! - Exported content providers without permissions
//! - Intent injection detection
//! - Intent hijacking detection
//! - Pending intent abuse
//! - Deep link hijacking
//! - Activity hijacking
//!
//! This agent analyzes AndroidManifest.xml and source code to identify
//! Inter-Process Communication (IPC) vulnerabilities related to Intent handling.

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_llm::{LlmClient, LlmConfig, Message};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentStatus, AgentType, AnalysisTarget,
    Confidence, Finding, FindingCollection, Location, Platform, Remediation, RemediationEffort,
    Severity,
};
use sh_tools::apk::{ApkParser, ManifestAnalyzer};

/// Intent analysis agent for IPC security assessment
pub struct IntentAgent {
    base: AgentBase,
    llm_client: Option<LlmClient>,
    intent_patterns: IntentPatterns,
    analysis_config: IntentAnalysisConfig,
}

/// Configuration for intent analysis
#[derive(Debug, Clone)]
pub struct IntentAnalysisConfig {
    /// Check for exported components without permissions
    pub check_exported_components: bool,
    /// Check for intent injection vulnerabilities
    pub check_intent_injection: bool,
    /// Check for intent hijacking vulnerabilities
    pub check_intent_hijacking: bool,
    /// Check for pending intent abuse
    pub check_pending_intent_abuse: bool,
    /// Check for deep link hijacking
    pub check_deep_link_hijacking: bool,
    /// Check for activity hijacking
    pub check_activity_hijacking: bool,
    /// Enable LLM-enhanced analysis
    pub enable_llm_analysis: bool,
    /// LLM model to use for analysis
    pub llm_model: String,
}

impl Default for IntentAnalysisConfig {
    fn default() -> Self {
        Self {
            check_exported_components: true,
            check_intent_injection: true,
            check_intent_hijacking: true,
            check_pending_intent_abuse: true,
            check_deep_link_hijacking: true,
            check_activity_hijacking: true,
            enable_llm_analysis: false,
            llm_model: "gpt-4".to_string(),
        }
    }
}

/// Intent vulnerability patterns
#[derive(Debug, Clone)]
struct IntentPatterns {
    /// Patterns for detecting implicit intent usage
    implicit_intent_patterns: Vec<Regex>,
    /// Patterns for detecting pending intent creation
    pending_intent_patterns: Vec<Regex>,
    /// Patterns for detecting intent data handling
    intent_data_patterns: Vec<Regex>,
    /// Patterns for detecting deep link handling
    deep_link_patterns: Vec<Regex>,
    /// Patterns for detecting task affinity issues
    task_affinity_patterns: Vec<Regex>,
    /// Patterns for detecting launch mode issues
    launch_mode_patterns: Vec<Regex>,
    /// Patterns for detecting intent extras handling
    intent_extras_patterns: Vec<Regex>,
    /// Patterns for detecting broadcast receiver registration
    broadcast_receiver_patterns: Vec<Regex>,
    /// Patterns for detecting sticky broadcasts
    sticky_broadcast_patterns: Vec<Regex>,
    /// Patterns for detecting ordered broadcasts
    ordered_broadcast_patterns: Vec<Regex>,
    /// Patterns for detecting result receivers
    result_receiver_patterns: Vec<Regex>,
}

impl IntentPatterns {
    fn new() -> Self {
        Self {
            implicit_intent_patterns: vec![
                Regex::new(r#"(?i)new\s+Intent\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)setAction\s*\("#).unwrap(),
                Regex::new(r#"(?i)addCategory\s*\("#).unwrap(),
                Regex::new(r#"(?i)startActivity\s*\(\s*new\s+Intent"#).unwrap(),
                Regex::new(r#"(?i)startService\s*\(\s*new\s+Intent"#).unwrap(),
                Regex::new(r#"(?i)sendBroadcast\s*\(\s*new\s+Intent"#).unwrap(),
            ],
            pending_intent_patterns: vec![
                Regex::new(r#"(?i)PendingIntent\.getActivity"#).unwrap(),
                Regex::new(r#"(?i)PendingIntent\.getService"#).unwrap(),
                Regex::new(r#"(?i)PendingIntent\.getBroadcast"#).unwrap(),
                Regex::new(r#"(?i)PendingIntent\.getForegroundService"#).unwrap(),
            ],
            intent_data_patterns: vec![
                Regex::new(r#"(?i)getIntent\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)getData\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)getStringExtra\s*\("#).unwrap(),
                Regex::new(r#"(?i)getParcelableExtra\s*\("#).unwrap(),
                Regex::new(r#"(?i)setData\s*\("#).unwrap(),
                Regex::new(r#"(?i)setDataAndType\s*\("#).unwrap(),
            ],
            deep_link_patterns: vec![
                Regex::new(r#"(?i)<data\s+android:scheme="#).unwrap(),
                Regex::new(r#"(?i)android:host="#).unwrap(),
                Regex::new(r#"(?i)android:pathPattern="#).unwrap(),
                Regex::new(r#"(?i)intent\.getDataString\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)Uri\.parse\s*\("#).unwrap(),
            ],
            task_affinity_patterns: vec![
                Regex::new(r#"(?i)android:taskAffinity="#).unwrap(),
                Regex::new(r#"(?i)taskAffinity\s*="#).unwrap(),
            ],
            launch_mode_patterns: vec![
                Regex::new(r#"(?i)android:launchMode="singleTask""#).unwrap(),
                Regex::new(r#"(?i)android:launchMode="singleInstance""#).unwrap(),
                Regex::new(r#"(?i)launchMode\s*=\s*["']singleTask["']"#).unwrap(),
                Regex::new(r#"(?i)launchMode\s*=\s*["']singleInstance["']"#).unwrap(),
            ],
            intent_extras_patterns: vec![
                Regex::new(r#"(?i)getIntent\s*\(\s*\)\.getExtras\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)getIntent\s*\(\s*\)\.getSerializableExtra"#).unwrap(),
                Regex::new(r#"(?i)getIntent\s*\(\s*\)\.getParcelableArrayExtra"#).unwrap(),
            ],
            broadcast_receiver_patterns: vec![
                Regex::new(r#"(?i)registerReceiver\s*\("#).unwrap(),
                Regex::new(r#"(?i)unregisterReceiver\s*\("#).unwrap(),
                Regex::new(r#"(?i)sendBroadcast\s*\("#).unwrap(),
                Regex::new(r#"(?i)sendOrderedBroadcast\s*\("#).unwrap(),
            ],
            sticky_broadcast_patterns: vec![
                Regex::new(r#"(?i)sendStickyBroadcast"#).unwrap(),
                Regex::new(r#"(?i)sendStickyOrderedBroadcast"#).unwrap(),
                Regex::new(r#"(?i)removeStickyBroadcast"#).unwrap(),
            ],
            ordered_broadcast_patterns: vec![
                Regex::new(r#"(?i)sendOrderedBroadcast"#).unwrap(),
                Regex::new(r#"(?i)sendOrderedBroadcastAsUser"#).unwrap(),
            ],
            result_receiver_patterns: vec![
                Regex::new(r#"(?i)setResult\s*\("#).unwrap(),
                Regex::new(r#"(?i)getResultCode\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)getResultData\s*\(\s*\)"#).unwrap(),
                Regex::new(r#"(?i)abortBroadcast\s*\(\s*\)"#).unwrap(),
            ],
        }
    }
}

/// Types of intent vulnerabilities
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum IntentVulnerabilityType {
    ExportedActivityNoPermission,
    ExportedServiceNoPermission,
    ExportedReceiverNoPermission,
    ExportedProviderNoPermission,
    ImplicitIntentUsage,
    PendingIntentAbuse,
    IntentInjection,
    IntentHijacking,
    DeepLinkHijacking,
    ActivityHijacking,
    TaskAffinityManipulation,
    InsecureBroadcast,
    StickyBroadcastUsage,
    UnprotectedBroadcastReceiver,
    IntentDataExposure,
    LaunchModeVulnerability,
}

impl IntentAgent {
    /// Create a new intent analysis agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Intent)
            .with_capabilities(vec![
                AgentCapability::IntentAnalysis,
                AgentCapability::ComponentAnalysis,
            ])
            .with_platform(Platform::Android);

        let mut agent = Self {
            base,
            llm_client: None,
            intent_patterns: IntentPatterns::new(),
            analysis_config: IntentAnalysisConfig::default(),
        };

        // Set initial heartbeat
        agent.update_heartbeat();
        agent
    }

    /// Create a new intent analysis agent with custom configuration
    pub fn with_config(mut self, config: IntentAnalysisConfig) -> Self {
        self.analysis_config = config;
        self
    }

    /// Initialize LLM client for enhanced analysis
    async fn init_llm_client(&mut self) -> Result<()> {
        if self.analysis_config.enable_llm_analysis && self.llm_client.is_none() {
            let config = LlmConfig::default()
                .with_model(&self.analysis_config.llm_model);
            
            match LlmClient::new(config) {
                Ok(client) => {
                    self.llm_client = Some(client);
                    info!("LLM client initialized for IntentAgent");
                }
                Err(e) => {
                    warn!("Failed to initialize LLM client: {}. Continuing without LLM analysis.", e);
                }
            }
        }
        Ok(())
    }

    /// Analyze an APK file for intent vulnerabilities
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn analyze_apk(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Starting Intent analysis for: {}", target.path);

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

        // Analyze manifest for exported components
        let manifest_analyzer = ManifestAnalyzer::new(&apk_parser);
        findings.extend(self.analyze_manifest(&manifest_analyzer).await?);

        // Analyze source code for intent vulnerabilities
        findings.extend(self.analyze_source_code(&apk_parser).await?);

        // Perform LLM-enhanced analysis if enabled
        if self.analysis_config.enable_llm_analysis && self.llm_client.is_some() {
            findings.extend(self.llm_enhanced_analysis(&apk_parser).await?);
        }

        info!(
            "Intent analysis completed. Found {} findings",
            findings.len()
        );

        Ok(FindingCollection::new(findings))
    }

    /// Analyze AndroidManifest.xml for exported components
    #[instrument(skip(self, analyzer))]
    async fn analyze_manifest(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if self.analysis_config.check_exported_components {
            // Check exported activities without permissions
            findings.extend(self.check_exported_activities(analyzer).await?);

            // Check exported services without permissions
            findings.extend(self.check_exported_services(analyzer).await?);

            // Check exported receivers without permissions
            findings.extend(self.check_exported_receivers(analyzer).await?);

            // Check exported providers without permissions
            findings.extend(self.check_exported_providers(analyzer).await?);
        }

        if self.analysis_config.check_deep_link_hijacking {
            // Check for deep link vulnerabilities
            findings.extend(self.check_deep_links(analyzer).await?);
        }

        if self.analysis_config.check_activity_hijacking {
            // Check for activity hijacking vulnerabilities
            findings.extend(self.check_activity_hijacking(analyzer).await?);
        }

        Ok(findings)
    }

    /// Check for exported activities without permissions
    #[instrument(skip(self, analyzer))]
    async fn check_exported_activities(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for activity in analyzer.get_exported_activities() {
            if activity.permission.is_none() {
                findings.push(
                    Finding::new(
                        format!("Exported Activity Without Permission: {}", activity.name),
                        "This activity is exported and accessible to other applications without requiring any permission. This can lead to unauthorized access and potential security vulnerabilities.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("exported_activity_no_permission")
                    .with_cwe("CWE-926")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Add android:permission attribute to require a custom permission, or set android:exported=\"false\" if the activity doesn't need to be accessed externally. If it must be exported, implement proper input validation and access controls.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/guide/components/activities")
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                    )
                    .with_tool("IntentAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for exported services without permissions
    #[instrument(skip(self, analyzer))]
    async fn check_exported_services(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for service in analyzer.get_exported_services() {
            if service.permission.is_none() {
                findings.push(
                    Finding::new(
                        format!("Exported Service Without Permission: {}", service.name),
                        "This service is exported and accessible to other applications without requiring any permission. Malicious apps can bind to or start this service, potentially accessing sensitive functionality.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("exported_service_no_permission")
                    .with_cwe("CWE-926")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Add android:permission attribute to require a custom permission, or set android:exported=\"false\" if the service doesn't need to be accessed externally. Implement proper caller verification in onBind() and onStartCommand().")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/guide/components/services")
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                    )
                    .with_tool("IntentAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for exported broadcast receivers without permissions
    #[instrument(skip(self, analyzer))]
    async fn check_exported_receivers(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for receiver in analyzer.get_exported_receivers() {
            if receiver.permission.is_none() {
                findings.push(
                    Finding::new(
                        format!("Exported BroadcastReceiver Without Permission: {}", receiver.name),
                        "This broadcast receiver is exported and can receive broadcasts from any application without permission checks. This can lead to intent injection attacks and unauthorized data access.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("exported_receiver_no_permission")
                    .with_cwe("CWE-926")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Add android:permission attribute to require a custom permission, or set android:exported=\"false\" if the receiver doesn't need external broadcasts. Validate intent data in onReceive() and check the sender's identity.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/guide/components/broadcasts")
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                    )
                    .with_tool("IntentAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for exported content providers without permissions
    #[instrument(skip(self, analyzer))]
    async fn check_exported_providers(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for provider in analyzer.get_content_providers() {
            if provider.exported && provider.read_permission.is_none() && provider.write_permission.is_none() {
                findings.push(
                    Finding::new(
                        format!("Exported ContentProvider Without Permission: {}", provider.name),
                        "This content provider is exported without read or write permissions, potentially exposing sensitive data to any application. This is a critical security vulnerability.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("exported_provider_no_permission")
                    .with_cwe("CWE-284")
                    .with_owasp("M2: Insecure Data Storage")
                    .with_location(
                        Location::new()
                            .with_file("AndroidManifest.xml")
                            .with_platform(Platform::Android),
                    )
                    .with_remediation(
                        Remediation::new("Add android:readPermission and/or android:writePermission attributes to protect this content provider. Alternatively, set android:exported=\"false\" if it doesn't need external access. Implement proper URI permissions for temporary access.")
                            .with_effort(RemediationEffort::High)
                            .add_reference("https://developer.android.com/guide/topics/providers/content-provider-basics")
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                    )
                    .with_tool("IntentAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for deep link vulnerabilities
    #[instrument(skip(self, analyzer))]
    async fn check_deep_links(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get components with intent filters that have data elements
        let components_with_deep_links = analyzer.components_with_intent_filters();
        
        for (component_name, intent_filters) in components_with_deep_links {
            for filter in intent_filters {
                // Check if this is a deep link (has data scheme like http/https or custom scheme)
                let has_deep_link = filter.data_schemes.iter().any(|s| {
                    s == "http" || s == "https" || !s.starts_with("android")
                });

                if has_deep_link {
                    findings.push(
                        Finding::new(
                            format!("Deep Link Vulnerability: {}", component_name),
                            format!("Component {} has deep link intent filters (schemes: {}). Deep links can be hijacked by malicious apps registering similar intent filters with higher priority.", 
                                component_name, 
                                filter.data_schemes.join(", ")
                            ),
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("deep_link_hijacking")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file("AndroidManifest.xml")
                                .with_platform(Platform::Android),
                        )
                        .with_remediation(
                            Remediation::new("Validate deep link URLs before processing. Use App Links (android:autoVerify=\"true\") to verify domain ownership. Implement proper input validation on data received through deep links.")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/training/app-links")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Check for activity hijacking vulnerabilities
    #[instrument(skip(self, analyzer))]
    async fn check_activity_hijacking(&self, analyzer: &ManifestAnalyzer) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for taskAffinity manipulation
        let activities = analyzer.get_activities();
        for activity in activities {
            if let Some(ref task_affinity) = activity.task_affinity {
                if task_affinity != analyzer.get_package_name() {
                    findings.push(
                        Finding::new(
                            format!("Task Affinity Manipulation: {}", activity.name),
                            format!("Activity {} has a custom taskAffinity ({}). This can be exploited by a malicious app to hijack the activity into its own task, potentially leading to UI spoofing and phishing attacks.", 
                                activity.name, 
                                task_affinity
                            ),
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("task_affinity_manipulation")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file("AndroidManifest.xml")
                                .with_platform(Platform::Android),
                        )
                        .with_remediation(
                            Remediation::new("Remove custom taskAffinity or set android:allowTaskReparenting=\"false\". Consider using android:launchMode=\"singleTask\" with proper intent validation.")
                                .with_effort(RemediationEffort::Low)
                                .add_reference("https://developer.android.com/guide/components/activities/tasks-and-back-stack")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                }
            }

            // Check for dangerous launch modes
            if let Some(ref launch_mode) = activity.launch_mode {
                if launch_mode == "singleTask" || launch_mode == "singleInstance" {
                    findings.push(
                        Finding::new(
                            format!("Dangerous Launch Mode: {}", activity.name),
                            format!("Activity {} uses launchMode=\"{}\" which can be exploited for task hijacking attacks. A malicious app can launch this activity with FLAG_ACTIVITY_NEW_TASK to hijack the task.", 
                                activity.name, 
                                launch_mode
                            ),
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("dangerous_launch_mode")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file("AndroidManifest.xml")
                                .with_platform(Platform::Android),
                        )
                        .with_remediation(
                            Remediation::new("Avoid using singleTask or singleInstance launch modes unless absolutely necessary. If required, implement proper intent validation and caller verification in onCreate().")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/guide/components/activities/tasks-and-back-stack")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Analyze source code for intent vulnerabilities
    #[instrument(skip(self, parser))]
    async fn analyze_source_code(&self, parser: &ApkParser) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get all text files from APK
        let text_files = parser
            .get_text_files()
            .map_err(|e| AgentError::Tool(format!("Failed to get text files: {}", e)))?;

        for (file_path, content) in text_files {
            // Check for implicit intent usage
            if self.analysis_config.check_intent_hijacking {
                findings.extend(self.check_implicit_intents(&content, &file_path).await?);
            }

            // Check for pending intent abuse
            if self.analysis_config.check_pending_intent_abuse {
                findings.extend(self.check_pending_intent_abuse(&content, &file_path).await?);
            }

            // Check for intent injection
            if self.analysis_config.check_intent_injection {
                findings.extend(self.check_intent_injection(&content, &file_path).await?);
            }

            // Check for insecure broadcasts
            findings.extend(self.check_insecure_broadcasts(&content, &file_path).await?);
        }

        Ok(findings)
    }

    /// Check for implicit intent usage
    #[instrument(skip(self, content, file_path))]
    async fn check_implicit_intents(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.intent_patterns.implicit_intent_patterns {
                if pattern.is_match(line) {
                    findings.push(
                        Finding::new(
                            "Implicit Intent Usage",
                            "Implicit intents can be intercepted by malicious apps that register for the same actions/categories. This can lead to intent hijacking and data theft.",
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Probable)
                        .with_type("implicit_intent_usage")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_line((line_num + 1) as u32)
                                .with_platform(Platform::Android)
                                .with_snippet(line.to_string()),
                        )
                        .with_remediation(
                            Remediation::new("Use explicit intents with setComponent() or setClass() to specify the exact target component. If implicit intents are necessary, validate the resolved component before sending.")
                                .with_effort(RemediationEffort::Low)
                                .add_reference("https://developer.android.com/guide/components/intents-filters")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                    break; // Only report once per line
                }
            }
        }

        Ok(findings)
    }

    /// Check for pending intent abuse
    #[instrument(skip(self, content, file_path))]
    async fn check_pending_intent_abuse(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            for pattern in &self.intent_patterns.pending_intent_patterns {
                if pattern.is_match(line) {
                    findings.push(
                        Finding::new(
                            "PendingIntent Usage",
                            "PendingIntents can be hijacked if not properly secured. A malicious app with the same PendingIntent can intercept or modify the intent before it's executed.",
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Probable)
                        .with_type("pending_intent_abuse")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_line((line_num + 1) as u32)
                                .with_platform(Platform::Android)
                                .with_snippet(line.to_string()),
                        )
                        .with_remediation(
                            Remediation::new("Use FLAG_IMMUTABLE when creating PendingIntents to prevent modification. Validate the intent data before creating the PendingIntent. Consider using explicit intents within PendingIntents.")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/reference/android/app/PendingIntent")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        Ok(findings)
    }

    /// Check for intent injection vulnerabilities
    #[instrument(skip(self, content, file_path))]
    async fn check_intent_injection(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check for intent data handling without validation
            for pattern in &self.intent_patterns.intent_data_patterns {
                if pattern.is_match(line) {
                    findings.push(
                        Finding::new(
                            "Potential Intent Injection",
                            "Intent data is being accessed without apparent validation. Malicious apps can send crafted intents with malicious data that could lead to injection attacks.",
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Tentative)
                        .with_type("intent_injection")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_line((line_num + 1) as u32)
                                .with_platform(Platform::Android)
                                .with_snippet(line.to_string()),
                        )
                        .with_remediation(
                            Remediation::new("Validate all intent data before use. Check the sender's identity using getCallingActivity() or getCallingPackage(). Sanitize input data and avoid deserializing untrusted data.")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/guide/components/intents-filters")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        Ok(findings)
    }

    /// Check for insecure broadcast usage
    #[instrument(skip(self, content, file_path))]
    async fn check_insecure_broadcasts(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check for sticky broadcasts
            for pattern in &self.intent_patterns.sticky_broadcast_patterns {
                if pattern.is_match(line) {
                    findings.push(
                        Finding::new(
                            "Sticky Broadcast Usage",
                            "Sticky broadcasts are deprecated and can leak sensitive information. Any app can access sticky broadcasts without permissions.",
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("sticky_broadcast_usage")
                        .with_cwe("CWE-927")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_line((line_num + 1) as u32)
                                .with_platform(Platform::Android)
                                .with_snippet(line.to_string()),
                        )
                        .with_remediation(
                            Remediation::new("Replace sticky broadcasts with non-sticky broadcasts or use LocalBroadcastManager for internal app communication. Consider using explicit intents with proper permissions.")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/reference/android/content/Context#sendStickyBroadcast(android.content.Intent)")
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05h-Testing-Platform-Interaction"),
                        )
                        .with_tool("IntentAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        Ok(findings)
    }

    /// LLM-enhanced analysis for complex intent vulnerabilities
    #[instrument(skip(self, parser))]
    async fn llm_enhanced_analysis(&self, parser: &ApkParser) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Some(ref llm_client) = self.llm_client {
            // Get manifest content for analysis
            let manifest_content = parser
                .get_manifest_content()
                .map_err(|e| AgentError::Tool(format!("Failed to get manifest: {}", e)))?;

            // Create analysis prompt
            let prompt = format!(
                r#"Analyze this AndroidManifest.xml for Intent-related security vulnerabilities.
                Focus on:
                1. Exported components that might be vulnerable to intent injection
                2. Intent filters that could be hijacked
                3. Task affinity and launch mode issues
                4. Missing permission protections
                
                Manifest content:
                {}
                
                Provide a JSON response with findings in this format:
                {{
                    "findings": [
                        {{
                            "title": "brief title",
                            "description": "detailed description",
                            "severity": "Critical|High|Medium|Low",
                            "type": "vulnerability_type",
                            "remediation": "how to fix"
                        }}
                    ]
                }}
                
                If no vulnerabilities are found, return an empty findings array."#,
                manifest_content
            );

            let messages = vec![
                Message::system("You are a security expert analyzing Android applications for Intent and IPC vulnerabilities."),
                Message::user(prompt),
            ];

            match llm_client.chat(messages).await {
                Ok(response) => {
                    if let Some(content) = response.content() {
                        // Parse LLM response and create findings
                        // This is a simplified implementation - in production, you'd want
                        // more robust JSON parsing and validation
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                            if let Some(llm_findings) = json.get("findings").and_then(|f| f.as_array()) {
                                for finding_json in llm_findings {
                                    if let (Some(title), Some(description), Some(severity_str)) = (
                                        finding_json.get("title").and_then(|t| t.as_str()),
                                        finding_json.get("description").and_then(|d| d.as_str()),
                                        finding_json.get("severity").and_then(|s| s.as_str()),
                                    ) {
                                        let severity = match severity_str.to_lowercase().as_str() {
                                            "critical" => Severity::Critical,
                                            "high" => Severity::High,
                                            "medium" => Severity::Medium,
                                            "low" => Severity::Low,
                                            _ => Severity::Medium,
                                        };

                                        let remediation = finding_json
                                            .get("remediation")
                                            .and_then(|r| r.as_str())
                                            .unwrap_or("Review and fix the vulnerability");

                                        findings.push(
                                            Finding::new(title, description)
                                                .with_severity(severity)
                                                .with_confidence(Confidence::Probable)
                                                .with_type("llm_enhanced_analysis")
                                                .with_cwe("CWE-927")
                                                .with_owasp("M1: Improper Platform Usage")
                                                .with_location(
                                                    Location::new()
                                                        .with_file("AndroidManifest.xml")
                                                        .with_platform(Platform::Android),
                                                )
                                                .with_remediation(
                                                    Remediation::new(remediation)
                                                        .with_effort(RemediationEffort::Medium),
                                                )
                                                .with_tool("IntentAgent", "0.1.0"),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("LLM analysis failed: {}", e);
                }
            }
        }

        Ok(findings)
    }

    /// Analyze source code directory
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
                    if let Some(ext) = file_path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if matches!(ext_str.as_str(), "java" | "kt") {
                            if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                                let path_str = file_path.to_string_lossy().to_string();
                                findings.extend(self.check_implicit_intents(&content, &path_str).await?);
                                findings.extend(self.check_pending_intent_abuse(&content, &path_str).await?);
                                findings.extend(self.check_intent_injection(&content, &path_str).await?);
                                findings.extend(self.check_insecure_broadcasts(&content, &path_str).await?);
                            }
                        }
                    }
                }
            }
        }

        Ok(FindingCollection::new(findings))
    }
}

#[async_trait]
impl SecurityAgent for IntentAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Intent
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        // This is a workaround - in practice, we'd want to avoid this
        unsafe { &*(self.base.config.read().unwrap() as *const AgentConfig) }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing IntentAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        // Initialize LLM client if enabled
        if self.analysis_config.enable_llm_analysis {
            self.init_llm_client().await?;
        }

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("IntentAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "IntentAgent executing task: {} on target: {}",
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
                    "IntentAgent completed task: {} with {} findings in {}ms",
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

                error!("IntentAgent failed task: {} with error: {}", context.task_id, e);

                Ok(AgentResult::failed(context.task_id, self.base.id, e.to_string()))
            }
        }
    }

    async fn health(&self) -> AgentHealth {
        self.base.get_health()
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down IntentAgent: {}", self.base.name);
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
    fn test_intent_agent_creation() {
        let agent = IntentAgent::new("Test Intent Agent");

        assert_eq!(agent.name(), "Test Intent Agent");
        assert_eq!(agent.agent_type(), AgentType::Intent);
        assert!(agent.has_capability(&AgentCapability::IntentAnalysis));
        assert!(agent.has_capability(&AgentCapability::ComponentAnalysis));
    }

    #[test]
    fn test_intent_patterns_initialized() {
        let patterns = IntentPatterns::new();
        assert!(!patterns.implicit_intent_patterns.is_empty());
        assert!(!patterns.pending_intent_patterns.is_empty());
        assert!(!patterns.intent_data_patterns.is_empty());
    }

    #[test]
    fn test_intent_analysis_config_default() {
        let config = IntentAnalysisConfig::default();
        assert!(config.check_exported_components);
        assert!(config.check_intent_injection);
        assert!(config.check_intent_hijacking);
        assert!(config.check_pending_intent_abuse);
        assert!(config.check_deep_link_hijacking);
        assert!(config.check_activity_hijacking);
        assert!(!config.enable_llm_analysis);
        assert_eq!(config.llm_model, "gpt-4");
    }

    #[test]
    fn test_intent_agent_with_config() {
        let config = IntentAnalysisConfig {
            check_exported_components: true,
            check_intent_injection: false,
            check_intent_hijacking: true,
            check_pending_intent_abuse: false,
            check_deep_link_hijacking: true,
            check_activity_hijacking: false,
            enable_llm_analysis: true,
            llm_model: "claude-3".to_string(),
        };

        let agent = IntentAgent::new("Test Agent").with_config(config);
        assert!(!agent.analysis_config.check_intent_injection);
        assert!(!agent.analysis_config.check_pending_intent_abuse);
        assert!(agent.analysis_config.enable_llm_analysis);
        assert_eq!(agent.analysis_config.llm_model, "claude-3");
    }

    #[tokio::test]
    async fn test_intent_agent_initialization() {
        let mut agent = IntentAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_intent_agent_health() {
        let agent = IntentAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }

    #[test]
    fn test_pattern_matching() {
        let patterns = IntentPatterns::new();
        
        // Test implicit intent pattern
        let code = "Intent intent = new Intent();";
        assert!(patterns.implicit_intent_patterns[0].is_match(code));
        
        // Test pending intent pattern
        let code2 = "PendingIntent.getActivity(context, 0, intent, 0);";
        assert!(patterns.pending_intent_patterns[0].is_match(code2));
        
        // Test sticky broadcast pattern
        let code3 = "sendStickyBroadcast(intent);";
        assert!(patterns.sticky_broadcast_patterns[0].is_match(code3));
    }

    #[tokio::test]
    async fn test_check_implicit_intents() {
        let agent = IntentAgent::new("Test Agent");
        let content = r#"
            public void sendData() {
                Intent intent = new Intent();
                intent.setAction("com.example.ACTION_SEND");
                startActivity(intent);
            }
        "#;

        let findings = agent.check_implicit_intents(content, "Test.java").await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "Implicit Intent Usage");
    }

    #[tokio::test]
    async fn test_check_pending_intent_abuse() {
        let agent = IntentAgent::new("Test Agent");
        let content = r#"
            PendingIntent pendingIntent = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT
            );
        "#;

        let findings = agent.check_pending_intent_abuse(content, "Test.java").await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "PendingIntent Usage");
    }

    #[tokio::test]
    async fn test_check_insecure_broadcasts() {
        let agent = IntentAgent::new("Test Agent");
        let content = r#"
            sendStickyBroadcast(intent);
        "#;

        let findings = agent.check_insecure_broadcasts(content, "Test.java").await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "Sticky Broadcast Usage");
    }
}
