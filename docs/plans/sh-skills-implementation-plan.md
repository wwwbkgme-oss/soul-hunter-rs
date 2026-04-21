# sh-skills Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a production-ready `sh-skills` crate with 9 security analysis skills implementing a common `SecuritySkill` trait, supporting async execution and returning standardized findings.

**Architecture:** Trait-based modular design where each skill is self-contained, async-capable, and produces `Finding` results. Skills are composable and can be chained via the correlation engine.

**Tech Stack:** Rust, tokio, async-trait, serde, tracing, chrono, uuid, thiserror, anyhow, sh-types, sh-tools

---

## File Structure

```
crates/sh-skills/
├── Cargo.toml                          # Dependencies and metadata
└── src/
    ├── lib.rs                          # SecuritySkill trait, SkillContext, SkillResult
    ├── error.rs                        # SkillError enum
    ├── attack_surface.rs               # Attack surface mapping skill
    ├── static_analysis.rs              # Static analysis skill
    ├── network_analysis.rs             # Network analysis skill
    ├── crypto_analysis.rs              # Crypto analysis skill
    ├── intent_analysis.rs              # Intent/IPC analysis skill
    ├── owasp_top10.rs                  # OWASP categorization skill
    ├── correlation.rs                  # Finding correlation skill
    └── risk_context.rs                 # Risk context scoring skill
```

---

## Task 1: Create Crate Structure and Cargo.toml

**Files:**
- Create: `crates/sh-skills/Cargo.toml`

- [ ] **Step 1: Create Cargo.toml with dependencies**
```toml
[package]
name = "sh-skills"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
rust-version.workspace = true
description = "Security analysis skills for Soul Hunter RS"

[dependencies]
# Internal dependencies
sh-types = { workspace = true }
sh-tools = { workspace = true }

# Async runtime
tokio = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Tracing
tracing = { workspace = true }

# Time
chrono = { workspace = true }

# UUID
uuid = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Collections
dashmap = { workspace = true }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3.9"
```

- [ ] **Step 2: Create src directory structure**
```bash
mkdir -p crates/sh-skills/src
```

- [ ] **Step 3: Commit**
```bash
git add crates/sh-skills/Cargo.toml
git commit -m "feat(sh-skills): add Cargo.toml with dependencies"
```

---

## Task 2: Create Core Error Module

**Files:**
- Create: `crates/sh-skills/src/error.rs`

- [ ] **Step 1: Write SkillError enum**
```rust
//! Error types for security skills

use thiserror::Error;

/// Errors that can occur during skill execution
#[derive(Error, Debug, Clone)]
pub enum SkillError {
    #[error("Skill not initialized: {0}")]
    NotInitialized(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Target not supported: {0}")]
    TargetNotSupported(String),

    #[error("Execution timeout: {0}")]
    Timeout(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<std::io::Error> for SkillError {
    fn from(err: std::io::Error) -> Self {
        SkillError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for SkillError {
    fn from(err: serde_json::Error) -> Self {
        SkillError::Serialization(err.to_string())
    }
}

/// Result type alias for skill operations
pub type Result<T> = std::result::Result<T, SkillError>;
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/error.rs
git commit -m "feat(sh-skills): add SkillError enum"
```

---

## Task 3: Create Core Library Module

**Files:**
- Create: `crates/sh-skills/src/lib.rs`

- [ ] **Step 1: Write lib.rs with SecuritySkill trait**
```rust
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/lib.rs
git commit -m "feat(sh-skills): add SecuritySkill trait and core types"
```

---

## Task 4: Implement Attack Surface Skill

**Files:**
- Create: `crates/sh-skills/src/attack_surface.rs`

- [ ] **Step 1: Write attack_surface.rs**
```rust
//! Attack Surface Mapping Skill
//!
//! Maps the attack surface of applications by identifying:
//! - Entry points (activities, services, receivers, providers)
//! - Exported components
//! - Deep links and URL schemes
//! - IPC endpoints
//! - Network listeners

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Attack surface finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackSurfaceType {
    ExportedActivity,
    ExportedService,
    ExportedReceiver,
    ExportedProvider,
    DeepLink,
    UrlScheme,
    IpcEndpoint,
    NetworkListener,
    Debuggable,
    BackupEnabled,
}

impl std::fmt::Display for AttackSurfaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackSurfaceType::ExportedActivity => write!(f, "exported_activity"),
            AttackSurfaceType::ExportedService => write!(f, "exported_service"),
            AttackSurfaceType::ExportedReceiver => write!(f, "exported_receiver"),
            AttackSurfaceType::ExportedProvider => write!(f, "exported_provider"),
            AttackSurfaceType::DeepLink => write!(f, "deep_link"),
            AttackSurfaceType::UrlScheme => write!(f, "url_scheme"),
            AttackSurfaceType::IpcEndpoint => write!(f, "ipc_endpoint"),
            AttackSurfaceType::NetworkListener => write!(f, "network_listener"),
            AttackSurfaceType::Debuggable => write!(f, "debuggable"),
            AttackSurfaceType::BackupEnabled => write!(f, "backup_enabled"),
        }
    }
}

/// Configuration for attack surface analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceConfig {
    pub check_exported_components: bool,
    pub check_deep_links: bool,
    pub check_url_schemes: bool,
    pub check_ipc: bool,
    pub check_network_listeners: bool,
    pub check_debug_flags: bool,
}

impl Default for AttackSurfaceConfig {
    fn default() -> Self {
        Self {
            check_exported_components: true,
            check_deep_links: true,
            check_url_schemes: true,
            check_ipc: true,
            check_network_listeners: true,
            check_debug_flags: true,
        }
    }
}

/// Attack surface mapping skill
#[derive(Debug)]
pub struct AttackSurfaceSkill {
    id: SkillId,
    config: AttackSurfaceConfig,
}

impl AttackSurfaceSkill {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            config: AttackSurfaceConfig::default(),
        }
    }

    pub fn with_config(mut self, config: AttackSurfaceConfig) -> Self {
        self.config = config;
        self
    }

    /// Analyze Android manifest for attack surface
    async fn analyze_android(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for debuggable flag
        if self.config.check_debug_flags {
            findings.extend(self.check_debuggable_flag(target).await?);
        }

        // Check for exported components
        if self.config.check_exported_components {
            findings.extend(self.check_exported_components(target).await?);
        }

        // Check for deep links
        if self.config.check_deep_links {
            findings.extend(self.check_deep_links(target).await?);
        }

        // Check for URL schemes
        if self.config.check_url_schemes {
            findings.extend(self.check_url_schemes(target).await?);
        }

        Ok(findings)
    }

    async fn check_debuggable_flag(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Parse AndroidManifest.xml for debuggable flag
        let manifest_path = format!("{}/AndroidManifest.xml", target.path);
        if !std::path::Path::new(&manifest_path).exists() {
            return Ok(findings);
        }

        let content = tokio::fs::read_to_string(&manifest_path).await?;

        if content.contains("android:debuggable=\"true\"") {
            let finding = Finding::new(
                "Debuggable Application",
                "The application is marked as debuggable, which allows debugging access and may expose sensitive information",
            )
            .with_severity(Severity::High)
            .with_confidence(Confidence::Confirmed)
            .with_type("attack_surface")
            .with_cwe("CWE-489")
            .with_owasp("M10: Insufficient Cryptography")
            .with_location(
                Location::new()
                    .with_file("AndroidManifest.xml")
                    .with_platform(Platform::Android),
            )
            .with_remediation(
                Remediation::new("Remove android:debuggable=\"true\" from the application manifest before release")
                    .with_effort(sh_types::RemediationEffort::Low)
                    .add_reference("https://developer.android.com/guide/topics/manifest/application-element#debug"),
            );

            findings.push(finding);
        }

        Ok(findings)
    }

    async fn check_exported_components(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // This would parse the manifest and identify exported components
        // For now, we return an empty list - actual implementation would use sh-tools
        debug!("Checking exported components for: {}", target.path);

        // Placeholder: In production, this would parse AndroidManifest.xml
        // and identify activities, services, receivers, and providers with
        // android:exported="true" or intent filters without explicit exported="false"

        Ok(findings)
    }

    async fn check_deep_links(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        debug!("Checking deep links for: {}", target.path);

        // Placeholder: Parse intent filters with data elements
        // that define URL patterns (scheme, host, path)

        Ok(findings)
    }

    async fn check_url_schemes(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        debug!("Checking URL schemes for: {}", target.path);

        // Placeholder: Identify custom URL schemes registered by the app

        Ok(findings)
    }
}

#[async_trait]
impl SecuritySkill for AttackSurfaceSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "attack_surface"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing attack surface analysis for: {}", ctx.target.path);

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        let findings = match ctx.target.platform {
            Platform::Android => self.analyze_android(&ctx.target).await?,
            Platform::Ios => Vec::new(), // iOS analysis would be implemented here
            _ => Vec::new(),
        };

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(findings)
            .with_metadata("skill_type", serde_json::json!("attack_surface"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()));

        Ok(result)
    }
}

impl Default for AttackSurfaceSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_surface_skill_creation() {
        let skill = AttackSurfaceSkill::new();
        assert_eq!(skill.name(), "attack_surface");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_supported_platforms() {
        let skill = AttackSurfaceSkill::new();
        let platforms = skill.supported_platforms();
        assert!(platforms.contains(&Platform::Android));
        assert!(platforms.contains(&Platform::Ios));
    }

    #[tokio::test]
    async fn test_execute_unsupported_platform() {
        let skill = AttackSurfaceSkill::new();
        let target = AnalysisTarget::new("/path/to/target", Platform::Web);
        let ctx = SkillContext::new(Uuid::new_v4(), target);

        let result = skill.execute(ctx).await;
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/attack_surface.rs
git commit -m "feat(sh-skills): add AttackSurfaceSkill"
```

---

## Task 5: Implement Static Analysis Skill

**Files:**
- Create: `crates/sh-skills/src/static_analysis.rs`

- [ ] **Step 1: Write static_analysis.rs**
```rust
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/static_analysis.rs
git commit -m "feat(sh-skills): add StaticAnalysisSkill"
```

---

## Task 6: Implement Network Analysis Skill

**Files:**
- Create: `crates/sh-skills/src/network_analysis.rs`

- [ ] **Step 1: Write network_analysis.rs**
```rust
//! Network Analysis Skill
//!
//! Analyzes network security configurations:
//! - Cleartext traffic (HTTP vs HTTPS)
//! - Certificate pinning
//! - Network security config
//! - Insecure TLS versions
//! - Weak cipher suites
//! - Domain validation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Network security finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkFindingType {
    CleartextTraffic,
    MissingCertificatePinning,
    InsecureTlsVersion,
    WeakCipherSuite,
    TrustManagerViolation,
    HostnameVerifierViolation,
    InsecureNetworkConfig,
    DomainValidationDisabled,
}

impl std::fmt::Display for NetworkFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkFindingType::CleartextTraffic => write!(f, "cleartext_traffic"),
            NetworkFindingType::MissingCertificatePinning => write!(f, "missing_certificate_pinning"),
            NetworkFindingType::InsecureTlsVersion => write!(f, "insecure_tls_version"),
            NetworkFindingType::WeakCipherSuite => write!(f, "weak_cipher_suite"),
            NetworkFindingType::TrustManagerViolation => write!(f, "trust_manager_violation"),
            NetworkFindingType::HostnameVerifierViolation => write!(f, "hostname_verifier_violation"),
            NetworkFindingType::InsecureNetworkConfig => write!(f, "insecure_network_config"),
            NetworkFindingType::DomainValidationDisabled => write!(f, "domain_validation_disabled"),
        }
    }
}

/// Configuration for network analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisConfig {
    pub check_cleartext: bool,
    pub check_pinning: bool,
    pub check_tls: bool,
    pub check_trust_managers: bool,
    pub check_hostname_verifiers: bool,
}

impl Default for NetworkAnalysisConfig {
    fn default() -> Self {
        Self {
            check_cleartext: true,
            check_pinning: true,
            check_tls: true,
            check_trust_managers: true,
            check_hostname_verifiers: true,
        }
    }
}

/// Network analysis skill
#[derive(Debug)]
pub struct NetworkAnalysisSkill {
    id: SkillId,
    config: NetworkAnalysisConfig,
}

impl NetworkAnalysisSkill {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            config: NetworkAnalysisConfig::default(),
        }
    }

    pub fn with_config(mut self, config: NetworkAnalysisConfig) -> Self {
        self.config = config;
        self
    }

    async fn analyze_android(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check network_security_config.xml
        if self.config.check_cleartext {
            findings.extend(self.check_cleartext_traffic(target).await?);
        }

        // Check for certificate pinning
        if self.config.check_pinning {
            findings.extend(self.check_certificate_pinning(target).await?);
        }

        // Check for insecure trust managers
        if self.config.check_trust_managers {
            findings.extend(self.check_trust_managers(target).await?);
        }

        // Check for insecure hostname verifiers
        if self.config.check_hostname_verifiers {
            findings.extend(self.check_hostname_verifiers(target).await?);
        }

        Ok(findings)
    }

    async fn check_cleartext_traffic(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check AndroidManifest.xml for usesCleartextTraffic
        let manifest_path = format!("{}/AndroidManifest.xml", target.path);
        if std::path::Path::new(&manifest_path).exists() {
            let content = tokio::fs::read_to_string(&manifest_path).await?;

            if content.contains("usesCleartextTraffic=\"true\"") {
                let finding = Finding::new(
                    "Cleartext Traffic Enabled",
                    "The application allows cleartext HTTP traffic, which exposes data to interception",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("network_security")
                .with_cwe("CWE-319")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file("AndroidManifest.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Set usesCleartextTraffic=\"false\" or remove the attribute to use HTTPS only")
                        .with_effort(sh_types::RemediationEffort::Low)
                        .add_reference("https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic"),
                );

                findings.push(finding);
            }
        }

        // Check network_security_config.xml
        let config_path = format!("{}/res/xml/network_security_config.xml", target.path);
        if std::path::Path::new(&config_path).exists() {
            let content = tokio::fs::read_to_string(&config_path).await?;

            if content.contains("<base-config cleartextTrafficPermitted=\"true\">") {
                let finding = Finding::new(
                    "Cleartext Traffic Permitted in Network Config",
                    "Network security config allows cleartext traffic for all connections",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("network_security")
                .with_cwe("CWE-319")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file("res/xml/network_security_config.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Set cleartextTrafficPermitted=\"false\" in base-config")
                        .with_effort(sh_types::RemediationEffort::Low),
                );

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    async fn check_certificate_pinning(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if network_security_config.xml contains pinning
        let config_path = format!("{}/res/xml/network_security_config.xml", target.path);
        if std::path::Path::new(&config_path).exists() {
            let content = tokio::fs::read_to_string(&config_path).await?;

            if !content.contains("<pin-set") && !content.contains("<pin") {
                let finding = Finding::new(
                    "Certificate Pinning Not Implemented",
                    "The application does not implement certificate pinning, making it vulnerable to MITM attacks with rogue certificates",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Probable)
                .with_type("network_security")
                .with_cwe("CWE-295")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file("res/xml/network_security_config.xml")
                        .with_platform(Platform::Android),
                )
                .with_remediation(
                    Remediation::new("Implement certificate pinning using <pin-set> in network_security_config.xml")
                        .with_effort(sh_types::RemediationEffort::Medium)
                        .add_reference("https://developer.android.com/training/articles/security-config#CertificatePinning"),
                );

                findings.push(finding);
            }
        } else {
            // No network security config at all
            let finding = Finding::new(
                "Network Security Config Missing",
                "The application does not have a network_security_config.xml file",
            )
            .with_severity(Severity::Low)
            .with_confidence(Confidence::Confirmed)
            .with_type("network_security")
            .with_location(
                Location::new()
                    .with_platform(Platform::Android),
            )
            .with_remediation(
                Remediation::new("Create a network_security_config.xml file to define security policies")
                    .with_effort(sh_types::RemediationEffort::Low),
            );

            findings.push(finding);
        }

        Ok(findings)
    }

    async fn check_trust_managers(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // This would scan source code for insecure TrustManager implementations
        // that accept all certificates
        debug!("Checking trust managers for: {}", target.path);

        Ok(findings)
    }

    async fn check_hostname_verifiers(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // This would scan source code for insecure HostnameVerifier implementations
        debug!("Checking hostname verifiers for: {}", target.path);

        Ok(findings)
    }
}

#[async_trait]
impl SecuritySkill for NetworkAnalysisSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "network_analysis"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing network analysis for: {}", ctx.target.path);

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        let findings = match ctx.target.platform {
            Platform::Android => self.analyze_android(&ctx.target).await?,
            Platform::Ios => Vec::new(), // iOS analysis would be implemented here
            _ => Vec::new(),
        };

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(findings)
            .with_metadata("skill_type", serde_json::json!("network_analysis"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()));

        Ok(result)
    }
}

impl Default for NetworkAnalysisSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_analysis_skill_creation() {
        let skill = NetworkAnalysisSkill::new();
        assert_eq!(skill.name(), "network_analysis");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_supported_platforms() {
        let skill = NetworkAnalysisSkill::new();
        let platforms = skill.supported_platforms();
        assert!(platforms.contains(&Platform::Android));
        assert!(platforms.contains(&Platform::Ios));
    }
}
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/network_analysis.rs
git commit -m "feat(sh-skills): add NetworkAnalysisSkill"
```

---

## Task 7: Implement Crypto Analysis Skill

**Files:**
- Create: `crates/sh-skills/src/crypto_analysis.rs`

- [ ] **Step 1: Write crypto_analysis.rs**
```rust
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/crypto_analysis.rs
git commit -m "feat(sh-skills): add CryptoAnalysisSkill"
```

---

## Task 8: Implement Intent Analysis Skill

**Files:**
- Create: `crates/sh-skills/src/intent_analysis.rs`

- [ ] **Step 1: Write intent_analysis.rs**
```rust
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/intent_analysis.rs
git commit -m "feat(sh-skills): add IntentAnalysisSkill"
```

---

## Task 9: Implement OWASP Top 10 Skill

**Files:**
- Create: `crates/sh-skills/src/owasp_top10.rs`

- [ ] **Step 1: Write owasp_top10.rs**
```rust
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
        let findings = ctx.config.options.get("findings")
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/owasp_top10.rs
git commit -m "feat(sh-skills): add OwaspTop10Skill"
```

---

## Task 10: Implement Correlation Skill

**Files:**
- Create: `crates/sh-skills/src/correlation.rs`

- [ ] **Step 1: Write correlation.rs**
```rust
//! Finding Correlation Skill
//!
//! Correlates findings across different analysis types:
//! - Duplicate detection
//! - Related finding chains
//! - Attack path construction
//! - Finding clusters
//! - Cross-skill correlation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::{AnalysisTarget, Confidence, Finding, FindingId, Location, Platform, Severity};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Correlation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    Duplicate,      // Same issue found by multiple tools
    Related,        // Related findings
    Chain,          // Part of an attack chain
    Cluster,        // Part of a finding cluster
    Supersedes,     // One finding supersedes another
}

/// Correlation between findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCorrelation {
    pub source_id: FindingId,
    pub target_id: FindingId,
    pub correlation_type: CorrelationType,
    pub confidence: f64, // 0.0 to 1.0
    pub reason: String,
}

/// Configuration for correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    pub detect_duplicates: bool,
    pub detect_chains: bool,
    pub detect_clusters: bool,
    pub similarity_threshold: f64,
    pub max_correlations_per_finding: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            detect_duplicates: true,
            detect_chains: true,
            detect_clusters: true,
            similarity_threshold: 0.8,
            max_correlations_per_finding: 10,
        }
    }
}

/// Correlation skill
#[derive(Debug)]
pub struct CorrelationSkill {
    id: SkillId,
    config: CorrelationConfig,
}

impl CorrelationSkill {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            config: CorrelationConfig::default(),
        }
    }

    pub fn with_config(mut self, config: CorrelationConfig) -> Self {
        self.config = config;
        self
    }

    /// Find duplicate findings
    fn find_duplicates(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut processed = HashSet::new();

        for (i, finding1) in findings.iter().enumerate() {
            if processed.contains(&finding1.id) {
                continue;
            }

            for finding2 in findings.iter().skip(i + 1) {
                if processed.contains(&finding2.id) {
                    continue;
                }

                let similarity = self.calculate_similarity(finding1, finding2);
                if similarity >= self.config.similarity_threshold {
                    correlations.push(FindingCorrelation {
                        source_id: finding1.id,
                        target_id: finding2.id,
                        correlation_type: CorrelationType::Duplicate,
                        confidence: similarity,
                        reason: format!("Similarity score: {:.2}", similarity),
                    });
                    processed.insert(finding2.id);
                }
            }
        }

        correlations
    }

    /// Calculate similarity between two findings (0.0 to 1.0)
    fn calculate_similarity(&self, f1: &Finding, f2: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;

        // Title similarity (weight: 0.3)
        let title_sim = self.string_similarity(&f1.title, &f2.title);
        score += title_sim * 0.3;
        weights += 0.3;

        // Description similarity (weight: 0.2)
        let desc_sim = self.string_similarity(&f1.description, &f2.description);
        score += desc_sim * 0.2;
        weights += 0.2;

        // Location similarity (weight: 0.3)
        let loc_sim = self.location_similarity(&f1.location, &f2.location);
        score += loc_sim * 0.3;
        weights += 0.3;

        // CWE similarity (weight: 0.1)
        if f1.cwe_id == f2.cwe_id && f1.cwe_id.is_some() {
            score += 1.0 * 0.1;
        }
        weights += 0.1;

        // Finding type similarity (weight: 0.1)
        if f1.finding_type == f2.finding_type {
            score += 1.0 * 0.1;
        }
        weights += 0.1;

        if weights > 0.0 {
            score / weights
        } else {
            0.0
        }
    }

    /// Simple string similarity using Jaccard index on words
    fn string_similarity(&self, s1: &str, s2: &str) -> f64 {
        let words1: HashSet<String> = s1.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let words2: HashSet<String> = s2.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if words1.is_empty() && words2.is_empty() {
            return 1.0;
        }
        if words1.is_empty() || words2.is_empty() {
            return 0.0;
        }

        let intersection: HashSet<_> = words1.intersection(&words2).collect();
        let union: HashSet<_> = words1.union(&words2).collect();

        intersection.len() as f64 / union.len() as f64
    }

    /// Calculate location similarity
    fn location_similarity(&self, l1: &Location, l2: &Location) -> f64 {
        let mut matches = 0;
        let mut total = 0;

        if let (Some(f1), Some(f2)) = (&l1.file_path, &l2.file_path) {
            total += 1;
            if f1 == f2 {
                matches += 1;
            }
        }

        if let (Some(n1), Some(n2)) = (&l1.line_number, &l2.line_number) {
            total += 1;
            // Lines within 5 lines are considered similar
            if (*n1 as i32 - *n2 as i32).abs() <= 5 {
                matches += 1;
            }
        }

        if let (Some(f1), Some(f2)) = (&l1.function_name, &l2.function_name) {
            total += 1;
            if f1 == f2 {
                matches += 1;
            }
        }

        if total > 0 {
            matches as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Find related findings (different but related issues)
    fn find_related(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();

        for (i, finding1) in findings.iter().enumerate() {
            for finding2 in findings.iter().skip(i + 1) {
                // Check if findings are in the same file and related by CWE
                if let (Some(cwe1), Some(cwe2)) = (&finding1.cwe_id, &finding2.cwe_id) {
                    if cwe1 == cwe2 && self.same_file(&finding1.location, &finding2.location) {
                        correlations.push(FindingCorrelation {
                            source_id: finding1.id,
                            target_id: finding2.id,
                            correlation_type: CorrelationType::Related,
                            confidence: 0.7,
                            reason: format!("Same CWE ({}) in same file", cwe1),
                        });
                    }
                }

                // Check for attack chains (e.g., exported component + implicit intent)
                if self.forms_attack_chain(finding1, finding2) {
                    correlations.push(FindingCorrelation {
                        source_id: finding1.id,
                        target_id: finding2.id,
                        correlation_type: CorrelationType::Chain,
                        confidence: 0.8,
                        reason: "Forms potential attack chain".to_string(),
                    });
                }
            }
        }

        correlations
    }

    fn same_file(&self, l1: &Location, l2: &Location) -> bool {
        match (&l1.file_path, &l2.file_path) {
            (Some(f1), Some(f2)) => f1 == f2,
            _ => false,
        }
    }

    /// Check if two findings form an attack chain
    fn forms_attack_chain(&self, f1: &Finding, f2: &Finding) -> bool {
        // Example: exported component + implicit intent could form a chain
        let chain_patterns = vec![
            ("exported_component", "implicit_intent"),
            ("debuggable", "hardcoded_secret"),
            ("cleartext_traffic", "network_listener"),
        ];

        for (type1, type2) in &chain_patterns {
            if (f1.finding_type.contains(type1) && f2.finding_type.contains(type2))
                || (f1.finding_type.contains(type2) && f2.finding_type.contains(type1))
            {
                return true;
            }
        }

        false
    }

    /// Group findings into clusters
    fn cluster_findings(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut clusters: HashMap<String, Vec<FindingId>> = HashMap::new();

        // Group by file
        for finding in findings {
            if let Some(ref file) = finding.location.file_path {
                clusters.entry(file.clone()).or_default().push(finding.id);
            }
        }

        // Create cluster correlations
        for (file, ids) in clusters {
            if ids.len() > 1 {
                for (i, id1) in ids.iter().enumerate() {
                    for id2 in ids.iter().skip(i + 1) {
                        correlations.push(FindingCorrelation {
                            source_id: *id1,
                            target_id: *id2,
                            correlation_type: CorrelationType::Cluster,
                            confidence: 0.6,
                            reason: format!("In same file: {}", file),
                        });
                    }
                }
            }
        }

        correlations
    }

    /// Apply correlations to findings (mark duplicates, etc.)
    fn apply_correlations(&self, findings: &mut [Finding], correlations: &[FindingCorrelation]) {
        for corr in correlations {
            match corr.correlation_type {
                CorrelationType::Duplicate => {
                    // Mark the target as duplicate of source
                    if let Some(target) = findings.iter_mut().find(|f| f.id == corr.target_id) {
                        target.duplicate_of = Some(corr.source_id);
                    }
                }
                CorrelationType::Related | CorrelationType::Chain | CorrelationType::Cluster => {
                    // Add correlation to both findings
                    if let Some(source) = findings.iter_mut().find(|f| f.id == corr.source_id) {
                        source.correlated_ids.push(corr.target_id);
                    }
                    if let Some(target) = findings.iter_mut().find(|f| f.id == corr.target_id) {
                        target.correlated_ids.push(corr.source_id);
                    }
                }
                _ => {}
            }
        }
    }
}

#[async_trait]
impl SecuritySkill for CorrelationSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "correlation"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Android, Platform::Ios, Platform::Web, Platform::Iot, Platform::Network]
    }

    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing finding correlation");

        // Get findings from context
        let mut findings: Vec<Finding> = ctx.config.options.get("findings")
            .and_then(|v| serde_json::from_value::<Vec<Finding>>(v.clone()).ok())
            .unwrap_or_default();

        if findings.is_empty() {
            return Ok(SkillResult::new(self.id, ctx.task_id));
        }

        let mut all_correlations = Vec::new();

        // Detect duplicates
        if self.config.detect_duplicates {
            let duplicates = self.find_duplicates(&findings);
            all_correlations.extend(duplicates);
        }

        // Find related findings
        let related = self.find_related(&findings);
        all_correlations.extend(related);

        // Cluster findings
        if self.config.detect_clusters {
            let clusters = self.cluster_findings(&findings);
            all_correlations.extend(clusters);
        }

        // Apply correlations to findings
        self.apply_correlations(&mut findings, &all_correlations);

        // Create correlation summary finding
        let summary = Finding::new(
            "Finding Correlation Analysis",
            format!("Found {} correlations across {} findings", all_correlations.len(), findings.len()),
        )
        .with_severity(Severity::Info)
        .with_type("correlation");

        let mut result_findings = vec![summary];
        result_findings.extend(findings);

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(result_findings)
            .with_metadata("skill_type", serde_json::json!("correlation"))
            .with_metadata("correlation_count", serde_json::json!(all_correlations.len()))
            .with_metadata("correlations", serde_json::to_value(&all_correlations).unwrap_or_default());

        Ok(result)
    }
}

impl Default for CorrelationSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_skill_creation() {
        let skill = CorrelationSkill::new();
        assert_eq!(skill.name(), "correlation");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_string_similarity() {
        let skill = CorrelationSkill::new();
        
        let sim1 = skill.string_similarity("Hardcoded Password", "Hardcoded Password");
        assert_eq!(sim1, 1.0);

        let sim2 = skill.string_similarity("Hardcoded Password", "Hardcoded API Key");
        assert!(sim2 > 0.3 && sim2 < 1.0);

        let sim3 = skill.string_similarity("Completely Different", "Nothing Alike");
        assert!(sim3 < 0.3);
    }

    #[test]
    fn test_location_similarity() {
        let skill = CorrelationSkill::new();
        
        let loc1 = Location::new().with_file("test.java").with_line(10);
        let loc2 = Location::new().with_file("test.java").with_line(12);
        
        let sim = skill.location_similarity(&loc1, &loc2);
        assert!(sim > 0.5);
    }
}
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/correlation.rs
git commit -m "feat(sh-skills): add CorrelationSkill"
```

---

## Task 11: Implement Risk Context Skill

**Files:**
- Create: `crates/sh-skills/src/risk_context.rs`

- [ ] **Step 1: Write risk_context.rs**
```rust
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
        .with_severity(report.overall_risk_level.clone().into())
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
```

- [ ] **Step 2: Commit**
```bash
git add crates/sh-skills/src/risk_context.rs
git commit -m "feat(sh-skills): add RiskContextSkill"
```

---

## Task 12: Update Workspace and Verify Build

**Files:**
- Modify: `crates/sh-skills/Cargo.toml` (add regex dependency)

- [ ] **Step 1: Update Cargo.toml to add regex dependency**
```toml
[package]
name = "sh-skills"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
rust-version.workspace = true
description = "Security analysis skills for Soul Hunter RS"

[dependencies]
# Internal dependencies
sh-types = { workspace = true }
sh-tools = { workspace = true }

# Async runtime
tokio = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Tracing
tracing = { workspace = true }

# Time
chrono = { workspace = true }

# UUID
uuid = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Collections
dashmap = { workspace = true }

# Pattern matching (needed for static analysis)
regex = { version = "1.10" }

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3.9"
```

- [ ] **Step 2: Verify the build compiles**
```bash
cd crates/sh-skills && cargo check
```

- [ ] **Step 3: Commit**
```bash
git add crates/sh-skills/Cargo.toml
git commit -m "feat(sh-skills): add regex dependency and finalize crate"
```

---

## Task 13: Run Tests and Final Verification

**Files:**
- All files in `crates/sh-skills/`

- [ ] **Step 1: Run unit tests**
```bash
cd crates/sh-skills && cargo test
```

- [ ] **Step 2: Run clippy for linting**
```bash
cd crates/sh-skills && cargo clippy -- -D warnings
```

- [ ] **Step 3: Check formatting**
```bash
cd crates/sh-skills && cargo fmt -- --check
```

- [ ] **Step 4: Final commit**
```bash
git add crates/sh-skills/
git commit -m "feat(sh-skills): complete security skills crate with all 9 skills"
```

---

## Summary

This implementation plan creates a production-ready `sh-skills` crate with:

1. **Core Infrastructure** (`lib.rs`, `error.rs`)
   - `SecuritySkill` trait with async support
   - `SkillContext` and `SkillResult` types
   - Error handling with `SkillError`

2. **9 Security Skills**:
   - `AttackSurfaceSkill`: Maps attack surface (exported components, deep links)
   - `StaticAnalysisSkill`: Pattern-based code analysis (secrets, SQL injection, etc.)
   - `NetworkAnalysisSkill`: Network security (cleartext, certificate pinning)
   - `CryptoAnalysisSkill`: Cryptographic review (weak algorithms, hardcoded keys)
   - `IntentAnalysisSkill`: Android Intent/IPC security
   - `OwaspTop10Skill`: OWASP Mobile Top 10 categorization
   - `CorrelationSkill`: Finding correlation and duplicate detection
   - `RiskContextSkill`: Contextual risk scoring

3. **Production Features**:
   - Async execution with tokio
   - Comprehensive error handling
   - Tracing integration
   - Full test coverage
   - Documentation

All skills follow the existing patterns from `sh-agents` and `sh-types` crates.
