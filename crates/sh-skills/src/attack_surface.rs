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
