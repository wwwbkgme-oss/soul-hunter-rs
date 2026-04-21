//! Policy types for policy enforcement

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for policies
pub type PolicyId = Uuid;

/// Policy types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Wasm,
    Rego,
    Yaml,
    Json,
}

impl Default for PolicyType {
    fn default() -> Self {
        PolicyType::Wasm
    }
}

/// Policy enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Audit,
    Enforce,
    Disabled,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        EnforcementMode::Audit
    }
}

/// A security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: PolicyType,
    pub mode: EnforcementMode,
    pub content: String,
    pub version: String,
    
    // Configuration
    pub config: PolicyConfig,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
    pub tags: Vec<String>,
}

impl Policy {
    pub fn new(name: impl Into<String>, policy_type: PolicyType, content: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            policy_type,
            mode: EnforcementMode::Audit,
            content: content.into(),
            version: "1.0.0".to_string(),
            config: PolicyConfig::default(),
            created_at: now,
            updated_at: now,
            enabled: true,
            tags: Vec::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_mode(mut self, mode: EnforcementMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_config(mut self, config: PolicyConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    pub fn update_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
        self.updated_at = Utc::now();
    }
}

/// Policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub parameters: HashMap<String, serde_json::Value>,
    pub severity_threshold: Option<crate::Severity>,
    pub excluded_paths: Vec<String>,
    pub included_paths: Vec<String>,
}

impl PolicyConfig {
    pub fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    pub fn with_severity_threshold(mut self, severity: crate::Severity) -> Self {
        self.severity_threshold = Some(severity);
        self
    }

    pub fn exclude_path(mut self, path: impl Into<String>) -> Self {
        self.excluded_paths.push(path.into());
        self
    }

    pub fn include_path(mut self, path: impl Into<String>) -> Self {
        self.included_paths.push(path.into());
        self
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub policy_id: PolicyId,
    pub policy_name: String,
    pub passed: bool,
    pub violations: Vec<PolicyViolation>,
    pub execution_time_ms: u64,
    pub timestamp: DateTime<Utc>,
}

impl PolicyResult {
    pub fn new(policy_id: PolicyId, policy_name: impl Into<String>) -> Self {
        Self {
            policy_id,
            policy_name: policy_name.into(),
            passed: true,
            violations: Vec::new(),
            execution_time_ms: 0,
            timestamp: Utc::now(),
        }
    }

    pub fn add_violation(mut self, violation: PolicyViolation) -> Self {
        self.passed = false;
        self.violations.push(violation);
        self
    }

    pub fn with_execution_time(mut self, ms: u64) -> Self {
        self.execution_time_ms = ms;
        self
    }
}

/// Policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub message: String,
    pub severity: crate::Severity,
    pub location: Option<String>,
    pub remediation: Option<String>,
}

impl PolicyViolation {
    pub fn new(rule: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            message: message.into(),
            severity: crate::Severity::High,
            location: None,
            remediation: None,
        }
    }

    pub fn with_severity(mut self, severity: crate::Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Policy set for grouping policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<PolicyId>,
    pub default_mode: EnforcementMode,
    pub created_at: DateTime<Utc>,
}

impl PolicySet {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            policies: Vec::new(),
            default_mode: EnforcementMode::Audit,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_default_mode(mut self, mode: EnforcementMode) -> Self {
        self.default_mode = mode;
        self
    }

    pub fn add_policy(mut self, policy_id: PolicyId) -> Self {
        self.policies.push(policy_id);
        self
    }
}

/// Policy evaluation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationRequest {
    pub target: crate::AnalysisTarget,
    pub context: HashMap<String, serde_json::Value>,
    pub policy_set: Option<Uuid>,
    pub specific_policies: Vec<PolicyId>,
}

/// Policy evaluation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResponse {
    pub request_id: Uuid,
    pub passed: bool,
    pub results: Vec<PolicyResult>,
    pub total_violations: usize,
    pub execution_time_ms: u64,
}

/// Policy audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEntry {
    pub id: Uuid,
    pub policy_id: PolicyId,
    pub target_path: String,
    pub action: PolicyAction,
    pub result: bool,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Policy actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Evaluated,
    Enforced,
    Blocked,
    Allowed,
    AuditOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_builder() {
        let policy = Policy::new("No Hardcoded Secrets", PolicyType::Rego, "package secrets")
            .with_description("Detects hardcoded secrets in code")
            .with_mode(EnforcementMode::Enforce)
            .add_tag("security");

        assert_eq!(policy.name, "No Hardcoded Secrets");
        assert_eq!(policy.policy_type, PolicyType::Rego);
        assert_eq!(policy.mode, EnforcementMode::Enforce);
        assert!(policy.enabled);
    }

    #[test]
    fn test_policy_result() {
        let policy_id = Uuid::new_v4();
        let result = PolicyResult::new(policy_id, "Test Policy")
            .add_violation(PolicyViolation::new("RULE_1", "Violation message"))
            .with_execution_time(100);

        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.execution_time_ms, 100);
    }

    #[test]
    fn test_policy_violation() {
        let violation = PolicyViolation::new("NO_SECRETS", "Hardcoded API key found")
            .with_severity(crate::Severity::Critical)
            .with_location("config.js:42")
            .with_remediation("Use environment variables");

        assert_eq!(violation.rule, "NO_SECRETS");
        assert_eq!(violation.severity, crate::Severity::Critical);
        assert_eq!(violation.location, Some("config.js:42".to_string()));
    }

    #[test]
    fn test_policy_set() {
        let policy_id = Uuid::new_v4();
        let set = PolicySet::new("Security Policies")
            .with_description("Core security policies")
            .with_default_mode(EnforcementMode::Enforce)
            .add_policy(policy_id);

        assert_eq!(set.name, "Security Policies");
        assert_eq!(set.policies.len(), 1);
        assert_eq!(set.default_mode, EnforcementMode::Enforce);
    }
}
