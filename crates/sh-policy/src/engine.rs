//! Policy engine with WASM and Rego support

use crate::error::{PolicyError, Result};
use crate::rego::{CompiledRegoPolicy, RegoConfig, RegoEngine};
use crate::store::PolicyStore;
use crate::wasm::{CompiledWasmPolicy, WasmRuntime};
use crate::{Action, EvaluationContext, EvaluationStats};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sh_types::{
    EnforcementMode, Finding, Policy, PolicyEvaluationRequest, PolicyEvaluationResponse,
    PolicyId, PolicyResult, PolicySet, PolicyType, PolicyViolation, Severity,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Policy engine configuration
#[derive(Debug, Clone)]
pub struct PolicyEngineConfig {
    /// Default enforcement mode
    pub default_mode: EnforcementMode,
    /// Enable WASM policies
    pub enable_wasm: bool,
    /// Enable Rego policies
    pub enable_rego: bool,
    /// Rego-specific configuration
    pub rego_config: RegoConfig,
    /// Maximum evaluation time in milliseconds
    pub max_evaluation_time_ms: u64,
    /// Enable caching of compiled policies
    pub enable_caching: bool,
    /// Cache size limit
    pub cache_size: usize,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            default_mode: EnforcementMode::Audit,
            enable_wasm: true,
            enable_rego: true,
            rego_config: RegoConfig::default(),
            max_evaluation_time_ms: 30000,
            enable_caching: true,
            cache_size: 1000,
        }
    }
}

/// Policy engine - main entry point for policy evaluation
#[derive(Debug)]
pub struct PolicyEngine {
    config: PolicyEngineConfig,
    store: PolicyStore,
    wasm_runtime: Option<WasmRuntime>,
    rego_engine: Option<RegoEngine>,
    compiled_wasm: RwLock<HashMap<PolicyId, CompiledWasmPolicy>>,
    compiled_rego: RwLock<HashMap<PolicyId, CompiledRegoPolicy>>,
    stats: RwLock<EvaluationStats>,
}

/// Validation phase for pre/post action validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationPhase {
    PreAction,
    PostAction,
}

/// Policy evaluation builder
#[derive(Debug)]
pub struct PolicyEvaluationBuilder {
    target: Option<sh_types::AnalysisTarget>,
    findings: Vec<Finding>,
    action: Option<Action>,
    phase: ValidationPhase,
    policy_set: Option<Uuid>,
    specific_policies: Vec<PolicyId>,
    context: EvaluationContext,
}

impl PolicyEvaluationBuilder {
    /// Create a new evaluation builder
    pub fn new() -> Self {
        Self {
            target: None,
            findings: Vec::new(),
            action: None,
            phase: ValidationPhase::PreAction,
            policy_set: None,
            specific_policies: Vec::new(),
            context: EvaluationContext::new(),
        }
    }

    /// Set the analysis target
    pub fn with_target(mut self, target: sh_types::AnalysisTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Add a finding to evaluate
    pub fn with_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }

    /// Add multiple findings
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings.extend(findings);
        self
    }

    /// Set the action to validate
    pub fn with_action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Set validation phase
    pub fn with_phase(mut self, phase: ValidationPhase) -> Self {
        self.phase = phase;
        self
    }

    /// Use a policy set
    pub fn with_policy_set(mut self, policy_set_id: Uuid) -> Self {
        self.policy_set = Some(policy_set_id);
        self
    }

    /// Use specific policies
    pub fn with_policy(mut self, policy_id: PolicyId) -> Self {
        self.specific_policies.push(policy_id);
        self
    }

    /// Add context metadata
    pub fn with_context(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.context = self.context.with_metadata(key, value);
        self
    }

    /// Set dry run mode
    pub fn dry_run(mut self) -> Self {
        self.context = self.context.dry_run();
        self
    }

    /// Build the evaluation request
    pub fn build(self) -> Result<PolicyEvaluationRequest> {
        let target = self.target.ok_or_else(|| {
            PolicyError::ValidationError("Target is required for policy evaluation".to_string())
        })?;

        Ok(PolicyEvaluationRequest {
            target,
            context: self.context.metadata,
            policy_set: self.policy_set,
            specific_policies: self.specific_policies,
        })
    }
}

impl Default for PolicyEvaluationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create a new policy engine
    pub async fn new(config: PolicyEngineConfig) -> Result<Self> {
        let wasm_runtime = if config.enable_wasm {
            Some(WasmRuntime::new()?)
        } else {
            None
        };

        let rego_engine = if config.enable_rego {
            Some(RegoEngine::new(config.rego_config.clone()))
        } else {
            None
        };

        info!(
            wasm_enabled = config.enable_wasm,
            rego_enabled = config.enable_rego,
            "Policy engine initialized"
        );

        Ok(Self {
            config,
            store: PolicyStore::new(),
            wasm_runtime,
            rego_engine,
            compiled_wasm: RwLock::new(HashMap::new()),
            compiled_rego: RwLock::new(HashMap::new()),
            stats: RwLock::new(EvaluationStats::default()),
        })
    }

    /// Get the policy store
    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    /// Load a policy into the engine
    #[instrument(skip(self, policy), fields(policy_id = %policy.id))]
    pub async fn load_policy(&self, policy: Policy) -> Result<()> {
        // Compile the policy based on type
        match policy.policy_type {
            PolicyType::Wasm => {
                if let Some(ref runtime) = self.wasm_runtime {
                    let compiled = runtime.compile(&policy)?;
                    let mut cache = self.compiled_wasm.write().await;
                    cache.insert(policy.id, compiled);
                    self.store.mark_compiled(policy.id, true, None)?;
                } else {
                    return Err(PolicyError::ConfigurationError(
                        "WASM runtime not enabled".to_string(),
                    ));
                }
            }
            PolicyType::Rego => {
                if let Some(ref engine) = self.rego_engine {
                    let compiled = engine.compile(&policy).await?;
                    let mut cache = self.compiled_rego.write().await;
                    cache.insert(policy.id, compiled);
                    self.store.mark_compiled(policy.id, true, None)?;
                } else {
                    return Err(PolicyError::ConfigurationError(
                        "Rego engine not enabled".to_string(),
                    ));
                }
            }
            PolicyType::Yaml | PolicyType::Json => {
                // These are configuration-based policies, no compilation needed
                self.store.mark_compiled(policy.id, true, None)?;
            }
        }

        // Store the policy
        self.store.store(policy)?;

        info!("Policy loaded successfully");
        Ok(())
    }

    /// Unload a policy
    #[instrument(skip(self), fields(policy_id = %policy_id))]
    pub async fn unload_policy(&self, policy_id: PolicyId) -> Result<bool> {
        // Remove from compiled caches
        {
            let mut wasm_cache = self.compiled_wasm.write().await;
            wasm_cache.remove(&policy_id);
        }
        {
            let mut rego_cache = self.compiled_rego.write().await;
            rego_cache.remove(&policy_id);
        }

        // Remove from store
        self.store.delete(policy_id)
    }

    /// Evaluate a single policy against findings
    #[instrument(skip(self, policy, findings), fields(policy_id = %policy.id))]
    pub async fn evaluate(&self, policy: &Policy, findings: &[Finding]) -> Result<PolicyResult> {
        let start = Instant::now();

        if !policy.enabled {
            return Ok(PolicyResult::new(policy.id, policy.name.clone())
                .with_execution_time(0));
        }

        let result = match policy.policy_type {
            PolicyType::Wasm => {
                if let Some(ref runtime) = self.wasm_runtime {
                    // Check cache first
                    let compiled = {
                        let cache = self.compiled_wasm.read().await;
                        cache.get(&policy.id).cloned()
                    };

                    if let Some(compiled) = compiled {
                        runtime.evaluate_findings(&compiled, findings).await?
                    } else {
                        // Compile on the fly
                        let compiled = runtime.compile(policy)?;
                        let result = runtime.evaluate_findings(&compiled, findings).await?;

                        // Cache if enabled
                        if self.config.enable_caching {
                            let mut cache = self.compiled_wasm.write().await;
                            if cache.len() < self.config.cache_size {
                                cache.insert(policy.id, compiled);
                            }
                        }

                        result
                    }
                } else {
                    return Err(PolicyError::ConfigurationError(
                        "WASM runtime not enabled".to_string(),
                    ));
                }
            }
            PolicyType::Rego => {
                if let Some(ref engine) = self.rego_engine {
                    // Check cache first
                    let compiled = {
                        let cache = self.compiled_rego.read().await;
                        cache.get(&policy.id).cloned()
                    };

                    if let Some(compiled) = compiled {
                        engine.evaluate_findings(&compiled, findings).await?
                    } else {
                        // Compile on the fly
                        let compiled = engine.compile(policy).await?;
                        let result = engine.evaluate_findings(&compiled, findings).await?;

                        // Cache if enabled
                        if self.config.enable_caching {
                            let mut cache = self.compiled_rego.write().await;
                            if cache.len() < self.config.cache_size {
                                cache.insert(policy.id, compiled);
                            }
                        }

                        result
                    }
                } else {
                    return Err(PolicyError::ConfigurationError(
                        "Rego engine not enabled".to_string(),
                    ));
                }
            }
            PolicyType::Yaml | PolicyType::Json => {
                // Evaluate configuration-based policies
                self.evaluate_config_policy(policy, findings).await?
            }
        };

        let execution_time = start.elapsed().as_millis() as u64;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.record_evaluation(result.passed, execution_time);
        }

        // Record evaluation in store
        self.store.record_evaluation(policy.id)?;

        info!(
            policy_id = %policy.id,
            passed = result.passed,
            violations = result.violations.len(),
            execution_time_ms = execution_time,
            "Policy evaluation completed"
        );

        Ok(result)
    }

    /// Evaluate multiple policies
    #[instrument(skip(self, request))]
    pub async fn evaluate_policies(
        &self,
        request: &PolicyEvaluationRequest,
    ) -> Result<PolicyEvaluationResponse> {
        let start = Instant::now();
        let request_id = Uuid::new_v4();

        // Get policies to evaluate
        let policies = if !request.specific_policies.is_empty() {
            // Use specific policies
            let mut policies = Vec::new();
            for policy_id in &request.specific_policies {
                if let Some(policy) = self.store.get(*policy_id)? {
                    policies.push(policy);
                }
            }
            policies
        } else if let Some(policy_set_id) = request.policy_set {
            // Use policy set
            self.store.get_policy_set_policies(policy_set_id)?
        } else {
            // Use all enabled policies
            self.store.get_enabled()
        };

        // Evaluate each policy
        let mut results = Vec::new();
        let mut total_violations = 0;
        let mut all_passed = true;

        for policy in policies {
            // Create dummy findings for now - in real usage, findings would come from analysis
            let findings: Vec<Finding> = Vec::new();

            match self.evaluate(&policy, &findings).await {
                Ok(result) => {
                    if !result.passed {
                        all_passed = false;
                        total_violations += result.violations.len();
                    }
                    results.push(result);
                }
                Err(e) => {
                    error!(policy_id = %policy.id, error = %e, "Policy evaluation failed");
                    all_passed = false;
                }
            }
        }

        let execution_time = start.elapsed().as_millis() as u64;

        Ok(PolicyEvaluationResponse {
            request_id,
            passed: all_passed,
            results,
            total_violations,
            execution_time_ms: execution_time,
        })
    }

    /// Validate an action before execution (pre-action validation)
    #[instrument(skip(self, action))]
    pub async fn validate_pre_action(&self, action: &Action) -> Result<PolicyResult> {
        // Get policies that apply to pre-action validation
        let policies = self.store.get_enabled();

        let mut all_violations = Vec::new();
        let mut all_passed = true;

        for policy in policies {
            // Check if policy applies to this action type
            if self.policy_applies_to_action(&policy, action) {
                // Create a dummy finding representing the action
                let finding = Finding::new(
                    format!("action:{}", action.action_type),
                    format!("Action validation: {}", action.operation),
                )
                .with_severity(Severity::Info);

                match self.evaluate(&policy, &[finding]).await {
                    Ok(result) => {
                        if !result.passed {
                            all_passed = false;
                            all_violations.extend(result.violations);
                        }
                    }
                    Err(e) => {
                        error!(policy_id = %policy.id, error = %e, "Pre-action validation failed");
                        all_passed = false;
                    }
                }
            }
        }

        let mut result = PolicyResult::new(Uuid::new_v4(), "pre-action-validation".to_string());
        result.passed = all_passed;
        result.violations = all_violations;

        Ok(result)
    }

    /// Validate an action after execution (post-action validation)
    #[instrument(skip(self, action, findings))]
    pub async fn validate_post_action(
        &self,
        action: &Action,
        findings: &[Finding],
    ) -> Result<PolicyResult> {
        // Get policies that apply to post-action validation
        let policies = self.store.get_enabled();

        let mut all_violations = Vec::new();
        let mut all_passed = true;

        for policy in policies {
            // Check if policy applies to this action type
            if self.policy_applies_to_action(&policy, action) {
                match self.evaluate(&policy, findings).await {
                    Ok(result) => {
                        if !result.passed {
                            all_passed = false;
                            all_violations.extend(result.violations);
                        }
                    }
                    Err(e) => {
                        error!(policy_id = %policy.id, error = %e, "Post-action validation failed");
                        all_passed = false;
                    }
                }
            }
        }

        let mut result = PolicyResult::new(Uuid::new_v4(), "post-action-validation".to_string());
        result.passed = all_passed;
        result.violations = all_violations;

        Ok(result)
    }

    /// Check if a policy applies to an action
    fn policy_applies_to_action(&self, policy: &Policy, action: &Action) -> bool {
        // Check included paths
        if !policy.config.included_paths.is_empty() {
            let matches = policy
                .config
                .included_paths
                .iter()
                .any(|path| action.resource.starts_with(path));
            if !matches {
                return false;
            }
        }

        // Check excluded paths
        if policy
            .config
            .excluded_paths
            .iter()
            .any(|path| action.resource.starts_with(path))
        {
            return false;
        }

        true
    }

    /// Evaluate a configuration-based policy (YAML/JSON)
    async fn evaluate_config_policy(
        &self,
        policy: &Policy,
        findings: &[Finding],
    ) -> Result<PolicyResult> {
        let mut result = PolicyResult::new(policy.id, policy.name.clone());

        // Parse configuration
        let config: serde_json::Value = match policy.policy_type {
            PolicyType::Yaml => {
                serde_yaml::from_str(&policy.content).map_err(|e| {
                    PolicyError::ValidationError(format!("Invalid YAML policy: {}", e))
                })?
            }
            PolicyType::Json => {
                serde_json::from_str(&policy.content).map_err(|e| {
                    PolicyError::ValidationError(format!("Invalid JSON policy: {}", e))
                })?
            }
            _ => {
                return Err(PolicyError::InvalidPolicyType(format!(
                    "Expected YAML or JSON policy, got {:?}",
                    policy.policy_type
                )))
            }
        };

        // Apply rules from configuration
        if let Some(rules) = config.get("rules").and_then(|r| r.as_array()) {
            for rule in rules {
                if let Some(condition) = rule.get("condition") {
                    if self.evaluate_condition(condition, findings) {
                        if let Some(violation) = self.create_violation_from_rule(rule) {
                            result = result.add_violation(violation);
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Evaluate a condition against findings
    fn evaluate_condition(&self, condition: &serde_json::Value, findings: &[Finding]) -> bool {
        // Simple condition evaluation - can be extended
        if let Some(severity) = condition.get("severity").and_then(|s| s.as_str()) {
            let min_severity = match severity {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };

            return findings.iter().any(|f| f.severity >= min_severity);
        }

        if let Some(finding_type) = condition.get("finding_type").and_then(|t| t.as_str()) {
            return findings.iter().any(|f| f.finding_type == finding_type);
        }

        false
    }

    /// Create a violation from a rule configuration
    fn create_violation_from_rule(&self, rule: &serde_json::Value) -> Option<PolicyViolation> {
        let rule_name = rule
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");
        let message = rule
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Policy violation");

        let severity = rule
            .get("severity")
            .and_then(|s| s.as_str())
            .map(|s| match s {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            })
            .unwrap_or(Severity::High);

        Some(
            PolicyViolation::new(rule_name, message)
                .with_severity(severity),
        )
    }

    /// Get evaluation statistics
    pub async fn get_stats(&self) -> EvaluationStats {
        self.stats.read().await.clone()
    }

    /// Clear compiled policy cache
    pub async fn clear_cache(&self) {
        {
            let mut wasm_cache = self.compiled_wasm.write().await;
            wasm_cache.clear();
        }
        {
            let mut rego_cache = self.compiled_rego.write().await;
            rego_cache.clear();
        }
        info!("Policy cache cleared");
    }

    /// Get engine health status
    pub fn health(&self) -> EngineHealth {
        EngineHealth {
            wasm_enabled: self.wasm_runtime.is_some(),
            rego_enabled: self.rego_engine.is_some(),
            policy_count: self.store.count(),
            wasm_policy_count: self.store.count_by_type(PolicyType::Wasm),
            rego_policy_count: self.store.count_by_type(PolicyType::Rego),
        }
    }
}

/// Engine health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineHealth {
    pub wasm_enabled: bool,
    pub rego_enabled: bool,
    pub policy_count: usize,
    pub wasm_policy_count: usize,
    pub rego_policy_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform, PolicyType};

    #[tokio::test]
    async fn test_policy_engine_creation() {
        let config = PolicyEngineConfig::default();
        let engine = PolicyEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[test]
    fn test_policy_evaluation_builder() {
        let target = AnalysisTarget::new("/test", Platform::Android);
        let builder = PolicyEvaluationBuilder::new()
            .with_target(target)
            .with_phase(ValidationPhase::PreAction)
            .dry_run();

        let request = builder.build().unwrap();
        assert!(request.context.get("dry_run").is_some());
    }

    #[tokio::test]
    async fn test_load_and_evaluate_policy() {
        let config = PolicyEngineConfig::default();
        let engine = PolicyEngine::new(config).await.unwrap();

        // Create a simple YAML policy
        let policy = Policy::new(
            "test-policy",
            PolicyType::Yaml,
            r#"
rules:
  - name: TEST_RULE
    condition:
      severity: high
    message: Test violation
    severity: high
"#,
        );

        engine.load_policy(policy.clone()).await.unwrap();

        // Create a finding that matches the condition
        let finding = Finding::new("Test", "Test finding").with_severity(Severity::High);

        let result = engine.evaluate(&policy, &[finding]).await.unwrap();
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
    }

    #[test]
    fn test_action_validation() {
        let action = Action::new("scan", "/path/to/target")
            .with_subject("user123")
            .with_operation("read");

        assert_eq!(action.action_type, "scan");
        assert_eq!(action.resource, "/path/to/target");
    }

    #[test]
    fn test_engine_health() {
        let health = EngineHealth {
            wasm_enabled: true,
            rego_enabled: true,
            policy_count: 10,
            wasm_policy_count: 3,
            rego_policy_count: 5,
        };

        assert!(health.wasm_enabled);
        assert!(health.rego_enabled);
        assert_eq!(health.policy_count, 10);
    }
}
