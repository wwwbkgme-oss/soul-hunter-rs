//! Rego (Open Policy Agent) policy support

use crate::error::{PolicyError, RegoError, Result};
use serde::{Deserialize, Serialize};
use sh_types::{Finding, Policy, PolicyResult, PolicyViolation, Severity};
use std::collections::HashMap;
use std::time::Instant;
use tokio::process::Command;
use tracing::{debug, info, instrument, warn};

/// Rego policy engine
#[derive(Debug, Clone)]
pub struct RegoEngine {
    config: RegoConfig,
}

/// Rego engine configuration
#[derive(Debug, Clone)]
pub struct RegoConfig {
    /// Path to OPA binary (optional, uses bundled or system OPA if not set)
    pub opa_path: Option<String>,
    /// OPA server URL (for remote evaluation)
    pub opa_server_url: Option<String>,
    /// Timeout for policy evaluation in seconds
    pub timeout_seconds: u64,
    /// Enable bundle support
    pub enable_bundles: bool,
    /// Bundle directory
    pub bundle_dir: Option<String>,
}

impl Default for RegoConfig {
    fn default() -> Self {
        Self {
            opa_path: None,
            opa_server_url: None,
            timeout_seconds: 30,
            enable_bundles: false,
            bundle_dir: None,
        }
    }
}

/// Rego evaluation input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoInput {
    pub finding: Finding,
    pub context: HashMap<String, serde_json::Value>,
}

/// Rego evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoEvaluationResult {
    pub result: Vec<RegoResult>,
}

/// Individual Rego result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoResult {
    pub expression: RegoExpression,
}

/// Rego expression value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoExpression {
    pub value: serde_json::Value,
}

/// Compiled Rego policy
#[derive(Debug, Clone)]
pub struct CompiledRegoPolicy {
    pub policy_id: sh_types::PolicyId,
    pub policy_name: String,
    pub content: String,
    pub package: String,
}

impl RegoEngine {
    /// Create a new Rego engine
    pub fn new(config: RegoConfig) -> Self {
        info!("Rego engine initialized");
        Self { config }
    }

    /// Compile a Rego policy
    #[instrument(skip(self, policy), fields(policy_id = %policy.id))]
    pub async fn compile(&self, policy: &Policy) -> Result<CompiledRegoPolicy> {
        let start = Instant::now();

        // Extract package name from policy content
        let package = self.extract_package(&policy.content)?;

        // Validate syntax by running OPA check
        self.validate_syntax(&policy.content).await?;

        let compile_time = start.elapsed().as_millis() as u64;
        debug!(
            compile_time_ms = compile_time,
            package = %package,
            "Rego policy compiled"
        );

        Ok(CompiledRegoPolicy {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            content: policy.content.clone(),
            package,
        })
    }

    /// Evaluate a finding against a compiled Rego policy
    #[instrument(skip(self, compiled, finding), fields(policy_id = %compiled.policy_id))]
    pub async fn evaluate_finding(
        &self,
        compiled: &CompiledRegoPolicy,
        finding: &Finding,
    ) -> Result<PolicyResult> {
        let start = Instant::now();

        // Prepare input
        let input = RegoInput {
            finding: finding.clone(),
            context: HashMap::new(),
        };

        let input_json = serde_json::to_string(&input).map_err(PolicyError::Serialization)?;

        // Evaluate using OPA
        let result = self
            .evaluate_opa(&compiled.content, &compiled.package, &input_json)
            .await?;

        let execution_time = start.elapsed().as_millis() as u64;

        // Parse result and create PolicyResult
        let mut policy_result =
            PolicyResult::new(compiled.policy_id, compiled.policy_name.clone())
                .with_execution_time(execution_time);

        // Check if policy allows or denies
        let passed = self.is_allowed(&result);

        if !passed {
            // Extract violations from result
            let violations = self.extract_violations(&result);
            for v in violations {
                policy_result = policy_result.add_violation(v);
            }
        }

        info!(
            policy_id = %compiled.policy_id,
            passed = passed,
            execution_time_ms = execution_time,
            "Rego policy evaluation completed"
        );

        Ok(policy_result)
    }

    /// Evaluate multiple findings
    #[instrument(skip(self, compiled, findings), fields(policy_id = %compiled.policy_id))]
    pub async fn evaluate_findings(
        &self,
        compiled: &CompiledRegoPolicy,
        findings: &[Finding],
    ) -> Result<PolicyResult> {
        let start = Instant::now();

        let mut all_violations = Vec::new();
        let mut all_passed = true;

        for finding in findings {
            let input = RegoInput {
                finding: finding.clone(),
                context: HashMap::new(),
            };

            let input_json = serde_json::to_string(&input).map_err(PolicyError::Serialization)?;
            let result = self
                .evaluate_opa(&compiled.content, &compiled.package, &input_json)
                .await?;

            if !self.is_allowed(&result) {
                all_passed = false;
                all_violations.extend(self.extract_violations(&result));
            }
        }

        let execution_time = start.elapsed().as_millis() as u64;

        let mut policy_result =
            PolicyResult::new(compiled.policy_id, compiled.policy_name.clone())
                .with_execution_time(execution_time);

        if !all_passed {
            for violation in all_violations {
                policy_result = policy_result.add_violation(violation);
            }
        }

        Ok(policy_result)
    }

    /// Extract package name from Rego content
    fn extract_package(&self, content: &str) -> Result<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("package ") {
                return Ok(trimmed[8..].trim().to_string());
            }
        }
        Err(RegoError::InvalidPolicy("No package declaration found".to_string()).into())
    }

    /// Validate Rego syntax using OPA check
    async fn validate_syntax(&self, content: &str) -> Result<()> {
        // Create temporary file for the policy
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("rego_check_{}.rego", uuid::Uuid::new_v4()));

        // Write policy to temp file
        tokio::fs::write(&temp_file, content)
            .await
            .map_err(|e| PolicyError::Io(e))?;

        // Run OPA check
        let opa_path = self.config.opa_path.as_deref().unwrap_or("opa");
        let output = Command::new(opa_path)
            .args(&["check", temp_file.to_str().unwrap()])
            .output()
            .await
            .map_err(|e| RegoError::CompilationFailed(format!("OPA check failed: {}", e)))?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&temp_file).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RegoError::CompilationFailed(format!(
                "Rego syntax error: {}",
                stderr
            ))
            .into());
        }

        Ok(())
    }

    /// Evaluate policy using OPA
    async fn evaluate_opa(
        &self,
        policy_content: &str,
        package: &str,
        input: &str,
    ) -> Result<RegoEvaluationResult> {
        // If OPA server URL is configured, use it
        if let Some(server_url) = &self.config.opa_server_url {
            return self.evaluate_opa_server(server_url, package, input).await;
        }

        // Otherwise use OPA CLI
        self.evaluate_opa_cli(policy_content, package, input).await
    }

    /// Evaluate using OPA CLI
    async fn evaluate_opa_cli(
        &self,
        policy_content: &str,
        package: &str,
        input: &str,
    ) -> Result<RegoEvaluationResult> {
        // Create temporary files
        let temp_dir = std::env::temp_dir();
        let policy_file = temp_dir.join(format!("rego_policy_{}.rego", uuid::Uuid::new_v4()));
        let input_file = temp_dir.join(format!("rego_input_{}.json", uuid::Uuid::new_v4()));

        // Write files
        tokio::fs::write(&policy_file, policy_content)
            .await
            .map_err(|e| PolicyError::Io(e))?;

        tokio::fs::write(&input_file, input)
            .await
            .map_err(|e| PolicyError::Io(e))?;

        // Run OPA eval
        let opa_path = self.config.opa_path.as_deref().unwrap_or("opa");
        let query = format!("data.{}".replace(".", "_"), package);

        let output = Command::new(opa_path)
            .args(&[
                "eval",
                "--data",
                policy_file.to_str().unwrap(),
                "--input",
                input_file.to_str().unwrap(),
                &query,
                "--format",
                "json",
            ])
            .output()
            .await
            .map_err(|e| RegoError::EvaluationFailed(format!("OPA eval failed: {}", e)))?;

        // Clean up temp files
        let _ = tokio::fs::remove_file(&policy_file).await;
        let _ = tokio::fs::remove_file(&input_file).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RegoError::EvaluationFailed(format!(
                "OPA evaluation failed: {}",
                stderr
            ))
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: RegoEvaluationResult = serde_json::from_str(&stdout).map_err(|e| {
            RegoError::EvaluationFailed(format!("Failed to parse OPA result: {}", e))
        })?;

        Ok(result)
    }

    /// Evaluate using OPA server
    async fn evaluate_opa_server(
        &self,
        server_url: &str,
        package: &str,
        input: &str,
    ) -> Result<RegoEvaluationResult> {
        let client = reqwest::Client::new();
        let url = format!("{}/v1/data/{}", server_url, package.replace(".", "/"));

        let input_json: serde_json::Value =
            serde_json::from_str(input).map_err(PolicyError::Serialization)?;

        let response = client
            .post(&url)
            .json(&input_json)
            .timeout(tokio::time::Duration::from_secs(self.config.timeout_seconds))
            .send()
            .await
            .map_err(|e| RegoError::OpaServerError(format!("OPA server request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(RegoError::OpaServerError(format!(
                "OPA server error {}: {}",
                status, body
            ))
            .into());
        }

        let result: RegoEvaluationResult = response.json().await.map_err(|e| {
            RegoError::OpaServerError(format!("Failed to parse OPA server response: {}", e))
        })?;

        Ok(result)
    }

    /// Check if result indicates allowed
    fn is_allowed(&self, result: &RegoEvaluationResult) -> bool {
        // Check if any result contains allow = true
        for r in &result.result {
            if let Some(allow) = r.expression.value.get("allow") {
                if let Some(allowed) = allow.as_bool() {
                    return allowed;
                }
            }
            // Check for violations
            if let Some(violations) = r.expression.value.get("violations") {
                if let Some(arr) = violations.as_array() {
                    return arr.is_empty();
                }
            }
        }
        // Default to allowed if no explicit deny
        true
    }

    /// Extract violations from result
    fn extract_violations(&self, result: &RegoEvaluationResult) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();

        for r in &result.result {
            if let Some(violations_array) = r.expression.value.get("violations") {
                if let Some(arr) = violations_array.as_array() {
                    for v in arr {
                        let rule = v
                            .get("rule")
                            .and_then(|r| r.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let message = v
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Policy violation")
                            .to_string();

                        let severity = v
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

                        let location = v.get("location").and_then(|l| l.as_str()).map(String::from);

                        let mut violation = PolicyViolation::new(&rule, &message).with_severity(severity);
                        if let Some(loc) = location {
                            violation = violation.with_location(loc);
                        }

                        violations.push(violation);
                    }
                }
            }
        }

        violations
    }
}

impl Default for RegoEngine {
    fn default() -> Self {
        Self::new(RegoConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Finding, PolicyType};

    #[test]
    fn test_rego_config_default() {
        let config = RegoConfig::default();
        assert_eq!(config.timeout_seconds, 30);
        assert!(!config.enable_bundles);
    }

    #[test]
    fn test_extract_package() {
        let engine = RegoEngine::default();
        let content = r#"
package example.security

import future.keywords.if

allow if true
"#;

        let package = engine.extract_package(content).unwrap();
        assert_eq!(package, "example.security");
    }

    #[test]
    fn test_extract_package_missing() {
        let engine = RegoEngine::default();
        let content = r#"
import future.keywords.if

allow if true
"#;

        let result = engine.extract_package(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_allowed() {
        let engine = RegoEngine::default();

        // Test with allow = true
        let result = RegoEvaluationResult {
            result: vec![RegoResult {
                expression: RegoExpression {
                    value: serde_json::json!({"allow": true}),
                },
            }],
        };
        assert!(engine.is_allowed(&result));

        // Test with allow = false
        let result = RegoEvaluationResult {
            result: vec![RegoResult {
                expression: RegoExpression {
                    value: serde_json::json!({"allow": false}),
                },
            }),
        };
        assert!(!engine.is_allowed(&result));

        // Test with empty violations
        let result = RegoEvaluationResult {
            result: vec![RegoResult {
                expression: RegoExpression {
                    value: serde_json::json!({"violations": []}),
                },
            }),
        };
        assert!(engine.is_allowed(&result));
    }

    #[test]
    fn test_extract_violations() {
        let engine = RegoEngine::default();

        let result = RegoEvaluationResult {
            result: vec![RegoResult {
                expression: RegoExpression {
                    value: serde_json::json!({
                        "violations": [
                            {
                                "rule": "NO_SECRETS",
                                "message": "Hardcoded secret found",
                                "severity": "high",
                                "location": "config.js:42"
                            }
                        ]
                    }),
                },
            }),
        };

        let violations = engine.extract_violations(&result);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "NO_SECRETS");
    }
}
