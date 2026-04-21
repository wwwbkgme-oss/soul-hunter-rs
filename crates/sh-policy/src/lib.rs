//! # Soul Hunter Policy Engine
//!
//! Production-ready policy enforcement engine supporting WASM and Rego (OPA) policies.
//!
//! ## Features
//!
//! - **WASM Policies**: Execute WebAssembly-based policies using wasmtime
//! - **Rego Policies**: Evaluate Open Policy Agent (OPA) Rego policies
//! - **Pre/Post Action Validation**: Validate actions before and after execution
//! - **Finding-based Evaluation**: Evaluate policies against security findings
//! - **Async Support**: Full async/await support with tokio
//!
//! ## Example
//!
//! ```rust
//! use sh_policy::{PolicyEngine, PolicyEngineConfig};
//! use sh_types::{Policy, PolicyType, EnforcementMode};
//!
//! async fn example() {
//!     let config = PolicyEngineConfig::default();
//!     let engine = PolicyEngine::new(config).await.unwrap();
//!
//!     // Load and evaluate a policy
//!     let policy = Policy::new("security-policy", PolicyType::Rego, "package example");
//!     let result = engine.evaluate(&policy, &target).await.unwrap();
//! }
//! ```

pub mod engine;
pub mod error;
pub mod rego;
pub mod store;
pub mod wasm;

// Re-export main types
pub use engine::{PolicyEngine, PolicyEngineConfig, ValidationPhase};
pub use error::{PolicyError, RegoError, WasmError, Result};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for policy evaluations
pub type EvaluationId = Uuid;

/// Policy evaluation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub evaluation_id: EvaluationId,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub dry_run: bool,
}

impl EvaluationContext {
    pub fn new() -> Self {
        Self {
            evaluation_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
            dry_run: false,
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
}

impl Default for EvaluationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to be validated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: String,
    pub resource: String,
    pub subject: String,
    pub operation: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

impl Action {
    pub fn new(action_type: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action_type: action_type.into(),
            resource: resource.into(),
            subject: String::new(),
            operation: String::new(),
            parameters: HashMap::new(),
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }
}

/// Policy evaluation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvaluationStats {
    pub total_evaluations: u64,
    pub passed_count: u64,
    pub failed_count: u64,
    pub average_execution_time_ms: f64,
    pub last_evaluation: Option<DateTime<Utc>>,
}

impl EvaluationStats {
    pub fn record_evaluation(&mut self, passed: bool, execution_time_ms: u64) {
        self.total_evaluations += 1;
        if passed {
            self.passed_count += 1;
        } else {
            self.failed_count += 1;
        }

        // Update rolling average
        let current_avg = self.average_execution_time_ms;
        let count = self.total_evaluations as f64;
        self.average_execution_time_ms =
            (current_avg * (count - 1.0) + execution_time_ms as f64) / count;

        self.last_evaluation = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluation_context() {
        let ctx = EvaluationContext::new()
            .with_metadata("key", serde_json::json!("value"))
            .dry_run();

        assert!(ctx.dry_run);
        assert_eq!(ctx.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn test_action_builder() {
        let action = Action::new("scan", "/path/to/target")
            .with_subject("user123")
            .with_operation("read")
            .with_parameter("depth", serde_json::json!(3));

        assert_eq!(action.action_type, "scan");
        assert_eq!(action.resource, "/path/to/target");
        assert_eq!(action.subject, "user123");
        assert_eq!(action.operation, "read");
    }

    #[test]
    fn test_evaluation_stats() {
        let mut stats = EvaluationStats::default();
        stats.record_evaluation(true, 100);
        stats.record_evaluation(false, 200);

        assert_eq!(stats.total_evaluations, 2);
        assert_eq!(stats.passed_count, 1);
        assert_eq!(stats.failed_count, 1);
        assert_eq!(stats.average_execution_time_ms, 150.0);
    }
}
