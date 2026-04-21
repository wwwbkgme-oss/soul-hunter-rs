//! WASM policy runtime using wasmtime

use crate::error::{PolicyError, Result, WasmError};
use serde::{Deserialize, Serialize};
use sh_types::{Finding, Policy, PolicyResult, PolicyViolation, Severity};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};
use wasmtime::{Config, Engine, Instance, Memory, Module, Store, TypedFunc};

/// WASM policy runtime
#[derive(Debug)]
pub struct WasmRuntime {
    engine: Engine,
}

/// WASM execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmContext {
    pub target: String,
    pub findings: Vec<Finding>,
    pub metadata: serde_json::Value,
}

/// WASM execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExecutionResult {
    pub passed: bool,
    pub violations: Vec<WasmViolation>,
    pub output: Option<serde_json::Value>,
}

/// WASM violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmViolation {
    pub rule: String,
    pub message: String,
    pub severity: String,
    pub location: Option<String>,
}

impl WasmRuntime {
    /// Create a new WASM runtime
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.async_support(true);
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| {
            WasmError::CompilationFailed(format!("Failed to create WASM engine: {}", e))
        })?;

        info!("WASM runtime initialized successfully");
        Ok(Self { engine })
    }

    /// Compile a WASM policy
    #[instrument(skip(self, policy), fields(policy_id = %policy.id))]
    pub fn compile(&self, policy: &Policy) -> Result<CompiledWasmPolicy> {
        let start = Instant::now();

        // Decode base64 or use raw bytes
        let wasm_bytes = if policy.content.starts_with("data:") {
            // Handle data URI
            let base64_content = policy
                .content
                .split(',')
                .nth(1)
                .ok_or_else(|| WasmError::InvalidModule("Invalid data URI".to_string()))?;
            base64::decode(base64_content)
                .map_err(|e| WasmError::InvalidModule(format!("Base64 decode failed: {}", e)))?
        } else if policy.content.starts_with("\0asm") {
            // Raw WASM binary
            policy.content.as_bytes().to_vec()
        } else {
            // Try base64 decode
            base64::decode(&policy.content).map_err(|_| {
                WasmError::InvalidModule("Content is not valid WASM or base64".to_string())
            })?
        };

        // Compile the module
        let module = Module::new(&self.engine, &wasm_bytes).map_err(|e| {
            WasmError::CompilationFailed(format!("WASM compilation failed: {}", e))
        })?;

        let compile_time = start.elapsed().as_millis() as u64;
        debug!(compile_time_ms = compile_time, "WASM policy compiled");

        Ok(CompiledWasmPolicy {
            module,
            policy_id: policy.id,
            policy_name: policy.name.clone(),
        })
    }

    /// Evaluate a finding against a compiled WASM policy
    #[instrument(skip(self, compiled, finding), fields(policy_id = %compiled.policy_id))]
    pub async fn evaluate_finding(
        &self,
        compiled: &CompiledWasmPolicy,
        finding: &Finding,
    ) -> Result<PolicyResult> {
        let start = Instant::now();

        // Create a store with limited resources
        let mut store = Store::new(&self.engine, ());

        // Set memory limits
        store.limiter(|_| ResourceLimiter);

        // Instantiate the module
        let instance = Instance::new(&mut store, &compiled.module, &[]).map_err(|e| {
            WasmError::InstantiationFailed(format!("WASM instantiation failed: {}", e))
        })?;

        // Prepare input data
        let context = WasmContext {
            target: finding.location.file_path.clone().unwrap_or_default(),
            findings: vec![finding.clone()],
            metadata: finding.metadata.clone().unwrap_or(serde_json::json!({})),
        };

        let input_json = serde_json::to_string(&context).map_err(PolicyError::Serialization)?;

        // Call the evaluate function
        let result = self
            .call_evaluate(&mut store, &instance, &input_json)
            .await?;

        let execution_time = start.elapsed().as_millis() as u64;

        // Convert WASM result to PolicyResult
        let mut policy_result =
            PolicyResult::new(compiled.policy_id, compiled.policy_name.clone())
                .with_execution_time(execution_time);

        if !result.passed {
            for violation in result.violations {
                let severity = match violation.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                policy_result = policy_result.add_violation(
                    PolicyViolation::new(&violation.rule, &violation.message)
                        .with_severity(severity)
                        .with_location(violation.location.unwrap_or_default()),
                );
            }
        }

        info!(
            policy_id = %compiled.policy_id,
            passed = result.passed,
            violations = result.violations.len(),
            execution_time_ms = execution_time,
            "WASM policy evaluation completed"
        );

        Ok(policy_result)
    }

    /// Evaluate multiple findings
    #[instrument(skip(self, compiled, findings), fields(policy_id = %compiled.policy_id))]
    pub async fn evaluate_findings(
        &self,
        compiled: &CompiledWasmPolicy,
        findings: &[Finding],
    ) -> Result<PolicyResult> {
        let start = Instant::now();

        let mut store = Store::new(&self.engine, ());
        store.limiter(|_| ResourceLimiter);

        let instance = Instance::new(&mut store, &compiled.module, &[]).map_err(|e| {
            WasmError::InstantiationFailed(format!("WASM instantiation failed: {}", e))
        })?;

        // Prepare input with all findings
        let context = WasmContext {
            target: "batch".to_string(),
            findings: findings.to_vec(),
            metadata: serde_json::json!({"count": findings.len()}),
        };

        let input_json = serde_json::to_string(&context).map_err(PolicyError::Serialization)?;

        let result = self
            .call_evaluate(&mut store, &instance, &input_json)
            .await?;

        let execution_time = start.elapsed().as_millis() as u64;

        let mut policy_result =
            PolicyResult::new(compiled.policy_id, compiled.policy_name.clone())
                .with_execution_time(execution_time);

        if !result.passed {
            for violation in result.violations {
                let severity = match violation.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                policy_result = policy_result.add_violation(
                    PolicyViolation::new(&violation.rule, &violation.message)
                        .with_severity(severity)
                        .with_location(violation.location.unwrap_or_default()),
                );
            }
        }

        Ok(policy_result)
    }

    /// Call the evaluate function in the WASM module
    async fn call_evaluate(
        &self,
        store: &mut Store<()>,
        instance: &Instance,
        input: &str,
    ) -> Result<WasmExecutionResult> {
        // Get memory export
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| WasmError::MemoryError("Memory export not found".to_string()))?;

        // Get exported functions
        let alloc_func: TypedFunc<i32, i32> = instance
            .get_typed_func(&mut *store, "alloc")
            .map_err(|e| WasmError::AbiError(format!("alloc function not found: {}", e)))?;

        let dealloc_func: TypedFunc<(i32, i32), ()> = instance
            .get_typed_func(&mut *store, "dealloc")
            .map_err(|e| WasmError::AbiError(format!("dealloc function not found: {}", e)))?;

        let evaluate_func: TypedFunc<i32, i32> = instance
            .get_typed_func(&mut *store, "evaluate")
            .map_err(|e| WasmError::AbiError(format!("evaluate function not found: {}", e)))?;

        // Allocate memory for input
        let input_bytes = input.as_bytes();
        let input_len = input_bytes.len() as i32;
        let input_ptr = alloc_func
            .call(&mut *store, input_len)
            .map_err(|e| WasmError::MemoryError(format!("Allocation failed: {}", e)))?;

        // Write input to memory
        memory
            .write(&mut *store, input_ptr as usize, input_bytes)
            .map_err(|e| WasmError::MemoryError(format!("Memory write failed: {}", e)))?;

        // Call evaluate
        let result_ptr = evaluate_func
            .call(&mut *store, input_ptr)
            .map_err(|e| WasmError::ExecutionFailed(format!("Evaluation failed: {}", e)))?;

        // Read result length (first 4 bytes)
        let mut len_bytes = [0u8; 4];
        memory
            .read(&mut *store, result_ptr as usize, &mut len_bytes)
            .map_err(|e| WasmError::MemoryError(format!("Memory read failed: {}", e)))?;
        let result_len = i32::from_le_bytes(len_bytes) as usize;

        // Read result data
        let mut result_bytes = vec![0u8; result_len];
        memory
            .read(&mut *store, (result_ptr + 4) as usize, &mut result_bytes)
            .map_err(|e| WasmError::MemoryError(format!("Memory read failed: {}", e)))?;

        // Deallocate memory
        let _ = dealloc_func.call(&mut *store, (input_ptr, input_len));
        let _ = dealloc_func.call(&mut *store, (result_ptr, (result_len + 4) as i32));

        // Parse result
        let result_str = String::from_utf8(result_bytes).map_err(|e| {
            WasmError::ExecutionFailed(format!("Invalid UTF-8 in result: {}", e))
        })?;

        let result: WasmExecutionResult = serde_json::from_str(&result_str).map_err(|e| {
            WasmError::ExecutionFailed(format!("Failed to parse result: {}", e))
        })?;

        Ok(result)
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM runtime")
    }
}

/// Compiled WASM policy
#[derive(Debug)]
pub struct CompiledWasmPolicy {
    module: Module,
    policy_id: sh_types::PolicyId,
    policy_name: String,
}

/// Resource limiter for WASM execution
struct ResourceLimiter;

impl wasmtime::ResourceLimiter for ResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // Limit memory growth to 128MB
        Ok(_desired <= 128 * 1024 * 1024)
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        // Limit table growth
        Ok(_desired <= 10000)
    }

    fn instances(&self) -> usize {
        100
    }

    fn tables(&self) -> usize {
        100
    }

    fn memories(&self) -> usize {
        100
    }
}

/// Base64 decoding helper
mod base64 {
    use crate::error::WasmError;
    use crate::Result;

    pub fn decode(input: &str) -> Result<Vec<u8>> {
        // Simple base64 decoder
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits_collected = 0u32;

        for c in input.chars().filter(|c| !c.is_whitespace()) {
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                '=' => break,
                _ => continue,
            };

            buffer = (buffer << 6) | val;
            bits_collected += 6;

            if bits_collected >= 8 {
                bits_collected -= 8;
                result.push(((buffer >> bits_collected) & 0xFF) as u8);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Finding, Location, PolicyType};

    // Simple test WASM module that always passes
    // This is a minimal valid WASM module in base64
    const TEST_WASM_BASE64: &str = "AGFzbQEAAAABBgFgAX8BfwMCAQAFDQEuZXZhbHVhdGUAAAZtZW1vcnkCAAIDBAEBAgEBBggBfwFBgIDAAAsKDgEEbmFtZQcBAGFsbG9jCgsBAWkAAWEBYQMACw==";

    #[tokio::test]
    async fn test_wasm_runtime_creation() {
        let runtime = WasmRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_wasm_context_serialization() {
        let finding = Finding::new("Test", "Test finding");
        let context = WasmContext {
            target: "/test/path".to_string(),
            findings: vec![finding],
            metadata: serde_json::json!({"key": "value"}),
        };

        let json = serde_json::to_string(&context).unwrap();
        assert!(json.contains("/test/path"));
    }

    #[test]
    fn test_wasm_execution_result() {
        let result = WasmExecutionResult {
            passed: false,
            violations: vec![WasmViolation {
                rule: "TEST_RULE".to_string(),
                message: "Test violation".to_string(),
                severity: "high".to_string(),
                location: Some("file.rs:10".to_string()),
            }],
            output: None,
        };

        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
    }
}
