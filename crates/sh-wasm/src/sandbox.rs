//! # WASM Sandbox
//!
//! Production-ready WASM sandbox with resource limits, WASI support,
//! and secure skill execution. Based on patterns from tracker-brain-rs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::error::{Result, WasmError};

/// Configuration for the WASM sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum memory per instance (in bytes)
    pub max_memory_bytes: u64,
    /// Maximum execution time (in milliseconds)
    pub max_execution_time_ms: u64,
    /// Maximum stack size (in bytes)
    pub max_stack_size: u64,
    /// Maximum number of instances
    pub max_instances: usize,
    /// Enable WASI
    pub enable_wasi: bool,
    /// WASI preopened directories
    pub wasi_preopened_dirs: Vec<String>,
    /// WASI environment variables
    pub wasi_env_vars: HashMap<String, String>,
    /// Enable fuel metering (for instruction counting)
    pub enable_fuel: bool,
    /// Maximum fuel units
    pub max_fuel: u64,
    /// Enable memory sandboxing
    pub enable_memory_sandbox: bool,
    /// Allow network access
    pub allow_network: bool,
    /// Allow filesystem access
    pub allow_filesystem: bool,
    /// Temporary directory for WASI
    pub temp_dir: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            max_execution_time_ms: 300_000,      // 5 minutes
            max_stack_size: 8 * 1024 * 1024,     // 8 MB
            max_instances: 100,
            enable_wasi: true,
            wasi_preopened_dirs: vec![],
            wasi_env_vars: HashMap::new(),
            enable_fuel: true,
            max_fuel: 10_000_000_000, // 10 billion fuel units
            enable_memory_sandbox: true,
            allow_network: false,
            allow_filesystem: true,
            temp_dir: None,
        }
    }
}

impl SandboxConfig {
    /// Create a new sandbox config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum memory
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    /// Set maximum execution time
    pub fn with_max_execution_time(mut self, ms: u64) -> Self {
        self.max_execution_time_ms = ms;
        self
    }

    /// Set maximum stack size
    pub fn with_max_stack_size(mut self, bytes: u64) -> Self {
        self.max_stack_size = bytes;
        self
    }

    /// Set maximum instances
    pub fn with_max_instances(mut self, count: usize) -> Self {
        self.max_instances = count;
        self
    }

    /// Enable/disable WASI
    pub fn with_wasi(mut self, enabled: bool) -> Self {
        self.enable_wasi = enabled;
        self
    }

    /// Add a preopened directory for WASI
    pub fn with_preopened_dir(mut self, dir: impl Into<String>) -> Self {
        self.wasi_preopened_dirs.push(dir.into());
        self
    }

    /// Add an environment variable for WASI
    pub fn with_env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.wasi_env_vars.insert(key.into(), value.into());
        self
    }

    /// Enable/disable fuel metering
    pub fn with_fuel(mut self, enabled: bool) -> Self {
        self.enable_fuel = enabled;
        self
    }

    /// Set maximum fuel
    pub fn with_max_fuel(mut self, fuel: u64) -> Self {
        self.max_fuel = fuel;
        self
    }

    /// Enable/disable memory sandboxing
    pub fn with_memory_sandbox(mut self, enabled: bool) -> Self {
        self.enable_memory_sandbox = enabled;
        self
    }

    /// Allow/disallow network access
    pub fn with_network(mut self, allowed: bool) -> Self {
        self.allow_network = allowed;
        self
    }

    /// Allow/disallow filesystem access
    pub fn with_filesystem(mut self, allowed: bool) -> Self {
        self.allow_filesystem = allowed;
        self
    }

    /// Set temporary directory
    pub fn with_temp_dir(mut self, dir: impl Into<String>) -> Self {
        self.temp_dir = Some(dir.into());
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.max_memory_bytes == 0 {
            return Err(WasmError::configuration(
                "max_memory_bytes must be greater than 0",
            ));
        }
        if self.max_execution_time_ms == 0 {
            return Err(WasmError::configuration(
                "max_execution_time_ms must be greater than 0",
            ));
        }
        if self.max_stack_size == 0 {
            return Err(WasmError::configuration(
                "max_stack_size must be greater than 0",
            ));
        }
        if self.max_instances == 0 {
            return Err(WasmError::configuration(
                "max_instances must be greater than 0",
            ));
        }
        Ok(())
    }
}

/// Resource usage statistics for a sandbox instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Memory used (in bytes)
    pub memory_bytes: u64,
    /// CPU time used (in milliseconds)
    pub cpu_time_ms: u64,
    /// Fuel consumed
    pub fuel_consumed: u64,
    /// Instructions executed
    pub instructions_executed: u64,
    /// Syscalls made
    pub syscalls_made: u64,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        let now = chrono::Utc::now();
        Self {
            memory_bytes: 0,
            cpu_time_ms: 0,
            fuel_consumed: 0,
            instructions_executed: 0,
            syscalls_made: 0,
            started_at: now,
            updated_at: now,
        }
    }
}

impl ResourceUsage {
    /// Create new resource usage tracking
    pub fn new() -> Self {
        Self::default()
    }

    /// Update memory usage
    pub fn update_memory(&mut self, bytes: u64) {
        self.memory_bytes = bytes;
        self.updated_at = chrono::Utc::now();
    }

    /// Update CPU time
    pub fn add_cpu_time(&mut self, ms: u64) {
        self.cpu_time_ms += ms;
        self.updated_at = chrono::Utc::now();
    }

    /// Update fuel consumed
    pub fn add_fuel(&mut self, fuel: u64) {
        self.fuel_consumed += fuel;
        self.updated_at = chrono::Utc::now();
    }

    /// Update instructions executed
    pub fn add_instructions(&mut self, count: u64) {
        self.instructions_executed += count;
        self.updated_at = chrono::Utc::now();
    }

    /// Update syscalls made
    pub fn add_syscalls(&mut self, count: u64) {
        self.syscalls_made += count;
        self.updated_at = chrono::Utc::now();
    }

    /// Get elapsed time since start
    pub fn elapsed_ms(&self) -> u64 {
        (chrono::Utc::now() - self.started_at).num_milliseconds() as u64
    }
}

/// Security policy for the sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Allowed host functions
    pub allowed_host_functions: Vec<String>,
    /// Blocked imports
    pub blocked_imports: Vec<String>,
    /// Allowed exports
    pub allowed_exports: Vec<String>,
    /// Maximum import count
    pub max_imports: usize,
    /// Maximum export count
    pub max_exports: usize,
    /// Maximum function count
    pub max_functions: usize,
    /// Maximum global count
    pub max_globals: usize,
    /// Maximum table size
    pub max_table_size: u32,
    /// Maximum memory pages
    pub max_memory_pages: u32,
    /// Require validation
    pub require_validation: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_host_functions: vec![],
            blocked_imports: vec!["env".to_string(), "wasi_snapshot_preview1".to_string()],
            allowed_exports: vec![],
            max_imports: 1000,
            max_exports: 1000,
            max_functions: 10000,
            max_globals: 1000,
            max_table_size: 100000,
            max_memory_pages: 1024, // 64 MB
            require_validation: true,
        }
    }
}

impl SecurityPolicy {
    /// Create a new security policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a host function
    pub fn allow_host_function(mut self, name: impl Into<String>) -> Self {
        self.allowed_host_functions.push(name.into());
        self
    }

    /// Block an import
    pub fn block_import(mut self, name: impl Into<String>) -> Self {
        self.blocked_imports.push(name.into());
        self
    }

    /// Allow an export
    pub fn allow_export(mut self, name: impl Into<String>) -> Self {
        self.allowed_exports.push(name.into());
        self
    }

    /// Check if a host function is allowed
    pub fn is_host_function_allowed(&self, name: &str) -> bool {
        self.allowed_host_functions.is_empty()
            || self.allowed_host_functions.contains(&name.to_string())
    }

    /// Check if an import is blocked
    pub fn is_import_blocked(&self, module: &str) -> bool {
        self.blocked_imports.contains(&module.to_string())
    }

    /// Validate module against policy
    pub fn validate_module(&self, module: &wasmtime::Module) -> Result<()> {
        if !self.require_validation {
            return Ok(());
        }

        // Check imports
        let imports = module.imports().count();
        if imports > self.max_imports {
            return Err(WasmError::SecurityViolation(format!(
                "Module has {} imports, max allowed is {}",
                imports, self.max_imports
            )));
        }

        // Check exports
        let exports = module.exports().count();
        if exports > self.max_exports {
            return Err(WasmError::SecurityViolation(format!(
                "Module has {} exports, max allowed is {}",
                exports, self.max_exports
            )));
        }

        // Check functions
        let functions = module
            .exports()
            .filter(|e| matches!(e.ty(), wasmtime::ExternType::Func(_)))
            .count();
        if functions > self.max_functions {
            return Err(WasmError::SecurityViolation(format!(
                "Module has {} functions, max allowed is {}",
                functions, self.max_functions
            )));
        }

        // Check globals
        let globals = module
            .exports()
            .filter(|e| matches!(e.ty(), wasmtime::ExternType::Global(_)))
            .count();
        if globals > self.max_globals {
            return Err(WasmError::SecurityViolation(format!(
                "Module has {} globals, max allowed is {}",
                globals, self.max_globals
            )));
        }

        // Check memory
        for export in module.exports() {
            if let wasmtime::ExternType::Memory(mem) = export.ty() {
                if mem.minimum() > self.max_memory_pages {
                    return Err(WasmError::SecurityViolation(format!(
                        "Module requests {} memory pages, max allowed is {}",
                        mem.minimum(),
                        self.max_memory_pages
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Sandbox instance metadata
#[derive(Debug, Clone)]
pub struct SandboxInstance {
    /// Instance ID
    pub id: Uuid,
    /// Module name
    pub module_name: String,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Resource usage
    pub usage: Arc<RwLock<ResourceUsage>>,
    /// Configuration
    pub config: SandboxConfig,
    /// Security policy
    pub security_policy: SecurityPolicy,
}

impl SandboxInstance {
    /// Create a new sandbox instance
    pub fn new(module_name: impl Into<String>, config: SandboxConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            module_name: module_name.into(),
            created_at: chrono::Utc::now(),
            usage: Arc::new(RwLock::new(ResourceUsage::new())),
            config,
            security_policy: SecurityPolicy::default(),
        }
    }

    /// Get current resource usage
    pub async fn get_usage(&self) -> ResourceUsage {
        self.usage.read().await.clone()
    }

    /// Update resource usage
    pub async fn update_usage<F>(&self, f: F)
    where
        F: FnOnce(&mut ResourceUsage),
    {
        let mut usage = self.usage.write().await;
        f(&mut usage);
    }

    /// Check if resource limits are exceeded
    pub async fn check_limits(&self) -> Result<()> {
        let usage = self.usage.read().await;

        if usage.memory_bytes > self.config.max_memory_bytes {
            return Err(WasmError::ResourceLimitExceeded {
                limit: "memory".to_string(),
                current: usage.memory_bytes,
                max: self.config.max_memory_bytes,
            });
        }

        if usage.elapsed_ms() > self.config.max_execution_time_ms {
            return Err(WasmError::TimeLimitExceeded {
                limit_ms: self.config.max_execution_time_ms,
            });
        }

        if usage.fuel_consumed > self.config.max_fuel {
            return Err(WasmError::ResourceLimitExceeded {
                limit: "fuel".to_string(),
                current: usage.fuel_consumed,
                max: self.config.max_fuel,
            });
        }

        Ok(())
    }
}

/// WASM Sandbox for secure execution
pub struct WasmSandbox {
    /// Sandbox configuration
    config: SandboxConfig,
    /// Security policy
    security_policy: SecurityPolicy,
    /// Active instances
    instances: Arc<DashMap<Uuid, Arc<SandboxInstance>>>,
    /// Instance count
    instance_count: Arc<RwLock<usize>>,
}

impl WasmSandbox {
    /// Create a new WASM sandbox
    pub fn new(config: SandboxConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            security_policy: SecurityPolicy::default(),
            instances: Arc::new(DashMap::new()),
            instance_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Create a sandbox with default configuration
    pub fn default() -> Result<Self> {
        Self::new(SandboxConfig::default())
    }

    /// Set security policy
    pub fn with_security_policy(mut self, policy: SecurityPolicy) -> Self {
        self.security_policy = policy;
        self
    }

    /// Get configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Get security policy
    pub fn security_policy(&self) -> &SecurityPolicy {
        &self.security_policy
    }

    /// Create a new sandbox instance
    #[instrument(skip(self, module_name))]
    pub async fn create_instance(&self, module_name: impl Into<String>) -> Result<Arc<SandboxInstance>> {
        let module_name = module_name.into();

        // Check instance limit
        let count = *self.instance_count.read().await;
        if count >= self.config.max_instances {
            return Err(WasmError::ResourceLimitExceeded {
                limit: "instances".to_string(),
                current: count as u64,
                max: self.config.max_instances as u64,
            });
        }

        // Create instance
        let instance = Arc::new(SandboxInstance::new(module_name, self.config.clone()));

        // Track instance
        self.instances.insert(instance.id, instance.clone());
        *self.instance_count.write().await += 1;

        info!("Created sandbox instance: {}", instance.id);

        Ok(instance)
    }

    /// Get an instance by ID
    pub fn get_instance(&self, id: Uuid) -> Option<Arc<SandboxInstance>> {
        self.instances.get(&id).map(|i| i.clone())
    }

    /// Remove an instance
    #[instrument(skip(self))]
    pub async fn remove_instance(&self, id: Uuid) -> Result<()> {
        if self.instances.remove(&id).is_some() {
            *self.instance_count.write().await -= 1;
            info!("Removed sandbox instance: {}", id);
        }
        Ok(())
    }

    /// Get all instance IDs
    pub fn instance_ids(&self) -> Vec<Uuid> {
        self.instances.iter().map(|e| *e.key()).collect()
    }

    /// Get instance count
    pub async fn instance_count(&self) -> usize {
        *self.instance_count.read().await
    }

    /// Get total resource usage across all instances
    pub async fn total_resource_usage(&self) -> ResourceUsage {
        let mut total = ResourceUsage::new();

        for entry in self.instances.iter() {
            let usage = entry.value().get_usage().await;
            total.memory_bytes += usage.memory_bytes;
            total.cpu_time_ms += usage.cpu_time_ms;
            total.fuel_consumed += usage.fuel_consumed;
            total.instructions_executed += usage.instructions_executed;
            total.syscalls_made += usage.syscalls_made;
        }

        total
    }

    /// Validate a WASM module against security policy
    pub fn validate_module(&self, module: &wasmtime::Module) -> Result<()> {
        self.security_policy.validate_module(module)
    }

    /// Clean up expired instances
    #[instrument(skip(self))]
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut removed = 0;
        let now = chrono::Utc::now();
        let max_age = Duration::from_millis(self.config.max_execution_time_ms);

        let to_remove: Vec<Uuid> = self
            .instances
            .iter()
            .filter(|e| {
                let age = now - e.value().created_at;
                age > chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::max_value())
            })
            .map(|e| *e.key())
            .collect();

        for id in to_remove {
            self.remove_instance(id).await?;
            removed += 1;
        }

        if removed > 0 {
            info!("Cleaned up {} expired sandbox instances", removed);
        }

        Ok(removed)
    }

    /// Shutdown the sandbox and clean up all instances
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        let ids: Vec<Uuid> = self.instance_ids();

        for id in ids {
            self.remove_instance(id).await?;
        }

        info!("Sandbox shutdown complete, cleaned up {} instances", ids.len());
        Ok(())
    }
}

impl Drop for WasmSandbox {
    fn drop(&mut self) {
        // Note: We can't use async here, but the instances will be dropped
        debug!("WASM sandbox dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_bytes, 128 * 1024 * 1024);
        assert_eq!(config.max_execution_time_ms, 300_000);
        assert!(config.enable_wasi);
    }

    #[test]
    fn test_sandbox_config_builder() {
        let config = SandboxConfig::new()
            .with_max_memory(256 * 1024 * 1024)
            .with_max_execution_time(600_000)
            .with_wasi(false);

        assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(config.max_execution_time_ms, 600_000);
        assert!(!config.enable_wasi);
    }

    #[test]
    fn test_sandbox_config_validation() {
        let config = SandboxConfig::new().with_max_memory(0);
        assert!(config.validate().is_err());

        let config = SandboxConfig::new().with_max_execution_time(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_security_policy() {
        let policy = SecurityPolicy::new()
            .allow_host_function("test".to_string())
            .block_import("env".to_string());

        assert!(policy.is_host_function_allowed("test"));
        assert!(!policy.is_host_function_allowed("other"));
        assert!(policy.is_import_blocked("env"));
    }

    #[tokio::test]
    async fn test_sandbox_instance() {
        let config = SandboxConfig::default();
        let instance = SandboxInstance::new("test.wasm", config);

        assert_eq!(instance.module_name, "test.wasm");

        let usage = instance.get_usage().await;
        assert_eq!(usage.memory_bytes, 0);

        instance.update_usage(|u| u.update_memory(1024)).await;
        let usage = instance.get_usage().await;
        assert_eq!(usage.memory_bytes, 1024);
    }

    #[tokio::test]
    async fn test_wasm_sandbox() {
        let config = SandboxConfig::default();
        let sandbox = WasmSandbox::new(config).unwrap();

        let instance = sandbox.create_instance("test.wasm").await.unwrap();
        assert_eq!(sandbox.instance_count().await, 1);

        let retrieved = sandbox.get_instance(instance.id);
        assert!(retrieved.is_some());

        sandbox.remove_instance(instance.id).await.unwrap();
        assert_eq!(sandbox.instance_count().await, 0);
    }
}
