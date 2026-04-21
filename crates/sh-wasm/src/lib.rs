//! # Soul Hunter WASM
//!
//! Production-ready WASM sandbox and runtime for the Soul Hunter security analysis platform.
//!
//! ## Features
//!
//! - **Secure Sandboxing**: Resource limits, memory sandboxing, and security policies
//! - **WASI Support**: Full WebAssembly System Interface support for filesystem and environment
//! - **Skill Execution**: Execute security analysis skills in isolated WASM modules
//! - **Resource Management**: Memory, CPU time, and fuel metering with configurable limits
//! - **Production Ready**: Based on patterns from tracker-brain-rs
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    WASM Runtime                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │   Sandbox   │  │   Engine    │  │   Module Cache      │  │
//! │  │             │  │             │  │                     │  │
//! │  │ - Instances │  │ - Compile   │  │ - Compiled modules  │  │
//! │  │ - Limits    │  │ - Link      │  │ - Name mapping      │  │
//! │  │ - Security  │  │ - Execute   │  │                     │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    WASI Layer                               │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    Host Functions                           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_wasm::{WasmRuntime, RuntimeConfig, SandboxConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create runtime with custom configuration
//!     let config = RuntimeConfig::new()
//!         .with_sandbox(
//!             SandboxConfig::new()
//!                 .with_max_memory(256 * 1024 * 1024)  // 256 MB
//!                 .with_max_execution_time(600_000)     // 10 minutes
//!                 .with_wasi(true)
//!         );
//!
//!     let runtime = WasmRuntime::new(config)?;
//!
//!     // Compile a WASM module
//!     let wasm_bytes = std::fs::read("skill.wasm")?;
//!     let module_id = runtime.compile_module("my_skill", &wasm_bytes).await?;
//!
//!     // Execute the module
//!     let result = runtime.execute(module_id).await?;
//!
//!     println!("Execution success: {}", result.success);
//!
//!     // Shutdown
//!     runtime.shutdown().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod runtime;
pub mod sandbox;

// Re-export main types
pub use error::{Result, WasmError};
pub use runtime::{
    ExecutionResult, FunctionResult, OptLevel, RuntimeConfig, RuntimeStats, SkillContext,
    SkillResult, WasmRuntime,
};
pub use sandbox::{
    ResourceUsage, SandboxConfig, SandboxInstance, SecurityPolicy, WasmSandbox,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// WASM module metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    /// Module ID
    pub id: Uuid,
    /// Module name
    pub name: String,
    /// Module version
    pub version: String,
    /// Module description
    pub description: Option<String>,
    /// Author
    pub author: Option<String>,
    /// Entry points
    pub entry_points: Vec<String>,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
    /// Resource requirements
    pub resource_requirements: ResourceRequirements,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Resource requirements for a WASM module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Minimum memory (bytes)
    pub min_memory_bytes: u64,
    /// Maximum memory (bytes)
    pub max_memory_bytes: u64,
    /// Estimated execution time (ms)
    pub estimated_execution_time_ms: u64,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            min_memory_bytes: 16 * 1024 * 1024,  // 16 MB
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            estimated_execution_time_ms: 60_000, // 1 minute
            required_capabilities: vec![],
        }
    }
}

impl ResourceRequirements {
    /// Create new resource requirements
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum memory
    pub fn with_min_memory(mut self, bytes: u64) -> Self {
        self.min_memory_bytes = bytes;
        self
    }

    /// Set maximum memory
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    /// Set estimated execution time
    pub fn with_estimated_time(mut self, ms: u64) -> Self {
        self.estimated_execution_time_ms = ms;
        self
    }

    /// Add required capability
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.required_capabilities.push(capability.into());
        self
    }
}

/// WASM module builder
pub struct WasmModuleBuilder {
    name: String,
    version: String,
    description: Option<String>,
    author: Option<String>,
    entry_points: Vec<String>,
    required_capabilities: Vec<String>,
    resource_requirements: ResourceRequirements,
    metadata: HashMap<String, serde_json::Value>,
}

impl WasmModuleBuilder {
    /// Create a new WASM module builder
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: None,
            author: None,
            entry_points: vec!["_start".to_string()],
            required_capabilities: vec![],
            resource_requirements: ResourceRequirements::default(),
            metadata: HashMap::new(),
        }
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Add entry point
    pub fn with_entry_point(mut self, entry: impl Into<String>) -> Self {
        self.entry_points.push(entry.into());
        self
    }

    /// Add required capability
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.required_capabilities.push(capability.into());
        self
    }

    /// Set resource requirements
    pub fn with_resource_requirements(mut self, requirements: ResourceRequirements) -> Self {
        self.resource_requirements = requirements;
        self
    }

    /// Add metadata
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Build the WASM module
    pub fn build(self) -> WasmModule {
        WasmModule {
            id: Uuid::new_v4(),
            name: self.name,
            version: self.version,
            description: self.description,
            author: self.author,
            entry_points: self.entry_points,
            required_capabilities: self.required_capabilities,
            resource_requirements: self.resource_requirements,
            metadata: self.metadata,
        }
    }
}

/// WASM execution options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOptions {
    /// Timeout (ms)
    pub timeout_ms: u64,
    /// Memory limit (bytes)
    pub memory_limit_bytes: u64,
    /// Enable WASI
    pub enable_wasi: bool,
    /// Environment variables
    pub env_vars: HashMap<String, String>,
    /// Arguments
    pub args: Vec<String>,
    /// Working directory
    pub working_dir: Option<String>,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 300_000,              // 5 minutes
            memory_limit_bytes: 128 * 1024 * 1024, // 128 MB
            enable_wasi: true,
            env_vars: HashMap::new(),
            args: vec![],
            working_dir: None,
        }
    }
}

impl ExecutionOptions {
    /// Create new execution options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set timeout
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set memory limit
    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit_bytes = bytes;
        self
    }

    /// Enable/disable WASI
    pub fn with_wasi(mut self, enabled: bool) -> Self {
        self.enable_wasi = enabled;
        self
    }

    /// Add environment variable
    pub fn with_env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Add argument
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set working directory
    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }
}

/// WASM module registry for managing compiled modules
pub struct WasmModuleRegistry {
    /// Registered modules
    modules: HashMap<Uuid, WasmModule>,
    /// Name to ID mapping
    name_to_id: HashMap<String, Uuid>,
}

impl WasmModuleRegistry {
    /// Create a new module registry
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            name_to_id: HashMap::new(),
        }
    }

    /// Register a module
    pub fn register(&mut self, module: WasmModule) {
        self.name_to_id.insert(module.name.clone(), module.id);
        self.modules.insert(module.id, module);
    }

    /// Get a module by ID
    pub fn get(&self, id: Uuid) -> Option<&WasmModule> {
        self.modules.get(&id)
    }

    /// Get a module by name
    pub fn get_by_name(&self, name: &str) -> Option<&WasmModule> {
        self.name_to_id.get(name).and_then(|id| self.modules.get(id))
    }

    /// Remove a module
    pub fn remove(&mut self, id: Uuid) -> Option<WasmModule> {
        if let Some(module) = self.modules.remove(&id) {
            self.name_to_id.remove(&module.name);
            Some(module)
        } else {
            None
        }
    }

    /// List all modules
    pub fn list(&self) -> Vec<&WasmModule> {
        self.modules.values().collect()
    }

    /// Check if a module exists
    pub fn contains(&self, id: Uuid) -> bool {
        self.modules.contains_key(&id)
    }

    /// Get module count
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl Default for WasmModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for WASM operations
pub mod utils {
    use super::*;
    use std::path::Path;

    /// Validate WASM module bytes
    pub fn validate_wasm_bytes(bytes: &[u8]) -> Result<()> {
        // Check magic number
        if bytes.len() < 8 {
            return Err(WasmError::invalid_module("Module too small"));
        }

        if &bytes[0..4] != &[0x00, 0x61, 0x73, 0x6d] {
            return Err(WasmError::invalid_module("Invalid magic number"));
        }

        // Check version
        if &bytes[4..8] != &[0x01, 0x00, 0x00, 0x00] {
            return Err(WasmError::invalid_module("Unsupported version"));
        }

        Ok(())
    }

    /// Get WASM module size from bytes
    pub fn get_module_size(bytes: &[u8]) -> usize {
        bytes.len()
    }

    /// Check if a file is a WASM module
    pub async fn is_wasm_file(path: impl AsRef<Path>) -> bool {
        match tokio::fs::read(path.as_ref()).await {
            Ok(bytes) => validate_wasm_bytes(&bytes).is_ok(),
            Err(_) => false,
        }
    }

    /// Read WASM module from file
    pub async fn read_wasm_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        tokio::fs::read(path.as_ref())
            .await
            .map_err(WasmError::Io)
    }

    /// Estimate memory requirements for a module
    pub fn estimate_memory_requirements(bytes: &[u8]) -> u64 {
        // Simple estimation based on module size
        // In production, this would parse the module and check memory sections
        let base = 16 * 1024 * 1024; // 16 MB base
        let size_based = (bytes.len() as u64) * 10; // 10x module size
        base + size_based
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use super::{
        error::{Result, WasmError},
        runtime::{
            ExecutionResult, FunctionResult, OptLevel, RuntimeConfig, RuntimeStats,
            SkillContext, SkillResult, WasmRuntime,
        },
        sandbox::{
            ResourceUsage, SandboxConfig, SandboxInstance, SecurityPolicy, WasmSandbox,
        },
        utils, ExecutionOptions, ResourceRequirements, WasmModule, WasmModuleBuilder,
        WasmModuleRegistry,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_module_builder() {
        let module = WasmModuleBuilder::new("test_skill", "1.0.0")
            .with_description("A test skill")
            .with_author("Test Author")
            .with_entry_point("analyze")
            .with_capability("filesystem")
            .with_metadata("key", serde_json::json!("value"))
            .build();

        assert_eq!(module.name, "test_skill");
        assert_eq!(module.version, "1.0.0");
        assert_eq!(module.description, Some("A test skill".to_string()));
        assert_eq!(module.author, Some("Test Author".to_string()));
        assert!(module.entry_points.contains(&"analyze".to_string()));
        assert!(module.required_capabilities.contains(&"filesystem".to_string()));
    }

    #[test]
    fn test_resource_requirements() {
        let req = ResourceRequirements::new()
            .with_min_memory(32 * 1024 * 1024)
            .with_max_memory(256 * 1024 * 1024)
            .with_estimated_time(120_000)
            .with_capability("network");

        assert_eq!(req.min_memory_bytes, 32 * 1024 * 1024);
        assert_eq!(req.max_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(req.estimated_execution_time_ms, 120_000);
        assert!(req.required_capabilities.contains(&"network".to_string()));
    }

    #[test]
    fn test_execution_options() {
        let opts = ExecutionOptions::new()
            .with_timeout(600_000)
            .with_memory_limit(512 * 1024 * 1024)
            .with_wasi(false)
            .with_env_var("KEY", "value")
            .with_arg("--verbose");

        assert_eq!(opts.timeout_ms, 600_000);
        assert_eq!(opts.memory_limit_bytes, 512 * 1024 * 1024);
        assert!(!opts.enable_wasi);
        assert_eq!(opts.env_vars.get("KEY"), Some(&"value".to_string()));
        assert!(opts.args.contains(&"--verbose".to_string()));
    }

    #[test]
    fn test_wasm_module_registry() {
        let mut registry = WasmModuleRegistry::new();

        let module = WasmModuleBuilder::new("test", "1.0.0").build();
        let id = module.id;

        registry.register(module);

        assert!(registry.contains(id));
        assert!(registry.get_by_name("test").is_some());
        assert_eq!(registry.len(), 1);

        registry.remove(id);
        assert!(!registry.contains(id));
        assert!(registry.is_empty());
    }

    #[test]
    fn test_validate_wasm_bytes() {
        // Valid WASM header
        let valid = &[
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];
        assert!(utils::validate_wasm_bytes(valid).is_ok());

        // Invalid magic
        let invalid = &[
            0x00, 0x00, 0x00, 0x00, // wrong magic
            0x01, 0x00, 0x00, 0x00, // version
        ];
        assert!(utils::validate_wasm_bytes(invalid).is_err());

        // Too small
        let too_small = &[0x00, 0x61];
        assert!(utils::validate_wasm_bytes(too_small).is_err());
    }

    #[test]
    fn test_estimate_memory_requirements() {
        let small = vec![0u8; 1024]; // 1 KB
        let large = vec![0u8; 1024 * 1024]; // 1 MB

        let small_estimate = utils::estimate_memory_requirements(&small);
        let large_estimate = utils::estimate_memory_requirements(&large);

        assert!(large_estimate > small_estimate);
        assert!(small_estimate >= 16 * 1024 * 1024); // At least 16 MB base
    }
}
