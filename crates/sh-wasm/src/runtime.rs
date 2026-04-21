//! # WASM Runtime
//!
//! Production-ready WASM runtime using wasmtime with WASI support,
//! resource limits, and skill execution capabilities.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use wasmtime::{Config, Engine, Instance, Linker, Memory, MemoryType, Module, Store, Trap};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

use crate::error::{Result, WasmError};
use crate::sandbox::{ResourceUsage, SandboxConfig, SandboxInstance, SecurityPolicy, WasmSandbox};

/// WASM runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Sandbox configuration
    pub sandbox: SandboxConfig,
    /// Enable async support
    pub async_support: bool,
    /// Enable parallel compilation
    pub parallel_compilation: bool,
    /// Enable debug info
    pub debug_info: bool,
    /// Enable profiling
    pub profiling: bool,
    /// Optimization level
    pub opt_level: OptLevel,
    /// Enable reference types
    pub reference_types: bool,
    /// Enable SIMD
    pub simd: bool,
    /// Enable bulk memory
    pub bulk_memory: bool,
    /// Enable multi-value returns
    pub multi_value: bool,
}

/// Optimization level for compilation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptLevel {
    /// No optimizations
    None,
    /// Speed optimizations
    Speed,
    /// Speed and size optimizations
    SpeedAndSize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            sandbox: SandboxConfig::default(),
            async_support: true,
            parallel_compilation: true,
            debug_info: false,
            profiling: false,
            opt_level: OptLevel::Speed,
            reference_types: true,
            simd: true,
            bulk_memory: true,
            multi_value: true,
        }
    }
}

impl RuntimeConfig {
    /// Create new runtime config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set sandbox config
    pub fn with_sandbox(mut self, sandbox: SandboxConfig) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Set async support
    pub fn with_async_support(mut self, enabled: bool) -> Self {
        self.async_support = enabled;
        self
    }

    /// Set parallel compilation
    pub fn with_parallel_compilation(mut self, enabled: bool) -> Self {
        self.parallel_compilation = enabled;
        self
    }

    /// Set debug info
    pub fn with_debug_info(mut self, enabled: bool) -> Self {
        self.debug_info = enabled;
        self
    }

    /// Set optimization level
    pub fn with_opt_level(mut self, level: OptLevel) -> Self {
        self.opt_level = level;
        self
    }

    /// Convert to wasmtime config
    fn to_wasmtime_config(&self) -> Config {
        let mut config = Config::new();

        // Async support
        if self.async_support {
            config.async_support(true);
        }

        // Parallel compilation
        config.parallel_compilation(self.parallel_compilation);

        // Debug info
        config.debug_info(self.debug_info);

        // Profiling
        if self.profiling {
            config.profiling_strategy(wasmtime::ProfilingStrategy::PerfMap);
        }

        // Optimization level
        match self.opt_level {
            OptLevel::None => config.cranelift_opt_level(wasmtime::OptLevel::None),
            OptLevel::Speed => config.cranelift_opt_level(wasmtime::OptLevel::Speed),
            OptLevel::SpeedAndSize => config.cranelift_opt_level(wasmtime::OptLevel::SpeedAndSize),
        };

        // WASM features
        config.wasm_reference_types(self.reference_types);
        config.wasm_simd(self.simd);
        config.wasm_bulk_memory(self.bulk_memory);
        config.wasm_multi_value(self.multi_value);

        // Enable component model
        config.wasm_component_model(true);

        config
    }
}

/// Store data for WASM instances
pub struct StoreData {
    /// WASI context
    wasi: Option<WasiCtx>,
    /// Resource usage tracking
    usage: Arc<RwLock<ResourceUsage>>,
    /// Memory limit
    memory_limit: u64,
    /// Fuel limit
    fuel_limit: u64,
    /// Instance ID
    instance_id: Uuid,
}

impl StoreData {
    /// Create new store data
    pub fn new(
        wasi: Option<WasiCtx>,
        usage: Arc<RwLock<ResourceUsage>>,
        memory_limit: u64,
        fuel_limit: u64,
        instance_id: Uuid,
    ) -> Self {
        Self {
            wasi,
            usage,
            memory_limit,
            fuel_limit,
            instance_id,
        }
    }

    /// Get WASI context
    pub fn wasi(&self) -> Option<&WasiCtx> {
        self.wasi.as_ref()
    }

    /// Get WASI context mutably
    pub fn wasi_mut(&mut self) -> Option<&mut WasiCtx> {
        self.wasi.as_mut()
    }

    /// Update resource usage
    pub async fn update_usage<F>(&self, f: F)
    where
        F: FnOnce(&mut ResourceUsage),
    {
        let mut usage = self.usage.write().await;
        f(&mut usage);
    }
}

impl WasiView for StoreData {
    fn table(&mut self) -> &mut wasmtime_wasi::ResourceTable {
        self.wasi.as_mut().unwrap().table()
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        self.wasi.as_mut().unwrap()
    }
}

/// Compiled WASM module
pub struct CompiledModule {
    /// Module ID
    pub id: Uuid,
    /// Module name
    pub name: String,
    /// Compiled module
    module: Module,
    /// Module size
    pub size_bytes: usize,
    /// Compiled at
    pub compiled_at: chrono::DateTime<chrono::Utc>,
}

impl CompiledModule {
    /// Get the underlying wasmtime module
    pub fn module(&self) -> &Module {
        &self.module
    }
}

/// WASM function result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResult {
    /// Function name
    pub function: String,
    /// Return values
    pub values: Vec<serde_json::Value>,
    /// Execution time (ms)
    pub execution_time_ms: u64,
    /// Fuel consumed
    pub fuel_consumed: u64,
    /// Memory used (bytes)
    pub memory_used: u64,
}

/// WASM execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Success
    pub success: bool,
    /// Function results
    pub function_results: Vec<FunctionResult>,
    /// Resource usage
    pub resource_usage: ResourceUsage,
    /// Output data
    pub output: Option<Bytes>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Execution time (ms)
    pub total_execution_time_ms: u64,
}

/// Skill execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillContext {
    /// Skill ID
    pub skill_id: Uuid,
    /// Task ID
    pub task_id: Uuid,
    /// Input data
    pub input: serde_json::Value,
    /// Configuration
    pub config: HashMap<String, serde_json::Value>,
}

/// Skill execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResult {
    /// Success
    pub success: bool,
    /// Output data
    pub output: serde_json::Value,
    /// Findings
    pub findings: Vec<serde_json::Value>,
    /// Resource usage
    pub resource_usage: ResourceUsage,
    /// Execution time (ms)
    pub execution_time_ms: u64,
    /// Error (if any)
    pub error: Option<String>,
}

/// WASM runtime for executing WASM modules
pub struct WasmRuntime {
    /// Runtime configuration
    config: RuntimeConfig,
    /// WASM engine
    engine: Engine,
    /// Sandbox
    sandbox: Arc<WasmSandbox>,
    /// Compiled modules cache
    modules: Arc<RwLock<HashMap<Uuid, CompiledModule>>>,
    /// Module name to ID mapping
    module_names: Arc<RwLock<HashMap<String, Uuid>>>,
}

impl WasmRuntime {
    /// Create a new WASM runtime
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        let wasmtime_config = config.to_wasmtime_config();
        let engine = Engine::new(&wasmtime_config)
            .map_err(|e| WasmError::configuration(format!("Failed to create engine: {}", e)))?;

        let sandbox = Arc::new(WasmSandbox::new(config.sandbox.clone())?);

        Ok(Self {
            config,
            engine,
            sandbox,
            modules: Arc::new(RwLock::new(HashMap::new())),
            module_names: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a runtime with default configuration
    pub fn default() -> Result<Self> {
        Self::new(RuntimeConfig::default())
    }

    /// Get the engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the sandbox
    pub fn sandbox(&self) -> &WasmSandbox {
        &self.sandbox
    }

    /// Compile a WASM module
    #[instrument(skip(self, wasm_bytes))]
    pub async fn compile_module(
        &self,
        name: impl Into<String>,
        wasm_bytes: &[u8],
    ) -> Result<Uuid> {
        let name = name.into();
        let id = Uuid::new_v4();

        info!("Compiling WASM module: {} ({})", name, id);

        // Compile the module
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmError::compilation(format!("Failed to compile module: {}", e)))?;

        // Validate against security policy
        self.sandbox.validate_module(&module)?;

        let compiled = CompiledModule {
            id,
            name: name.clone(),
            module,
            size_bytes: wasm_bytes.len(),
            compiled_at: chrono::Utc::now(),
        };

        // Cache the module
        self.modules.write().await.insert(id, compiled);
        self.module_names.write().await.insert(name, id);

        info!("Successfully compiled WASM module: {} ({})", name, id);

        Ok(id)
    }

    /// Compile a WASM module from a file
    #[instrument(skip(self))]
    pub async fn compile_module_from_file(
        &self,
        name: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Uuid> {
        let wasm_bytes = tokio::fs::read(path.as_ref()).await.map_err(WasmError::Io)?;
        self.compile_module(name, &wasm_bytes).await
    }

    /// Get a compiled module by ID
    pub async fn get_module(&self, id: Uuid) -> Option<CompiledModule> {
        self.modules.read().await.get(&id).cloned()
    }

    /// Get a compiled module by name
    pub async fn get_module_by_name(&self, name: &str) -> Option<CompiledModule> {
        let id = self.module_names.read().await.get(name).copied()?;
        self.get_module(id).await
    }

    /// Remove a compiled module
    pub async fn remove_module(&self, id: Uuid) -> Result<()> {
        if let Some(module) = self.modules.write().await.remove(&id) {
            self.module_names.write().await.remove(&module.name);
            info!("Removed compiled module: {} ({})", module.name, id);
        }
        Ok(())
    }

    /// Create a WASI context
    fn create_wasi_context(&self, config: &SandboxConfig) -> Result<WasiCtx> {
        let mut builder = WasiCtxBuilder::new();

        // Set environment variables
        for (key, value) in &config.wasi_env_vars {
            builder.env(key, value);
        }

        // Preopen directories
        if config.allow_filesystem {
            for dir in &config.wasi_preopened_dirs {
                let path = std::path::Path::new(dir);
                if path.exists() {
                    builder.preopened_dir(
                        wasmtime_wasi::Dir::open_ambient_dir(path, wasmtime_wasi::ambient_authority())
                            .map_err(|e| WasmError::wasi(format!("Failed to preopen dir: {}", e)))?,
                        wasmtime_wasi::ambient_authority(),
                        dir,
                    );
                }
            }
        }

        // Set temp directory
        if let Some(temp_dir) = &config.temp_dir {
            builder.env("TMPDIR", temp_dir);
        }

        // Inherit stdin/stdout/stderr for debugging
        if config.debug_info {
            builder.inherit_stdio();
        }

        Ok(builder.build())
    }

    /// Instantiate a WASM module
    #[instrument(skip(self, module_id))]
    pub async fn instantiate(
        &self,
        module_id: Uuid,
    ) -> Result<(Instance, Store<StoreData>, Arc<SandboxInstance>)> {
        let module = self
            .get_module(module_id)
            .await
            .ok_or_else(|| WasmError::invalid_module(format!("Module not found: {}", module_id)))?;

        // Create sandbox instance
        let sandbox_instance = self
            .sandbox
            .create_instance(&module.name)
            .await?;

        // Create store data
        let wasi_ctx = if self.config.sandbox.enable_wasi {
            Some(self.create_wasi_context(&self.config.sandbox)?)
        } else {
            None
        };

        let store_data = StoreData::new(
            wasi_ctx,
            sandbox_instance.usage.clone(),
            self.config.sandbox.max_memory_bytes,
            self.config.sandbox.max_fuel,
            sandbox_instance.id,
        );

        // Create store
        let mut store = Store::new(&self.engine, store_data);

        // Add fuel if enabled
        if self.config.sandbox.enable_fuel {
            store
                .add_fuel(self.config.sandbox.max_fuel)
                .map_err(|e| WasmError::configuration(format!("Failed to add fuel: {}", e)))?;
        }

        // Create linker
        let mut linker = Linker::new(&self.engine);

        // Add WASI to linker if enabled
        if self.config.sandbox.enable_wasi {
            wasmtime_wasi::add_to_linker_async(&mut linker)?;
        }

        // Instantiate the module
        let instance = linker
            .instantiate_async(&mut store, &module.module)
            .await
            .map_err(|e| WasmError::instantiation(format!("Failed to instantiate module: {}", e)))?;

        info!(
            "Instantiated WASM module: {} (instance: {})",
            module.name, sandbox_instance.id
        );

        Ok((instance, store, sandbox_instance))
    }

    /// Execute a function in a WASM module
    #[instrument(skip(self, instance, store, args))]
    pub async fn execute_function<T>(
        &self,
        instance: &Instance,
        store: &mut Store<StoreData>,
        function_name: &str,
        args: &[wasmtime::Val],
    ) -> Result<Vec<wasmtime::Val>>
    where
        T: wasmtime::WasmParams,
    {
        let start = Instant::now();

        // Get the function
        let func = instance
            .get_func(store, function_name)
            .ok_or_else(|| WasmError::InvalidFunction(function_name.to_string()))?;

        // Check resource limits before execution
        let sandbox_instance = self
            .sandbox
            .get_instance(store.data().instance_id)
            .ok_or_else(|| WasmError::Unknown("Sandbox instance not found".to_string()))?;

        sandbox_instance.check_limits().await?;

        // Execute the function
        let mut results = vec![wasmtime::Val::null(); func.results(store).len()];

        let execution_result = func
            .call_async(store, args, &mut results)
            .await
            .map_err(|e| WasmError::execution(format!("Function execution failed: {}", e)))?;

        // Update resource usage
        let elapsed = start.elapsed().as_millis() as u64;
        let fuel_consumed = if self.config.sandbox.enable_fuel {
            store.get_fuel().unwrap_or(0)
        } else {
            0
        };

        sandbox_instance
            .update_usage(|usage| {
                usage.add_cpu_time(elapsed);
                usage.add_fuel(self.config.sandbox.max_fuel - fuel_consumed);
            })
            .await;

        info!(
            "Executed function {} in {}ms (fuel: {})",
            function_name, elapsed, fuel_consumed
        );

        Ok(results)
    }

    /// Execute a skill in a WASM module
    #[instrument(skip(self, module_id, context))]
    pub async fn execute_skill(
        &self,
        module_id: Uuid,
        context: SkillContext,
    ) -> Result<SkillResult> {
        let start = Instant::now();

        // Instantiate the module
        let (instance, mut store, sandbox_instance) = self.instantiate(module_id).await?;

        // Serialize input
        let input_json = serde_json::to_vec(&context.input)
            .map_err(|e| WasmError::Serialization(e))?;

        // Allocate memory for input
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmError::execution("Memory export not found".to_string()))?;

        // Write input to memory
        let input_ptr = 1024u32; // Start after stack
        memory.write(&mut store, input_ptr as usize, &input_json)?;

        // Call the skill entry point
        let results = self
            .execute_function::<(u32, u32, u32, u32)>(
                &instance,
                &mut store,
                "skill_execute",
                &[
                    wasmtime::Val::I32(input_ptr as i32),
                    wasmtime::Val::I32(input_json.len() as i32),
                ],
            )
            .await?;

        // Get output pointer and length from results
        let output_ptr = results
            .get(0)
            .and_then(|v| v.i32())
            .ok_or_else(|| WasmError::execution("Invalid output pointer".to_string()))? as u32;
        let output_len = results
            .get(1)
            .and_then(|v| v.i32())
            .ok_or_else(|| WasmError::execution("Invalid output length".to_string()))? as u32;

        // Read output from memory
        let mut output_bytes = vec![0u8; output_len as usize];
        memory.read(&store, output_ptr as usize, &mut output_bytes)?;

        // Parse output
        let output: serde_json::Value =
            serde_json::from_slice(&output_bytes).map_err(|e| WasmError::Serialization(e))?;

        // Get resource usage
        let resource_usage = sandbox_instance.get_usage().await;

        // Clean up
        self.sandbox.remove_instance(sandbox_instance.id).await?;

        let elapsed = start.elapsed().as_millis() as u64;

        info!(
            "Skill {} executed successfully in {}ms",
            context.skill_id, elapsed
        );

        Ok(SkillResult {
            success: true,
            output,
            findings: vec![],
            resource_usage,
            execution_time_ms: elapsed,
            error: None,
        })
    }

    /// Execute a WASM module with a simple entry point
    #[instrument(skip(self, module_id))]
    pub async fn execute(&self, module_id: Uuid) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Instantiate the module
        let (instance, mut store, sandbox_instance) = self.instantiate(module_id).await?;

        // Look for _start or main function
        let entry_point = if instance.get_func(&mut store, "_start").is_some() {
            "_start"
        } else if instance.get_func(&mut store, "main").is_some() {
            "main"
        } else {
            return Err(WasmError::InvalidFunction(
                "No entry point found (_start or main)".to_string(),
            ));
        };

        // Execute the entry point
        let func_results = self
            .execute_function::<()>(
                &instance,
                &mut store,
                entry_point,
                &[],
            )
            .await;

        // Get resource usage
        let resource_usage = sandbox_instance.get_usage().await;

        // Clean up
        self.sandbox.remove_instance(sandbox_instance.id).await?;

        let elapsed = start.elapsed().as_millis() as u64;

        match func_results {
            Ok(_) => Ok(ExecutionResult {
                success: true,
                function_results: vec![],
                resource_usage,
                output: None,
                error: None,
                total_execution_time_ms: elapsed,
            }),
            Err(e) => Ok(ExecutionResult {
                success: false,
                function_results: vec![],
                resource_usage,
                output: None,
                error: Some(e.to_string()),
                total_execution_time_ms: elapsed,
            }),
        }
    }

    /// Get runtime statistics
    pub async fn stats(&self) -> RuntimeStats {
        let modules = self.modules.read().await.len();
        let instances = self.sandbox.instance_count().await;
        let resource_usage = self.sandbox.total_resource_usage().await;

        RuntimeStats {
            compiled_modules: modules,
            active_instances: instances,
            total_resource_usage: resource_usage,
        }
    }

    /// Shutdown the runtime
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down WASM runtime");

        // Clean up sandbox
        self.sandbox.shutdown().await?;

        // Clear module cache
        self.modules.write().await.clear();
        self.module_names.write().await.clear();

        info!("WASM runtime shutdown complete");
        Ok(())
    }
}

/// Runtime statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStats {
    /// Number of compiled modules
    pub compiled_modules: usize,
    /// Number of active instances
    pub active_instances: usize,
    /// Total resource usage
    pub total_resource_usage: ResourceUsage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_config_default() {
        let config = RuntimeConfig::default();
        assert!(config.async_support);
        assert!(config.parallel_compilation);
        assert!(!config.debug_info);
    }

    #[test]
    fn test_runtime_config_builder() {
        let config = RuntimeConfig::new()
            .with_async_support(false)
            .with_debug_info(true)
            .with_opt_level(OptLevel::None);

        assert!(!config.async_support);
        assert!(config.debug_info);
    }

    #[tokio::test]
    async fn test_wasm_runtime_creation() {
        let runtime = WasmRuntime::default();
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_compile_simple_module() {
        // Simple WASM module that exports an "add" function
        // (module
        //   (func $add (param i32 i32) (result i32)
        //     local.get 0
        //     local.get 1
        //     i32.add)
        //   (export "add" (func $add))
        // )
        let wasm_bytes = &[
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x07, 0x01, // type section
            0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // func type (i32, i32) -> i32
            0x03, 0x02, 0x01, 0x00, // func section
            0x07, 0x07, 0x01, // export section
            0x03, 0x61, 0x64, 0x64, // "add"
            0x00, 0x00, // func 0
            0x0a, 0x09, 0x01, // code section
            0x07, 0x00, // func body
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6a, // i32.add
            0x0b, // end
        ];

        let runtime = WasmRuntime::default().unwrap();
        let module_id = runtime.compile_module("test", wasm_bytes).await.unwrap();

        let module = runtime.get_module(module_id).await;
        assert!(module.is_some());
        assert_eq!(module.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_runtime_stats() {
        let runtime = WasmRuntime::default().unwrap();
        let stats = runtime.stats().await;

        assert_eq!(stats.compiled_modules, 0);
        assert_eq!(stats.active_instances, 0);
    }
}
