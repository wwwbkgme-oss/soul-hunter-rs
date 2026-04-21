//! Hook System with Phase Ordering and Topological Execution
//!
//! Provides a flexible lifecycle hook mechanism for orchestrating complex
//! workflows with dependency-aware execution.
//!
//! ## Features
//!
//! - **Phased Execution**: Hooks organized into phases (early, normal, late)
//! - **Dependency Resolution**: Topological sort ensures hooks run in correct order
//! - **Conditional Execution**: Hooks can be conditioned on context state
//! - **Priority Within Phase**: Fine-grained ordering within each phase
//! - **Async Support**: Hook functions can be async
//!
//! ## Hook Phases
//!
//! 1. **Early** (before main action): Validation, setup, pre-checks
//! 2. **Normal** (during main action): Core processing, agent coordination
//! 3. **Late** (after main action): Cleanup, post-processing, reporting
//!
//! ## Usage
//!
//! ```rust
//! use sh_orchestrator::hooks::{HookRegistry, Hook, HookPhase, HookContext};
//!
//! let mut registry = HookRegistry::new();
//!
//! // Register hooks with dependencies
//! registry.register(Hook::new(
//!     "validate_target".to_string(),
//!     HookPhase::Early,
//!     1,
//!     |ctx| async move {
//!         println!("Validating target...");
//!         Ok(())
//!     },
//! ));
//!
//! registry.register(Hook::new(
//!     "run_analysis".to_string(),
//!     HookPhase::Normal,
//!     ︎
//!     |ctx| async move {
//!         println!("Running analysis...");
//!         Ok(())
//!     },
//! ).depends_on("validate_target"));
//!
//! // Execute all hooks in order
//! let mut context = HookContext::new();
//! registry.execute_all(&mut context).await?;
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use sh_types::prelude::*;

/// Hook execution phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookPhase {
    /// Before main action (validation, setup)
    Early,
    /// Main processing (core work)
    Normal,
    /// After main action (cleanup, reporting)
    Late,
}

impl HookPhase {
    /// Get ordering value (lower = earlier)
    pub fn order(&self) -> u8 {
        match self {
            Self::Early => 0,
            Self::Normal => 1,
            Self::Late => 2,
        }
    }
}

/// Hook execution context passed to all hooks
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Shared mutable state accessible to all hooks
    pub state: Arc<tokio::sync::RwLock<HashMap<String, serde_json::Value>>>,
    /// Hook execution metadata
    pub metadata: HookMetadata,
    /// Global context (read-only)
    pub global: GlobalContext,
}

impl HookContext {
    /// Create new hook context
    pub fn new() -> Self {
        Self {
            state: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            metadata: HookMetadata::default(),
            global: GlobalContext::default(),
        }
    }

    /// Set state value
    pub async fn set(&self, key: impl Into<String>, value: impl Serialize) -> Result<(), HookError> {
        let json = serde_json::to_value(value)
            .map_err(|e| HookError::StateError(e.to_string()))?;
        self.state.write().await.insert(key.into(), json);
        Ok(())
    }

    /// Get state value
    pub async fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.state.read().await.get(key).cloned()
    }

    /// Check if state contains key
    pub async fn contains(&self, key: &str) -> bool {
        self.state.read().await.contains_key(key)
    }
}

/// Metadata about the current hook execution
#[derive(Debug, Clone, Default)]
pub struct HookMetadata {
    /// Current hook name being executed
    pub current_hook: Option<String>,
    /// Phase currently executing
    pub current_phase: Option<HookPhase>,
    /// Execution start time
    pub start_time: Option<Instant>,
    /// Number of hooks executed so far
    pub hooks_executed: usize,
    /// Total number of hooks to execute
    pub total_hooks: usize,
}

/// Global read-only context
#[derive(Debug, Clone, Default)]
pub struct GlobalContext {
    /// Assessment/task ID
    pub assessment_id: Option<String>,
    /// Target being processed
    pub target_path: Option<String>,
    /// Agent ID executing hooks
    pub agent_id: Option<String>,
}

/// A single hook function
pub struct Hook {
    /// Unique identifier
    name: String,
    /// Execution phase
    phase: HookPhase,
    /// Priority within phase (higher = earlier)
    priority: i32,
    /// The actual hook function
    function: Arc<dyn HookFunction + Send + Sync>,
    /// Dependencies (must execute before this hook)
    dependencies: Vec<String>,
    /// Condition for execution (optional)
    condition: Option<Arc<dyn HookCondition + Send + Sync>>,
    /// Timeout for hook execution
    timeout: Option<Duration>,
}

#[async_trait]
trait HookFunction: Send + Sync {
    async fn call(&self, context: &mut HookContext) -> Result<(), HookError>;
}

#[async_trait]
trait HookCondition: Send + Sync {
    async fn check(&self, context: &HookContext) -> Result<bool, HookError>;
}

impl Hook {
    /// Create new hook
    pub fn new<F>(name: String, phase: HookPhase, priority: i32, function: F) -> Self
    where
        F: Fn(&mut HookContext) -> BoxFuture<'static, Result<(), HookError>> + Send + Sync + 'static,
    {
        Self {
            name,
            phase,
            priority,
            function: Arc::new(HookFn(function)),
            dependencies: Vec::new(),
            condition: None,
            timeout: None,
        }
    }

    /// Add dependency
    pub fn depends_on(mut self, dependency: impl Into<String>) -> Self {
        self.dependencies.push(dependency.into());
        self
    }

    /// Set conditional execution
    pub fn with_condition<C>(mut self, condition: C) -> Self
    where
        C: Fn(&HookContext) -> BoxFuture<'static, Result<bool, HookError>> + Send + Sync + 'static,
    {
        self.condition = Some(Arc::new(ConditionFn(condition)));
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Get name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get phase
    pub fn phase(&self) -> HookPhase {
        self.phase
    }

    /// Get priority
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Get dependencies
    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    /// Execute the hook
    pub async fn execute(&self, context: &mut HookContext) -> Result<(), HookError> {
        // Check condition if present
        if let Some(condition) = &self.condition {
            let should_run = condition.check(context).await?;
            if !should_run {
                debug!("Hook '{}' skipped due to condition", self.name);
                return Ok(());
            }
        }

        // Update context metadata
        {
            let mut metadata = &mut context.metadata;
            metadata.current_hook = Some(self.name.clone());
            metadata.current_phase = Some(self.phase);
        }

        // Execute with timeout if specified
        let result = if let Some(timeout) = self.timeout {
            tokio::time::timeout(timeout, self.function.call(context))
                .await
                .map_err(|_| HookError::Timeout(self.name.clone()))?
        } else {
            self.function.call(context).await
        };

        if let Ok(()) = &result {
            debug!("Hook '{}' executed successfully", self.name);
        } else {
            error!("Hook '{}' failed: {:?}", self.name, result);
        }

        result
    }
}

/// Wrapper for async hook function
struct HookFn<F>(F);

#[async_trait]
impl<F> HookFunction for HookFn<F>
where
    F: Fn(&mut HookContext) -> BoxFuture<'static, Result<(), HookError>> + Send + Sync + 'static,
{
    async fn call(&self, context: &mut HookContext) -> Result<(), HookError> {
        (self.0)(context).await
    }
}

/// Wrapper for async condition function
struct ConditionFn<C>(C);

#[async_trait]
impl<C> HookCondition for ConditionFn<C>
where
    C: Fn(&HookContext) -> BoxFuture<'static, Result<bool, HookError>> + Send + Sync + 'static,
{
    async fn check(&self, context: &HookContext) -> Result<bool, HookError> {
        (self.0)(context).await
    }
}

/// Hook registry that manages all hooks and their execution order
pub struct HookRegistry {
    hooks: DashMap<String, Arc<Hook>>,
    execution_order: Arc<RwLock<Option<Vec<String>>>>,
    /// Cache of phase ordering
    phase_order: Arc<RwLock<HashMap<HookPhase, Vec<String>>>>,
}

impl HookRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            hooks: DashMap::new(),
            execution_order: Arc::new(RwLock::new(None)),
            phase_order: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a hook
    pub fn register(&self, hook: Hook) -> Result<(), HookError> {
        let name = hook.name().to_string();

        if self.hooks.contains_key(&name) {
            return Err(HookError::DuplicateHook(name));
        }

        self.hooks.insert(name.clone(), Arc::new(hook));
        debug!("Registered hook: {}", name);

        // Invalidate cached order
        *self.execution_order.write() = None;
        *self.phase_order.write() = HashMap::new();

        Ok(())
    }

    /// Register multiple hooks at once
    pub fn register_many(&self, hooks: Vec<Hook>) -> Result<(), HookError> {
        for hook in hooks {
            self.register(hook)?;
        }
        Ok(())
    }

    /// Get a hook by name
    pub fn get(&self, name: &str) -> Option<Arc<Hook>> {
        self.hooks.get(name).map(|h| h.clone())
    }

    /// List all hook names
    pub fn list(&self) -> Vec<String> {
        self.hooks.iter().map(|h| h.key().clone()).collect()
    }

    /// Build execution order using topological sort within phases
    pub async fn build_execution_order(&self) -> Result<(), HookError> {
        let mut phases: HashMap<HookPhase, Vec<Arc<Hook>>> = HashMap::new();
        let mut dependency_graph: HashMap<String, Vec<String>> = HashMap::new();
        let mut all_hook_names: HashSet<String> = HashSet::new();

        // Group hooks by phase
        for entry in &self.hooks {
            let hook = entry.value();
            phases
                .entry(hook.phase())
                .or_default()
                .push(hook.clone());
            all_hook_names.insert(hook.name().to_string());
            dependency_graph.insert(hook.name().to_string(), hook.dependencies().to_vec());
        }

        // Sort phases
        let mut sorted_phases: Vec<_> = phases.into_iter().collect();
        sorted_phases.sort_by_key(|(phase, _)| phase.order());

        // For each phase, do topological sort within phase
        let mut final_order = Vec::new();

        for (phase, mut phase_hooks) in sorted_phases {
            // Sort by priority within phase (higher priority first)
            phase_hooks.sort_by(|a, b| b.priority().cmp(&a.priority()));

            // Build dependency graph for hooks in this phase
            let mut in_degree: HashMap<String, usize> = HashMap::new();
            let mut adj_list: HashMap<String, Vec<String>> = HashMap::new();

            for hook in &phase_hooks {
                in_degree.insert(hook.name().to_string(), 0);
            }

            for hook in &phase_hooks {
                if let Some(deps) = dependency_graph.get(hook.name()) {
                    for dep in deps {
                        if all_hook_names.contains(dep) {
                            adj_list.entry(dep.clone()).or_default().push(hook.name().to_string());
                            *in_degree.get_mut(hook.name()).unwrap() += 1;
                        }
                    }
                }
            }

            // Kahn's algorithm for topological sort
            let mut queue: VecDeque<String> = VecDeque::new();
            for (name, &deg) in &in_degree {
                if deg == 0 {
                    queue.push_back(name.clone());
                }
            }

            let mut phase_order = Vec::new();

            while let Some(name) = queue.pop_front() {
                phase_order.push(name.clone());

                if let Some(neighbors) = adj_list.get(&name) {
                    for neighbor in neighbors {
                        if let Some(deg) = in_degree.get_mut(neighbor) {
                            *deg -= 1;
                            if *deg == 0 {
                                queue.push_back(neighbor.clone());
                            }
                        }
                    }
                }
            }

            // Check for cycles
            if phase_order.len() != phase_hooks.len() {
                let hooks_missing: Vec<_> = phase_hooks.iter()
                    .map(|h| h.name().to_string())
                    .filter(|name| !phase_order.contains(name))
                    .collect();
                return Err(HookError::CyclicDependency(format!(
                    "Cyclic dependency among hooks: {:?}",
                    hooks_missing
                )));
            }

            debug!("Phase {:?} order: {:?}", phase, phase_order);
            final_order.extend(phase_order);
        }

        // Cache the order
        *self.execution_order.write().await = Some(final_order.clone());

        // Also cache phase grouping
        let mut phase_cache = HashMap::new();
        for (phase, _, ) in sorted_phases {
            phase_cache.insert(phase, Vec::new());
        }
        for name in &final_order {
            if let Some(hook) = self.hooks.get(name) {
                phase_cache.entry(hook.phase()).or_default().push(name.clone());
            }
        }
        *self.phase_order.write().await = phase_cache;

        info!("Built execution order with {} hooks", final_order.len());
        Ok(())
    }

    /// Execute all hooks in the computed order
    pub async fn execute_all(&self, context: &mut HookContext) -> Result<(), HookError> {
        // Ensure order is built
        if self.execution_order.read().await.is_none() {
            self.build_execution_order().await?;
        }

        let order = self.execution_order.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| HookError::Uninitialized("execution order not built".to_string()))?;

        context.metadata.total_hooks = order.len();

        info!("Executing {} hooks in order", order.len());

        for hook_name in order {
            // Check if hook exists
            let hook = match self.hooks.get(&hook_name) {
                Some(h) => h,
                None => {
                    warn!("Hook '{}' not found, skipping", hook_name);
                    continue;
                }
            };

            context.metadata.current_hook = Some(hook_name.clone());
            context.metadata.hooks_executed += 1;

            debug!("Executing hook: {} ({}/{})",
                hook_name,
                context.metadata.hooks_executed,
                context.metadata.total_hooks);

            let start = Instant::now();

            if let Err(e) = hook.execute(context).await {
                error!("Hook '{}' failed: {}", hook_name, e);
                return Err(e);
            }

            let elapsed = start.elapsed();
            debug!("Hook '{}' completed in {:?}", hook_name, elapsed);
        }

        info!("All {} hooks executed successfully", order.len());
        Ok(())
    }

    /// Execute hooks for a specific phase only
    pub async fn execute_phase(
        &self,
        context: &mut HookContext,
        phase: HookPhase,
    ) -> Result<(), HookError> {
        let phase_order = self.phase_order.read().await;
        let hook_names = phase_order.get(&phase)
            .ok_or_else(|| HookError::PhaseNotFound(phase))?;

        info!("Executing {} hooks in phase {:?}", hook_names.len(), phase);

        for hook_name in hook_names {
            let hook = self.hooks.get(hook_name)
                .ok_or_else(|| HookError::HookNotFound(hook_name.clone()))?;

            context.metadata.current_hook = Some(hook_name.clone());
            context.metadata.current_phase = Some(phase);

            hook.execute(context).await?;
        }

        Ok(())
    }

    /// Remove a hook by name
    pub fn remove(&self, name: &str) -> Option<Arc<Hook>> {
        let result = self.hooks.remove(name);
        if result.is_some() {
            // Invalidate cache
            *self.execution_order.write().blocking_read() = None;
            *self.phase_order.write().blocking_read() = HashMap::new();
        }
        result
    }

    /// Clear all hooks
    pub fn clear(&self) {
        self.hooks.clear();
        *self.execution_order.write().blocking_read() = None;
        *self.phase_order.write().blocking_read() = HashMap::new();
    }

    /// Get number of registered hooks
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Hook execution error
#[derive(Error, Debug)]
pub enum HookError {
    #[error("Hook not found: {0}")]
    HookNotFound(String),

    #[error("Duplicate hook: {0}")]
    DuplicateHook(String),

    #[error("Cyclic dependency: {0}")]
    CyclicDependency(String),

    #[error("Phase not found: {:?}", phase)]
    PhaseNotFound { phase: HookPhase },

    #[error("Hook timeout: {0}")]
    Timeout(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Uninitialized: {0}")]
    Uninitialized(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hook_registry_basic() {
        let registry = HookRegistry::new();

        registry.register(Hook::new(
            "early_hook".to_string(),
            HookPhase::Early,
            1,
            |_ctx| Box::pin(async { Ok(()) }),
        )).unwrap();

        registry.register(Hook::new(
            "normal_hook".to_string(),
            HookPhase::Normal,
            1,
            |_ctx| Box::pin(async { Ok(()) }),
        )).unwrap();

        assert_eq!(registry.len(), 2);
    }

    #[tokio::test]
    async fn test_hook_execution_order() {
        let registry = HookRegistry::new();
        let mut context = HookContext::new();

        let mut execution_order = Vec::new();

        registry.register(Hook::new(
            "validate".to_string(),
            HookPhase::Early,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("validate".to_string());
                Ok(())
            }),
        )).unwrap();

        registry.register(Hook::new(
            "process".to_string(),
            HookPhase::Normal,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("process".to_string());
                Ok(())
            }),
        )).unwrap();

        registry.register(Hook::new(
            "cleanup".to_string(),
            HookPhase::Late,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("cleanup".to_string());
                Ok(())
            }),
        )).unwrap();

        registry.execute_all(&mut context).await.unwrap();

        // Should be in phase order: validate (Early), process (Normal), cleanup (Late)
        assert_eq!(execution_order, vec!["validate", "process", "cleanup"]);
    }

    #[tokio::test]
    async fn test_hook_dependencies() {
        let registry = HookRegistry::new();
        let mut context = HookContext::new();

        let mut execution_order = Vec::new();

        registry.register(Hook::new(
            "setup".to_string(),
            HookPhase::Early,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("setup".to_string());
                Ok(())
            }),
        )).unwrap();

        registry.register(Hook::new(
            "validate".to_string(),
            HookPhase::Early,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("validate".to_string());
                Ok(())
            }),
        ).depends_on("setup"));

        registry.register(Hook::new(
            "process".to_string(),
            HookPhase::Normal,
            1,
            |_ctx| Box::pin(async move {
                execution_order.push("process".to_string());
                Ok(())
            }),
        ).depends_on("validate"));

        registry.execute_all(&mut context).await.unwrap();

        // setup must come before validate, validate before process
        let idx_setup = execution_order.iter().position(|s| s == "setup").unwrap();
        let idx_validate = execution_order.iter().position(|s| s == "validate").unwrap();
        let idx_process = execution_order.iter().position(|s| s == "process").unwrap();

        assert!(idx_setup < idx_validate);
        assert!(idx_validate < idx_process);
    }
}
