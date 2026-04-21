//! # Soul Hunter Agents
//!
//! Production-ready security analysis agents for the Soul Hunter platform.
//!
//! This crate provides specialized agents for different types of security analysis:
//! - **Static Analysis Agent**: Analyzes code and binaries without execution
//! - **Dynamic Analysis Agent**: Performs runtime analysis and behavior monitoring
//! - **Network Analysis Agent**: Analyzes network traffic and communications
//! - **Crypto Analysis Agent**: Identifies cryptographic issues and misconfigurations
//! - **Orchestrator**: Coordinates multiple agents and manages analysis workflows
//!
//! ## Architecture
//!
//! All agents implement the `SecurityAgent` trait, providing a consistent interface
//! for task execution, health monitoring, and result reporting.

pub mod crypto_agent;
pub mod dynamic_agent;
pub mod fuzzing_agent;
pub mod network_agent;
pub mod orchestrator;
pub mod static_agent;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentPriority, AgentStatus, AgentTask,
    AgentType, AnalysisTarget, FindingCollection, Platform, TaskStatus,
};

/// Result type for agent operations
pub type Result<T> = std::result::Result<T, AgentError>;

/// Errors that can occur during agent operations
#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Agent not initialized: {0}")]
    NotInitialized(String),

    #[error("Agent already running: {0}")]
    AlreadyRunning(AgentId),

    #[error("Agent not found: {0}")]
    AgentNotFound(AgentId),

    #[error("Task execution failed: {0}")]
    TaskExecution(String),

    #[error("Task timeout: {0}")]
    TaskTimeout(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Context for agent task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    pub task_id: Uuid,
    pub job_id: Uuid,
    pub target: AnalysisTarget,
    pub options: HashMap<String, serde_json::Value>,
    pub timeout_secs: u64,
    pub created_at: DateTime<Utc>,
}

impl AgentContext {
    pub fn new(task_id: Uuid, job_id: Uuid, target: AnalysisTarget) -> Self {
        Self {
            task_id,
            job_id,
            target,
            options: HashMap::new(),
            timeout_secs: 300,
            created_at: Utc::now(),
        }
    }

    pub fn with_options(mut self, options: HashMap<String, serde_json::Value>) -> Self {
        self.options = options;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
}

/// Result of agent task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    pub task_id: Uuid,
    pub agent_id: AgentId,
    pub status: TaskStatus,
    pub findings: FindingCollection,
    pub execution_time_ms: u64,
    pub metadata: HashMap<String, serde_json::Value>,
    pub error: Option<String>,
    pub completed_at: DateTime<Utc>,
}

impl AgentResult {
    pub fn success(
        task_id: Uuid,
        agent_id: AgentId,
        findings: FindingCollection,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            task_id,
            agent_id,
            status: TaskStatus::Completed,
            findings,
            execution_time_ms,
            metadata: HashMap::new(),
            error: None,
            completed_at: Utc::now(),
        }
    }

    pub fn failed(task_id: Uuid, agent_id: AgentId, error: impl Into<String>) -> Self {
        Self {
            task_id,
            agent_id,
            status: TaskStatus::Failed,
            findings: FindingCollection::default(),
            execution_time_ms: 0,
            metadata: HashMap::new(),
            error: Some(error.into()),
            completed_at: Utc::now(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Core trait for all security analysis agents
#[async_trait]
pub trait SecurityAgent: Send + Sync {
    /// Get the agent's unique identifier
    fn id(&self) -> AgentId;

    /// Get the agent's name
    fn name(&self) -> &str;

    /// Get the agent type
    fn agent_type(&self) -> AgentType;

    /// Get the agent's capabilities
    fn capabilities(&self) -> Vec<AgentCapability>;

    /// Check if the agent has a specific capability
    fn has_capability(&self, capability: &AgentCapability) -> bool {
        self.capabilities().contains(capability)
    }

    /// Get the agent's current status
    fn status(&self) -> AgentStatus;

    /// Get the agent's configuration
    fn config(&self) -> &AgentConfig;

    /// Initialize the agent with the given configuration
    async fn initialize(&mut self, config: AgentConfig) -> Result<()>;

    /// Execute a security analysis task
    async fn execute(&self, context: AgentContext) -> Result<AgentResult>;

    /// Get agent health information
    async fn health(&self) -> AgentHealth;

    /// Shutdown the agent gracefully
    async fn shutdown(&mut self) -> Result<()>;

    /// Update the agent's heartbeat
    fn update_heartbeat(&self);

    /// Check if the agent is healthy and available
    fn is_available(&self) -> bool {
        self.status() == AgentStatus::Idle
    }
}

/// Base implementation shared by all agents
#[derive(Debug)]
pub struct AgentBase {
    pub id: AgentId,
    pub name: String,
    pub agent_type: AgentType,
    pub status: std::sync::RwLock<AgentStatus>,
    pub config: std::sync::RwLock<AgentConfig>,
    pub capabilities: Vec<AgentCapability>,
    pub platform: Platform,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: std::sync::RwLock<DateTime<Utc>>,
    pub completed_tasks: std::sync::atomic::AtomicU64,
    pub failed_tasks: std::sync::atomic::AtomicU64,
}

impl AgentBase {
    pub fn new(name: impl Into<String>, agent_type: AgentType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            agent_type,
            status: std::sync::RwLock::new(AgentStatus::Idle),
            config: std::sync::RwLock::new(AgentConfig::default()),
            capabilities: Vec::new(),
            platform: Platform::Unknown,
            created_at: now,
            last_heartbeat: std::sync::RwLock::new(now),
            completed_tasks: std::sync::atomic::AtomicU64::new(0),
            failed_tasks: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<AgentCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    pub fn set_status(&self, status: AgentStatus) {
        if let Ok(mut guard) = self.status.write() {
            *guard = status;
        }
    }

    pub fn get_status(&self) -> AgentStatus {
        self.status
            .read()
            .map(|g| *g)
            .unwrap_or(AgentStatus::Offline)
    }

    pub fn update_heartbeat(&self) {
        if let Ok(mut guard) = self.last_heartbeat.write() {
            *guard = Utc::now();
        }
    }

    pub fn get_last_heartbeat(&self) -> DateTime<Utc> {
        self.last_heartbeat
            .read()
            .map(|g| *g)
            .unwrap_or(self.created_at)
    }

    pub fn increment_completed(&self) {
        self.completed_tasks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_failed(&self) {
        self.failed_tasks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_health(&self) -> AgentHealth {
        let uptime_secs = (Utc::now() - self.created_at).num_seconds() as u64;
        let completed = self.completed_tasks.load(std::sync::atomic::Ordering::Relaxed);
        let failed = self.failed_tasks.load(std::sync::atomic::Ordering::Relaxed);

        AgentHealth {
            agent_id: self.id,
            status: self.get_status(),
            cpu_usage: 0.0, // Would be populated by system metrics
            memory_usage_mb: 0,
            active_jobs: if self.get_status() == AgentStatus::Busy {
                1
            } else {
                0
            },
            completed_jobs: completed,
            failed_jobs: failed,
            last_heartbeat: self.get_last_heartbeat(),
            uptime_secs,
        }
    }
}

/// Agent builder for constructing agents
pub struct AgentBuilder {
    name: String,
    agent_type: AgentType,
    capabilities: Vec<AgentCapability>,
    platform: Platform,
    config: AgentConfig,
}

impl AgentBuilder {
    pub fn new(name: impl Into<String>, agent_type: AgentType) -> Self {
        Self {
            name: name.into(),
            agent_type,
            capabilities: Vec::new(),
            platform: Platform::Unknown,
            config: AgentConfig::default(),
        }
    }

    pub fn with_capability(mut self, capability: AgentCapability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn with_capabilities(mut self, capabilities: Vec<AgentCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    pub fn with_config(mut self, config: AgentConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.config = self.config.with_timeout(timeout_secs);
        self
    }

    pub fn with_priority(mut self, priority: AgentPriority) -> Self {
        self.config = self.config.with_priority(priority);
        self
    }
}

/// Factory for creating agents
pub struct AgentFactory;

impl AgentFactory {
    /// Create a static analysis agent
    pub fn create_static_agent(name: impl Into<String>) -> static_agent::StaticAgent {
        static_agent::StaticAgent::new(name)
    }

    /// Create a dynamic analysis agent
    pub fn create_dynamic_agent(name: impl Into<String>) -> dynamic_agent::DynamicAgent {
        dynamic_agent::DynamicAgent::new(name)
    }

    /// Create a network analysis agent
    pub fn create_network_agent(name: impl Into<String>) -> network_agent::NetworkAgent {
        network_agent::NetworkAgent::new(name)
    }

    /// Create a crypto analysis agent
    pub fn create_crypto_agent(name: impl Into<String>) -> crypto_agent::CryptoAgent {
        crypto_agent::CryptoAgent::new(name)
    }

    /// Create an intent analysis agent
    pub fn create_intent_agent(name: impl Into<String>) -> intent_agent::IntentAgent {
        intent_agent::IntentAgent::new(name)
    }
}

/// Utility functions for agents
pub mod utils {
    use super::*;
    use std::time::{Duration, Instant};

    /// Execute a task with timeout
    pub async fn execute_with_timeout<F, Fut, T>(
        task: F,
        timeout: Duration,
    ) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let start = Instant::now();

        match tokio::time::timeout(timeout, task()).await {
            Ok(result) => {
                let elapsed = start.elapsed().as_millis() as u64;
                tracing::debug!("Task completed in {}ms", elapsed);
                result
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                tracing::warn!("Task timed out after {}ms", elapsed);
                Err(AgentError::TaskTimeout(format!(
                    "Task exceeded timeout of {:?}",
                    timeout
                )))
            }
        }
    }

    /// Validate that a target exists and is accessible
    pub async fn validate_target(target: &AnalysisTarget) -> Result<()> {
        let path = std::path::Path::new(&target.path);

        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "Target path does not exist: {}",
                target.path
            )));
        }

        // Additional platform-specific validation could be added here
        Ok(())
    }

    /// Create a unique task identifier
    pub fn generate_task_id() -> Uuid {
        Uuid::new_v4()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_context_creation() {
        let task_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);

        let context = AgentContext::new(task_id, job_id, target.clone());

        assert_eq!(context.task_id, task_id);
        assert_eq!(context.job_id, job_id);
        assert_eq!(context.target.path, "/path/to/app.apk");
        assert_eq!(context.timeout_secs, 300);
    }

    #[test]
    fn test_agent_result_success() {
        let task_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let findings = FindingCollection::default();

        let result = AgentResult::success(task_id, agent_id, findings, 1000);

        assert_eq!(result.task_id, task_id);
        assert_eq!(result.agent_id, agent_id);
        assert_eq!(result.status, TaskStatus::Completed);
        assert_eq!(result.execution_time_ms, 1000);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_agent_result_failed() {
        let task_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let result = AgentResult::failed(task_id, agent_id, "Test error");

        assert_eq!(result.status, TaskStatus::Failed);
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_agent_base_creation() {
        let base = AgentBase::new("Test Agent", AgentType::Static);

        assert_eq!(base.name, "Test Agent");
        assert_eq!(base.agent_type, AgentType::Static);
        assert_eq!(base.get_status(), AgentStatus::Idle);
        assert!(base.capabilities.is_empty());
    }

    #[test]
    fn test_agent_base_with_capabilities() {
        let base = AgentBase::new("Test Agent", AgentType::Static).with_capabilities(vec![
            AgentCapability::StaticAnalysis,
            AgentCapability::SecretDetection,
        ]);

        assert_eq!(base.capabilities.len(), 2);
        assert!(base.capabilities.contains(&AgentCapability::StaticAnalysis));
    }

    #[test]
    fn test_agent_base_status_management() {
        let base = AgentBase::new("Test Agent", AgentType::Static);

        assert_eq!(base.get_status(), AgentStatus::Idle);

        base.set_status(AgentStatus::Busy);
        assert_eq!(base.get_status(), AgentStatus::Busy);

        base.set_status(AgentStatus::Idle);
        assert_eq!(base.get_status(), AgentStatus::Idle);
    }

    #[test]
    fn test_agent_base_task_counters() {
        let base = AgentBase::new("Test Agent", AgentType::Static);

        assert_eq!(
            base.completed_tasks.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            base.failed_tasks.load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        base.increment_completed();
        assert_eq!(
            base.completed_tasks.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        base.increment_failed();
        assert_eq!(
            base.failed_tasks.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_agent_builder() {
        let builder = AgentBuilder::new("Test Agent", AgentType::Static)
            .with_capability(AgentCapability::StaticAnalysis)
            .with_platform(Platform::Android)
            .with_timeout(600);

        assert_eq!(builder.name, "Test Agent");
        assert_eq!(builder.agent_type, AgentType::Static);
        assert_eq!(builder.capabilities.len(), 1);
        assert_eq!(builder.platform, Platform::Android);
        assert_eq!(builder.config.timeout_secs, 600);
    }
}
