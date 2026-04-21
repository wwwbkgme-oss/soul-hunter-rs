//! Agent types for security analysis agents

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{AnalysisTarget, FindingCollection, JobId, Platform};

/// Unique identifier for agents
pub type AgentId = Uuid;

/// Agent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Idle,
    Busy,
    Paused,
    Error,
    Offline,
}

impl Default for AgentStatus {
    fn default() -> Self {
        AgentStatus::Idle
    }
}

/// Agent types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Static,
    Dynamic,
    Network,
    Crypto,
    Intent,
    Orchestrator,
    Manager,
    Architect,
    Engineer,
}

impl fmt::Display for AgentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentType::Static => write!(f, "static"),
            AgentType::Dynamic => write!(f, "dynamic"),
            AgentType::Network => write!(f, "network"),
            AgentType::Crypto => write!(f, "crypto"),
            AgentType::Intent => write!(f, "intent"),
            AgentType::Orchestrator => write!(f, "orchestrator"),
            AgentType::Manager => write!(f, "manager"),
            AgentType::Architect => write!(f, "architect"),
            AgentType::Engineer => write!(f, "engineer"),
        }
    }
}

impl Default for AgentType {
    fn default() -> Self {
        AgentType::Static
    }
}

use std::fmt;

/// A security analysis agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: AgentId,
    pub name: String,
    pub agent_type: AgentType,
    pub status: AgentStatus,
    pub capabilities: Vec<AgentCapability>,
    
    // Configuration
    pub config: AgentConfig,
    
    // State
    pub current_job: Option<JobId>,
    pub completed_jobs: Vec<JobId>,
    
    // Metadata
    pub version: String,
    pub platform: Platform,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

impl Agent {
    pub fn new(name: impl Into<String>, agent_type: AgentType) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            agent_type,
            status: AgentStatus::Idle,
            capabilities: Vec::new(),
            config: AgentConfig::default(),
            current_job: None,
            completed_jobs: Vec::new(),
            version: "0.1.0".to_string(),
            platform: Platform::Unknown,
            created_at: Utc::now(),
            last_heartbeat: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<AgentCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn add_capability(mut self, capability: AgentCapability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn with_config(mut self, config: AgentConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    pub fn can_handle(&self, capability: &AgentCapability) -> bool {
        self.capabilities.contains(capability)
    }

    pub fn is_available(&self) -> bool {
        self.status == AgentStatus::Idle
    }

    pub fn assign_job(&mut self, job_id: JobId) {
        self.status = AgentStatus::Busy;
        self.current_job = Some(job_id);
    }

    pub fn complete_job(&mut self) {
        if let Some(job_id) = self.current_job.take() {
            self.completed_jobs.push(job_id);
        }
        self.status = AgentStatus::Idle;
    }

    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Some(Utc::now());
    }
}

/// Agent capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCapability {
    StaticAnalysis,
    DynamicAnalysis,
    NetworkAnalysis,
    CryptoAnalysis,
    IntentAnalysis,
    ManifestParsing,
    SecretDetection,
    PermissionAnalysis,
    ComponentAnalysis,
    TrafficAnalysis,
    Fuzzing,
    Correlation,
    RiskScoring,
    ReportGeneration,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub max_concurrent_jobs: u32,
    pub timeout_secs: u64,
    pub retry_count: u32,
    pub priority: AgentPriority,
    pub options: HashMap<String, serde_json::Value>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 1,
            timeout_secs: 300,
            retry_count: 3,
            priority: AgentPriority::Normal,
            options: HashMap::new(),
        }
    }
}

impl AgentConfig {
    pub fn with_max_concurrent_jobs(mut self, max: u32) -> Self {
        self.max_concurrent_jobs = max;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn with_priority(mut self, priority: AgentPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn add_option(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.options.insert(key.into(), value);
        self
    }
}

/// Agent priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPriority {
    Low = 0,
    Normal = 50,
    High = 75,
    Critical = 100,
}

impl Default for AgentPriority {
    fn default() -> Self {
        AgentPriority::Normal
    }
}

/// Agent team for hierarchical orchestration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeam {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub architect: Option<AgentId>,
    pub managers: Vec<AgentId>,
    pub engineers: Vec<AgentId>,
    pub status: TeamStatus,
    pub created_at: DateTime<Utc>,
}

impl AgentTeam {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            architect: None,
            managers: Vec::new(),
            engineers: Vec::new(),
            status: TeamStatus::Inactive,
            created_at: Utc::now(),
        }
    }

    pub fn with_architect(mut self, agent_id: AgentId) -> Self {
        self.architect = Some(agent_id);
        self
    }

    pub fn add_manager(mut self, agent_id: AgentId) -> Self {
        self.managers.push(agent_id);
        self
    }

    pub fn add_engineer(mut self, agent_id: AgentId) -> Self {
        self.engineers.push(agent_id);
        self
    }

    pub fn activate(&mut self) {
        self.status = TeamStatus::Active;
    }

    pub fn deactivate(&mut self) {
        self.status = TeamStatus::Inactive;
    }
}

/// Team status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamStatus {
    Active,
    Inactive,
    Paused,
}

/// Agent task assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: Uuid,
    pub agent_id: AgentId,
    pub job_id: JobId,
    pub target: AnalysisTarget,
    pub task_type: String,
    pub priority: AgentPriority,
    pub status: TaskStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<FindingCollection>,
    pub error: Option<String>,
}

impl AgentTask {
    pub fn new(agent_id: AgentId, job_id: JobId, target: AnalysisTarget, task_type: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            job_id,
            target,
            task_type: task_type.into(),
            priority: AgentPriority::Normal,
            status: TaskStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result: None,
            error: None,
        }
    }

    pub fn with_priority(mut self, priority: AgentPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn mark_started(&mut self) {
        self.status = TaskStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn mark_completed(&mut self, result: FindingCollection) {
        self.status = TaskStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.result = Some(result);
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = TaskStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error.into());
    }
}

/// Task status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Agent health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_id: AgentId,
    pub status: AgentStatus,
    pub cpu_usage: f64,
    pub memory_usage_mb: u64,
    pub active_jobs: u32,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub last_heartbeat: DateTime<Utc>,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_builder() {
        let agent = Agent::new("Static Analyzer", AgentType::Static)
            .with_version("1.0.0")
            .add_capability(AgentCapability::StaticAnalysis)
            .add_capability(AgentCapability::SecretDetection);

        assert_eq!(agent.name, "Static Analyzer");
        assert_eq!(agent.agent_type, AgentType::Static);
        assert_eq!(agent.version, "1.0.0");
        assert_eq!(agent.capabilities.len(), 2);
        assert!(agent.can_handle(&AgentCapability::StaticAnalysis));
    }

    #[test]
    fn test_agent_lifecycle() {
        let mut agent = Agent::new("Test Agent", AgentType::Static);
        assert!(agent.is_available());
        
        let job_id = Uuid::new_v4();
        agent.assign_job(job_id);
        assert!(!agent.is_available());
        assert_eq!(agent.status, AgentStatus::Busy);
        
        agent.complete_job();
        assert!(agent.is_available());
        assert_eq!(agent.completed_jobs.len(), 1);
    }

    #[test]
    fn test_agent_team() {
        let architect_id = Uuid::new_v4();
        let manager_id = Uuid::new_v4();
        let engineer_id = Uuid::new_v4();
        
        let team = AgentTeam::new("Security Team")
            .with_architect(architect_id)
            .add_manager(manager_id)
            .add_engineer(engineer_id);

        assert_eq!(team.name, "Security Team");
        assert_eq!(team.architect, Some(architect_id));
        assert_eq!(team.managers.len(), 1);
        assert_eq!(team.engineers.len(), 1);
    }

    #[test]
    fn test_agent_task() {
        let agent_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        
        let mut task = AgentTask::new(agent_id, job_id, target, "static_analysis")
            .with_priority(AgentPriority::High);

        assert_eq!(task.task_type, "static_analysis");
        assert_eq!(task.priority, AgentPriority::High);
        
        task.mark_started();
        assert_eq!(task.status, TaskStatus::Running);
        
        let findings = FindingCollection::default();
        task.mark_completed(findings);
        assert_eq!(task.status, TaskStatus::Completed);
    }
}
