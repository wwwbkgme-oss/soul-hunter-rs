//! # Agent Orchestrator
//!
//! Coordinates multiple security analysis agents and manages analysis workflows.
//! Capabilities include:
//! - Agent registration and lifecycle management
//! - Task distribution and scheduling
//! - Result aggregation and correlation
//! - Workflow orchestration
//! - Health monitoring
//! - Load balancing

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentPriority, AgentStatus, AgentTask,
    AgentTeam, AgentType, AnalysisTarget, Finding, FindingCollection, JobId, Platform,
    TaskStatus, TeamStatus,
};

/// Agent orchestrator for managing multiple agents
pub struct AgentOrchestrator {
    base: AgentBase,
    agents: DashMap<AgentId, Arc<dyn SecurityAgent + Send + Sync>>,
    agent_health: DashMap<AgentId, AgentHealth>,
    task_queue: Arc<Mutex<VecDeque<AgentTask>>>,
    task_results: DashMap<Uuid, AgentResult>,
    active_tasks: DashMap<Uuid, AgentTask>,
    teams: DashMap<Uuid, AgentTeam>,
    max_concurrent_tasks: usize,
    task_semaphore: Arc<Semaphore>,
    result_sender: Option<mpsc::Sender<OrchestratorEvent>>,
    shutdown_signal: Arc<RwLock<bool>>,
}

/// Orchestrator events
#[derive(Debug, Clone)]
pub enum OrchestratorEvent {
    TaskAssigned { task_id: Uuid, agent_id: AgentId },
    TaskCompleted { task_id: Uuid, agent_id: AgentId, findings_count: usize },
    TaskFailed { task_id: Uuid, agent_id: AgentId, error: String },
    AgentRegistered { agent_id: AgentId, agent_type: AgentType },
    AgentDeregistered { agent_id: AgentId },
    AgentHealthChanged { agent_id: AgentId, status: AgentStatus },
}

/// Workflow definition
#[derive(Debug, Clone)]
pub struct Workflow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<WorkflowStep>,
    pub status: WorkflowStatus,
    pub created_at: chrono::DateTime<Utc>,
    pub started_at: Option<chrono::DateTime<Utc>>,
    pub completed_at: Option<chrono::DateTime<Utc>>,
}

/// Workflow step
#[derive(Debug, Clone)]
pub struct WorkflowStep {
    pub id: Uuid,
    pub name: String,
    pub agent_type: AgentType,
    pub capabilities: Vec<AgentCapability>,
    pub depends_on: Vec<Uuid>,
    pub status: StepStatus,
    pub result: Option<AgentResult>,
}

/// Workflow status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Step status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Waiting,
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Task assignment strategy
#[derive(Debug, Clone, Copy)]
pub enum AssignmentStrategy {
    RoundRobin,
    LeastLoaded,
    CapabilityMatch,
    PriorityBased,
}

impl AgentOrchestrator {
    /// Create a new agent orchestrator
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Orchestrator)
            .with_capabilities(vec![
                AgentCapability::Correlation,
                AgentCapability::RiskScoring,
                AgentCapability::ReportGeneration,
            ]);

        let max_concurrent_tasks = 10;

        Self {
            base,
            agents: DashMap::new(),
            agent_health: DashMap::new(),
            task_queue: Arc::new(Mutex::new(VecDeque::new())),
            task_results: DashMap::new(),
            active_tasks: DashMap::new(),
            teams: DashMap::new(),
            max_concurrent_tasks,
            task_semaphore: Arc::new(Semaphore::new(max_concurrent_tasks)),
            result_sender: None,
            shutdown_signal: Arc::new(RwLock::new(false)),
        }
    }

    /// Register an agent with the orchestrator
    #[instrument(skip(self, agent), fields(agent_id = %agent.id()))]
    pub async fn register_agent(
        &mut self,
        agent: Arc<dyn SecurityAgent + Send + Sync>,
    ) -> Result<()> {
        let agent_id = agent.id();
        let agent_type = agent.agent_type();

        info!("Registering agent: {} ({:?})", agent_id, agent_type);

        // Store agent
        self.agents.insert(agent_id, agent.clone());

        // Initialize health tracking
        let health = agent.health().await;
        self.agent_health.insert(agent_id, health);

        info!("Agent {} registered successfully", agent_id);
        Ok(())
    }

    /// Deregister an agent
    #[instrument(skip(self), fields(agent_id = %agent_id))]
    pub async fn deregister_agent(&mut self, agent_id: AgentId) -> Result<()> {
        info!("Deregistering agent: {}", agent_id);

        if self.agents.remove(&agent_id).is_none() {
            return Err(AgentError::AgentNotFound(agent_id));
        }

        self.agent_health.remove(&agent_id);

        info!("Agent {} deregistered successfully", agent_id);
        Ok(())
    }

    /// Get all registered agents
    pub fn get_agents(&self) -> Vec<AgentId> {
        self.agents.iter().map(|entry| *entry.key()).collect()
    }

    /// Get agents by type
    pub fn get_agents_by_type(&self, agent_type: AgentType) -> Vec<AgentId> {
        self.agents
            .iter()
            .filter(|entry| entry.value().agent_type() == agent_type)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get agents by capability
    pub fn get_agents_by_capability(&self, capability: AgentCapability) -> Vec<AgentId> {
        self.agents
            .iter()
            .filter(|entry| entry.value().has_capability(&capability))
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get available agents (idle and healthy)
    pub fn get_available_agents(&self) -> Vec<AgentId> {
        self.agents
            .iter()
            .filter(|entry| {
                let agent = entry.value();
                agent.status() == AgentStatus::Idle && agent.is_available()
            })
            .map(|entry| *entry.key())
            .collect()
    }

    /// Submit a task for execution
    #[instrument(skip(self, target), fields(job_id = %job_id))]
    pub async fn submit_task(
        &self,
        job_id: JobId,
        target: AnalysisTarget,
        agent_type: AgentType,
        priority: AgentPriority,
    ) -> Result<Uuid> {
        let task_id = Uuid::new_v4();

        info!(
            "Submitting task {} for job {} targeting {}",
            task_id, job_id, target.path
        );

        // Find suitable agent
        let suitable_agents = self.get_agents_by_type(agent_type);
        if suitable_agents.is_empty() {
            return Err(AgentError::AgentNotFound(Uuid::nil()));
        }

        // Create task
        let task = AgentTask::new(suitable_agents[0], job_id, target, format!("{:?}", agent_type))
            .with_priority(priority);

        // Add to queue
        {
            let mut queue = self.task_queue.lock().await;
            queue.push_back(task.clone());
        }

        info!("Task {} submitted successfully", task_id);
        Ok(task_id)
    }

    /// Submit a task with specific capabilities
    #[instrument(skip(self, target), fields(job_id = %job_id))]
    pub async fn submit_task_with_capabilities(
        &self,
        job_id: JobId,
        target: AnalysisTarget,
        capabilities: Vec<AgentCapability>,
        priority: AgentPriority,
    ) -> Result<Uuid> {
        let task_id = Uuid::new_v4();

        info!(
            "Submitting task {} for job {} with capabilities {:?}",
            task_id, job_id, capabilities
        );

        // Find agent with required capabilities
        let suitable_agents: Vec<_> = self
            .agents
            .iter()
            .filter(|entry| {
                let agent = entry.value();
                capabilities.iter().all(|cap| agent.has_capability(cap))
            })
            .map(|entry| *entry.key())
            .collect();

        if suitable_agents.is_empty() {
            return Err(AgentError::InvalidConfig(
                "No agent found with required capabilities".to_string(),
            ));
        }

        // Create task
        let task = AgentTask::new(suitable_agents[0], job_id, target, "capability_task")
            .with_priority(priority);

        // Add to queue
        {
            let mut queue = self.task_queue.lock().await;
            queue.push_back(task.clone());
        }

        info!("Task {} submitted successfully", task_id);
        Ok(task_id)
    }

    /// Execute a task immediately
    #[instrument(skip(self, target, agent_id), fields(agent_id = %agent_id))]
    pub async fn execute_task(
        &self,
        agent_id: AgentId,
        target: AnalysisTarget,
        options: HashMap<String, serde_json::Value>,
    ) -> Result<AgentResult> {
        let task_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        info!(
            "Executing task {} on agent {} for target {}",
            task_id, agent_id, target.path
        );

        // Get agent
        let agent = self
            .agents
            .get(&agent_id)
            .ok_or(AgentError::AgentNotFound(agent_id))?;

        // Check if agent is available
        if !agent.is_available() {
            return Err(AgentError::AlreadyRunning(agent_id));
        }

        // Create context
        let context = AgentContext::new(task_id, job_id, target)
            .with_options(options);

        // Execute task
        let result = agent.execute(context).await?;

        // Store result
        self.task_results.insert(task_id, result.clone());

        info!("Task {} completed with status: {:?}", task_id, result.status);

        Ok(result)
    }

    /// Execute a workflow
    #[instrument(skip(self, workflow))]
    pub async fn execute_workflow(&self, workflow: &mut Workflow) -> Result<Vec<AgentResult>> {
        info!("Executing workflow: {} ({})", workflow.name, workflow.id);

        workflow.status = WorkflowStatus::Running;
        workflow.started_at = Some(Utc::now());

        let mut results = Vec::new();
        let mut completed_steps = HashMap::new();

        // Process steps in dependency order
        for step in &mut workflow.steps {
            // Check if dependencies are met
            let deps_met = step
                .depends_on
                .iter()
                .all(|dep_id| completed_steps.get(dep_id) == Some(&true));

            if !deps_met {
                step.status = StepStatus::Waiting;
                continue;
            }

            step.status = StepStatus::Running;

            // Find suitable agent
            let suitable_agents = self.get_agents_by_type(step.agent_type);
            if suitable_agents.is_empty() {
                step.status = StepStatus::Failed;
                continue;
            }

            // Execute step
            let agent_id = suitable_agents[0];
            let target = AnalysisTarget::new("workflow_target", Platform::Unknown);
            let options = HashMap::new();

            match self.execute_task(agent_id, target, options).await {
                Ok(result) => {
                    step.result = Some(result.clone());
                    step.status = StepStatus::Completed;
                    completed_steps.insert(step.id, true);
                    results.push(result);
                }
                Err(e) => {
                    error!("Step {} failed: {}", step.name, e);
                    step.status = StepStatus::Failed;
                    completed_steps.insert(step.id, false);
                }
            }
        }

        // Update workflow status
        let all_completed = workflow
            .steps
            .iter()
            .all(|s| s.status == StepStatus::Completed || s.status == StepStatus::Skipped);

        workflow.status = if all_completed {
            WorkflowStatus::Completed
        } else {
            WorkflowStatus::Failed
        };
        workflow.completed_at = Some(Utc::now());

        info!("Workflow {} completed with {} results", workflow.name, results.len());

        Ok(results)
    }

    /// Create a comprehensive security analysis workflow
    pub fn create_security_workflow(&self, target: AnalysisTarget) -> Workflow {
        let workflow_id = Uuid::new_v4();
        let mut steps = Vec::new();

        // Step 1: Static Analysis
        steps.push(WorkflowStep {
            id: Uuid::new_v4(),
            name: "Static Analysis".to_string(),
            agent_type: AgentType::Static,
            capabilities: vec![AgentCapability::StaticAnalysis],
            depends_on: vec![],
            status: StepStatus::Pending,
            result: None,
        });

        // Step 2: Crypto Analysis (can run in parallel with static)
        steps.push(WorkflowStep {
            id: Uuid::new_v4(),
            name: "Crypto Analysis".to_string(),
            agent_type: AgentType::Crypto,
            capabilities: vec![AgentCapability::CryptoAnalysis],
            depends_on: vec![],
            status: StepStatus::Pending,
            result: None,
        });

        // Step 3: Network Analysis (can run in parallel)
        steps.push(WorkflowStep {
            id: Uuid::new_v4(),
            name: "Network Analysis".to_string(),
            agent_type: AgentType::Network,
            capabilities: vec![AgentCapability::NetworkAnalysis],
            depends_on: vec![],
            status: StepStatus::Pending,
            result: None,
        });

        // Step 4: Dynamic Analysis (depends on static analysis)
        let static_step_id = steps[0].id;
        steps.push(WorkflowStep {
            id: Uuid::new_v4(),
            name: "Dynamic Analysis".to_string(),
            agent_type: AgentType::Dynamic,
            capabilities: vec![AgentCapability::DynamicAnalysis],
            depends_on: vec![static_step_id],
            status: StepStatus::Pending,
            result: None,
        });

        // Step 5: Correlation and Risk Scoring (depends on all previous)
        let all_step_ids: Vec<_> = steps.iter().map(|s| s.id).collect();
        steps.push(WorkflowStep {
            id: Uuid::new_v4(),
            name: "Correlation and Risk Scoring".to_string(),
            agent_type: AgentType::Orchestrator,
            capabilities: vec![AgentCapability::Correlation, AgentCapability::RiskScoring],
            depends_on: all_step_ids,
            status: StepStatus::Pending,
            result: None,
        });

        Workflow {
            id: workflow_id,
            name: "Comprehensive Security Analysis".to_string(),
            description: Some("Performs static, crypto, network, and dynamic analysis with correlation".to_string()),
            steps,
            status: WorkflowStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        }
    }

    /// Start the task processor
    #[instrument(skip(self))]
    pub async fn start_task_processor(&self) {
        info!("Starting task processor");

        let task_queue = self.task_queue.clone();
        let agents = self.agents.clone();
        let active_tasks = self.active_tasks.clone();
        let task_results = self.task_results.clone();
        let semaphore = self.task_semaphore.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));

            loop {
                interval.tick().await;

                // Check shutdown signal
                if *shutdown_signal.read().await {
                    break;
                }

                // Process tasks from queue
                let task = {
                    let mut queue = task_queue.lock().await;
                    queue.pop_front()
                };

                if let Some(task) = task {
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    let agents = agents.clone();
                    let active_tasks = active_tasks.clone();
                    let task_results = task_results.clone();

                    tokio::spawn(async move {
                        let _permit = permit; // Keep permit alive for duration of task

                        // Get agent
                        if let Some(agent) = agents.get(&task.agent_id) {
                            active_tasks.insert(task.id, task.clone());

                            // Create context and execute
                            let context = AgentContext::new(task.id, task.job_id, task.target.clone());

                            match agent.execute(context).await {
                                Ok(result) => {
                                    task_results.insert(task.id, result);
                                }
                                Err(e) => {
                                    error!("Task {} failed: {}", task.id, e);
                                }
                            }

                            active_tasks.remove(&task.id);
                        }
                    });
                }
            }
        });

        info!("Task processor started");
    }

    /// Start health monitoring
    #[instrument(skip(self))]
    pub async fn start_health_monitor(&self) {
        info!("Starting health monitor");

        let agents = self.agents.clone();
        let agent_health = self.agent_health.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Check shutdown signal
                if *shutdown_signal.read().await {
                    break;
                }

                // Update health for all agents
                for entry in agents.iter() {
                    let agent_id = *entry.key();
                    let agent = entry.value();

                    match agent.health().await {
                        health => {
                            agent_health.insert(agent_id, health);
                        }
                    }
                }
            }
        });

        info!("Health monitor started");
    }

    /// Get health status for all agents
    pub fn get_all_health(&self) -> Vec<AgentHealth> {
        self.agent_health
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get task result
    pub fn get_task_result(&self, task_id: Uuid) -> Option<AgentResult> {
        self.task_results.get(&task_id).map(|r| r.clone())
    }

    /// Get active tasks
    pub fn get_active_tasks(&self) -> Vec<AgentTask> {
        self.active_tasks
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get queue length
    pub async fn get_queue_length(&self) -> usize {
        let queue = self.task_queue.lock().await;
        queue.len()
    }

    /// Create an agent team
    pub fn create_team(&self, name: impl Into<String>) -> Uuid {
        let team_id = Uuid::new_v4();
        let team = AgentTeam::new(name);

        self.teams.insert(team_id, team);
        team_id
    }

    /// Add agent to team
    pub fn add_agent_to_team(&self, team_id: Uuid, agent_id: AgentId, role: TeamRole) -> Result<()> {
        let mut team = self
            .teams
            .get_mut(&team_id)
            .ok_or_else(|| AgentError::InvalidConfig("Team not found".to_string()))?;

        match role {
            TeamRole::Architect => team.architect = Some(agent_id),
            TeamRole::Manager => team.managers.push(agent_id),
            TeamRole::Engineer => team.engineers.push(agent_id),
        }

        Ok(())
    }

    /// Shutdown the orchestrator
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down orchestrator");

        // Signal shutdown
        {
            let mut shutdown = self.shutdown_signal.write().await;
            *shutdown = true;
        }

        // Shutdown all agents
        for entry in self.agents.iter() {
            let agent_id = *entry.key();
            info!("Shutting down agent: {}", agent_id);
            // Note: In a real implementation, we'd need mutable access to shutdown
            // This is simplified for the example
        }

        self.base.set_status(AgentStatus::Offline);
        info!("Orchestrator shutdown complete");

        Ok(())
    }
}

/// Team roles
#[derive(Debug, Clone, Copy)]
pub enum TeamRole {
    Architect,
    Manager,
    Engineer,
}

#[async_trait]
impl SecurityAgent for AgentOrchestrator {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Orchestrator
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        unsafe { &*(self.base.config.read().unwrap() as *const AgentConfig) }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing AgentOrchestrator: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        // Start background tasks
        self.start_task_processor().await;
        self.start_health_monitor().await;

        info!("AgentOrchestrator initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "Orchestrator executing task: {} on target: {}",
            context.task_id, context.target.path
        );

        self.base.set_status(AgentStatus::Busy);
        self.base.update_heartbeat();

        // Create and execute a comprehensive workflow
        let mut workflow = self.create_security_workflow(context.target.clone());

        let result = match self.execute_workflow(&mut workflow).await {
            Ok(results) => {
                // Aggregate findings from all steps
                let mut all_findings = Vec::new();
                for r in &results {
                    all_findings.extend(r.findings.findings.clone());
                }

                let findings = FindingCollection::new(all_findings);

                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "Orchestrator completed task: {} with {} findings",
                    context.task_id,
                    findings.total_count
                );

                AgentResult::success(
                    context.task_id,
                    self.base.id,
                    findings,
                    start_time.elapsed().as_millis() as u64,
                )
            }
            Err(e) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!(
                    "Orchestrator failed task: {} with error: {}",
                    context.task_id, e
                );

                AgentResult::failed(context.task_id, self.base.id, e.to_string())
            }
        };

        Ok(result)
    }

    async fn health(&self) -> AgentHealth {
        self.base.get_health()
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.shutdown().await
    }

    fn update_heartbeat(&self) {
        self.base.update_heartbeat();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_agent::StaticAgent;

    #[test]
    fn test_orchestrator_creation() {
        let orchestrator = AgentOrchestrator::new("Test Orchestrator");

        assert_eq!(orchestrator.name(), "Test Orchestrator");
        assert_eq!(orchestrator.agent_type(), AgentType::Orchestrator);
        assert!(orchestrator.agents.is_empty());
    }

    #[tokio::test]
    async fn test_orchestrator_initialization() {
        let mut orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let config = AgentConfig::default().with_timeout(600);

        assert!(orchestrator.initialize(config).await.is_ok());
        assert_eq!(orchestrator.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_agent_registration() {
        let mut orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let config = AgentConfig::default();
        orchestrator.initialize(config).await.unwrap();

        let agent = Arc::new(StaticAgent::new("Test Static Agent"));
        let agent_id = agent.id();

        assert!(orchestrator.register_agent(agent).await.is_ok());
        assert_eq!(orchestrator.get_agents().len(), 1);
        assert!(orchestrator.get_agents().contains(&agent_id));
    }

    #[tokio::test]
    async fn test_agent_deregistration() {
        let mut orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let config = AgentConfig::default();
        orchestrator.initialize(config).await.unwrap();

        let agent = Arc::new(StaticAgent::new("Test Static Agent"));
        let agent_id = agent.id();

        orchestrator.register_agent(agent).await.unwrap();
        assert_eq!(orchestrator.get_agents().len(), 1);

        assert!(orchestrator.deregister_agent(agent_id).await.is_ok());
        assert!(orchestrator.get_agents().is_empty());
    }

    #[tokio::test]
    async fn test_get_agents_by_type() {
        let mut orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let config = AgentConfig::default();
        orchestrator.initialize(config).await.unwrap();

        let agent = Arc::new(StaticAgent::new("Test Static Agent"));
        orchestrator.register_agent(agent).await.unwrap();

        let static_agents = orchestrator.get_agents_by_type(AgentType::Static);
        assert_eq!(static_agents.len(), 1);

        let dynamic_agents = orchestrator.get_agents_by_type(AgentType::Dynamic);
        assert!(dynamic_agents.is_empty());
    }

    #[test]
    fn test_create_security_workflow() {
        let orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);

        let workflow = orchestrator.create_security_workflow(target);

        assert_eq!(workflow.name, "Comprehensive Security Analysis");
        assert_eq!(workflow.steps.len(), 5);
        assert_eq!(workflow.status, WorkflowStatus::Pending);
    }

    #[test]
    fn test_workflow_step_dependencies() {
        let orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);

        let workflow = orchestrator.create_security_workflow(target);

        // Dynamic analysis should depend on static analysis
        let dynamic_step = workflow.steps.iter().find(|s| s.agent_type == AgentType::Dynamic);
        let static_step = workflow.steps.iter().find(|s| s.agent_type == AgentType::Static);

        assert!(dynamic_step.is_some());
        assert!(static_step.is_some());
        assert!(dynamic_step.unwrap().depends_on.contains(&static_step.unwrap().id));
    }

    #[tokio::test]
    async fn test_create_team() {
        let orchestrator = AgentOrchestrator::new("Test Orchestrator");
        let team_id = orchestrator.create_team("Security Team");

        assert!(!team_id.to_string().is_empty());
    }
}
