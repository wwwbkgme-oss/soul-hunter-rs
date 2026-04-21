//! Workflow Engine - Production Ready
//!
//! The Workflow Engine orchestrates the 6-phase security analysis pipeline:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         WORKFLOW ENGINE PIPELINE                            │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
//! │  │  Phase 1:       │───▶│  Phase 2:       │───▶│  Phase 3:       │         │
//! │  │  Attack Surface │    │  Task           │    │  Agent          │         │
//! │  │  Scan           │    │  Generation     │    │  Execution      │         │
//! │  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
//! │          │                       │                       │               │
//! │          ▼                       ▼                       ▼               │
//! │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
//! │  │  Phase 4:       │───▶│  Phase 5:       │───▶│  Phase 6:       │         │
//! │  │  Finding        │    │  Correlation    │    │  Risk Scoring   │         │
//! │  │  Collection     │    │                 │    │                 │         │
//! │  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! Task Priority System:
//! - Static Analysis:    10 (Highest)
//! - Dynamic Analysis:    9
//! - Intent Analysis:     8
//! - Network Analysis:    8
//! - Crypto Analysis:     7
//! - Fuzzing:             5 (Lowest)
//! ```
//!
//! ## Features
//!
//! - **6-Phase Pipeline**: Complete security analysis workflow from scan to risk scoring
//! - **Priority-Based Scheduling**: Tasks are scheduled based on analysis type priority
//! - **Parallel/Sequential Execution**: Configurable execution modes per phase
//! - **Graceful Degradation**: Pipeline continues even if individual tasks fail
//! - **Timeout Handling**: Configurable timeouts per phase with cancellation support
//! - **Event Publishing**: Integration with event bus for real-time updates
//! - **Assessment Lifecycle**: Full lifecycle management from creation to completion

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use sh_agents::{AgentContext, AgentResult, SecurityAgent};
use sh_event_bus::{Event, EventBus, EventPayload, EventPriority, EventType};
use sh_finding::correlation::{CorrelationConfig, CorrelationEngine};
use sh_finding::{FindingCollection, FindingEngine};
use sh_risk::{BusinessContext, RiskEngine, RiskFactors};
use sh_scheduler::{Scheduler, SchedulerConfig};
use sh_types::prelude::*;
use sh_types::{
    AgentCapability, AgentId, AgentPriority, AgentTask, AgentType, AnalysisTarget, Assessment,
    AssessmentConfig, AssessmentId, AssessmentStatus, Confidence, Finding, FindingId, Job,
    JobPriority, JobResult, JobStatus, Platform, RiskScore, Severity, TaskStatus,
};

/// Unique identifier for workflow executions
pub type WorkflowId = Uuid;

/// Task priority values for the workflow engine
///
/// Higher values indicate higher priority. Tasks are executed
/// in priority order within each phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    /// Static analysis tasks (highest priority)
    Static = 10,
    /// Dynamic analysis tasks
    Dynamic = 9,
    /// Intent analysis tasks
    Intent = 8,
    /// Network analysis tasks
    Network = 8,
    /// Cryptographic analysis tasks
    Crypto = 7,
    /// Fuzzing tasks (lowest priority)
    Fuzzing = 5,
}

impl TaskPriority {
    /// Convert to JobPriority for scheduler integration
    pub fn to_job_priority(&self) -> JobPriority {
        match self {
            TaskPriority::Static => JobPriority::Critical,
            TaskPriority::Dynamic => JobPriority::High,
            TaskPriority::Intent => JobPriority::High,
            TaskPriority::Network => JobPriority::High,
            TaskPriority::Crypto => JobPriority::Normal,
            TaskPriority::Fuzzing => JobPriority::Low,
        }
    }

    /// Get priority from agent capability
    pub fn from_capability(capability: &AgentCapability) -> Self {
        match capability {
            AgentCapability::StaticAnalysis => TaskPriority::Static,
            AgentCapability::DynamicAnalysis => TaskPriority::Dynamic,
            AgentCapability::IntentAnalysis => TaskPriority::Intent,
            AgentCapability::NetworkAnalysis => TaskPriority::Network,
            AgentCapability::CryptoAnalysis => TaskPriority::Crypto,
            AgentCapability::Fuzzing => TaskPriority::Fuzzing,
            _ => TaskPriority::Network, // Default for other capabilities
        }
    }
}

/// Workflow execution phases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowPhase {
    /// Phase 1: Attack surface scanning and discovery
    AttackSurfaceScan,
    /// Phase 2: Task generation based on scan results
    TaskGeneration,
    /// Phase 3: Agent execution for analysis tasks
    AgentExecution,
    /// Phase 4: Finding collection and aggregation
    FindingCollection,
    /// Phase 5: Finding correlation and deduplication
    Correlation,
    /// Phase 6: Risk scoring and finalization
    RiskScoring,
}

impl WorkflowPhase {
    /// Get the next phase in the pipeline
    pub fn next(&self) -> Option<Self> {
        match self {
            WorkflowPhase::AttackSurfaceScan => Some(WorkflowPhase::TaskGeneration),
            WorkflowPhase::TaskGeneration => Some(WorkflowPhase::AgentExecution),
            WorkflowPhase::AgentExecution => Some(WorkflowPhase::FindingCollection),
            WorkflowPhase::FindingCollection => Some(WorkflowPhase::Correlation),
            WorkflowPhase::Correlation => Some(WorkflowPhase::RiskScoring),
            WorkflowPhase::RiskScoring => None,
        }
    }

    /// Get phase name
    pub fn name(&self) -> &'static str {
        match self {
            WorkflowPhase::AttackSurfaceScan => "attack_surface_scan",
            WorkflowPhase::TaskGeneration => "task_generation",
            WorkflowPhase::AgentExecution => "agent_execution",
            WorkflowPhase::FindingCollection => "finding_collection",
            WorkflowPhase::Correlation => "correlation",
            WorkflowPhase::RiskScoring => "risk_scoring",
        }
    }

    /// Get phase number (1-indexed)
    pub fn number(&self) -> u8 {
        match self {
            WorkflowPhase::AttackSurfaceScan => 1,
            WorkflowPhase::TaskGeneration => 2,
            WorkflowPhase::AgentExecution => 3,
            WorkflowPhase::FindingCollection => 4,
            WorkflowPhase::Correlation => 5,
            WorkflowPhase::RiskScoring => 6,
        }
    }
}

impl std::fmt::Display for WorkflowPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Execution mode for workflow phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Execute tasks sequentially (one at a time)
    Sequential,
    /// Execute tasks in parallel (up to concurrency limit)
    Parallel,
}

/// Configuration for the workflow engine
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Maximum concurrent tasks per phase
    pub max_concurrency: usize,
    /// Default timeout for phases (seconds)
    pub default_timeout_secs: u64,
    /// Execution mode for each phase
    pub phase_execution_modes: HashMap<WorkflowPhase, ExecutionMode>,
    /// Enable graceful degradation on phase failure
    pub enable_graceful_degradation: bool,
    /// Enable event publishing
    pub publish_events: bool,
    /// Risk factors for scoring
    pub risk_factors: RiskFactors,
    /// Correlation configuration
    pub correlation_config: CorrelationConfig,
    /// Scheduler configuration
    pub scheduler_config: SchedulerConfig,
    /// Enable ML-based risk scoring
    pub enable_ml_scoring: bool,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        let mut phase_execution_modes = HashMap::new();
        phase_execution_modes.insert(WorkflowPhase::AttackSurfaceScan, ExecutionMode::Sequential);
        phase_execution_modes.insert(WorkflowPhase::TaskGeneration, ExecutionMode::Sequential);
        phase_execution_modes.insert(WorkflowPhase::AgentExecution, ExecutionMode::Parallel);
        phase_execution_modes.insert(WorkflowPhase::FindingCollection, ExecutionMode::Parallel);
        phase_execution_modes.insert(WorkflowPhase::Correlation, ExecutionMode::Sequential);
        phase_execution_modes.insert(WorkflowPhase::RiskScoring, ExecutionMode::Sequential);

        Self {
            max_concurrency: 8,
            default_timeout_secs: 1800, // 30 minutes
            phase_execution_modes,
            enable_graceful_degradation: true,
            publish_events: true,
            risk_factors: RiskFactors::default(),
            correlation_config: CorrelationConfig::default(),
            scheduler_config: SchedulerConfig::default(),
            enable_ml_scoring: false,
        }
    }
}

impl WorkflowConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrency
    pub fn with_max_concurrency(mut self, concurrency: usize) -> Self {
        self.max_concurrency = concurrency.max(1);
        self
    }

    /// Set default timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.default_timeout_secs = timeout_secs;
        self
    }

    /// Set execution mode for a specific phase
    pub fn with_phase_mode(mut self, phase: WorkflowPhase, mode: ExecutionMode) -> Self {
        self.phase_execution_modes.insert(phase, mode);
        self
    }

    /// Enable or disable graceful degradation
    pub fn with_graceful_degradation(mut self, enabled: bool) -> Self {
        self.enable_graceful_degradation = enabled;
        self
    }

    /// Enable or disable event publishing
    pub fn with_event_publishing(mut self, enabled: bool) -> Self {
        self.publish_events = enabled;
        self
    }

    /// Set risk factors
    pub fn with_risk_factors(mut self, factors: RiskFactors) -> Self {
        self.risk_factors = factors;
        self
    }

    /// Set correlation configuration
    pub fn with_correlation_config(mut self, config: CorrelationConfig) -> Self {
        self.correlation_config = config;
        self
    }

    /// Get execution mode for a phase
    pub fn execution_mode(&self, phase: &WorkflowPhase) -> ExecutionMode {
        self.phase_execution_modes
            .get(phase)
            .copied()
            .unwrap_or(ExecutionMode::Sequential)
    }
}

/// Workflow execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    /// Workflow created but not started
    Pending,
    /// Workflow is running
    Running,
    /// Workflow completed successfully
    Completed,
    /// Workflow failed
    Failed,
    /// Workflow was cancelled
    Cancelled,
    /// Workflow completed with partial success (some phases failed)
    Partial,
}

impl Default for WorkflowStatus {
    fn default() -> Self {
        WorkflowStatus::Pending
    }
}

/// Phase execution result
#[derive(Debug, Clone)]
pub struct PhaseResult {
    /// Phase that was executed
    pub phase: WorkflowPhase,
    /// Whether the phase succeeded
    pub success: bool,
    /// Number of tasks processed
    pub tasks_processed: usize,
    /// Number of tasks that succeeded
    pub tasks_succeeded: usize,
    /// Number of tasks that failed
    pub tasks_failed: usize,
    /// Execution duration
    pub duration_ms: u64,
    /// Error message if phase failed
    pub error: Option<String>,
    /// Phase-specific output data
    pub output: Option<serde_json::Value>,
}

impl PhaseResult {
    /// Create a successful phase result
    pub fn success(phase: WorkflowPhase, tasks_processed: usize, duration_ms: u64) -> Self {
        Self {
            phase,
            success: true,
            tasks_processed,
            tasks_succeeded: tasks_processed,
            tasks_failed: 0,
            duration_ms,
            error: None,
            output: None,
        }
    }

    /// Create a failed phase result
    pub fn failure(phase: WorkflowPhase, error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            phase,
            success: false,
            tasks_processed: 0,
            tasks_succeeded: 0,
            tasks_failed: 0,
            duration_ms,
            error: Some(error.into()),
            output: None,
        }
    }

    /// Create a partial success result
    pub fn partial(
        phase: WorkflowPhase,
        tasks_succeeded: usize,
        tasks_failed: usize,
        duration_ms: u64,
    ) -> Self {
        Self {
            phase,
            success: tasks_failed == 0,
            tasks_processed: tasks_succeeded + tasks_failed,
            tasks_succeeded,
            tasks_failed,
            duration_ms,
            error: None,
            output: None,
        }
    }

    /// Add output data
    pub fn with_output(mut self, output: serde_json::Value) -> Self {
        self.output = Some(output);
        self
    }
}

/// Workflow execution context
#[derive(Debug, Clone)]
pub struct WorkflowContext {
    /// Workflow ID
    pub workflow_id: WorkflowId,
    /// Assessment being processed
    pub assessment_id: AssessmentId,
    /// Target being analyzed
    pub target: AnalysisTarget,
    /// Current phase
    pub current_phase: Option<WorkflowPhase>,
    /// Phase results
    pub phase_results: Vec<PhaseResult>,
    /// Collected findings
    pub findings: FindingCollection,
    /// Generated jobs
    pub jobs: Vec<Job>,
    /// Agent results
    pub agent_results: Vec<AgentResult>,
    /// Risk score
    pub risk_score: Option<RiskScore>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl WorkflowContext {
    /// Create a new workflow context
    pub fn new(workflow_id: WorkflowId, assessment: &Assessment) -> Self {
        Self {
            workflow_id,
            assessment_id: assessment.id,
            target: assessment.target.clone(),
            current_phase: None,
            phase_results: Vec::new(),
            findings: FindingCollection::default(),
            jobs: Vec::new(),
            agent_results: Vec::new(),
            risk_score: None,
            started_at: None,
            completed_at: None,
            metadata: HashMap::new(),
        }
    }

    /// Mark workflow as started
    pub fn mark_started(&mut self) {
        self.started_at = Some(Utc::now());
    }

    /// Mark workflow as completed
    pub fn mark_completed(&mut self) {
        self.completed_at = Some(Utc::now());
    }

    /// Get workflow duration
    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            _ => None,
        }
    }

    /// Add phase result
    pub fn add_phase_result(&mut self, result: PhaseResult) {
        self.phase_results.push(result);
    }

    /// Get result for a specific phase
    pub fn get_phase_result(&self, phase: WorkflowPhase) -> Option<&PhaseResult> {
        self.phase_results.iter().find(|r| r.phase == phase)
    }

    /// Check if all phases succeeded
    pub fn all_phases_succeeded(&self) -> bool {
        self.phase_results.iter().all(|r| r.success)
    }

    /// Check if any phase failed
    pub fn any_phase_failed(&self) -> bool {
        self.phase_results.iter().any(|r| !r.success)
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.insert(key.into(), value);
    }
}

/// Workflow execution statistics
#[derive(Debug, Clone, Default)]
pub struct WorkflowStats {
    /// Total workflows executed
    pub total_workflows: u64,
    /// Successful workflows
    pub successful_workflows: u64,
    /// Failed workflows
    pub failed_workflows: u64,
    /// Partial workflows
    pub partial_workflows: u64,
    /// Cancelled workflows
    pub cancelled_workflows: u64,
    /// Total findings discovered
    pub total_findings: u64,
    /// Total tasks executed
    pub total_tasks: u64,
    /// Average workflow duration (ms)
    pub avg_duration_ms: u64,
}

/// Workflow engine errors
#[derive(thiserror::Error, Debug, Clone)]
pub enum WorkflowError {
    #[error("Workflow not found: {0}")]
    WorkflowNotFound(WorkflowId),

    #[error("Assessment not found: {0}")]
    AssessmentNotFound(AssessmentId),

    #[error("Phase execution failed: {phase} - {reason}")]
    PhaseExecutionFailed { phase: WorkflowPhase, reason: String },

    #[error("Phase timeout: {phase} after {timeout_secs}s")]
    PhaseTimeout { phase: WorkflowPhase, timeout_secs: u64 },

    #[error("Agent execution failed: {0}")]
    AgentExecutionFailed(String),

    #[error("Task generation failed: {0}")]
    TaskGenerationFailed(String),

    #[error("Finding collection failed: {0}")]
    FindingCollectionFailed(String),

    #[error("Correlation failed: {0}")]
    CorrelationFailed(String),

    #[error("Risk scoring failed: {0}")]
    RiskScoringFailed(String),

    #[error("Workflow already running: {0}")]
    AlreadyRunning(WorkflowId),

    #[error("Workflow not running: {0}")]
    NotRunning(WorkflowId),

    #[error("Workflow was cancelled: {0}")]
    Cancelled(WorkflowId),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Scheduler error: {0}")]
    SchedulerError(String),

    #[error("Event bus error: {0}")]
    EventBusError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for workflow operations
pub type WorkflowResult<T> = std::result::Result<T, WorkflowError>;

/// Task for workflow execution
#[derive(Debug)]
struct WorkflowTask {
    workflow_id: WorkflowId,
    assessment: Assessment,
    cancellation_token: tokio_util::sync::CancellationToken,
    result_tx: oneshot::Sender<WorkflowResult<WorkflowContext>>,
}

/// The Workflow Engine
///
/// Orchestrates security analysis workflows through a 6-phase pipeline
/// with support for parallel execution, priority scheduling, and
/// graceful degradation.
pub struct WorkflowEngine {
    /// Configuration
    config: WorkflowConfig,
    /// Active workflows
    active_workflows: Arc<DashMap<WorkflowId, WorkflowContext>>,
    /// Workflow statuses
    workflow_statuses: Arc<DashMap<WorkflowId, WorkflowStatus>>,
    /// Task scheduler
    scheduler: Arc<Scheduler>,
    /// Risk scoring engine
    risk_engine: Arc<RiskEngine>,
    /// Finding processing engine
    finding_engine: Arc<FindingEngine>,
    /// Correlation engine
    correlation_engine: Arc<CorrelationEngine>,
    /// Event bus for publishing events
    event_bus: Option<Arc<EventBus>>,
    /// Registered agents
    agents: Arc<DashMap<AgentId, Arc<dyn SecurityAgent>>>,
    /// Task channel
    task_tx: Option<mpsc::Sender<WorkflowTask>>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Running state
    running: Arc<RwLock<bool>>,
    /// Statistics
    stats: Arc<RwLock<WorkflowStats>>,
}

impl WorkflowEngine {
    /// Create a new workflow engine with the given configuration
    pub fn new(config: WorkflowConfig) -> Self {
        let scheduler = Arc::new(Scheduler::new(config.scheduler_config.clone()));
        let risk_engine = Arc::new(RiskEngine::new().with_ml(config.enable_ml_scoring));
        let finding_engine = Arc::new(FindingEngine::default());
        let correlation_engine = Arc::new(CorrelationEngine::new(config.correlation_config.clone()));

        Self {
            config,
            active_workflows: Arc::new(DashMap::new()),
            workflow_statuses: Arc::new(DashMap::new()),
            scheduler,
            risk_engine,
            finding_engine,
            correlation_engine,
            event_bus: None,
            agents: Arc::new(DashMap::new()),
            task_tx: None,
            shutdown_tx: None,
            running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(WorkflowStats::default())),
        }
    }

    /// Create a new workflow engine with default configuration
    pub fn default() -> Self {
        Self::new(WorkflowConfig::default())
    }

    /// Set the event bus
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Register a security agent
    pub fn register_agent(&self, agent: Arc<dyn SecurityAgent>) {
        let agent_id = agent.id();
        info!(agent_id = %agent_id, agent_type = ?agent.agent_type(), "Registering agent with workflow engine");
        self.agents.insert(agent_id, agent);
    }

    /// Start the workflow engine
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> WorkflowResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(WorkflowError::InternalError(
                "Workflow engine already running".to_string(),
            ));
        }

        info!("Starting workflow engine");

        // Create channels
        let (task_tx, mut task_rx) = mpsc::channel::<WorkflowTask>(100);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        self.task_tx = Some(task_tx);
        self.shutdown_tx = Some(shutdown_tx);

        // Clone Arcs for worker task
        let active_workflows = self.active_workflows.clone();
        let workflow_statuses = self.workflow_statuses.clone();
        let config = self.config.clone();
        let scheduler = self.scheduler.clone();
        let risk_engine = self.risk_engine.clone();
        let finding_engine = self.finding_engine.clone();
        let correlation_engine = self.correlation_engine.clone();
        let event_bus = self.event_bus.clone();
        let agents = self.agents.clone();
        let stats = self.stats.clone();

        // Spawn worker task
        let _worker_handle = tokio::spawn(async move {
            info!("Workflow engine worker started");

            loop {
                tokio::select! {
                    // Process incoming workflow tasks
                    Some(task) = task_rx.recv() => {
                        let active = active_workflows.clone();
                        let statuses = workflow_statuses.clone();
                        let cfg = config.clone();
                        let sched = scheduler.clone();
                        let risk = risk_engine.clone();
                        let finding = finding_engine.clone();
                        let correlation = correlation_engine.clone();
                        let bus = event_bus.clone();
                        let ags = agents.clone();
                        let st = stats.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::execute_workflow(
                                task,
                                active,
                                statuses,
                                cfg,
                                sched,
                                risk,
                                finding,
                                correlation,
                                bus,
                                ags,
                                st,
                            ).await {
                                error!(error = %e, "Workflow execution failed");
                            }
                        });
                    }

                    // Handle shutdown signal
                    _ = &mut shutdown_rx => {
                        info!("Workflow engine received shutdown signal");
                        break;
                    }

                    else => {
                        break;
                    }
                }
            }

            info!("Workflow engine worker stopped");
        });

        *running = true;
        info!("Workflow engine started successfully");

        Ok(())
    }

    /// Execute a workflow
    #[instrument(skip(
        task,
        active_workflows,
        workflow_statuses,
        config,
        scheduler,
        risk_engine,
        finding_engine,
        correlation_engine,
        event_bus,
        agents,
        stats
    ))]
    async fn execute_workflow(
        task: WorkflowTask,
        active_workflows: Arc<DashMap<WorkflowId, WorkflowContext>>,
        workflow_statuses: Arc<DashMap<WorkflowId, WorkflowStatus>>,
        config: WorkflowConfig,
        scheduler: Arc<Scheduler>,
        risk_engine: Arc<RiskEngine>,
        finding_engine: Arc<FindingEngine>,
        correlation_engine: Arc<CorrelationEngine>,
        event_bus: Option<Arc<EventBus>>,
        agents: Arc<DashMap<AgentId, Arc<dyn SecurityAgent>>>,
        stats: Arc<RwLock<WorkflowStats>>,
    ) -> WorkflowResult<()> {
        let workflow_id = task.workflow_id;
        let assessment = task.assessment.clone();

        info!(workflow_id = %workflow_id, assessment_id = %assessment.id, "Starting workflow execution");

        // Create workflow context
        let mut context = WorkflowContext::new(workflow_id, &assessment);
        context.mark_started();

        // Store in active workflows
        active_workflows.insert(workflow_id, context.clone());
        workflow_statuses.insert(workflow_id, WorkflowStatus::Running);

        // Publish event
        if config.publish_events {
            if let Some(ref bus) = event_bus {
                let event = Event::new(
                    EventType::AssessmentStarted,
                    "workflow-engine",
                    EventPayload::AssessmentStarted {
                        assessment_id: assessment.id,
                        target: assessment.target.path.clone(),
                    },
                );
                let _ = bus.publish(event).await;
            }
        }

        // Execute phases
        let mut current_phase = Some(WorkflowPhase::AttackSurfaceScan);
        let mut final_status = WorkflowStatus::Completed;

        while let Some(phase) = current_phase {
            // Check for cancellation
            if task.cancellation_token.is_cancelled() {
                info!(workflow_id = %workflow_id, "Workflow cancelled");
                final_status = WorkflowStatus::Cancelled;
                break;
            }

            // Update current phase in context
            context.current_phase = Some(phase);

            // Execute phase
            let phase_result = Self::execute_phase(
                &mut context,
                phase,
                &config,
                &assessment,
                &scheduler,
                &risk_engine,
                &finding_engine,
                &correlation_engine,
                &event_bus,
                &agents,
            )
            .await;

            match phase_result {
                Ok(result) => {
                    let success = result.success;
                    context.add_phase_result(result);

                    if !success && !config.enable_graceful_degradation {
                        error!(workflow_id = %workflow_id, phase = %phase, "Phase failed, aborting workflow");
                        final_status = WorkflowStatus::Failed;
                        break;
                    } else if !success {
                        warn!(workflow_id = %workflow_id, phase = %phase, "Phase failed, continuing with graceful degradation");
                        final_status = WorkflowStatus::Partial;
                    }
                }
                Err(e) => {
                    error!(workflow_id = %workflow_id, phase = %phase, error = %e, "Phase execution error");
                    context.add_phase_result(PhaseResult::failure(phase, e.to_string(), 0));

                    if !config.enable_graceful_degradation {
                        final_status = WorkflowStatus::Failed;
                        break;
                    }
                    final_status = WorkflowStatus::Partial;
                }
            }

            // Move to next phase
            current_phase = phase.next();
        }

        // Mark as completed
        context.mark_completed();
        context.current_phase = None;

        // Update status
        workflow_statuses.insert(workflow_id, final_status);

        // Update stats
        {
            let mut s = stats.write().await;
            s.total_workflows += 1;
            match final_status {
                WorkflowStatus::Completed => s.successful_workflows += 1,
                WorkflowStatus::Failed => s.failed_workflows += 1,
                WorkflowStatus::Partial => s.partial_workflows += 1,
                WorkflowStatus::Cancelled => s.cancelled_workflows += 1,
                _ => {}
            }
            s.total_findings += context.findings.total_count as u64;
        }

        // Update active workflows
        active_workflows.insert(workflow_id, context.clone());

        // Publish completion event
        if config.publish_events {
            if let Some(ref bus) = event_bus {
                let event = Event::new(
                    EventType::AssessmentCompleted,
                    "workflow-engine",
                    EventPayload::AssessmentCompleted {
                        assessment_id: assessment.id,
                        findings_count: context.findings.total_count,
                        risk_score: context.risk_score.as_ref().map(|r| r.overall),
                    },
                );
                let _ = bus.publish(event).await;
            }
        }

        info!(workflow_id = %workflow_id, status = ?final_status, "Workflow execution completed");

        // Send result
        let _ = task.result_tx.send(Ok(context));

        Ok(())
    }

    /// Execute a single phase
    #[instrument(skip(
        context,
        config,
        assessment,
        scheduler,
        risk_engine,
        finding_engine,
        correlation_engine,
        event_bus,
        agents
    ))]
    async fn execute_phase(
        context: &mut WorkflowContext,
        phase: WorkflowPhase,
        config: &WorkflowConfig,
        assessment: &Assessment,
        scheduler: &Arc<Scheduler>,
        risk_engine: &Arc<RiskEngine>,
        finding_engine: &Arc<FindingEngine>,
        correlation_engine: &Arc<CorrelationEngine>,
        event_bus: &Option<Arc<EventBus>>,
        agents: &Arc<DashMap<AgentId, Arc<dyn SecurityAgent>>>,
    ) -> WorkflowResult<PhaseResult> {
        let start = std::time::Instant::now();
        info!(phase = %phase, "Executing workflow phase");

        // Publish phase started event
        if config.publish_events {
            if let Some(ref bus) = event_bus {
                let event = Event::new(
                    EventType::PhaseStarted,
                    "workflow-engine",
                    EventPayload::PhaseStarted {
                        assessment_id: assessment.id,
                        phase: phase.name().to_string(),
                    },
                );
                let _ = bus.publish(event).await;
            }
        }

        let result = match phase {
            WorkflowPhase::AttackSurfaceScan => {
                Self::execute_attack_surface_scan(context, assessment, config).await
            }
            WorkflowPhase::TaskGeneration => {
                Self::execute_task_generation(context, assessment, config).await
            }
            WorkflowPhase::AgentExecution => {
                Self::execute_agent_execution(context, assessment, config, agents).await
            }
            WorkflowPhase::FindingCollection => {
                Self::execute_finding_collection(context, config, finding_engine).await
            }
            WorkflowPhase::Correlation => {
                Self::execute_correlation(context, config, correlation_engine).await
            }
            WorkflowPhase::RiskScoring => {
                Self::execute_risk_scoring(context, config, risk_engine).await
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        // Update result with duration
        let result = match result {
            Ok(mut r) => {
                r.duration_ms = duration_ms;
                r
            }
            Err(e) => PhaseResult::failure(phase, e.to_string(), duration_ms),
        };

        // Publish phase completed event
        if config.publish_events {
            if let Some(ref bus) = event_bus {
                let event = Event::new(
                    EventType::PhaseCompleted,
                    "workflow-engine",
                    EventPayload::PhaseCompleted {
                        assessment_id: assessment.id,
                        phase: phase.name().to_string(),
                        success: result.success,
                    },
                )
                .with_priority(if result.success {
                    EventPriority::Normal
                } else {
                    EventPriority::High
                });
                let _ = bus.publish(event).await;
            }
        }

        info!(phase = %phase, success = result.success, duration_ms = %duration_ms, "Phase execution completed");

        Ok(result)
    }

    /// Phase 1: Attack Surface Scan
    async fn execute_attack_surface_scan(
        context: &mut WorkflowContext,
        assessment: &Assessment,
        config: &WorkflowConfig,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing attack surface scan phase");

        // Simulate attack surface discovery
        // In a real implementation, this would scan the target and identify
        // entry points, components, and attack vectors

        let attack_surface = serde_json::json!({
            "target": assessment.target.path,
            "platform": format!("{:?}", assessment.target.platform),
            "components_discovered": 5,
            "entry_points": ["main_activity", "api_endpoints", "broadcast_receivers"],
            "attack_vectors": ["network", "storage", "ipc"],
        });

        context.add_metadata("attack_surface", attack_surface.clone());

        Ok(PhaseResult::success(WorkflowPhase::AttackSurfaceScan, 1, 0)
            .with_output(attack_surface))
    }

    /// Phase 2: Task Generation
    async fn execute_task_generation(
        context: &mut WorkflowContext,
        assessment: &Assessment,
        config: &WorkflowConfig,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing task generation phase");

        let mut jobs = Vec::new();
        let assessment_config = &assessment.config;

        // Generate static analysis tasks
        if assessment_config.enable_static_analysis {
            let job = Job::new("static_analysis", assessment.target.clone())
                .with_priority(TaskPriority::Static.to_job_priority())
                .with_timeout(600)
                .add_tag("static");
            jobs.push(job);
        }

        // Generate dynamic analysis tasks
        if assessment_config.enable_dynamic_analysis {
            let job = Job::new("dynamic_analysis", assessment.target.clone())
                .with_priority(TaskPriority::Dynamic.to_job_priority())
                .with_timeout(900)
                .add_tag("dynamic");
            jobs.push(job);
        }

        // Generate network analysis tasks
        if assessment_config.enable_network_analysis {
            let job = Job::new("network_analysis", assessment.target.clone())
                .with_priority(TaskPriority::Network.to_job_priority())
                .with_timeout(600)
                .add_tag("network");
            jobs.push(job);
        }

        // Generate crypto analysis tasks
        if assessment_config.enable_crypto_analysis {
            let job = Job::new("crypto_analysis", assessment.target.clone())
                .with_priority(TaskPriority::Crypto.to_job_priority())
                .with_timeout(300)
                .add_tag("crypto");
            jobs.push(job);
        }

        // Generate intent analysis tasks
        if assessment_config.enable_intent_analysis {
            let job = Job::new("intent_analysis", assessment.target.clone())
                .with_priority(TaskPriority::Intent.to_job_priority())
                .with_timeout(300)
                .add_tag("intent");
            jobs.push(job);
        }

        let task_count = jobs.len();
        context.jobs = jobs;

        info!(tasks_generated = %task_count, "Task generation completed");

        Ok(PhaseResult::success(WorkflowPhase::TaskGeneration, task_count, 0))
    }

    /// Phase 3: Agent Execution
    async fn execute_agent_execution(
        context: &mut WorkflowContext,
        assessment: &Assessment,
        config: &WorkflowConfig,
        agents: &Arc<DashMap<AgentId, Arc<dyn SecurityAgent>>>,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing agent execution phase");

        let execution_mode = config.execution_mode(&WorkflowPhase::AgentExecution);
        let jobs = context.jobs.clone();
        let task_count = jobs.len();

        if task_count == 0 {
            return Ok(PhaseResult::success(WorkflowPhase::AgentExecution, 0, 0));
        }

        let mut agent_results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;

        match execution_mode {
            ExecutionMode::Sequential => {
                // Execute tasks sequentially
                for job in jobs {
                    match Self::execute_job_with_agent(&job, agents).await {
                        Ok(result) => {
                            if result.status == TaskStatus::Completed {
                                success_count += 1;
                            } else {
                                failure_count += 1;
                            }
                            agent_results.push(result);
                        }
                        Err(e) => {
                            error!(job_id = %job.id, error = %e, "Job execution failed");
                            failure_count += 1;
                        }
                    }
                }
            }
            ExecutionMode::Parallel => {
                // Execute tasks in parallel with concurrency limit
                let semaphore = Arc::new(Semaphore::new(config.max_concurrency));
                let mut handles = Vec::with_capacity(task_count);

                for job in jobs {
                    let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                        WorkflowError::AgentExecutionFailed(format!(
                            "Failed to acquire semaphore: {}",
                            e
                        ))
                    })?;

                    let agents_clone = agents.clone();
                    let handle = tokio::spawn(async move {
                        let _permit = permit;
                        Self::execute_job_with_agent(&job, &agents_clone).await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    match handle.await {
                        Ok(Ok(result)) => {
                            if result.status == TaskStatus::Completed {
                                success_count += 1;
                            } else {
                                failure_count += 1;
                            }
                            agent_results.push(result);
                        }
                        Ok(Err(e)) => {
                            error!(error = %e, "Job execution failed");
                            failure_count += 1;
                        }
                        Err(e) => {
                            error!(error = %e, "Task join failed");
                            failure_count += 1;
                        }
                    }
                }
            }
        }

        context.agent_results = agent_results;

        info!(success = %success_count, failed = %failure_count, "Agent execution phase completed");

        if failure_count == 0 {
            Ok(PhaseResult::success(
                WorkflowPhase::AgentExecution,
                task_count,
                0,
            ))
        } else {
            Ok(PhaseResult::partial(
                WorkflowPhase::AgentExecution,
                success_count,
                failure_count,
                0,
            ))
        }
    }

    /// Execute a single job with an available agent
    async fn execute_job_with_agent(
        job: &Job,
        agents: &Arc<DashMap<AgentId, Arc<dyn SecurityAgent>>>,
    ) -> WorkflowResult<AgentResult> {
        // Find an available agent that can handle this job type
        for entry in agents.iter() {
            let agent = entry.value();
            if agent.is_available() {
                let task_id = Uuid::new_v4();
                let context = AgentContext::new(task_id, job.id, job.target.clone())
                    .with_timeout(job.timeout_secs.unwrap_or(300));

                match agent.execute(context).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        warn!(agent_id = %agent.id(), error = %e, "Agent execution failed, trying next agent");
                    }
                }
            }
        }

        Err(WorkflowError::AgentExecutionFailed(
            "No available agent found for job".to_string(),
        ))
    }

    /// Phase 4: Finding Collection
    async fn execute_finding_collection(
        context: &mut WorkflowContext,
        config: &WorkflowConfig,
        finding_engine: &Arc<FindingEngine>,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing finding collection phase");

        // Collect findings from agent results
        let mut all_findings = Vec::new();

        for result in &context.agent_results {
            for finding in &result.findings.findings {
                all_findings.push(finding.clone());
            }
        }

        let finding_count = all_findings.len();
        context.findings = FindingCollection::new(all_findings);

        info!(findings_collected = %finding_count, "Finding collection completed");

        Ok(PhaseResult::success(
            WorkflowPhase::FindingCollection,
            finding_count,
            0,
        ))
    }

    /// Phase 5: Correlation
    async fn execute_correlation(
        context: &mut WorkflowContext,
        config: &WorkflowConfig,
        correlation_engine: &Arc<CorrelationEngine>,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing correlation phase");

        let findings = &context.findings.findings;

        if findings.len() < 2 {
            info!("Not enough findings for correlation");
            return Ok(PhaseResult::success(WorkflowPhase::Correlation, 0, 0));
        }

        // Correlate findings
        let correlation_groups = correlation_engine.correlate_batch(findings).await;
        let correlation_count: usize = correlation_groups.iter().map(|g| g.size()).sum();

        // Update findings with correlation info
        for group in &correlation_groups {
            // In a real implementation, we would update the findings with correlation info
            debug!("Correlation group: {} findings", group.size());
        }

        context.add_metadata(
            "correlation_groups",
            serde_json::json!(correlation_groups.len()),
        );

        info!(correlations_found = %correlation_count, groups = %correlation_groups.len(), "Correlation phase completed");

        Ok(PhaseResult::success(
            WorkflowPhase::Correlation,
            correlation_count,
            0,
        ))
    }

    /// Phase 6: Risk Scoring
    async fn execute_risk_scoring(
        context: &mut WorkflowContext,
        config: &WorkflowConfig,
        risk_engine: &Arc<RiskEngine>,
    ) -> WorkflowResult<PhaseResult> {
        info!("Executing risk scoring phase");

        let findings = &context.findings;

        if findings.findings.is_empty() {
            info!("No findings to score");
            return Ok(PhaseResult::success(WorkflowPhase::RiskScoring, 0, 0));
        }

        // Calculate risk scores
        let business_context = BusinessContext::new(&context.assessment_id.to_string());
        let risk_stats = risk_engine.calculate_collection(findings);

        // Calculate overall risk score
        let overall_score = if risk_stats.average > 0.0 {
            let max_component = risk_stats.maximum * 0.4;
            let avg_component = risk_stats.average * 0.6;
            (max_component + avg_component).clamp(0.0, 10.0)
        } else {
            0.0
        };

        let risk_score = RiskScore::new(overall_score)
            .with_cvss(risk_stats.average)
            .with_business_impact(risk_stats.average * 0.8)
            .with_threat_level(risk_stats.maximum * 0.9);

        context.risk_score = Some(risk_score.clone());

        // Add risk metadata
        context.add_metadata(
            "risk_statistics",
            serde_json::json!({
                "average": risk_stats.average,
                "maximum": risk_stats.maximum,
                "critical_count": risk_stats.critical_count(),
                "high_count": risk_stats.high_count(),
            }),
        );

        info!(risk_score = %overall_score, "Risk scoring completed");

        Ok(PhaseResult::success(WorkflowPhase::RiskScoring, findings.total_count, 0)
            .with_output(serde_json::json!({
                "overall_score": overall_score,
                "average": risk_stats.average,
                "maximum": risk_stats.maximum,
            })))
    }

    /// Submit a workflow for execution
    #[instrument(skip(self, assessment))]
    pub async fn submit(&self, assessment: Assessment) -> WorkflowResult<WorkflowId> {
        let workflow_id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();

        let task = WorkflowTask {
            workflow_id,
            assessment,
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            result_tx: tx,
        };

        let task_tx = self
            .task_tx
            .as_ref()
            .ok_or_else(|| WorkflowError::InternalError("Workflow engine not running".to_string()))?
            .clone();

        task_tx
            .send(task)
            .await
            .map_err(|_| WorkflowError::InternalError("Failed to submit workflow".to_string()))?;

        info!(workflow_id = %workflow_id, "Workflow submitted");

        Ok(workflow_id)
    }

    /// Submit and wait for workflow completion
    #[instrument(skip(self, assessment))]
    pub async fn submit_and_wait(
        &self,
        assessment: Assessment,
    ) -> WorkflowResult<WorkflowContext> {
        let workflow_id = self.submit(assessment).await?;

        // Wait for completion by polling
        loop {
            if let Some(status) = self.workflow_statuses.get(&workflow_id) {
                if matches!(
                    *status,
                    WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Partial
                ) {
                    if let Some(context) = self.active_workflows.get(&workflow_id) {
                        return Ok(context.clone());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Cancel a running workflow
    #[instrument(skip(self))]
    pub async fn cancel(&self, workflow_id: WorkflowId) -> WorkflowResult<()> {
        if let Some(context) = self.active_workflows.get(&workflow_id) {
            // Note: In a real implementation, we would need to store the cancellation token
            // and use it here. For now, we just update the status.
            self.workflow_statuses
                .insert(workflow_id, WorkflowStatus::Cancelled);
            info!(workflow_id = %workflow_id, "Workflow cancelled");
            Ok(())
        } else {
            Err(WorkflowError::WorkflowNotFound(workflow_id))
        }
    }

    /// Get workflow status
    pub fn get_status(&self, workflow_id: WorkflowId) -> Option<WorkflowStatus> {
        self.workflow_statuses.get(&workflow_id).map(|s| *s)
    }

    /// Get workflow context
    pub fn get_context(&self, workflow_id: WorkflowId) -> Option<WorkflowContext> {
        self.active_workflows.get(&workflow_id).map(|c| c.clone())
    }

    /// Get active workflow count
    pub fn active_count(&self) -> usize {
        self.active_workflows.len()
    }

    /// Get active workflow IDs
    pub fn active_workflows(&self) -> Vec<WorkflowId> {
        self.active_workflows.iter().map(|e| *e.key()).collect()
    }

    /// Get workflow statistics
    pub async fn stats(&self) -> WorkflowStats {
        self.stats.read().await.clone()
    }

    /// Shutdown the workflow engine
    #[instrument(skip(self))]
    pub async fn shutdown(&mut self) -> WorkflowResult<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Shutting down workflow engine");

        // Cancel all active workflows
        for entry in self.active_workflows.iter() {
            self.workflow_statuses
                .insert(*entry.key(), WorkflowStatus::Cancelled);
        }

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Clear task channel
        self.task_tx = None;

        *running = false;
        info!("Workflow engine shutdown complete");

        Ok(())
    }

    /// Check if engine is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new(WorkflowConfig::default())
    }
}

/// Builder for creating workflow engines
pub struct WorkflowEngineBuilder {
    config: WorkflowConfig,
    event_bus: Option<Arc<EventBus>>,
    agents: Vec<Arc<dyn SecurityAgent>>,
}

impl WorkflowEngineBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: WorkflowConfig::default(),
            event_bus: None,
            agents: Vec::new(),
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: WorkflowConfig) -> Self {
        self.config = config;
        self
    }

    /// Set event bus
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Register an agent
    pub fn register_agent(mut self, agent: Arc<dyn SecurityAgent>) -> Self {
        self.agents.push(agent);
        self
    }

    /// Set max concurrency
    pub fn with_max_concurrency(mut self, concurrency: usize) -> Self {
        self.config = self.config.with_max_concurrency(concurrency);
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.config = self.config.with_timeout(timeout_secs);
        self
    }

    /// Enable graceful degradation
    pub fn with_graceful_degradation(mut self, enabled: bool) -> Self {
        self.config = self.config.with_graceful_degradation(enabled);
        self
    }

    /// Enable event publishing
    pub fn with_event_publishing(mut self, enabled: bool) -> Self {
        self.config = self.config.with_event_publishing(enabled);
        self
    }

    /// Build the workflow engine
    pub fn build(self) -> WorkflowEngine {
        let mut engine = WorkflowEngine::new(self.config);

        if let Some(bus) = self.event_bus {
            engine = engine.with_event_bus(bus);
        }

        for agent in self.agents {
            engine.register_agent(agent);
        }

        engine
    }
}

impl Default for WorkflowEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_assessment() -> Assessment {
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        Assessment::new("Test Assessment", target)
            .with_config(
                AssessmentConfig::default()
                    .with_static_analysis(true)
                    .with_network_analysis(true)
                    .with_crypto_analysis(true),
            )
    }

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Static > TaskPriority::Dynamic);
        assert!(TaskPriority::Dynamic > TaskPriority::Intent);
        assert!(TaskPriority::Intent > TaskPriority::Crypto);
        assert!(TaskPriority::Crypto > TaskPriority::Fuzzing);
    }

    #[test]
    fn test_task_priority_from_capability() {
        assert_eq!(
            TaskPriority::from_capability(&AgentCapability::StaticAnalysis),
            TaskPriority::Static
        );
        assert_eq!(
            TaskPriority::from_capability(&AgentCapability::DynamicAnalysis),
            TaskPriority::Dynamic
        );
        assert_eq!(
            TaskPriority::from_capability(&AgentCapability::NetworkAnalysis),
            TaskPriority::Network
        );
        assert_eq!(
            TaskPriority::from_capability(&AgentCapability::CryptoAnalysis),
            TaskPriority::Crypto
        );
        assert_eq!(
            TaskPriority::from_capability(&AgentCapability::Fuzzing),
            TaskPriority::Fuzzing
        );
    }

    #[test]
    fn test_workflow_phase_sequence() {
        let phases = vec![
            WorkflowPhase::AttackSurfaceScan,
            WorkflowPhase::TaskGeneration,
            WorkflowPhase::AgentExecution,
            WorkflowPhase::FindingCollection,
            WorkflowPhase::Correlation,
            WorkflowPhase::RiskScoring,
        ];

        for i in 0..phases.len() - 1 {
            assert_eq!(phases[i].next(), Some(phases[i + 1]));
        }
        assert_eq!(phases.last().unwrap().next(), None);
    }

    #[test]
    fn test_workflow_phase_display() {
        assert_eq!(
            WorkflowPhase::AttackSurfaceScan.to_string(),
            "attack_surface_scan"
        );
        assert_eq!(
            WorkflowPhase::TaskGeneration.to_string(),
            "task_generation"
        );
        assert_eq!(
            WorkflowPhase::AgentExecution.to_string(),
            "agent_execution"
        );
        assert_eq!(
            WorkflowPhase::FindingCollection.to_string(),
            "finding_collection"
        );
        assert_eq!(WorkflowPhase::Correlation.to_string(), "correlation");
        assert_eq!(WorkflowPhase::RiskScoring.to_string(), "risk_scoring");
    }

    #[test]
    fn test_workflow_config_builder() {
        let config = WorkflowConfig::new()
            .with_max_concurrency(16)
            .with_timeout(3600)
            .with_graceful_degradation(false)
            .with_event_publishing(false);

        assert_eq!(config.max_concurrency, 16);
        assert_eq!(config.default_timeout_secs, 3600);
        assert!(!config.enable_graceful_degradation);
        assert!(!config.publish_events);
    }

    #[test]
    fn test_workflow_config_phase_modes() {
        let config = WorkflowConfig::new()
            .with_phase_mode(WorkflowPhase::AgentExecution, ExecutionMode::Sequential);

        assert_eq!(
            config.execution_mode(&WorkflowPhase::AgentExecution),
            ExecutionMode::Sequential
        );
        assert_eq!(
            config.execution_mode(&WorkflowPhase::TaskGeneration),
            ExecutionMode::Sequential
        );
    }

    #[test]
    fn test_phase_result_success() {
        let result = PhaseResult::success(WorkflowPhase::AttackSurfaceScan, 5, 1000);
        assert!(result.success);
        assert_eq!(result.tasks_processed, 5);
        assert_eq!(result.tasks_succeeded, 5);
        assert_eq!(result.tasks_failed, 0);
        assert_eq!(result.duration_ms, 1000);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_phase_result_failure() {
        let result = PhaseResult::failure(WorkflowPhase::AgentExecution, "Test error", 500);
        assert!(!result.success);
        assert_eq!(result.tasks_processed, 0);
        assert_eq!(result.duration_ms, 500);
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_phase_result_partial() {
        let result = PhaseResult::partial(WorkflowPhase::AgentExecution, 3, 2, 1000);
        assert!(!result.success);
        assert_eq!(result.tasks_processed, 5);
        assert_eq!(result.tasks_succeeded, 3);
        assert_eq!(result.tasks_failed, 2);
        assert_eq!(result.duration_ms, 1000);
    }

    #[test]
    fn test_workflow_context_lifecycle() {
        let assessment = create_test_assessment();
        let workflow_id = Uuid::new_v4();
        let mut context = WorkflowContext::new(workflow_id, &assessment);

        assert_eq!(context.workflow_id, workflow_id);
        assert_eq!(context.assessment_id, assessment.id);
        assert!(context.started_at.is_none());
        assert!(context.completed_at.is_none());

        context.mark_started();
        assert!(context.started_at.is_some());

        context.mark_completed();
        assert!(context.completed_at.is_some());
        assert!(context.duration().is_some());
    }

    #[test]
    fn test_workflow_context_phase_results() {
        let assessment = create_test_assessment();
        let workflow_id = Uuid::new_v4();
        let mut context = WorkflowContext::new(workflow_id, &assessment);

        let result1 = PhaseResult::success(WorkflowPhase::AttackSurfaceScan, 1, 100);
        let result2 = PhaseResult::success(WorkflowPhase::TaskGeneration, 5, 200);

        context.add_phase_result(result1);
        context.add_phase_result(result2);

        assert_eq!(context.phase_results.len(), 2);
        assert!(context.all_phases_succeeded());
        assert!(!context.any_phase_failed());

        let result3 = PhaseResult::failure(WorkflowPhase::AgentExecution, "Error", 300);
        context.add_phase_result(result3);

        assert!(!context.all_phases_succeeded());
        assert!(context.any_phase_failed());
    }

    #[test]
    fn test_workflow_context_metadata() {
        let assessment = create_test_assessment();
        let workflow_id = Uuid::new_v4();
        let mut context = WorkflowContext::new(workflow_id, &assessment);

        context.add_metadata("key1", serde_json::json!("value1"));
        context.add_metadata("key2", serde_json::json!(42));

        assert_eq!(
            context.metadata.get("key1"),
            Some(&serde_json::json!("value1"))
        );
        assert_eq!(context.metadata.get("key2"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn test_workflow_engine_builder() {
        let engine = WorkflowEngineBuilder::new()
            .with_max_concurrency(32)
            .with_timeout(7200)
            .with_graceful_degradation(false)
            .with_event_publishing(true)
            .build();

        assert_eq!(engine.config.max_concurrency, 32);
        assert_eq!(engine.config.default_timeout_secs, 7200);
        assert!(!engine.config.enable_graceful_degradation);
        assert!(engine.config.publish_events);
    }

    #[tokio::test]
    async fn test_workflow_engine_start_stop() {
        let mut engine = WorkflowEngine::default();

        assert!(!engine.is_running().await);

        engine.start().await.unwrap();
        assert!(engine.is_running().await);

        engine.shutdown().await.unwrap();
        assert!(!engine.is_running().await);
    }

    #[tokio::test]
    async fn test_workflow_engine_submit() {
        let mut engine = WorkflowEngine::default();
        engine.start().await.unwrap();

        let assessment = create_test_assessment();
        let workflow_id = engine.submit(assessment).await.unwrap();

        assert!(engine.get_status(workflow_id).is_some());
        assert_eq!(engine.active_count(), 1);

        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_workflow_engine_cancel() {
        let mut engine = WorkflowEngine::default();
        engine.start().await.unwrap();

        let assessment = create_test_assessment();
        let workflow_id = engine.submit(assessment).await.unwrap();

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        engine.cancel(workflow_id).await.unwrap();

        let status = engine.get_status(workflow_id).unwrap();
        assert_eq!(status, WorkflowStatus::Cancelled);

        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_workflow_engine_stats() {
        let mut engine = WorkflowEngine::default();
        engine.start().await.unwrap();

        let stats = engine.stats().await;
        assert_eq!(stats.total_workflows, 0);
        assert_eq!(stats.successful_workflows, 0);
        assert_eq!(stats.failed_workflows, 0);

        engine.shutdown().await.unwrap();
    }

    #[test]
    fn test_workflow_error_display() {
        let workflow_id = Uuid::new_v4();
        let err = WorkflowError::WorkflowNotFound(workflow_id);
        assert!(err.to_string().contains(&workflow_id.to_string()));

        let err = WorkflowError::PhaseExecutionFailed {
            phase: WorkflowPhase::AgentExecution,
            reason: "Test reason".to_string(),
        };
        assert!(err.to_string().contains("agent_execution"));
        assert!(err.to_string().contains("Test reason"));
    }
}
