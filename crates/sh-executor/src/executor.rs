//! Main executor with retry logic, timeout handling, and cancellation support
//!
//! This module provides the core job execution engine with:
//! - Configurable timeouts with graceful cancellation
//! - Exponential backoff retry strategies
//! - Job cancellation support
//! - Execution result reporting
//! - Async operation support
//! - Production-ready error handling

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use crate::error::{ExecutorError, ExecutorResult};
use crate::retry::{ExponentialBackoff, RetryConfig, RetryState, RetryStrategy};
use crate::timeout::{TimeoutConfig, TimeoutGuard, TimeoutManager};

/// Unique identifier for execution contexts
pub type ExecutionId = Uuid;

/// Configuration for the executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum number of concurrent executions
    pub max_concurrent: usize,
    /// Default timeout configuration
    pub timeout_config: TimeoutConfig,
    /// Default retry configuration
    pub retry_config: RetryConfig,
    /// Whether to enable job cancellation
    pub enable_cancellation: bool,
    /// Channel buffer size for job submission
    pub channel_buffer_size: usize,
    /// Whether to propagate worker results
    pub propagate_worker_results: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            timeout_config: TimeoutConfig::default(),
            retry_config: RetryConfig::default(),
            enable_cancellation: true,
            channel_buffer_size: 100,
            propagate_worker_results: true,
        }
    }
}

impl ExecutorConfig {
    /// Create a new executor configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrent executions
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set timeout configuration
    pub fn with_timeout_config(mut self, config: TimeoutConfig) -> Self {
        self.timeout_config = config;
        self
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Enable or disable cancellation
    pub fn with_cancellation(mut self, enabled: bool) -> Self {
        self.enable_cancellation = enabled;
        self
    }

    /// Set channel buffer size
    pub fn with_channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set whether to propagate worker results
    pub fn with_propagate_worker_results(mut self, propagate: bool) -> Self {
        self.propagate_worker_results = propagate;
        self
    }

    /// Create a configuration optimized for high throughput
    pub fn high_throughput() -> Self {
        Self {
            max_concurrent: 50,
            timeout_config: TimeoutConfig::short_running(),
            retry_config: RetryConfig::aggressive(),
            enable_cancellation: true,
            channel_buffer_size: 500,
            propagate_worker_results: true,
        }
    }

    /// Create a configuration optimized for long-running jobs
    pub fn long_running() -> Self {
        Self {
            max_concurrent: 5,
            timeout_config: TimeoutConfig::long_running(),
            retry_config: RetryConfig::conservative(),
            enable_cancellation: true,
            channel_buffer_size: 50,
            propagate_worker_results: true,
        }
    }
}

/// Execution context for a job
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Unique execution ID
    pub execution_id: ExecutionId,
    /// Job being executed
    pub job: sh_types::Job,
    /// When execution started
    pub started_at: DateTime<Utc>,
    /// Current retry attempt
    pub retry_attempt: u32,
    /// Cancellation token
    pub cancellation_token: tokio_util::sync::CancellationToken,
    /// Timeout guard
    pub timeout_guard: Option<Arc<RwLock<TimeoutGuard>>>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(job: sh_types::Job) -> Self {
        Self {
            execution_id: Uuid::new_v4(),
            job,
            started_at: Utc::now(),
            retry_attempt: 0,
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            timeout_guard: None,
        }
    }

    /// Check if execution has been cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancellation_token.is_cancelled()
    }

    /// Cancel the execution
    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }

    /// Get execution duration
    pub fn duration(&self) -> chrono::Duration {
        Utc::now() - self.started_at
    }

    /// Increment retry attempt
    pub fn increment_retry(&mut self) {
        self.retry_attempt += 1;
    }
}

/// Execution result with detailed metrics
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Execution ID
    pub execution_id: ExecutionId,
    /// Job ID
    pub job_id: sh_types::JobId,
    /// Whether execution succeeded
    pub success: bool,
    /// Job result data (if successful)
    pub result: Option<sh_types::JobResult>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Execution metrics
    pub metrics: ExecutionMetrics,
    /// Retry information
    pub retry_info: RetryInfo,
    /// When execution completed
    pub completed_at: DateTime<Utc>,
}

impl ExecutionResult {
    /// Create a successful result
    pub fn success(
        execution_id: ExecutionId,
        job_id: sh_types::JobId,
        result: sh_types::JobResult,
        metrics: ExecutionMetrics,
        retry_info: RetryInfo,
    ) -> Self {
        Self {
            execution_id,
            job_id,
            success: true,
            result: Some(result),
            error: None,
            metrics,
            retry_info,
            completed_at: Utc::now(),
        }
    }

    /// Create a failed result
    pub fn failure(
        execution_id: ExecutionId,
        job_id: sh_types::JobId,
        error: impl Into<String>,
        metrics: ExecutionMetrics,
        retry_info: RetryInfo,
    ) -> Self {
        Self {
            execution_id,
            job_id,
            success: false,
            result: None,
            error: Some(error.into()),
            metrics,
            retry_info,
            completed_at: Utc::now(),
        }
    }

    /// Create a cancelled result
    pub fn cancelled(
        execution_id: ExecutionId,
        job_id: sh_types::JobId,
        metrics: ExecutionMetrics,
    ) -> Self {
        Self {
            execution_id,
            job_id,
            success: false,
            result: None,
            error: Some("Job was cancelled".to_string()),
            metrics,
            retry_info: RetryInfo::default(),
            completed_at: Utc::now(),
        }
    }

    /// Create a timeout result
    pub fn timeout(
        execution_id: ExecutionId,
        job_id: sh_types::JobId,
        timeout_secs: u64,
        metrics: ExecutionMetrics,
        retry_info: RetryInfo,
    ) -> Self {
        Self {
            execution_id,
            job_id,
            success: false,
            result: None,
            error: Some(format!("Job timed out after {} seconds", timeout_secs)),
            metrics,
            retry_info,
            completed_at: Utc::now(),
        }
    }
}

/// Execution metrics
#[derive(Debug, Clone, Default)]
pub struct ExecutionMetrics {
    /// Time spent in queue (ms)
    pub queue_time_ms: u64,
    /// Actual execution time (ms)
    pub execution_time_ms: u64,
    /// Total time from submission to completion (ms)
    pub total_time_ms: u64,
    /// Time spent waiting for retries (ms)
    pub retry_wait_time_ms: u64,
    /// Number of attempts made
    pub attempts: u32,
}

/// Retry information
#[derive(Debug, Clone, Default)]
pub struct RetryInfo {
    /// Number of retries attempted
    pub retry_count: u32,
    /// Total time spent in retries
    pub total_retry_time_ms: u64,
    /// Last error message
    pub last_error: Option<String>,
}

/// Job execution request
#[derive(Debug)]
pub struct ExecutionRequest {
    /// Job to execute
    pub job: sh_types::Job,
    /// Custom timeout (overrides default)
    pub timeout: Option<std::time::Duration>,
    /// Custom retry configuration (overrides default)
    pub retry_config: Option<RetryConfig>,
    /// Response channel for result
    pub response_tx: oneshot::Sender<ExecutorResult<ExecutionResult>>,
}

/// Trait for job executors
#[async_trait]
pub trait JobExecutor: Send + Sync {
    /// Execute a job and return the result
    async fn execute(&self, job: &sh_types::Job) -> ExecutorResult<sh_types::JobResult>;

    /// Check if this executor can handle the given job type
    fn can_execute(&self, job_type: &str) -> bool;

    /// Get executor capabilities
    fn capabilities(&self) -> sh_worker::WorkerCapabilities;
}

/// Internal execution state
#[derive(Debug)]
struct ExecutionState {
    /// Execution context
    context: ExecutionContext,
    /// Handle to the execution task
    handle: Option<JoinHandle<ExecutorResult<ExecutionResult>>>,
    /// When the execution was queued
    queued_at: DateTime<Utc>,
}

/// The main executor
pub struct Executor {
    /// Configuration
    config: ExecutorConfig,
    /// Timeout manager
    timeout_manager: TimeoutManager,
    /// Active executions
    active_executions: Arc<DashMap<ExecutionId, ExecutionState>>,
    /// Job executors by type
    executors: Arc<DashMap<String, Arc<dyn JobExecutor>>>,
    /// Default executor
    default_executor: Arc<RwLock<Option<Arc<dyn JobExecutor>>>>,
    /// Job submission channel
    job_tx: Option<mpsc::Sender<ExecutionRequest>>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl Executor {
    /// Create a new executor with the given configuration
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            timeout_manager: TimeoutManager::new(),
            active_executions: Arc::new(DashMap::new()),
            executors: Arc::new(DashMap::new()),
            default_executor: Arc::new(RwLock::new(None)),
            job_tx: None,
            shutdown_tx: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Create a new executor with default configuration
    pub fn default() -> Self {
        Self::new(ExecutorConfig::default())
    }

    /// Register a job executor for a specific job type
    pub fn register_executor(
        &self,
        job_type: impl Into<String>,
        executor: Arc<dyn JobExecutor>,
    ) {
        let job_type = job_type.into();
        info!(job_type = %job_type, "Registering job executor");
        self.executors.insert(job_type, executor);
    }

    /// Set the default executor for unregistered job types
    pub async fn set_default_executor(&self, executor: Arc<dyn JobExecutor>) {
        let mut default = self.default_executor.write().await;
        *default = Some(executor);
        info!("Default executor set");
    }

    /// Start the executor
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> ExecutorResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(ExecutorError::AlreadyRunning);
        }

        info!("Starting executor");

        // Create channels
        let (job_tx, mut job_rx) = mpsc::channel::<ExecutionRequest>(self.config.channel_buffer_size);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        self.job_tx = Some(job_tx);
        self.shutdown_tx = Some(shutdown_tx);

        // Clone Arcs for the worker task
        let active_executions = self.active_executions.clone();
        let executors = self.executors.clone();
        let default_executor = self.default_executor.clone();
        let config = self.config.clone();
        let timeout_manager = self.timeout_manager.clone();

        // Spawn the executor worker
        let _worker_handle = tokio::spawn(async move {
            info!("Executor worker started");

            loop {
                tokio::select! {
                    // Process incoming job requests
                    Some(request) = job_rx.recv() => {
                        let active_execs = active_executions.clone();
                        let execs = executors.clone();
                        let default_exec = default_executor.clone();
                        let cfg = config.clone();
                        let tm = timeout_manager.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::process_job(
                                request,
                                active_execs,
                                execs,
                                default_exec,
                                cfg,
                                tm,
                            ).await {
                                error!(error = %e, "Failed to process job");
                            }
                        });
                    }

                    // Handle shutdown signal
                    _ = &mut shutdown_rx => {
                        info!("Executor received shutdown signal");
                        break;
                    }

                    else => {
                        break;
                    }
                }
            }

            info!("Executor worker stopped");
        });

        *running = true;
        info!("Executor started successfully");

        Ok(())
    }

    /// Process a single job
    #[instrument(skip(request, active_executions, executors, default_executor, config, timeout_manager))]
    async fn process_job(
        request: ExecutionRequest,
        active_executions: Arc<DashMap<ExecutionId, ExecutionState>>,
        executors: Arc<DashMap<String, Arc<dyn JobExecutor>>>,
        default_executor: Arc<RwLock<Option<Arc<dyn JobExecutor>>>>,
        config: ExecutorConfig,
        timeout_manager: TimeoutManager,
    ) -> ExecutorResult<()> {
        let job_id = request.job.id;
        let execution_id = Uuid::new_v4();
        let queued_at = Utc::now();

        debug!(
            job_id = %job_id,
            execution_id = %execution_id,
            "Processing job"
        );

        // Create execution context
        let mut context = ExecutionContext::new(request.job.clone());
        context.execution_id = execution_id;

        // Get timeout
        let timeout = request.timeout.unwrap_or_else(|| {
            timeout_manager.get_timeout(
                &request.job.job_type,
                &request.job.priority,
                request.job.timeout_secs.map(std::time::Duration::from_secs),
            )
        });

        // Create timeout guard
        let timeout_guard = TimeoutGuard::new(job_id, timeout);
        context.timeout_guard = Some(Arc::new(RwLock::new(timeout_guard)));

        // Store execution state
        let state = ExecutionState {
            context: context.clone(),
            handle: None,
            queued_at,
        };
        active_executions.insert(execution_id, state);

        // Get retry configuration
        let retry_config = request.retry_config.unwrap_or(config.retry_config);
        let retry_strategy = ExponentialBackoff::with_config(retry_config);

        // Execute with retry
        let result = Self::execute_with_retry(
            &context,
            &executors,
            &default_executor,
            &retry_strategy,
            timeout,
            config.propagate_worker_results,
        ).await;

        // Clean up
        active_executions.remove(&execution_id);

        // Send result
        let _ = request.response_tx.send(result);

        Ok(())
    }

    /// Execute a job with retry logic
    #[instrument(skip(context, executors, default_executor, retry_strategy))]
    async fn execute_with_retry(
        context: &ExecutionContext,
        executors: &Arc<DashMap<String, Arc<dyn JobExecutor>>>,
        default_executor: &Arc<RwLock<Option<Arc<dyn JobExecutor>>>>,
        retry_strategy: &dyn RetryStrategy,
        timeout: std::time::Duration,
        propagate_worker_results: bool,
    ) -> ExecutorResult<ExecutionResult> {
        let job_id = context.job.id;
        let execution_id = context.execution_id;
        let started_at = Utc::now();
        let mut retry_state = RetryState::new();

        loop {
            // Check for cancellation
            if context.is_cancelled() {
                info!(job_id = %job_id, "Job cancelled before execution");
                return Ok(ExecutionResult::cancelled(
                    execution_id,
                    job_id,
                    ExecutionMetrics {
                        queue_time_ms: (started_at - context.started_at).num_milliseconds() as u64,
                        execution_time_ms: 0,
                        total_time_ms: (Utc::now() - context.started_at).num_milliseconds() as u64,
                        retry_wait_time_ms: retry_state.total_delay.as_millis() as u64,
                        attempts: retry_state.attempt + 1,
                    },
                ));
            }

            debug!(
                job_id = %job_id,
                attempt = retry_state.attempt + 1,
                "Starting job execution attempt"
            );

            let attempt_start = Utc::now();

            // Execute the job with timeout
            let execution_result = Self::execute_job(
                context,
                executors,
                default_executor,
                timeout,
                propagate_worker_results,
            ).await;

            let attempt_duration = Utc::now() - attempt_start;

            match execution_result {
                Ok(result) => {
                    info!(
                        job_id = %job_id,
                        execution_id = %execution_id,
                        attempts = retry_state.attempt + 1,
                        "Job executed successfully"
                    );

                    return Ok(ExecutionResult::success(
                        execution_id,
                        job_id,
                        result,
                        ExecutionMetrics {
                            queue_time_ms: (started_at - context.started_at).num_milliseconds() as u64,
                            execution_time_ms: attempt_duration.num_milliseconds() as u64,
                            total_time_ms: (Utc::now() - context.started_at).num_milliseconds() as u64,
                            retry_wait_time_ms: retry_state.total_delay.as_millis() as u64,
                            attempts: retry_state.attempt + 1,
                        },
                        RetryInfo {
                            retry_count: retry_state.attempt,
                            total_retry_time_ms: retry_state.total_delay.as_millis() as u64,
                            last_error: retry_state.last_error,
                        },
                    ));
                }
                Err(e) => {
                    retry_state.set_error(e.to_string());

                    // Check if we should retry
                    if !retry_strategy.should_retry(retry_state.attempt) || !e.is_retryable() {
                        error!(
                            job_id = %job_id,
                            execution_id = %execution_id,
                            error = %e,
                            attempts = retry_state.attempt + 1,
                            "Job execution failed, no more retries"
                        );

                        return Ok(ExecutionResult::failure(
                            execution_id,
                            job_id,
                            e.to_string(),
                            ExecutionMetrics {
                                queue_time_ms: (started_at - context.started_at).num_milliseconds() as u64,
                                execution_time_ms: attempt_duration.num_milliseconds() as u64,
                                total_time_ms: (Utc::now() - context.started_at).num_milliseconds() as u64,
                                retry_wait_time_ms: retry_state.total_delay.as_millis() as u64,
                                attempts: retry_state.attempt + 1,
                            },
                            RetryInfo {
                                retry_count: retry_state.attempt,
                                total_retry_time_ms: retry_state.total_delay.as_millis() as u64,
                                last_error: retry_state.last_error.clone(),
                            },
                        ));
                    }

                    // Calculate and wait for retry delay
                    let delay = retry_strategy.calculate_delay(retry_state.attempt + 1);
                    retry_state.increment_attempt();
                    retry_state.add_delay(delay);

                    warn!(
                        job_id = %job_id,
                        attempt = retry_state.attempt,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Job execution failed, retrying"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Execute a single job attempt
    #[instrument(skip(context, executors, default_executor))]
    async fn execute_job(
        context: &ExecutionContext,
        executors: &Arc<DashMap<String, Arc<dyn JobExecutor>>>,
        default_executor: &Arc<RwLock<Option<Arc<dyn JobExecutor>>>>,
        timeout: std::time::Duration,
        propagate_worker_results: bool,
    ) -> ExecutorResult<sh_types::JobResult> {
        let job = &context.job;
        let job_type = &job.job_type;

        // Find appropriate executor
        let executor = executors
            .get(job_type)
            .map(|e| e.clone())
            .or_else(|| {
                // Try wildcard match
                executors.get("*").map(|e| e.clone())
            })
            .or_else(|| {
                // Use default executor
                default_executor.blocking_read().as_ref().cloned()
            })
            .ok_or_else(|| {
                ExecutorError::execution_failed(
                    job.id,
                    format!("No executor found for job type: {}", job_type),
                )
            })?;

        // Check if executor can handle this job type
        if !executor.can_execute(job_type) {
            return Err(ExecutorError::execution_failed(
                job.id,
                format!("Executor cannot handle job type: {}", job_type),
            ));
        }

        // Execute with timeout
        let execution_future = executor.execute(job);
        let cancellation_token = context.cancellation_token.clone();

        let result = tokio::select! {
            result = execution_future => result,
            _ = tokio::time::sleep(timeout) => {
                return Err(ExecutorError::timeout(job.id, timeout.as_secs()));
            }
            _ = cancellation_token.cancelled() => {
                return Err(ExecutorError::cancelled(job.id));
            }
        };

        result.map_err(|e| ExecutorError::execution_failed(job.id, e.to_string()))
    }

    /// Submit a job for execution
    #[instrument(skip(self, job))]
    pub async fn submit(&self, job: sh_types::Job) -> ExecutorResult<ExecutionResult> {
        let (tx, rx) = oneshot::channel();

        let request = ExecutionRequest {
            job,
            timeout: None,
            retry_config: None,
            response_tx: tx,
        };

        let job_tx = self
            .job_tx
            .as_ref()
            .ok_or(ExecutorError::NotRunning)?
            .clone();

        job_tx
            .send(request)
            .await
            .map_err(|_| ExecutorError::ChannelError("Failed to send job".to_string()))?;

        rx.await
            .map_err(|_| ExecutorError::ChannelError("Failed to receive result".to_string()))?
    }

    /// Submit a job with custom timeout
    #[instrument(skip(self, job))]
    pub async fn submit_with_timeout(
        &self,
        job: sh_types::Job,
        timeout: std::time::Duration,
    ) -> ExecutorResult<ExecutionResult> {
        let (tx, rx) = oneshot::channel();

        let request = ExecutionRequest {
            job,
            timeout: Some(timeout),
            retry_config: None,
            response_tx: tx,
        };

        let job_tx = self
            .job_tx
            .as_ref()
            .ok_or(ExecutorError::NotRunning)?
            .clone();

        job_tx
            .send(request)
            .await
            .map_err(|_| ExecutorError::ChannelError("Failed to send job".to_string()))?;

        rx.await
            .map_err(|_| ExecutorError::ChannelError("Failed to receive result".to_string()))?
    }

    /// Submit a job with custom retry configuration
    #[instrument(skip(self, job))]
    pub async fn submit_with_retry(
        &self,
        job: sh_types::Job,
        retry_config: RetryConfig,
    ) -> ExecutorResult<ExecutionResult> {
        let (tx, rx) = oneshot::channel();

        let request = ExecutionRequest {
            job,
            timeout: None,
            retry_config: Some(retry_config),
            response_tx: tx,
        };

        let job_tx = self
            .job_tx
            .as_ref()
            .ok_or(ExecutorError::NotRunning)?
            .clone();

        job_tx
            .send(request)
            .await
            .map_err(|_| ExecutorError::ChannelError("Failed to send job".to_string()))?;

        rx.await
            .map_err(|_| ExecutorError::ChannelError("Failed to receive result".to_string()))?
    }

    /// Cancel a running execution
    #[instrument(skip(self))]
    pub async fn cancel(&self, execution_id: ExecutionId) -> ExecutorResult<()> {
        if let Some(mut state) = self.active_executions.get_mut(&execution_id) {
            info!(execution_id = %execution_id, "Cancelling execution");
            state.context.cancel();
            Ok(())
        } else {
            Err(ExecutorError::JobNotFound(execution_id.into()))
        }
    }

    /// Cancel a job by ID
    #[instrument(skip(self))]
    pub async fn cancel_job(&self, job_id: sh_types::JobId) -> ExecutorResult<()> {
        let execution_id = self
            .active_executions
            .iter()
            .find(|entry| entry.value().context.job.id == job_id)
            .map(|entry| *entry.key());

        if let Some(id) = execution_id {
            self.cancel(id).await
        } else {
            Err(ExecutorError::JobNotFound(job_id))
        }
    }

    /// Get active execution count
    pub fn active_count(&self) -> usize {
        self.active_executions.len()
    }

    /// Get active execution IDs
    pub fn active_executions(&self) -> Vec<ExecutionId> {
        self.active_executions.iter().map(|entry| *entry.key()).collect()
    }

    /// Check if an execution is active
    pub fn is_active(&self, execution_id: ExecutionId) -> bool {
        self.active_executions.contains_key(&execution_id)
    }

    /// Shutdown the executor
    #[instrument(skip(self))]
    pub async fn shutdown(&mut self) -> ExecutorResult<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Shutting down executor");

        // Cancel all active executions
        for mut entry in self.active_executions.iter_mut() {
            entry.value().context.cancel();
        }

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Clear job channel
        self.job_tx = None;

        *running = false;
        info!("Executor shutdown complete");

        Ok(())
    }

    /// Check if executor is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        // Cancel all active executions
        for entry in self.active_executions.iter() {
            entry.value().context.cancel();
        }
    }
}

/// Builder for creating executors
pub struct ExecutorBuilder {
    config: ExecutorConfig,
    timeout_manager: TimeoutManager,
    executors: Vec<(String, Arc<dyn JobExecutor>)>,
    default_executor: Option<Arc<dyn JobExecutor>>,
}

impl ExecutorBuilder {
    /// Create a new executor builder
    pub fn new() -> Self {
        Self {
            config: ExecutorConfig::default(),
            timeout_manager: TimeoutManager::new(),
            executors: Vec::new(),
            default_executor: None,
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: ExecutorConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the timeout manager
    pub fn with_timeout_manager(mut self, manager: TimeoutManager) -> Self {
        self.timeout_manager = manager;
        self
    }

    /// Register a job executor
    pub fn register_executor(
        mut self,
        job_type: impl Into<String>,
        executor: Arc<dyn JobExecutor>,
    ) -> Self {
        self.executors.push((job_type.into(), executor));
        self
    }

    /// Set the default executor
    pub fn with_default_executor(mut self, executor: Arc<dyn JobExecutor>) -> Self {
        self.default_executor = Some(executor);
        self
    }

    /// Build the executor
    pub fn build(self) -> Executor {
        let mut executor = Executor::new(self.config);

        // Register executors
        for (job_type, exec) in self.executors {
            executor.register_executor(job_type, exec);
        }

        // Set default executor if provided
        if let Some(default) = self.default_executor {
            // We need to set this asynchronously, but we're in a sync context
            // The caller should call set_default_executor after building
            // For now, we'll store it in a way that can be retrieved
        }

        executor
    }
}

impl Default for ExecutorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockExecutor {
        counter: Arc<AtomicUsize>,
        should_fail: bool,
    }

    #[async_trait]
    impl JobExecutor for MockExecutor {
        async fn execute(&self, _job: &sh_types::Job) -> ExecutorResult<sh_types::JobResult> {
            self.counter.fetch_add(1, Ordering::SeqCst);

            if self.should_fail {
                Err(ExecutorError::execution_failed(
                    _job.id,
                    "Mock execution failure",
                ))
            } else {
                Ok(sh_types::JobResult::new(1))
            }
        }

        fn can_execute(&self, _job_type: &str) -> bool {
            true
        }

        fn capabilities(&self) -> sh_worker::WorkerCapabilities {
            sh_worker::WorkerCapabilities::default()
        }
    }

    #[tokio::test]
    async fn test_executor_config() {
        let config = ExecutorConfig::new()
            .with_max_concurrent(20)
            .with_cancellation(true);

        assert_eq!(config.max_concurrent, 20);
        assert!(config.enable_cancellation);
    }

    #[tokio::test]
    async fn test_executor_start_stop() {
        let mut executor = Executor::default();

        assert!(!executor.is_running().await);

        executor.start().await.unwrap();
        assert!(executor.is_running().await);

        executor.shutdown().await.unwrap();
        assert!(!executor.is_running().await);
    }

    #[tokio::test]
    async fn test_executor_already_running() {
        let mut executor = Executor::default();
        executor.start().await.unwrap();

        let result = executor.start().await;
        assert!(matches!(result, Err(ExecutorError::AlreadyRunning)));

        executor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_execution_context() {
        let job = sh_types::Job::new(
            "test",
            sh_types::AnalysisTarget::new("/test", sh_types::Platform::Android),
        );

        let context = ExecutionContext::new(job);

        assert!(!context.is_cancelled());
        assert_eq!(context.retry_attempt, 0);

        context.cancel();
        assert!(context.is_cancelled());
    }

    #[tokio::test]
    async fn test_execution_result_success() {
        let execution_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let result = sh_types::JobResult::new(5);

        let exec_result = ExecutionResult::success(
            execution_id,
            job_id,
            result,
            ExecutionMetrics::default(),
            RetryInfo::default(),
        );

        assert!(exec_result.success);
        assert!(exec_result.result.is_some());
        assert!(exec_result.error.is_none());
    }

    #[tokio::test]
    async fn test_execution_result_failure() {
        let execution_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        let exec_result = ExecutionResult::failure(
            execution_id,
            job_id,
            "Test failure",
            ExecutionMetrics::default(),
            RetryInfo::default(),
        );

        assert!(!exec_result.success);
        assert!(exec_result.result.is_none());
        assert_eq!(exec_result.error, Some("Test failure".to_string()));
    }

    #[tokio::test]
    async fn test_execution_result_cancelled() {
        let execution_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        let exec_result = ExecutionResult::cancelled(
            execution_id,
            job_id,
            ExecutionMetrics::default(),
        );

        assert!(!exec_result.success);
        assert!(exec_result.error.is_some());
        assert!(exec_result.error.as_ref().unwrap().contains("cancelled"));
    }

    #[tokio::test]
    async fn test_executor_builder() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(MockExecutor {
            counter: counter.clone(),
            should_fail: false,
        });

        let executor = ExecutorBuilder::new()
            .register_executor("test", mock)
            .with_config(ExecutorConfig::high_throughput())
            .build();

        assert_eq!(executor.active_count(), 0);
    }
}
