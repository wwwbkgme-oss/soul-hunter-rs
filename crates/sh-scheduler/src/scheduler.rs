//! Main Scheduler Implementation
//!
//! The scheduler manages job lifecycle including:
//! - Priority-based job dispatching
//! - Timeout handling
//! - Retry logic with exponential backoff
//! - Job status tracking
//! - Concurrent job execution

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use futures::future::join_all;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{interval, sleep, timeout as tokio_timeout, Instant};
use tracing::{debug, error, info, trace, warn};

use sh_types::{Job, JobId, JobPriority, JobResult, JobStatus, QueueStats};

use crate::priority_queue::{JobPriorityQueue, PriorityQueueError};

/// Configuration for the scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum number of jobs in the priority queue
    pub max_queue_size: usize,
    /// Default timeout for jobs (in seconds)
    pub default_timeout_secs: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay in milliseconds
    pub retry_initial_delay_ms: u64,
    /// Maximum retry delay in milliseconds
    pub retry_max_delay_ms: u64,
    /// Backoff multiplier for retries
    pub retry_backoff_multiplier: f64,
    /// Number of concurrent workers
    pub worker_count: usize,
    /// Interval for cleanup of completed jobs (in seconds)
    pub cleanup_interval_secs: u64,
    /// How long to keep completed jobs before cleanup (in seconds)
    pub completed_job_ttl_secs: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10000,
            default_timeout_secs: 1800, // 30 minutes
            max_retries: 3,
            retry_initial_delay_ms: 1000,
            retry_max_delay_ms: 60000,
            retry_backoff_multiplier: 2.0,
            worker_count: 4,
            cleanup_interval_secs: 60,
            completed_job_ttl_secs: 3600, // 1 hour
        }
    }
}

/// Job with execution metadata
#[derive(Debug, Clone)]
pub struct ScheduledJob {
    pub job: Job,
    pub scheduled_at: Instant,
    pub retry_after: Option<Instant>,
}

impl ScheduledJob {
    pub fn new(job: Job) -> Self {
        Self {
            job,
            scheduled_at: Instant::now(),
            retry_after: None,
        }
    }
}

/// Job completion callback type
pub type JobCompletionCallback = Arc<dyn Fn(JobId, Result<JobResult, SchedulerError>) + Send + Sync>;

/// Job executor trait for custom job execution logic
#[async_trait::async_trait]
pub trait JobExecutor: Send + Sync {
    /// Execute a job and return the result
    async fn execute(&self, job: &Job) -> Result<JobResult, SchedulerError>;
}

/// Default job executor that simulates execution
pub struct DefaultJobExecutor;

#[async_trait::async_trait]
impl JobExecutor for DefaultJobExecutor {
    async fn execute(&self, _job: &Job) -> Result<JobResult, SchedulerError> {
        // Default implementation - just return empty result
        // Real implementations should override this
        Ok(JobResult::new(0))
    }
}

/// The main scheduler struct
///
/// Manages job lifecycle from submission through completion,
/// including retries, timeouts, and concurrent execution.
pub struct Scheduler {
    config: SchedulerConfig,
    /// Priority queue for pending jobs
    priority_queue: JobPriorityQueue,
    /// Map of active (running) jobs
    active_jobs: DashMap<JobId, ScheduledJob>,
    /// Map of completed/failed jobs (for result retrieval)
    completed_jobs: DashMap<JobId, ScheduledJob>,
    /// Retry queue: job_id -> retry time
    retry_queue: Arc<Mutex<HashMap<JobId, Instant>>>,
    /// Channel for job dispatching to workers
    job_tx: mpsc::UnboundedSender<Job>,
    job_rx: Arc<Mutex<mpsc::UnboundedReceiver<Job>>>,
    /// Shutdown signal
    shutdown_notify: Arc<Notify>,
    /// Job executor
    executor: Arc<dyn JobExecutor>,
    /// Completion callbacks
    callbacks: Arc<RwLock<HashMap<JobId, Vec<JobCompletionCallback>>>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
}

impl Scheduler {
    /// Create a new scheduler with the given configuration
    pub fn new(config: SchedulerConfig) -> Self {
        let (job_tx, job_rx) = mpsc::unbounded_channel();

        Self {
            config: config.clone(),
            priority_queue: JobPriorityQueue::new(config.max_queue_size),
            active_jobs: DashMap::new(),
            completed_jobs: DashMap::new(),
            retry_queue: Arc::new(Mutex::new(HashMap::new())),
            job_tx,
            job_rx: Arc::new(Mutex::new(job_rx)),
            shutdown_notify: Arc::new(Notify::new()),
            executor: Arc::new(DefaultJobExecutor),
            callbacks: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Create a new scheduler with a custom executor
    pub fn with_executor(config: SchedulerConfig, executor: Arc<dyn JobExecutor>) -> Self {
        let (job_tx, job_rx) = mpsc::unbounded_channel();

        Self {
            config: config.clone(),
            priority_queue: JobPriorityQueue::new(config.max_queue_size),
            active_jobs: DashMap::new(),
            completed_jobs: DashMap::new(),
            retry_queue: Arc::new(Mutex::new(HashMap::new())),
            job_tx,
            job_rx: Arc::new(Mutex::new(job_rx)),
            shutdown_notify: Arc::new(Notify::new()),
            executor,
            callbacks: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Submit a job to the scheduler
    ///
    /// The job will be added to the priority queue and processed
    /// according to its priority.
    pub async fn submit(&self, job: Job) -> Result<JobId, SchedulerError> {
        let job_id = job.id;

        // Check if job already exists
        if self.active_jobs.contains_key(&job_id) {
            return Err(SchedulerError::DuplicateJob(job_id));
        }

        // Add to priority queue
        self.priority_queue.push(job).await.map_err(|e| match e {
            PriorityQueueError::QueueFull(max) => SchedulerError::QueueFull(max),
            PriorityQueueError::JobNotFound(_) => SchedulerError::InternalError("Unexpected error".to_string()),
        })?;

        info!("Job {} submitted to scheduler", job_id);
        Ok(job_id)
    }

    /// Submit a job with a completion callback
    pub async fn submit_with_callback(
        &self,
        job: Job,
        callback: JobCompletionCallback,
    ) -> Result<JobId, SchedulerError> {
        let job_id = job.id;

        // Register callback
        let mut callbacks = self.callbacks.write().await;
        callbacks.entry(job_id).or_default().push(callback);
        drop(callbacks);

        self.submit(job).await
    }

    /// Cancel a pending or running job
    pub async fn cancel(&self, job_id: JobId) -> Result<(), SchedulerError> {
        // Try to remove from priority queue first
        if let Some(job) = self.priority_queue.remove(job_id).await {
            let mut job = job;
            job.status = JobStatus::Cancelled;
            self.completed_jobs.insert(job_id, ScheduledJob::new(job));
            info!("Job {} cancelled (was in queue)", job_id);
            return Ok(());
        }

        // Check if it's running
        if let Some((_, mut scheduled)) = self.active_jobs.remove(&job_id) {
            scheduled.job.status = JobStatus::Cancelled;
            self.completed_jobs.insert(job_id, scheduled);
            info!("Job {} cancelled (was running)", job_id);
            return Ok(());
        }

        Err(SchedulerError::JobNotFound(job_id))
    }

    /// Get the status of a job
    pub fn get_status(&self, job_id: JobId) -> Option<JobStatus> {
        if let Some(entry) = self.active_jobs.get(&job_id) {
            return Some(entry.value().job.status);
        }
        if let Some(entry) = self.completed_jobs.get(&job_id) {
            return Some(entry.value().job.status);
        }
        None
    }

    /// Get a job by ID
    pub fn get_job(&self, job_id: JobId) -> Option<Job> {
        if let Some(entry) = self.active_jobs.get(&job_id) {
            return Some(entry.value().job.clone());
        }
        if let Some(entry) = self.completed_jobs.get(&job_id) {
            return Some(entry.value().job.clone());
        }
        None
    }

    /// Get the result of a completed job
    pub fn get_result(&self, job_id: JobId) -> Option<JobResult> {
        self.completed_jobs.get(&job_id).and_then(|entry| {
            entry.value().job.result.clone()
        })
    }

    /// Get current queue statistics
    pub async fn get_stats(&self) -> QueueStats {
        let pending = self.priority_queue.len().await;
        let running = self.active_jobs.len();
        let completed = self.completed_jobs.len();

        QueueStats {
            pending: pending.try_into().unwrap_or(0),
            running: running.try_into().unwrap_or(0),
            completed: completed.try_into().unwrap_or(0),
            failed: 0, // Calculated below
            total: (pending + running + completed).try_into().unwrap_or(0),
            avg_wait_time_ms: 0, // TODO: Calculate from actual data
            avg_execution_time_ms: 0, // TODO: Calculate from actual data
        }
    }

    /// Start the scheduler
    ///
    /// This will start the worker pool and background tasks.
    pub async fn start(&self) -> Result<(), SchedulerError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(SchedulerError::AlreadyRunning);
        }
        *is_running = true;
        drop(is_running);

        info!("Starting scheduler with {} workers", self.config.worker_count);

        // Start worker tasks
        let mut worker_handles = Vec::new();
        for worker_id in 0..self.config.worker_count {
            let handle = self.spawn_worker(worker_id).await;
            worker_handles.push(handle);
        }

        // Start background tasks
        let scheduler = Arc::new(self.clone_scheduler());
        tokio::spawn(Self::dispatch_loop(scheduler.clone()));
        tokio::spawn(Self::retry_loop(scheduler.clone()));
        tokio::spawn(Self::cleanup_loop(scheduler, self.config.cleanup_interval_secs));

        info!("Scheduler started successfully");
        Ok(())
    }

    /// Shutdown the scheduler gracefully
    pub async fn shutdown(&self) {
        info!("Initiating scheduler shutdown...");

        let mut is_running = self.is_running.write().await;
        *is_running = false;
        drop(is_running);

        self.shutdown_notify.notify_waiters();

        // Wait for active jobs to complete (with timeout)
        let timeout_duration = Duration::from_secs(30);
        let start = Instant::now();

        while !self.active_jobs.is_empty() && start.elapsed() < timeout_duration {
            sleep(Duration::from_millis(100)).await;
        }

        if !self.active_jobs.is_empty() {
            warn!("{} jobs still active after shutdown timeout", self.active_jobs.len());
        }

        info!("Scheduler shutdown complete");
    }

    /// Clone the scheduler for use in spawned tasks
    fn clone_scheduler(&self) -> Self {
        // Create a new scheduler with same config but shared state
        let (job_tx, job_rx) = mpsc::unbounded_channel();

        Self {
            config: self.config.clone(),
            priority_queue: self.priority_queue.clone(),
            active_jobs: self.active_jobs.clone(),
            completed_jobs: self.completed_jobs.clone(),
            retry_queue: Arc::clone(&self.retry_queue),
            job_tx,
            job_rx: Arc::new(Mutex::new(job_rx)),
            shutdown_notify: Arc::clone(&self.shutdown_notify),
            executor: Arc::clone(&self.executor),
            callbacks: Arc::clone(&self.callbacks),
            is_running: Arc::clone(&self.is_running),
        }
    }

    /// Spawn a worker task
    async fn spawn_worker(&self, worker_id: usize) -> tokio::task::JoinHandle<()> {
        let job_rx = Arc::clone(&self.job_rx);
        let active_jobs = self.active_jobs.clone();
        let completed_jobs = self.completed_jobs.clone();
        let executor = Arc::clone(&self.executor);
        let callbacks = Arc::clone(&self.callbacks);
        let config = self.config.clone();
        let shutdown = Arc::clone(&self.shutdown_notify);

        tokio::spawn(async move {
            info!("Worker {} started", worker_id);

            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        debug!("Worker {} received shutdown signal", worker_id);
                        break;
                    }
                    result = async {
                        let mut rx = job_rx.lock().await;
                        rx.recv().await
                    } => {
                        match result {
                            Some(job) => {
                                Self::execute_job(
                                    worker_id,
                                    job,
                                    &active_jobs,
                                    &completed_jobs,
                                    &executor,
                                    &callbacks,
                                    &config,
                                ).await;
                            }
                            None => {
                                debug!("Worker {}: job channel closed", worker_id);
                                break;
                            }
                        }
                    }
                }
            }

            info!("Worker {} stopped", worker_id);
        })
    }

    /// Execute a single job
    async fn execute_job(
        worker_id: usize,
        mut job: Job,
        active_jobs: &DashMap<JobId, ScheduledJob>,
        completed_jobs: &DashMap<JobId, ScheduledJob>,
        executor: &Arc<dyn JobExecutor>,
        callbacks: &Arc<RwLock<HashMap<JobId, Vec<JobCompletionCallback>>>>,
        config: &SchedulerConfig,
    ) {
        let job_id = job.id;
        let timeout_secs = job.timeout_secs.unwrap_or(config.default_timeout_secs);

        // Mark as running
        job.mark_started(format!("worker-{}", worker_id));
        active_jobs.insert(job_id, ScheduledJob::new(job.clone()));

        trace!("Worker {} executing job {}", worker_id, job_id);

        // Execute with timeout
        let result = tokio_timeout(
            Duration::from_secs(timeout_secs),
            executor.execute(&job)
        ).await;

        // Remove from active
        active_jobs.remove(&job_id);

        // Process result
        let final_result = match result {
            Ok(Ok(job_result)) => {
                job.mark_completed(job_result.clone());
                info!("Job {} completed successfully", job_id);
                Ok(job_result)
            }
            Ok(Err(e)) => {
                job.mark_failed(e.to_string());
                error!("Job {} failed: {}", job_id, e);
                Err(e)
            }
            Err(_) => {
                job.mark_timeout();
                warn!("Job {} timed out after {} seconds", job_id, timeout_secs);
                Err(SchedulerError::Timeout(job_id))
            }
        };

        // Store completed job
        completed_jobs.insert(job_id, ScheduledJob::new(job.clone()));

        // Trigger callbacks
        if let Ok(callbacks_list) = callbacks.try_read() {
            if let Some(cb_list) = callbacks_list.get(&job_id) {
                for cb in cb_list {
                    cb(job_id, final_result.clone());
                }
            }
        }
    }

    /// Main dispatch loop - moves jobs from priority queue to workers
    async fn dispatch_loop(scheduler: Arc<Scheduler>) {
        let mut interval = interval(Duration::from_millis(10));

        loop {
            interval.tick().await;

            // Check if running
            if !*scheduler.is_running.read().await {
                break;
            }

            // Try to get next job from priority queue
            if let Some(job) = scheduler.priority_queue.pop().await {
                let job_id = job.id;
                trace!("Dispatching job {} to workers", job_id);

                if let Err(e) = scheduler.job_tx.send(job) {
                    error!("Failed to dispatch job {}: {}", job_id, e);
                }
            }
        }

        debug!("Dispatch loop ended");
    }

    /// Retry loop - processes jobs in the retry queue
    async fn retry_loop(scheduler: Arc<Scheduler>) {
        let mut interval = interval(Duration::from_secs(1));

        loop {
            interval.tick().await;

            // Check if running
            if !*scheduler.is_running.read().await {
                break;
            }

            // Process retry queue
            let now = Instant::now();
            let mut retry_jobs = Vec::new();

            {
                let mut retry_queue = scheduler.retry_queue.lock().await;
                let ready: Vec<JobId> = retry_queue
                    .iter()
                    .filter(|(_, &time)| time <= now)
                    .map(|(id, _)| *id)
                    .collect();

                for job_id in ready {
                    if let Some((id, _)) = retry_queue.remove_entry(&job_id) {
                        retry_jobs.push(id);
                    }
                }
            }

            // Re-submit retry jobs
            for job_id in retry_jobs {
                if let Some((_, scheduled)) = scheduler.completed_jobs.remove(&job_id) {
                    let mut job = scheduled.job;
                    if job.can_retry() {
                        job.retry_count += 1;
                        job.status = JobStatus::Pending;
                        job.error = None;

                        info!(
                            "Retrying job {} (attempt {}/{})",
                            job_id, job.retry_count, job.max_retries
                        );

                        if let Err(e) = scheduler.submit(job).await {
                            error!("Failed to retry job {}: {}", job_id, e);
                        }
                    }
                }
            }
        }

        debug!("Retry loop ended");
    }

    /// Cleanup loop - removes old completed jobs
    async fn cleanup_loop(scheduler: Arc<Scheduler>, interval_secs: u64) {
        let mut interval = interval(Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            // Check if running
            if !*scheduler.is_running.read().await {
                break;
            }

            let cutoff = Utc::now() - chrono::Duration::seconds(scheduler.config.completed_job_ttl_secs as i64);
            let mut to_remove = Vec::new();

            for entry in scheduler.completed_jobs.iter() {
                if let Some(completed_at) = entry.value().job.completed_at {
                    if completed_at < cutoff {
                        to_remove.push(*entry.key());
                    }
                }
            }

            let count = to_remove.len();
            for job_id in to_remove {
                scheduler.completed_jobs.remove(&job_id);
            }

            if count > 0 {
                debug!("Cleaned up {} completed jobs", count);
            }
        }

        debug!("Cleanup loop ended");
    }

    /// Schedule a job for retry with exponential backoff
    async fn schedule_retry(&self, job_id: JobId) {
        if let Some(scheduled) = self.completed_jobs.get(&job_id) {
            let job = &scheduled.job;
            if job.can_retry() {
                let delay_ms = (self.config.retry_initial_delay_ms as f64
                    * self.config.retry_backoff_multiplier.powi(job.retry_count as i32))
                    .min(self.config.retry_max_delay_ms as f64) as u64;

                let retry_time = Instant::now() + Duration::from_millis(delay_ms);

                let mut retry_queue = self.retry_queue.lock().await;
                retry_queue.insert(job_id, retry_time);
                drop(retry_queue);

                info!(
                    "Scheduled job {} for retry in {}ms (attempt {}/{})",
                    job_id, delay_ms, job.retry_count + 1, job.max_retries
                );
            }
        }
    }
}

impl Clone for Scheduler {
    fn clone(&self) -> Self {
        self.clone_scheduler()
    }
}

/// Scheduler errors
#[derive(Debug, thiserror::Error, Clone)]
pub enum SchedulerError {
    #[error("Queue is full (max capacity: {0})")]
    QueueFull(usize),

    #[error("Job not found: {0}")]
    JobNotFound(JobId),

    #[error("Duplicate job: {0}")]
    DuplicateJob(JobId),

    #[error("Job timed out: {0}")]
    Timeout(JobId),

    #[error("Scheduler is already running")]
    AlreadyRunning,

    #[error("Scheduler is not running")]
    NotRunning,

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform};

    fn create_test_job(job_type: &str) -> Job {
        let target = AnalysisTarget::new("/test", Platform::Android);
        Job::new(job_type, target)
    }

    #[tokio::test]
    async fn test_scheduler_submit() {
        let config = SchedulerConfig {
            max_queue_size: 10,
            ..Default::default()
        };
        let scheduler = Scheduler::new(config);

        let job = create_test_job("test");
        let job_id = job.id;

        let result = scheduler.submit(job).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), job_id);
    }

    #[tokio::test]
    async fn test_scheduler_duplicate_job() {
        let scheduler = Scheduler::new(SchedulerConfig::default());

        let job = create_test_job("test");
        let job_clone = job.clone();

        scheduler.submit(job).await.unwrap();

        let result = scheduler.submit(job_clone).await;
        assert!(matches!(result, Err(SchedulerError::DuplicateJob(_))));
    }

    #[tokio::test]
    async fn test_scheduler_cancel() {
        let scheduler = Scheduler::new(SchedulerConfig::default());

        let job = create_test_job("test");
        let job_id = job.id;

        scheduler.submit(job).await.unwrap();

        let result = scheduler.cancel(job_id).await;
        assert!(result.is_ok());

        let status = scheduler.get_status(job_id);
        assert_eq!(status, Some(JobStatus::Cancelled));
    }

    #[tokio::test]
    async fn test_scheduler_get_job() {
        let scheduler = Scheduler::new(SchedulerConfig::default());

        let job = create_test_job("test");
        let job_id = job.id;

        scheduler.submit(job.clone()).await.unwrap();

        let retrieved = scheduler.get_job(job_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, job_id);
    }

    #[tokio::test]
    async fn test_scheduler_stats() {
        let scheduler = Scheduler::new(SchedulerConfig::default());

        let stats = scheduler.get_stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.running, 0);
        assert_eq!(stats.total, 0);

        let job = create_test_job("test");
        scheduler.submit(job).await.unwrap();

        let stats = scheduler.get_stats();
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.total, 1);
    }
}
