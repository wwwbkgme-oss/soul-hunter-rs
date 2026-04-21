//! Individual worker implementation
//!
//! Each worker runs in its own tokio task and processes jobs from the pool's
//! job channel. Workers maintain their own health state and report back to
//! the pool via the shared state.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::{
    ExecutionId, ExecutionMetrics, JobExecutionResult, JobProcessor, SharedWorkerState,
    WorkerCapabilities, WorkerId, WorkerResult, WorkerSnapshot,
};
use crate::error::WorkerError;

/// Worker status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    #[default]
    /// Worker is idle and ready to accept jobs
    Idle,
    /// Worker is currently processing a job
    Busy,
    /// Worker is shutting down
    ShuttingDown,
    /// Worker has stopped
    Stopped,
    /// Worker is unhealthy
    Unhealthy,
}

impl std::fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerStatus::Idle => write!(f, "idle"),
            WorkerStatus::Busy => write!(f, "busy"),
            WorkerStatus::ShuttingDown => write!(f, "shutting_down"),
            WorkerStatus::Stopped => write!(f, "stopped"),
            WorkerStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Worker health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHealth {
    /// Whether the worker is healthy
    pub is_healthy: bool,
    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,
    /// Time since last heartbeat in seconds
    pub seconds_since_heartbeat: i64,
    /// Consecutive health check failures
    pub consecutive_failures: u32,
    /// Average job execution time in ms
    pub avg_job_duration_ms: f64,
    /// Current memory usage in MB (if available)
    pub memory_usage_mb: Option<u64>,
    /// Current CPU usage percentage (if available)
    pub cpu_usage_percent: Option<f64>,
}

/// Worker state for external observation
#[derive(Debug, Clone)]
pub struct WorkerState {
    /// Worker ID
    pub id: WorkerId,
    /// Current status
    pub status: WorkerStatus,
    /// Current job being processed
    pub current_job: Option<sh_types::JobId>,
    /// Total jobs completed
    pub jobs_completed: u64,
    /// Total jobs failed
    pub jobs_failed: u64,
    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,
    /// Worker capabilities
    pub capabilities: WorkerCapabilities,
    /// When the worker started
    pub started_at: DateTime<Utc>,
}

/// Internal job message sent to workers
#[derive(Debug)]
pub(crate) struct WorkerJob {
    /// The job to execute
    pub job: sh_types::Job,
    /// Channel to send result back
    pub result_tx: oneshot::Sender<JobExecutionResult>,
    /// When the job was queued
    pub queued_at: DateTime<Utc>,
}

/// Handle to control a worker
pub struct WorkerHandle {
    /// Worker ID
    pub id: WorkerId,
    /// Join handle for the worker task
    task_handle: Mutex<Option<JoinHandle<()>>>,
    /// Shared state for health monitoring
    shared_state: Arc<SharedWorkerState>,
    /// Worker capabilities
    capabilities: WorkerCapabilities,
    /// Shutdown signal sender
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl WorkerHandle {
    /// Get current worker state snapshot
    pub async fn snapshot(&self) -> WorkerSnapshot {
        let current_job = *self.shared_state.current_job.read().await;
        let jobs_completed = *self.shared_state.jobs_completed.read().await;
        let jobs_failed = *self.shared_state.jobs_failed.read().await;
        let last_heartbeat = *self.shared_state.last_heartbeat.read().await;
        let avg_duration = self.shared_state.avg_job_duration_ms().await;
        
        WorkerSnapshot {
            worker_id: self.id.clone(),
            status: if current_job.is_some() {
                WorkerStatus::Busy
            } else {
                WorkerStatus::Idle
            },
            current_job,
            jobs_completed,
            jobs_failed,
            avg_job_duration_ms: avg_duration,
            last_heartbeat,
            capabilities: self.capabilities.clone(),
        }
    }
    
    /// Get worker health information
    pub async fn health(&self) -> WorkerHealth {
        let last_heartbeat = *self.shared_state.last_heartbeat.read().await;
        let seconds_since_heartbeat = (Utc::now() - last_heartbeat).num_seconds();
        let avg_duration = self.shared_state.avg_job_duration_ms().await;
        
        WorkerHealth {
            is_healthy: seconds_since_heartbeat < 60, // Consider unhealthy if no heartbeat for 60s
            last_heartbeat,
            seconds_since_heartbeat,
            consecutive_failures: 0, // TODO: Track consecutive failures
            avg_job_duration_ms: avg_duration,
            memory_usage_mb: None, // TODO: Implement memory tracking
            cpu_usage_percent: None, // TODO: Implement CPU tracking
        }
    }
    
    /// Check if worker is healthy
    pub async fn is_healthy(&self) -> bool {
        let health = self.health().await;
        health.is_healthy
    }
    
    /// Stop the worker gracefully
    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        
        if let Some(handle) = self.task_handle.lock().await.take() {
            // Give the worker a chance to shut down gracefully
            tokio::time::timeout(Duration::from_secs(5), handle).await.ok();
        }
    }
    
    /// Abort the worker immediately
    pub async fn abort(&self) {
        if let Some(handle) = self.task_handle.lock().await.take() {
            handle.abort();
        }
    }
}

/// Individual worker that processes jobs
pub struct Worker {
    /// Worker ID
    id: WorkerId,
    /// Job receiver channel
    job_rx: Arc<Mutex<mpsc::UnboundedReceiver<WorkerJob>>>,
    /// Shared state for health monitoring
    shared_state: Arc<SharedWorkerState>,
    /// Worker capabilities
    capabilities: WorkerCapabilities,
    /// Job processor
    processor: Arc<dyn JobProcessor>,
    /// Heartbeat interval in seconds
    heartbeat_interval_secs: u64,
    /// Default job timeout in seconds
    default_timeout_secs: u64,
}

impl Worker {
    /// Create a new worker
    pub fn new(
        id: impl Into<WorkerId>,
        job_rx: mpsc::UnboundedReceiver<WorkerJob>,
        processor: Arc<dyn JobProcessor>,
        capabilities: WorkerCapabilities,
        heartbeat_interval_secs: u64,
        default_timeout_secs: u64,
    ) -> Self {
        Self {
            id: id.into(),
            job_rx: Arc::new(Mutex::new(job_rx)),
            shared_state: Arc::new(SharedWorkerState::new()),
            capabilities,
            processor,
            heartbeat_interval_secs,
            default_timeout_secs,
        }
    }
    
    /// Get the worker ID
    pub fn id(&self) -> &WorkerId {
        &self.id
    }
    
    /// Start the worker and return a handle
    pub fn start(self) -> WorkerHandle {
        let id = self.id.clone();
        let shared_state = self.shared_state.clone();
        let capabilities = self.capabilities.clone();
        
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        
        let task_handle = tokio::spawn(async move {
            self.run(shutdown_rx).await;
        });
        
        WorkerHandle {
            id,
            task_handle: Mutex::new(Some(task_handle)),
            shared_state,
            capabilities,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }
    }
    
    /// Main worker loop
    async fn run(self, mut shutdown_rx: oneshot::Receiver<()>) {
        info!(worker_id = %self.id, "Worker started");
        
        // Start heartbeat task
        let heartbeat_handle = self.spawn_heartbeat_task();
        
        let mut job_rx = self.job_rx.lock().await;
        
        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = &mut shutdown_rx => {
                    info!(worker_id = %self.id, "Worker received shutdown signal");
                    break;
                }
                
                // Wait for jobs
                Some(worker_job) = job_rx.recv() => {
                    trace!(worker_id = %self.id, job_id = %worker_job.job.id, "Received job");
                    
                    // Update current job
                    {
                        let mut current = self.shared_state.current_job.write().await;
                        *current = Some(worker_job.job.id);
                    }
                    
                    // Execute the job
                    let result = self.execute_job(&worker_job).await;
                    
                    // Send result back
                    if let Err(_) = worker_job.result_tx.send(result) {
                        warn!(worker_id = %self.id, job_id = %worker_job.job.id, "Failed to send job result - receiver dropped");
                    }
                    
                    // Clear current job
                    {
                        let mut current = self.shared_state.current_job.write().await;
                        *current = None;
                    }
                }
            }
        }
        
        // Cleanup
        drop(job_rx);
        heartbeat_handle.abort();
        info!(worker_id = %self.id, "Worker stopped");
    }
    
    /// Spawn heartbeat task
    fn spawn_heartbeat_task(&self) -> JoinHandle<()> {
        let shared_state = self.shared_state.clone();
        let worker_id = self.id.clone();
        let interval_secs = self.heartbeat_interval_secs;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            
            loop {
                interval.tick().await;
                shared_state.update_heartbeat().await;
                trace!(worker_id = %worker_id, "Heartbeat");
            }
        })
    }
    
    /// Execute a single job
    async fn execute_job(&self, worker_job: &WorkerJob) -> JobExecutionResult {
        let job = &worker_job.job;
        let execution_id = Uuid::new_v4();
        let started_at = Utc::now();
        
        let queue_time_ms = (started_at - worker_job.queued_at).num_milliseconds() as u64;
        
        info!(
            worker_id = %self.id,
            job_id = %job.id,
            execution_id = %execution_id,
            job_type = %job.job_type,
            "Starting job execution"
        );
        
        // Determine timeout
        let timeout_secs = job.timeout_secs.unwrap_or(self.default_timeout_secs);
        
        // Execute with timeout
        let execution_result = timeout(
            Duration::from_secs(timeout_secs),
            self.processor.process(job)
        ).await;
        
        let completed_at = Utc::now();
        let execution_time_ms = (completed_at - started_at).num_milliseconds() as u64;
        
        match execution_result {
            Ok(Ok(job_result)) => {
                // Success
                self.shared_state.record_completion(execution_time_ms).await;
                
                info!(
                    worker_id = %self.id,
                    job_id = %job.id,
                    execution_id = %execution_id,
                    execution_time_ms = execution_time_ms,
                    "Job completed successfully"
                );
                
                JobExecutionResult {
                    execution_id,
                    worker_id: self.id.clone(),
                    job_id: job.id,
                    success: true,
                    result: Some(job_result),
                    error: None,
                    metrics: ExecutionMetrics {
                        queue_time_ms,
                        execution_time_ms,
                        total_time_ms: queue_time_ms + execution_time_ms,
                        memory_usage_mb: 0, // TODO: Implement memory tracking
                        cpu_usage_percent: 0.0, // TODO: Implement CPU tracking
                    },
                    started_at,
                    completed_at,
                }
            }
            Ok(Err(e)) => {
                // Processor returned an error
                self.shared_state.record_failure().await;
                
                error!(
                    worker_id = %self.id,
                    job_id = %job.id,
                    execution_id = %execution_id,
                    error = %e,
                    "Job execution failed"
                );
                
                JobExecutionResult {
                    execution_id,
                    worker_id: self.id.clone(),
                    job_id: job.id,
                    success: false,
                    result: None,
                    error: Some(e.to_string()),
                    metrics: ExecutionMetrics {
                        queue_time_ms,
                        execution_time_ms,
                        total_time_ms: queue_time_ms + execution_time_ms,
                        memory_usage_mb: 0,
                        cpu_usage_percent: 0.0,
                    },
                    started_at,
                    completed_at,
                }
            }
            Err(_) => {
                // Timeout
                self.shared_state.record_failure().await;
                
                error!(
                    worker_id = %self.id,
                    job_id = %job.id,
                    execution_id = %execution_id,
                    timeout_secs = timeout_secs,
                    "Job execution timed out"
                );
                
                JobExecutionResult {
                    execution_id,
                    worker_id: self.id.clone(),
                    job_id: job.id,
                    success: false,
                    result: None,
                    error: Some(format!("Job timed out after {} seconds", timeout_secs)),
                    metrics: ExecutionMetrics {
                        queue_time_ms,
                        execution_time_ms: timeout_secs * 1000,
                        total_time_ms: queue_time_ms + (timeout_secs * 1000),
                        memory_usage_mb: 0,
                        cpu_usage_percent: 0.0,
                    },
                    started_at,
                    completed_at,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    
    struct MockProcessor {
        should_succeed: bool,
        delay_ms: u64,
    }
    
    #[async_trait]
    impl JobProcessor for MockProcessor {
        async fn process(&self, _job: &sh_types::Job) -> WorkerResult<sh_types::JobResult> {
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }
            
            if self.should_succeed {
                Ok(sh_types::JobResult::new(0))
            } else {
                Err(WorkerError::Internal("Mock failure".to_string()))
            }
        }
        
        fn can_process(&self, _job_type: &str) -> bool {
            true
        }
        
        fn capabilities(&self) -> WorkerCapabilities {
            WorkerCapabilities::default()
        }
    }
    
    #[tokio::test]
    async fn test_worker_job_execution_success() {
        let (tx, rx) = mpsc::unbounded_channel();
        let processor = Arc::new(MockProcessor {
            should_succeed: true,
            delay_ms: 10,
        });
        
        let worker = Worker::new(
            "test-worker",
            rx,
            processor,
            WorkerCapabilities::default(),
            1,
            30,
        );
        
        let handle = worker.start();
        
        // Create a test job
        let target = sh_types::AnalysisTarget::new("/test", sh_types::Platform::Android);
        let job = sh_types::Job::new("test_job", target);
        
        let (result_tx, result_rx) = oneshot::channel();
        let worker_job = WorkerJob {
            job,
            result_tx,
            queued_at: Utc::now(),
        };
        
        tx.send(worker_job).unwrap();
        
        let result = result_rx.await.expect("Should receive result");
        assert!(result.success);
        assert!(result.result.is_some());
        assert!(result.error.is_none());
        
        handle.stop().await;
    }
    
    #[tokio::test]
    async fn test_worker_job_execution_failure() {
        let (tx, rx) = mpsc::unbounded_channel();
        let processor = Arc::new(MockProcessor {
            should_succeed: false,
            delay_ms: 0,
        });
        
        let worker = Worker::new(
            "test-worker",
            rx,
            processor,
            WorkerCapabilities::default(),
            1,
            30,
        );
        
        let handle = worker.start();
        
        let target = sh_types::AnalysisTarget::new("/test", sh_types::Platform::Android);
        let job = sh_types::Job::new("test_job", target);
        
        let (result_tx, result_rx) = oneshot::channel();
        let worker_job = WorkerJob {
            job,
            result_tx,
            queued_at: Utc::now(),
        };
        
        tx.send(worker_job).unwrap();
        
        let result = result_rx.await.expect("Should receive result");
        assert!(!result.success);
        assert!(result.error.is_some());
        
        handle.stop().await;
    }
    
    #[tokio::test]
    async fn test_worker_job_timeout() {
        let (tx, rx) = mpsc::unbounded_channel();
        let processor = Arc::new(MockProcessor {
            should_succeed: true,
            delay_ms: 5000, // Long delay
        });
        
        let worker = Worker::new(
            "test-worker",
            rx,
            processor,
            WorkerCapabilities::default(),
            1,
            1, // 1 second timeout
        );
        
        let handle = worker.start();
        
        let target = sh_types::AnalysisTarget::new("/test", sh_types::Platform::Android);
        let job = sh_types::Job::new("test_job", target);
        
        let (result_tx, result_rx) = oneshot::channel();
        let worker_job = WorkerJob {
            job,
            result_tx,
            queued_at: Utc::now(),
        };
        
        tx.send(worker_job).unwrap();
        
        let result = result_rx.await.expect("Should receive result");
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("timed out"));
        
        handle.stop().await;
    }
    
    #[tokio::test]
    async fn test_worker_health() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let processor = Arc::new(MockProcessor {
            should_succeed: true,
            delay_ms: 0,
        });
        
        let worker = Worker::new(
            "test-worker",
            rx,
            processor,
            WorkerCapabilities::default(),
            1,
            30,
        );
        
        let handle = worker.start();
        
        // Wait for heartbeat
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let health = handle.health().await;
        assert!(health.is_healthy);
        assert!(health.seconds_since_heartbeat < 1);
        
        handle.stop().await;
    }
    
    #[tokio::test]
    async fn test_worker_snapshot() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let processor = Arc::new(MockProcessor {
            should_succeed: true,
            delay_ms: 0,
        });
        
        let worker = Worker::new(
            "test-worker",
            rx,
            processor,
            WorkerCapabilities::default(),
            1,
            30,
        );
        
        let handle = worker.start();
        
        let snapshot = handle.snapshot().await;
        assert_eq!(snapshot.worker_id, "test-worker");
        assert_eq!(snapshot.status, WorkerStatus::Idle);
        assert_eq!(snapshot.jobs_completed, 0);
        
        handle.stop().await;
    }
}
