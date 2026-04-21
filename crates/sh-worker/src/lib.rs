//! # sh-worker
//!
//! Async worker pool for executing security analysis jobs with health monitoring,
//! dynamic scaling, and timeout handling.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    WorkerPool                               │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │  Worker 1   │  │  Worker 2   │  │  Worker N   │         │
//! │  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
//! │  │ │Job Task │ │  │ │Job Task │ │  │ │Job Task │ │         │
//! │  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
//! │  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
//! │  │ │Health   │ │  │ │Health   │ │  │ │Health   │ │         │
//! │  │ │Monitor  │ │  │ │Monitor  │ │  │ │Monitor  │ │         │
//! │  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
//! │  └─────┬───────┘  └─────┬───────┘  └─────┬───────┘         │
//! │        │                │                │                 │
//! │        └────────────────┴────────────────┘                 │
//! │                         │                                   │
//! │              ┌──────────▼──────────┐                        │
//! │              │   Job Channel       │◄── From Scheduler      │
//! │              └─────────────────────┘                        │
//! │                         │                                   │
//! │              ┌──────────▼──────────┐                        │
//! │              │   Result Channel    │──► To Scheduler         │
//! │              └─────────────────────┘                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Async Job Execution**: Full tokio-based async job processing
//! - **Health Monitoring**: Automatic worker health checks with heartbeat tracking
//! - **Dynamic Scaling**: Scale workers up/down based on queue depth and load
//! - **Timeout Handling**: Configurable job timeouts with graceful cancellation
//! - **Result Reporting**: Structured job results with metrics and artifacts
//! - **Error Recovery**: Automatic retry logic with exponential backoff

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod error;
mod pool;
mod worker;

pub use error::{WorkerError, WorkerResult};
pub use pool::{WorkerPool, WorkerPoolConfig, WorkerPoolStats, ScalingPolicy};
pub use worker::{Worker, WorkerHandle, WorkerHealth, WorkerState, WorkerStatus};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Unique identifier for workers
pub type WorkerId = String;

/// Unique identifier for job executions
pub type ExecutionId = Uuid;

/// Job execution result sent back to the scheduler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecutionResult {
    /// Execution ID
    pub execution_id: ExecutionId,
    /// Worker ID that processed the job
    pub worker_id: WorkerId,
    /// Job ID from the scheduler
    pub job_id: sh_types::JobId,
    /// Whether the job succeeded
    pub success: bool,
    /// Job result data
    pub result: Option<sh_types::JobResult>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution metrics
    pub metrics: ExecutionMetrics,
    /// When execution started
    pub started_at: DateTime<Utc>,
    /// When execution completed
    pub completed_at: DateTime<Utc>,
}

/// Execution metrics for a job
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Time spent in queue (ms)
    pub queue_time_ms: u64,
    /// Actual execution time (ms)
    pub execution_time_ms: u64,
    /// Total time from submission to completion (ms)
    pub total_time_ms: u64,
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
}

/// Worker capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Job types this worker can handle
    pub job_types: Vec<String>,
    /// Platforms supported
    pub platforms: Vec<sh_types::Platform>,
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: usize,
    /// Memory limit in MB
    pub memory_limit_mb: Option<u64>,
    /// CPU limit (percentage)
    pub cpu_limit_percent: Option<f64>,
}

impl Default for WorkerCapabilities {
    fn default() -> Self {
        Self {
            job_types: vec!["*".to_string()], // Can handle all job types by default
            platforms: vec![
                sh_types::Platform::Android,
                sh_types::Platform::Ios,
                sh_types::Platform::Iot,
                sh_types::Platform::Network,
                sh_types::Platform::Web,
            ],
            max_concurrent_jobs: 1,
            memory_limit_mb: None,
            cpu_limit_percent: None,
        }
    }
}

/// Worker statistics snapshot
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerSnapshot {
    /// Worker ID
    pub worker_id: WorkerId,
    /// Current status
    pub status: WorkerStatus,
    /// Current job being processed (if any)
    pub current_job: Option<sh_types::JobId>,
    /// Total jobs completed
    pub jobs_completed: u64,
    /// Total jobs failed
    pub jobs_failed: u64,
    /// Average job duration in ms
    pub avg_job_duration_ms: f64,
    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,
    /// Worker capabilities
    pub capabilities: WorkerCapabilities,
}

/// Trait for job processors
#[async_trait::async_trait]
pub trait JobProcessor: Send + Sync {
    /// Process a job and return the result
    async fn process(&self, job: &sh_types::Job) -> WorkerResult<sh_types::JobResult>;
    
    /// Check if this processor can handle the given job type
    fn can_process(&self, job_type: &str) -> bool;
    
    /// Get processor capabilities
    fn capabilities(&self) -> WorkerCapabilities;
}

/// Shared state for worker health tracking
#[derive(Debug, Clone)]
pub(crate) struct SharedWorkerState {
    /// Last heartbeat timestamp
    pub last_heartbeat: Arc<RwLock<DateTime<Utc>>>,
    /// Current job being processed
    pub current_job: Arc<RwLock<Option<sh_types::JobId>>>,
    /// Jobs completed count
    pub jobs_completed: Arc<RwLock<u64>>,
    /// Jobs failed count
    pub jobs_failed: Arc<RwLock<u64>>,
    /// Total execution time for average calculation
    pub total_execution_time_ms: Arc<RwLock<u64>>,
}

impl SharedWorkerState {
    pub(crate) fn new() -> Self {
        Self {
            last_heartbeat: Arc::new(RwLock::new(Utc::now())),
            current_job: Arc::new(RwLock::new(None)),
            jobs_completed: Arc::new(RwLock::new(0)),
            jobs_failed: Arc::new(RwLock::new(0)),
            total_execution_time_ms: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Update heartbeat timestamp
    pub(crate) async fn update_heartbeat(&self) {
        let mut hb = self.last_heartbeat.write().await;
        *hb = Utc::now();
    }
    
    /// Record job completion
    pub(crate) async fn record_completion(&self, execution_time_ms: u64) {
        let mut completed = self.jobs_completed.write().await;
        *completed += 1;
        let mut total = self.total_execution_time_ms.write().await;
        *total += execution_time_ms;
    }
    
    /// Record job failure
    pub(crate) async fn record_failure(&self) {
        let mut failed = self.jobs_failed.write().await;
        *failed += 1;
    }
    
    /// Get average job duration
    pub(crate) async fn avg_job_duration_ms(&self) -> f64 {
        let completed = *self.jobs_completed.read().await;
        if completed == 0 {
            return 0.0;
        }
        let total = *self.total_execution_time_ms.read().await;
        total as f64 / completed as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_worker_capabilities_default() {
        let caps = WorkerCapabilities::default();
        assert_eq!(caps.job_types, vec!["*"]);
        assert_eq!(caps.max_concurrent_jobs, 1);
    }
    
    #[tokio::test]
    async fn test_shared_worker_state() {
        let state = SharedWorkerState::new();
        
        // Test initial state
        assert_eq!(*state.jobs_completed.read().await, 0);
        assert_eq!(*state.jobs_failed.read().await, 0);
        
        // Test recording
        state.record_completion(1000).await;
        state.record_completion(2000).await;
        state.record_failure().await;
        
        assert_eq!(*state.jobs_completed.read().await, 2);
        assert_eq!(*state.jobs_failed.read().await, 1);
        assert_eq!(state.avg_job_duration_ms().await, 1500.0);
    }
}
