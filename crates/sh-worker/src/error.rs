//! Error types for the worker crate

use thiserror::Error;

/// Result type alias for worker operations
pub type WorkerResult<T> = std::result::Result<T, WorkerError>;

/// Errors that can occur in the worker system
#[derive(Error, Debug, Clone)]
pub enum WorkerError {
    /// Worker is already running
    #[error("Worker {0} is already running")]
    AlreadyRunning(String),
    
    /// Worker is not running
    #[error("Worker {0} is not running")]
    NotRunning(String),
    
    /// Worker failed to start
    #[error("Worker {0} failed to start: {1}")]
    StartFailed(String, String),
    
    /// Worker failed to stop
    #[error("Worker {0} failed to stop: {1}")]
    StopFailed(String, String),
    
    /// Job execution timed out
    #[error("Job {job_id} execution timed out after {timeout_secs}s")]
    JobTimeout {
        /// Job ID that timed out
        job_id: sh_types::JobId,
        /// Timeout duration in seconds
        timeout_secs: u64,
    },
    
    /// Job execution failed
    #[error("Job {job_id} execution failed: {reason}")]
    JobExecutionFailed {
        /// Job ID that failed
        job_id: sh_types::JobId,
        /// Failure reason
        reason: String,
    },
    
    /// Worker pool is at capacity
    #[error("Worker pool at capacity (max: {max_workers})")]
    PoolAtCapacity {
        /// Maximum number of workers
        max_workers: usize,
    },
    
    /// Failed to scale worker pool
    #[error("Failed to scale worker pool: {0}")]
    ScalingFailed(String),
    
    /// Worker is unhealthy
    #[error("Worker {worker_id} is unhealthy: {reason}")]
    Unhealthy {
        /// Worker ID
        worker_id: String,
        /// Health check failure reason
        reason: String,
    },
    
    /// No available workers
    #[error("No available workers to process job")]
    NoAvailableWorkers,
    
    /// Job processor not found for job type
    #[error("No processor found for job type: {0}")]
    ProcessorNotFound(String),
    
    /// Channel communication error
    #[error("Channel communication error: {0}")]
    ChannelError(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl WorkerError {
    /// Create a job timeout error
    pub fn timeout(job_id: sh_types::JobId, timeout_secs: u64) -> Self {
        Self::JobTimeout { job_id, timeout_secs }
    }
    
    /// Create a job execution failed error
    pub fn job_failed(job_id: sh_types::JobId, reason: impl Into<String>) -> Self {
        Self::JobExecutionFailed {
            job_id,
            reason: reason.into(),
        }
    }
    
    /// Create an unhealthy worker error
    pub fn unhealthy(worker_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Unhealthy {
            worker_id: worker_id.into(),
            reason: reason.into(),
        }
    }
    
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::JobTimeout { .. }
                | Self::JobExecutionFailed { .. }
                | Self::NoAvailableWorkers
                | Self::ChannelError(_)
        )
    }
    
    /// Get the job ID if this error is job-related
    pub fn job_id(&self) -> Option<sh_types::JobId> {
        match self {
            Self::JobTimeout { job_id, .. } => Some(*job_id),
            Self::JobExecutionFailed { job_id, .. } => Some(*job_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    
    #[test]
    fn test_error_creation() {
        let job_id = Uuid::new_v4();
        let err = WorkerError::timeout(job_id, 30);
        assert!(matches!(err, WorkerError::JobTimeout { .. }));
        assert_eq!(err.job_id(), Some(job_id));
        assert!(err.is_retryable());
        
        let err = WorkerError::job_failed(job_id, "test failure");
        assert!(matches!(err, WorkerError::JobExecutionFailed { .. }));
        assert!(err.is_retryable());
        
        let err = WorkerError::unhealthy("worker-1", "heartbeat timeout");
        assert!(matches!(err, WorkerError::Unhealthy { .. }));
        assert!(!err.is_retryable());
    }
    
    #[test]
    fn test_error_messages() {
        let job_id = Uuid::new_v4();
        
        let err = WorkerError::timeout(job_id, 30);
        let msg = err.to_string();
        assert!(msg.contains("timed out"));
        assert!(msg.contains("30s"));
        
        let err = WorkerError::PoolAtCapacity { max_workers: 10 };
        assert_eq!(err.to_string(), "Worker pool at capacity (max: 10)");
    }
}
