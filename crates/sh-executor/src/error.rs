//! Error types for the executor crate

use thiserror::Error;

/// Result type alias for executor operations
pub type ExecutorResult<T> = std::result::Result<T, ExecutorError>;

/// Errors that can occur in the executor system
#[derive(Error, Debug, Clone)]
pub enum ExecutorError {
    /// Job execution timed out
    #[error("Job {job_id} execution timed out after {timeout_secs}s")]
    Timeout {
        /// Job ID that timed out
        job_id: sh_types::JobId,
        /// Timeout duration in seconds
        timeout_secs: u64,
    },

    /// Job was cancelled
    #[error("Job {job_id} was cancelled")]
    Cancelled {
        /// Job ID that was cancelled
        job_id: sh_types::JobId,
    },

    /// Maximum retry attempts exceeded
    #[error("Job {job_id} exceeded maximum retry attempts ({max_retries})")]
    MaxRetriesExceeded {
        /// Job ID that exceeded retries
        job_id: sh_types::JobId,
        /// Maximum number of retries allowed
        max_retries: u32,
        /// Last error message
        last_error: String,
    },

    /// Job execution failed
    #[error("Job {job_id} execution failed: {reason}")]
    ExecutionFailed {
        /// Job ID that failed
        job_id: sh_types::JobId,
        /// Failure reason
        reason: String,
    },

    /// Executor is not running
    #[error("Executor is not running")]
    NotRunning,

    /// Executor is already running
    #[error("Executor is already running")]
    AlreadyRunning,

    /// Invalid job configuration
    #[error("Invalid job configuration: {0}")]
    InvalidConfiguration(String),

    /// Job not found
    #[error("Job {0} not found")]
    JobNotFound(sh_types::JobId),

    /// Channel communication error
    #[error("Channel communication error: {0}")]
    ChannelError(String),

    /// Worker error
    #[error("Worker error: {0}")]
    WorkerError(String),

    /// Scheduler error
    #[error("Scheduler error: {0}")]
    SchedulerError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl ExecutorError {
    /// Create a timeout error
    pub fn timeout(job_id: sh_types::JobId, timeout_secs: u64) -> Self {
        Self::Timeout { job_id, timeout_secs }
    }

    /// Create a cancelled error
    pub fn cancelled(job_id: sh_types::JobId) -> Self {
        Self::Cancelled { job_id }
    }

    /// Create a max retries exceeded error
    pub fn max_retries_exceeded(
        job_id: sh_types::JobId,
        max_retries: u32,
        last_error: impl Into<String>,
    ) -> Self {
        Self::MaxRetriesExceeded {
            job_id,
            max_retries,
            last_error: last_error.into(),
        }
    }

    /// Create an execution failed error
    pub fn execution_failed(job_id: sh_types::JobId, reason: impl Into<String>) -> Self {
        Self::ExecutionFailed {
            job_id,
            reason: reason.into(),
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::ExecutionFailed { .. }
                | Self::WorkerError(_)
                | Self::ChannelError(_)
        )
    }

    /// Check if this error is a cancellation
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Get the job ID if this error is job-related
    pub fn job_id(&self) -> Option<sh_types::JobId> {
        match self {
            Self::Timeout { job_id, .. } => Some(*job_id),
            Self::Cancelled { job_id, .. } => Some(*job_id),
            Self::MaxRetriesExceeded { job_id, .. } => Some(*job_id),
            Self::ExecutionFailed { job_id, .. } => Some(*job_id),
            Self::JobNotFound(job_id) => Some(*job_id),
            _ => None,
        }
    }

    /// Get the retry count from max retries exceeded error
    pub fn max_retries(&self) -> Option<u32> {
        match self {
            Self::MaxRetriesExceeded { max_retries, .. } => Some(*max_retries),
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

        let err = ExecutorError::timeout(job_id, 30);
        assert!(matches!(err, ExecutorError::Timeout { .. }));
        assert_eq!(err.job_id(), Some(job_id));
        assert!(err.is_retryable());

        let err = ExecutorError::cancelled(job_id);
        assert!(matches!(err, ExecutorError::Cancelled { .. }));
        assert!(err.is_cancelled());
        assert!(!err.is_retryable());

        let err = ExecutorError::max_retries_exceeded(job_id, 3, "last error");
        assert!(matches!(err, ExecutorError::MaxRetriesExceeded { .. }));
        assert_eq!(err.max_retries(), Some(3));

        let err = ExecutorError::execution_failed(job_id, "test failure");
        assert!(matches!(err, ExecutorError::ExecutionFailed { .. }));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_error_messages() {
        let job_id = Uuid::new_v4();

        let err = ExecutorError::timeout(job_id, 30);
        let msg = err.to_string();
        assert!(msg.contains("timed out"));
        assert!(msg.contains("30s"));

        let err = ExecutorError::cancelled(job_id);
        assert!(err.to_string().contains("cancelled"));

        let err = ExecutorError::max_retries_exceeded(job_id, 3, "connection failed");
        let msg = err.to_string();
        assert!(msg.contains("exceeded maximum retry attempts"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_non_retryable_errors() {
        let job_id = Uuid::new_v4();

        let err = ExecutorError::InvalidConfiguration("bad config".to_string());
        assert!(!err.is_retryable());

        let err = ExecutorError::NotRunning;
        assert!(!err.is_retryable());

        let err = ExecutorError::AlreadyRunning;
        assert!(!err.is_retryable());

        let err = ExecutorError::JobNotFound(job_id);
        assert!(!err.is_retryable());
    }
}
