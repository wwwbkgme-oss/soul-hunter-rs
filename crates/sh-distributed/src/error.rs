//! Error types for distributed execution

use std::fmt;

/// Result type alias for distributed operations
pub type Result<T> = std::result::Result<T, DistributedError>;

/// Errors that can occur in distributed execution
#[derive(Debug)]
pub enum DistributedError {
    /// Redis backend error
    Redis(String),

    /// NATS backend error
    Nats(String),

    /// Connection error
    Connection(String),

    /// Serialization error
    Serialization(serde_json::Error),

    /// Job not found
    JobNotFound(String),

    /// Worker not found
    WorkerNotFound(String),

    /// Invalid configuration
    InvalidConfig(String),

    /// Backend not available
    BackendNotAvailable(String),

    /// Timeout error
    Timeout(String),

    /// Worker registration failed
    WorkerRegistrationFailed(String),

    /// Job submission failed
    JobSubmissionFailed(String),

    /// Job execution failed
    JobExecutionFailed(String),

    /// Cluster error
    ClusterError(String),

    /// Generic error
    Other(String),
}

impl fmt::Display for DistributedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DistributedError::Redis(msg) => write!(f, "Redis error: {}", msg),
            DistributedError::Nats(msg) => write!(f, "NATS error: {}", msg),
            DistributedError::Connection(msg) => write!(f, "Connection error: {}", msg),
            DistributedError::Serialization(e) => write!(f, "Serialization error: {}", e),
            DistributedError::JobNotFound(id) => write!(f, "Job not found: {}", id),
            DistributedError::WorkerNotFound(id) => write!(f, "Worker not found: {}", id),
            DistributedError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            DistributedError::BackendNotAvailable(name) => {
                write!(f, "Backend not available: {}", name)
            }
            DistributedError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            DistributedError::WorkerRegistrationFailed(msg) => {
                write!(f, "Worker registration failed: {}", msg)
            }
            DistributedError::JobSubmissionFailed(msg) => {
                write!(f, "Job submission failed: {}", msg)
            }
            DistributedError::JobExecutionFailed(msg) => {
                write!(f, "Job execution failed: {}", msg)
            }
            DistributedError::ClusterError(msg) => write!(f, "Cluster error: {}", msg),
            DistributedError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for DistributedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DistributedError::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for DistributedError {
    fn from(err: serde_json::Error) -> Self {
        DistributedError::Serialization(err)
    }
}

impl From<std::io::Error> for DistributedError {
    fn from(err: std::io::Error) -> Self {
        DistributedError::Connection(err.to_string())
    }
}

impl From<redis::RedisError> for DistributedError {
    fn from(err: redis::RedisError) -> Self {
        DistributedError::Redis(err.to_string())
    }
}

impl From<async_nats::Error> for DistributedError {
    fn from(err: async_nats::Error) -> Self {
        DistributedError::Nats(err.to_string())
    }
}

impl From<anyhow::Error> for DistributedError {
    fn from(err: anyhow::Error) -> Self {
        DistributedError::Other(err.to_string())
    }
}

impl From<String> for DistributedError {
    fn from(msg: String) -> Self {
        DistributedError::Other(msg)
    }
}

impl From<&str> for DistributedError {
    fn from(msg: &str) -> Self {
        DistributedError::Other(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DistributedError::Redis("connection refused".to_string());
        assert_eq!(err.to_string(), "Redis error: connection refused");

        let err = DistributedError::JobNotFound("job-123".to_string());
        assert_eq!(err.to_string(), "Job not found: job-123");
    }

    #[test]
    fn test_error_from_string() {
        let err: DistributedError = "test error".into();
        assert!(matches!(err, DistributedError::Other(_)));
    }

    #[test]
    fn test_error_from_str() {
        let err: DistributedError = "test error".into();
        assert!(matches!(err, DistributedError::Other(_)));
    }
}
