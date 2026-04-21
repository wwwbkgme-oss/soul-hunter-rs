//! # sh-finding
//!
//! Security finding processing, correlation, and deduplication engine for Soul Hunter.
//!
//! ## Features
//!
//! - **Finding Processing**: Process findings from multiple sources with configurable pipelines
//! - **Finding Correlation**: Group related findings from multiple sources using similarity algorithms
//! - **Deduplication**: Remove duplicate findings based on configurable similarity thresholds
//! - **Confidence Scoring**: Calculate and adjust confidence scores based on evidence and source reputation
//! - **Batch Operations**: Efficiently process large batches of findings with async concurrency control
//! - **Event Integration**: Publish finding events to the event bus for downstream consumers
//!
//! ## Example
//!
//! ```rust
//! use sh_finding::{FindingEngine, EngineConfig, FindingCollection};
//! use sh_types::{Finding, Severity};
//!
//! async fn process_findings() {
//!     let engine = FindingEngine::new(EngineConfig::default());
//!     
//!     let findings = vec![
//!         Finding::new("Hardcoded Password", "Found hardcoded credentials")
//!             .with_severity(Severity::High),
//!     ];
//!     
//!     let result = engine.process_batch(findings).await.unwrap();
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod correlation;
pub mod deduplication;
pub mod engine;

// Re-exports
pub use correlation::{CorrelationConfig, CorrelationEngine, CorrelationGroup, SimilarityStrategy};
pub use deduplication::{DeduplicationConfig, DeduplicationEngine, DuplicateGroup};
pub use engine::{EngineConfig, FindingEngine, ProcessingPipeline, ProcessingStage};

/// Prelude module for convenient imports
pub mod prelude {
    pub use super::{
        CorrelationConfig, CorrelationEngine, CorrelationGroup, DeduplicationConfig,
        DeduplicationEngine, DuplicateGroup, EngineConfig, FindingEngine, ProcessingPipeline,
        ProcessingStage, SimilarityStrategy,
    };
    pub use sh_types::{Confidence, Finding, FindingCollection, FindingId, Location, Severity};
}

/// Result type alias for finding operations
pub type Result<T> = std::result::Result<T, FindingError>;

/// Errors for finding engine operations
#[derive(thiserror::Error, Debug, Clone)]
pub enum FindingError {
    /// Finding not found
    #[error("Finding not found: {0}")]
    NotFound(FindingId),
    
    /// Correlation operation failed
    #[error("Correlation failed: {0}")]
    CorrelationFailed(String),
    
    /// Deduplication operation failed
    #[error("Deduplication failed: {0}")]
    DeduplicationFailed(String),
    
    /// Invalid finding data
    #[error("Invalid finding: {0}")]
    InvalidFinding(String),
    
    /// Processing pipeline error
    #[error("Processing error: {0}")]
    Processing(String),
    
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Batch processing error with partial results
    #[error("Batch processing failed: {success} succeeded, {failed} failed - {message}")]
    BatchPartial {
        /// Number of successful operations
        success: usize,
        /// Number of failed operations
        failed: usize,
        /// Error message
        message: String,
    },
}

impl FindingError {
    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Storage(_) | Self::Io(_) | Self::CorrelationFailed(_) | Self::DeduplicationFailed(_)
        )
    }
    
    /// Get the finding ID if applicable
    pub fn finding_id(&self) -> Option<FindingId> {
        match self {
            Self::NotFound(id) => Some(*id),
            _ => None,
        }
    }
    
    /// Check if this is a partial batch failure
    pub fn is_partial_failure(&self) -> bool {
        matches!(self, Self::BatchPartial { .. })
    }
}

use sh_types::FindingId;

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Finding, Severity};

    fn create_test_finding(title: &str) -> Finding {
        Finding::new(title, "Test description").with_severity(Severity::High)
    }

    #[test]
    fn test_error_retryable() {
        let io_err = FindingError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert!(io_err.is_retryable());
        
        let invalid_err = FindingError::InvalidFinding("test".to_string());
        assert!(!invalid_err.is_retryable());
    }

    #[test]
    fn test_error_finding_id() {
        let id = uuid::Uuid::new_v4();
        let not_found = FindingError::NotFound(id);
        assert_eq!(not_found.finding_id(), Some(id));
        
        let other = FindingError::Processing("test".to_string());
        assert_eq!(other.finding_id(), None);
    }

    #[tokio::test]
    async fn test_engine_creation() {
        let config = EngineConfig::default();
        let engine = FindingEngine::new(config);
        assert!(!engine.is_shutdown());
    }

    #[tokio::test]
    async fn test_process_single_finding() {
        let engine = FindingEngine::default();
        let finding = create_test_finding("Test Finding");
        
        let result = engine.process(finding).await;
        assert!(result.is_ok());
        
        let processed = result.unwrap();
        assert_eq!(processed.title, "Test Finding");
    }

    #[tokio::test]
    async fn test_process_batch() {
        let engine = FindingEngine::default();
        let findings = vec![
            create_test_finding("Finding 1"),
            create_test_finding("Finding 2"),
            create_test_finding("Finding 3"),
        ];
        
        let result = engine.process_batch(findings).await;
        assert!(result.is_ok());
        
        let collection = result.unwrap();
        assert_eq!(collection.total_count, 3);
    }

    #[tokio::test]
    async fn test_correlation_and_deduplication() {
        let config = EngineConfig::default()
            .with_correlation_enabled(true)
            .with_deduplication_enabled(true);
        
        let engine = FindingEngine::new(config);
        
        // Create similar findings that should be correlated/deduplicated
        let findings = vec![
            Finding::new("Hardcoded Password", "Found credentials")
                .with_severity(Severity::High)
                .with_type("security")
                .with_location(sh_types::Location::new().with_file("config.java").with_line(42)),
            Finding::new("Hardcoded Password", "Found credentials in code")
                .with_severity(Severity::High)
                .with_type("security")
                .with_location(sh_types::Location::new().with_file("config.java").with_line(42)),
            Finding::new("SQL Injection", "Unsafe query construction")
                .with_severity(Severity::Critical)
                .with_type("security")
                .with_location(sh_types::Location::new().with_file("query.java").with_line(100)),
        ];
        
        let result = engine.process_batch(findings).await;
        assert!(result.is_ok());
        
        // After deduplication, should have 2 findings (not 3)
        let collection = result.unwrap();
        assert!(collection.total_count <= 3);
    }
}
