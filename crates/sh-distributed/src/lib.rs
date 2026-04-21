//! # sh-distributed
//!
//! Distributed execution coordination for the Soul Hunter security analysis platform.
//!
//! ## Features
//!
//! - **Redis Backend**: Distributed job queue using Redis with cluster support
//! - **NATS Backend**: High-performance messaging with NATS JetStream
//! - **Worker Coordination**: Automatic worker discovery and load balancing
//! - **Job Distribution**: Fair job distribution across worker nodes
//! - **Horizontal Scaling**: Add/remove workers dynamically
//! - **Fault Tolerance**: Automatic failover and job recovery
//! - **Metrics**: Distributed metrics collection and aggregation
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           Distributed System                                │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
//! │  │   Worker 1  │    │   Worker 2  │    │   Worker 3  │    │   Worker N  │ │
//! │  │  ┌───────┐  │    │  ┌───────┐  │    │  ┌───────┐  │    │  ┌───────┐  │ │
//! │  │  │Queue  │  │    │  │Queue  │  │    │  │Queue  │  │    │  │Queue  │  │ │
//! │  │  │Consumer│  │    │  │Consumer│  │    │  │Consumer│  │    │  │Consumer│  │ │
//! │  │  └───────┘  │    │  └───────┘  │    │  └───────┘  │    │  └───────┘  │ │
//! │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘ │
//! │         │                  │                  │                  │        │
//! │         └──────────────────┴──────────────────┴──────────────────┘        │
//! │                                    │                                       │
//! │                                    ▼                                       │
//! │  ┌─────────────────────────────────────────────────────────────────────┐  │
//! │  │                    Distributed Coordinator                           │  │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │  │
//! │  │  │   Redis     │  │    NATS     │  │   Worker    │  │   Health   │ │  │
//! │  │  │   Backend   │  │   Backend   │  │   Registry  │  │   Monitor  │ │  │
//! │  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │  │
//! │  └─────────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_distributed::{DistributedCoordinator, CoordinatorConfig, BackendType};
//! use sh_types::{Job, AnalysisTarget, Platform};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create coordinator with Redis backend
//!     let config = CoordinatorConfig {
//!         backend: BackendType::Redis,
//!         redis_url: "redis://localhost:6379".to_string(),
//!         worker_id: "worker-1".to_string(),
//!         ..Default::default()
//!     };
//!
//!     let coordinator = DistributedCoordinator::new(config).await?;
//!
//!     // Start the coordinator
//!     coordinator.start().await?;
//!
//!     // Submit a job
//!     let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
//!     let job = Job::new("static_analysis", target);
//!     let job_id = coordinator.submit_job(job).await?;
//!
//!     // Wait for completion
//!     let result = coordinator.wait_for_job(job_id).await?;
//!
//!     // Shutdown gracefully
//!     coordinator.shutdown().await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod coordinator;
mod error;
mod metrics;
mod nats;
mod redis;
mod worker;

/// CI/CD Integration module
pub mod cicd;

// Re-export public types
pub use coordinator::{
    BackendType, CoordinatorConfig, DistributedCoordinator, JobDistributionStrategy,
};
pub use error::{DistributedError, Result};
pub use metrics::{DistributedMetrics, MetricsCollector};
pub use nats::{NatsBackend, NatsConfig};
pub use redis::{RedisBackend, RedisConfig};
pub use worker::{WorkerInfo, WorkerRegistry, WorkerStatus};

// Re-export CI/CD types
pub use cicd::{
    AnnotationLevel, CICDConclusion, CICDConfig, CICDIntegration, CICDPlatform,
    CICDReportFormatter, CodeAnnotation, FindingSummary, RiskThreshold, SecurityReport,
};

// Re-export commonly used types from sh-types
pub use sh_types::{Job, JobId, JobPriority, JobStatus, JobResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_display() {
        assert_eq!(BackendType::Redis.to_string(), "redis");
        assert_eq!(BackendType::Nats.to_string(), "nats");
    }

    #[test]
    fn test_worker_status_lifecycle() {
        let info = WorkerInfo::new("test-worker", "127.0.0.1:8080");
        assert_eq!(info.status, WorkerStatus::Starting);
        assert_eq!(info.id, "test-worker");
    }
}
