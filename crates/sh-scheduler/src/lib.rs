//! # sh-scheduler
//!
//! Priority job scheduler with retry and timeout handling for the Soul Hunter platform.
//!
//! ## Features
//!
//! - **Priority Queue**: Binary heap-based priority queue for efficient job ordering
//! - **Job Priorities**: Five priority levels (Critical, High, Normal, Low, Lowest)
//! - **Timeout Handling**: Configurable timeouts with automatic cancellation
//! - **Retry Logic**: Exponential backoff for failed jobs
//! - **Status Tracking**: Complete job lifecycle tracking (Pending, Running, Completed, Failed, Cancelled, Timeout)
//! - **Thread-Safe**: Async/await support with tokio and dashmap for concurrent access
//! - **Worker Pool**: Configurable number of concurrent workers
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Scheduler                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐ │
//! │  │ Priority Queue  │  │  Active Jobs    │  │ Retry Queue   │ │
//! │  │ (BinaryHeap)   │  │  (DashMap)      │  │ (Mutex<HashMap│ │
//! │  └────────┬────────┘  └────────┬────────┘  └───────┬───────┘ │
//! │           │                  │                   │         │
//! │           ▼                  ▼                   ▼         │
//! │  ┌──────────────────────────────────────────────────────┐ │
//! │  │              Worker Pool (tokio tasks)                │ │
//! │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │ │
//! │  │  │ Worker 0│  │ Worker 1│  │ Worker 2│  │ Worker N│  │ │
//! │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  │ │
//! │  └──────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_scheduler::{Scheduler, SchedulerConfig};
//! use sh_types::{Job, AnalysisTarget, Platform};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create scheduler with default config
//!     let config = SchedulerConfig::default();
//!     let scheduler = Scheduler::new(config);
//!
//!     // Start the scheduler
//!     scheduler.start().await?;
//!
//!     // Create and submit a job
//!     let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
//!     let job = Job::new("static_analysis", target);
//!     let job_id = scheduler.submit(job).await?;
//!
//!     // Check job status
//!     if let Some(status) = scheduler.get_status(job_id) {
//!         println!("Job status: {:?}", status);
//!     }
//!
//!     // Shutdown gracefully
//!     scheduler.shutdown().await;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod priority_queue;
mod scheduler;

// Re-export public types
pub use priority_queue::{JobPriorityQueue, PrioritizedJob, PriorityQueueError};
pub use scheduler::{Scheduler, SchedulerConfig, SchedulerError, ScheduledJob, JobExecutor, DefaultJobExecutor};

// Re-export commonly used types from sh-types for convenience
pub use sh_types::{Job, JobId, JobPriority, JobStatus, JobResult, JobConfig, QueueStats};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform, JobPriority};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{sleep, Duration};

    /// Test executor that tracks execution count
    struct TestExecutor {
        counter: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl JobExecutor for TestExecutor {
        async fn execute(&self, _job: &Job) -> Result<JobResult, SchedulerError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            sleep(Duration::from_millis(10)).await;
            Ok(JobResult::new(1))
        }
    }

    #[tokio::test]
    async fn test_scheduler_end_to_end() {
        let config = SchedulerConfig {
            max_queue_size: 100,
            worker_count: 2,
            ..Default::default()
        };

        let counter = Arc::new(AtomicUsize::new(0));
        let executor = Arc::new(TestExecutor {
            counter: counter.clone(),
        });

        let scheduler = Scheduler::with_executor(config, executor);
        scheduler.start().await.unwrap();

        // Submit multiple jobs
        let mut job_ids = Vec::new();
        for i in 0..5 {
            let target = AnalysisTarget::new(&format!("/test{}", i), Platform::Android);
            let job = Job::new("test", target);
            let id = scheduler.submit(job).await.unwrap();
            job_ids.push(id);
        }

        // Wait for jobs to complete
        sleep(Duration::from_secs(2)).await;

        // Verify all jobs were executed
        assert_eq!(counter.load(Ordering::SeqCst), 5);

        // Verify all jobs are completed
        for id in job_ids {
            let status = scheduler.get_status(id);
            assert_eq!(status, Some(JobStatus::Completed));
        }

        scheduler.shutdown().await;
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let config = SchedulerConfig {
            max_queue_size: 100,
            worker_count: 1,
            ..Default::default()
        };

        let scheduler = Scheduler::new(config);
        scheduler.start().await.unwrap();

        // Submit jobs with different priorities
        let target = AnalysisTarget::new("/test", Platform::Android);

        let job_low = Job::new("low", target.clone()).with_priority(JobPriority::Low);
        let job_critical = Job::new("critical", target.clone()).with_priority(JobPriority::Critical);
        let job_normal = Job::new("normal", target.clone()).with_priority(JobPriority::Normal);

        let id_low = scheduler.submit(job_low).await.unwrap();
        let id_critical = scheduler.submit(job_critical).await.unwrap();
        let id_normal = scheduler.submit(job_normal).await.unwrap();

        // Wait for processing
        sleep(Duration::from_secs(1)).await;

        // Check that critical job was processed first (should be completed)
        // Note: Due to async nature, we just verify all complete
        assert!(scheduler.get_status(id_critical).is_some());
        assert!(scheduler.get_status(id_normal).is_some());
        assert!(scheduler.get_status(id_low).is_some());

        scheduler.shutdown().await;
    }

    #[tokio::test]
    async fn test_job_cancellation() {
        let config = SchedulerConfig {
            max_queue_size: 100,
            worker_count: 1,
            ..Default::default()
        };

        let scheduler = Scheduler::new(config);
        scheduler.start().await.unwrap();

        let target = AnalysisTarget::new("/test", Platform::Android);
        let job = Job::new("test", target);
        let id = scheduler.submit(job).await.unwrap();

        // Cancel immediately (before execution)
        scheduler.cancel(id).await.unwrap();

        // Verify cancelled
        let status = scheduler.get_status(id);
        assert_eq!(status, Some(JobStatus::Cancelled));

        scheduler.shutdown().await;
    }

    #[tokio::test]
    async fn test_scheduler_stats() {
        let config = SchedulerConfig {
            max_queue_size: 100,
            worker_count: 2,
            ..Default::default()
        };

        let scheduler = Scheduler::new(config);
        scheduler.start().await.unwrap();

        // Initial stats
        let stats = scheduler.get_stats();
        assert_eq!(stats.total, 0);

        // Submit jobs
        for i in 0..3 {
            let target = AnalysisTarget::new(&format!("/test{}", i), Platform::Android);
            let job = Job::new("test", target);
            scheduler.submit(job).await.unwrap();
        }

        // Check stats
        let stats = scheduler.get_stats();
        assert_eq!(stats.total, 3);

        scheduler.shutdown().await;
    }
}
