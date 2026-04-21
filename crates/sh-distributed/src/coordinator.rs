//! Distributed coordinator for job distribution across worker nodes

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::{DistributedError, Result};
use crate::metrics::{DistributedMetrics, MetricsCollector};
use crate::nats::{NatsBackend, NatsConfig};
use crate::redis::{RedisBackend, RedisConfig};
use crate::worker::{WorkerInfo, WorkerRegistry, WorkerSelector, WorkerStatus};
use sh_types::{Job, JobId, JobPriority, JobResult, JobStatus};

/// Backend type for distributed execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    /// Redis backend
    Redis,
    /// NATS backend
    Nats,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::Redis
    }
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendType::Redis => write!(f, "redis"),
            BackendType::Nats => write!(f, "nats"),
        }
    }
}

/// Job distribution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobDistributionStrategy {
    /// Round-robin distribution
    RoundRobin,
    /// Least loaded worker
    LeastLoaded,
    /// Random selection
    Random,
    /// Most capacity
    MostCapacity,
    /// Priority-based (higher priority workers get more jobs)
    PriorityBased,
}

impl Default for JobDistributionStrategy {
    fn default() -> Self {
        JobDistributionStrategy::LeastLoaded
    }
}

/// Coordinator configuration
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Backend type
    pub backend: BackendType,
    /// Redis URL (for Redis backend)
    pub redis_url: String,
    /// NATS URL (for NATS backend)
    pub nats_url: String,
    /// Worker ID
    pub worker_id: String,
    /// Distribution strategy
    pub distribution_strategy: JobDistributionStrategy,
    /// Max concurrent jobs per worker
    pub max_concurrent_jobs: usize,
    /// Job timeout in seconds
    pub job_timeout_secs: u64,
    /// Enable auto-scaling
    pub enable_autoscaling: bool,
    /// Min workers
    pub min_workers: usize,
    /// Max workers
    pub max_workers: usize,
    /// Scale up threshold (queue length)
    pub scale_up_threshold: usize,
    /// Scale down threshold (idle workers)
    pub scale_down_threshold: usize,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Worker timeout in seconds
    pub worker_timeout_secs: u64,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Metrics flush interval in seconds
    pub metrics_flush_interval_secs: u64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::Redis,
            redis_url: "redis://localhost:6379".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            worker_id: format!("worker-{}", Uuid::new_v4()),
            distribution_strategy: JobDistributionStrategy::LeastLoaded,
            max_concurrent_jobs: 10,
            job_timeout_secs: 300,
            enable_autoscaling: false,
            min_workers: 1,
            max_workers: 10,
            scale_up_threshold: 100,
            scale_down_threshold: 5,
            heartbeat_interval_secs: 10,
            worker_timeout_secs: 30,
            enable_metrics: true,
            metrics_flush_interval_secs: 60,
        }
    }
}

impl CoordinatorConfig {
    /// Create new config with backend type
    pub fn with_backend(mut self, backend: BackendType) -> Self {
        self.backend = backend;
        self
    }

    /// Set Redis URL
    pub fn with_redis_url(mut self, url: impl Into<String>) -> Self {
        self.redis_url = url.into();
        self
    }

    /// Set NATS URL
    pub fn with_nats_url(mut self, url: impl Into<String>) -> Self {
        self.nats_url = url.into();
        self
    }

    /// Set worker ID
    pub fn with_worker_id(mut self, id: impl Into<String>) -> Self {
        self.worker_id = id.into();
        self
    }

    /// Set distribution strategy
    pub fn with_strategy(mut self, strategy: JobDistributionStrategy) -> Self {
        self.distribution_strategy = strategy;
        self
    }

    /// Enable autoscaling
    pub fn with_autoscaling(mut self, min: usize, max: usize) -> Self {
        self.enable_autoscaling = true;
        self.min_workers = min;
        self.max_workers = max;
        self
    }
}

/// Distributed coordinator trait
#[async_trait]
pub trait DistributedBackend: Send + Sync {
    /// Start the backend
    async fn start(&self) -> Result<()>;
    /// Stop the backend
    async fn stop(&self) -> Result<()>;
    /// Submit a job
    async fn submit_job(&self, job: Job) -> Result<JobId>;
    /// Claim a job
    async fn claim_job(&self) -> Result<Option<Job>>;
    /// Complete a job
    async fn complete_job(&self, job_id: JobId, result: JobResult) -> Result<()>;
    /// Fail a job
    async fn fail_job(&self, job_id: JobId, error: String) -> Result<()>;
    /// Get job result
    async fn get_result(&self, job_id: JobId) -> Result<Option<JobResult>>;
    /// Wait for job completion
    async fn wait_for_job(&self, job_id: JobId, timeout_secs: u64) -> Result<JobResult>;
    /// Get pending count
    async fn pending_count(&self) -> Result<usize>;
    /// Get worker count
    async fn get_worker_count(&self) -> Result<usize>;
}

/// Backend wrapper enum
#[derive(Clone)]
pub enum BackendWrapper {
    /// Redis backend
    Redis(RedisBackend),
    /// NATS backend
    Nats(NatsBackend),
}

#[async_trait]
impl DistributedBackend for BackendWrapper {
    async fn start(&self) -> Result<()> {
        match self {
            BackendWrapper::Redis(backend) => backend.start().await,
            BackendWrapper::Nats(backend) => backend.start().await,
        }
    }

    async fn stop(&self) -> Result<()> {
        match self {
            BackendWrapper::Redis(backend) => backend.stop().await,
            BackendWrapper::Nats(backend) => backend.stop().await,
        }
    }

    async fn submit_job(&self, job: Job) -> Result<JobId> {
        match self {
            BackendWrapper::Redis(backend) => backend.submit_job(job).await,
            BackendWrapper::Nats(backend) => backend.submit_job(job).await,
        }
    }

    async fn claim_job(&self) -> Result<Option<Job>> {
        match self {
            BackendWrapper::Redis(backend) => backend.claim_job().await,
            BackendWrapper::Nats(backend) => backend.claim_job().await,
        }
    }

    async fn complete_job(&self, job_id: JobId, result: JobResult) -> Result<()> {
        match self {
            BackendWrapper::Redis(backend) => backend.complete_job(job_id, result).await,
            BackendWrapper::Nats(backend) => backend.complete_job(job_id, result).await,
        }
    }

    async fn fail_job(&self, job_id: JobId, error: String) -> Result<()> {
        match self {
            BackendWrapper::Redis(backend) => backend.fail_job(job_id, error).await,
            BackendWrapper::Nats(backend) => backend.fail_job(job_id, error).await,
        }
    }

    async fn get_result(&self, job_id: JobId) -> Result<Option<JobResult>> {
        match self {
            BackendWrapper::Redis(backend) => backend.get_result(job_id).await,
            BackendWrapper::Nats(backend) => backend.get_result(job_id).await,
        }
    }

    async fn wait_for_job(&self, job_id: JobId, timeout_secs: u64) -> Result<JobResult> {
        match self {
            BackendWrapper::Redis(backend) => backend.wait_for_job(job_id, timeout_secs).await,
            BackendWrapper::Nats(backend) => backend.wait_for_job(job_id, timeout_secs).await,
        }
    }

    async fn pending_count(&self) -> Result<usize> {
        match self {
            BackendWrapper::Redis(backend) => backend.queue_length().await,
            BackendWrapper::Nats(backend) => backend.pending_count().await.map(|n| n as usize),
        }
    }

    async fn get_worker_count(&self) -> Result<usize> {
        match self {
            BackendWrapper::Redis(backend) => backend.get_worker_count().await,
            BackendWrapper::Nats(backend) => backend.get_worker_count().await,
        }
    }
}

/// Distributed coordinator
#[derive(Clone)]
pub struct DistributedCoordinator {
    config: CoordinatorConfig,
    backend: BackendWrapper,
    worker_registry: WorkerRegistry,
    metrics: Option<DistributedMetrics>,
    running: Arc<RwLock<bool>>,
    round_robin_index: Arc<RwLock<usize>>,
}

impl DistributedCoordinator {
    /// Create a new distributed coordinator
    pub async fn new(config: CoordinatorConfig) -> Result<Self> {
        let backend = match config.backend {
            BackendType::Redis => {
                let redis_config = RedisConfig::new(&config.redis_url);
                let backend = RedisBackend::new(redis_config, &config.worker_id).await?;
                BackendWrapper::Redis(backend)
            }
            BackendType::Nats => {
                let nats_config = NatsConfig::new(&config.nats_url);
                let backend = NatsBackend::new(nats_config, &config.worker_id).await?;
                BackendWrapper::Nats(backend)
            }
        };

        let metrics = if config.enable_metrics {
            Some(DistributedMetrics::new())
        } else {
            None
        };

        Ok(Self {
            config,
            backend,
            worker_registry: WorkerRegistry::with_timeout(30),
            metrics,
            running: Arc::new(RwLock::new(false)),
            round_robin_index: Arc::new(RwLock::new(0)),
        })
    }

    /// Start the coordinator
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = true;
        drop(running);

        // Start backend
        self.backend.start().await?;

        // Start worker monitoring
        self.start_worker_monitor().await;

        // Start autoscaling if enabled
        if self.config.enable_autoscaling {
            self.start_autoscaling().await;
        }

        // Start metrics collection
        if let Some(metrics) = &self.metrics {
            self.start_metrics_collection(metrics.clone()).await;
        }

        info!(
            "Distributed coordinator started with {} backend",
            self.config.backend
        );
        Ok(())
    }

    /// Stop the coordinator
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = false;
        drop(running);

        // Stop backend
        self.backend.stop().await?;

        info!("Distributed coordinator stopped");
        Ok(())
    }

    /// Submit a job to the distributed queue
    pub async fn submit_job(&self, job: Job) -> Result<JobId> {
        let job_id = self.backend.submit_job(job).await?;

        if let Some(metrics) = &self.metrics {
            metrics.record_job_submitted().await;
        }

        Ok(job_id)
    }

    /// Submit multiple jobs
    pub async fn submit_jobs(&self, jobs: Vec<Job>) -> Result<Vec<JobId>> {
        let mut job_ids = Vec::with_capacity(jobs.len());
        for job in jobs {
            job_ids.push(self.submit_job(job).await?);
        }
        Ok(job_ids)
    }

    /// Claim and execute a job
    pub async fn claim_and_execute<F, Fut>(&self, executor: F) -> Result<Option<JobResult>>
    where
        F: FnOnce(Job) -> Fut + Send,
        Fut: std::future::Future<Output = Result<JobResult>> + Send,
    {
        if let Some(job) = self.backend.claim_job().await? {
            let job_id = job.id;
            info!("Claimed job {} for execution", job_id);

            // Update worker status
            if let Some(mut worker) = self.worker_registry.get(&self.config.worker_id) {
                worker.increment_active();
                self.worker_registry.update_status(&worker.id, WorkerStatus::Busy)?;
            }

            // Execute job
            let start = std::time::Instant::now();
            let result = executor(job.clone()).await;
            let duration = start.elapsed();

            // Handle result
            match result {
                Ok(job_result) => {
                    self.backend.complete_job(job_id, job_result.clone()).await?;

                    if let Some(metrics) = &self.metrics {
                        metrics.record_job_completed(duration).await;
                    }

                    // Update worker status
                    if let Some(mut worker) = self.worker_registry.get(&self.config.worker_id) {
                        worker.record_success();
                        self.worker_registry
                            .update_status(&worker.id, WorkerStatus::Ready)?;
                    }

                    info!("Job {} completed successfully in {:?}", job_id, duration);
                    Ok(Some(job_result))
                }
                Err(e) => {
                    self.backend.fail_job(job_id, e.to_string()).await?;

                    if let Some(metrics) = &self.metrics {
                        metrics.record_job_failed().await;
                    }

                    // Update worker status
                    if let Some(mut worker) = self.worker_registry.get(&self.config.worker_id) {
                        worker.record_failure();
                        self.worker_registry
                            .update_status(&worker.id, WorkerStatus::Ready)?;
                    }

                    error!("Job {} failed: {}", job_id, e);
                    Err(e)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Wait for a job to complete
    pub async fn wait_for_job(&self, job_id: JobId) -> Result<JobResult> {
        self.backend.wait_for_job(job_id, self.config.job_timeout_secs).await
    }

    /// Get job result
    pub async fn get_result(&self, job_id: JobId) -> Result<Option<JobResult>> {
        self.backend.get_result(job_id).await
    }

    /// Get queue length
    pub async fn queue_length(&self) -> Result<usize> {
        self.backend.pending_count().await
    }

    /// Get worker count
    pub async fn worker_count(&self) -> Result<usize> {
        self.backend.get_worker_count().await
    }

    /// Get coordinator stats
    pub async fn get_stats(&self) -> CoordinatorStats {
        let queue_len = self.queue_length().await.unwrap_or(0);
        let worker_count = self.worker_count().await.unwrap_or(0);

        CoordinatorStats {
            queue_length: queue_len,
            worker_count,
            healthy_workers: self.worker_registry.healthy_count(),
            available_workers: self.worker_registry.available_count(),
            total_jobs_processed: self.worker_registry.total_jobs_processed(),
            total_jobs_failed: self.worker_registry.total_jobs_failed(),
            average_load: self.worker_registry.average_load(),
        }
    }

    /// Select best worker for a job
    async fn select_worker(&self, job: &Job) -> Option<WorkerInfo> {
        let available = self.worker_registry.get_available();

        if available.is_empty() {
            return None;
        }

        // Filter by job type support
        let candidates: Vec<WorkerInfo> = available
            .into_iter()
            .filter(|w| w.capabilities.supports_job_type(&job.job_type))
            .filter(|w| w.capabilities.supports_platform(&job.target.platform.to_string()))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        match self.config.distribution_strategy {
            JobDistributionStrategy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                WorkerSelector::round_robin(&candidates, &mut *index)
            }
            JobDistributionStrategy::LeastLoaded => WorkerSelector::least_loaded(&candidates),
            JobDistributionStrategy::Random => WorkerSelector::random(&candidates),
            JobDistributionStrategy::MostCapacity => WorkerSelector::most_capacity(&candidates),
            JobDistributionStrategy::PriorityBased => {
                // Sort by priority (higher first) then by load
                candidates
                    .into_iter()
                    .min_by(|a, b| {
                        a.load
                            .partial_cmp(&b.load)
                            .unwrap()
                            .then_with(|| b.active_jobs.cmp(&a.active_jobs))
                    })
            }
        }
    }

    /// Start worker monitoring task
    async fn start_worker_monitor(&self) {
        let worker_registry = self.worker_registry.clone();
        let worker_timeout_secs = self.config.worker_timeout_secs;
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Remove stale workers
                let removed = worker_registry.remove_stale();
                if !removed.is_empty() {
                    warn!("Removed {} stale workers: {:?}", removed.len(), removed);
                }
            }

            debug!("Worker monitor stopped");
        });
    }

    /// Start autoscaling task
    async fn start_autoscaling(&self) {
        let config = self.config.clone();
        let backend = self.backend.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Check queue length
                if let Ok(queue_len) = backend.pending_count().await {
                    if let Ok(worker_count) = backend.get_worker_count().await {
                        // Scale up if queue is backing up
                        if queue_len > config.scale_up_threshold
                            && worker_count < config.max_workers
                        {
                            info!(
                                "Scale up triggered: queue_len={}, workers={}",
                                queue_len, worker_count
                            );
                            // In a real implementation, this would trigger provisioning
                        }

                        // Scale down if workers are idle
                        if queue_len < config.scale_down_threshold
                            && worker_count > config.min_workers
                        {
                            info!(
                                "Scale down triggered: queue_len={}, workers={}",
                                queue_len, worker_count
                            );
                            // In a real implementation, this would trigger deprovisioning
                        }
                    }
                }
            }

            debug!("Autoscaling stopped");
        });
    }

    /// Start metrics collection task
    async fn start_metrics_collection(&self, metrics: DistributedMetrics) {
        let config = self.config.clone();
        let backend = self.backend.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.metrics_flush_interval_secs));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Collect metrics
                if let Ok(queue_len) = backend.pending_count().await {
                    metrics.update_queue_length(queue_len).await;
                }

                if let Ok(worker_count) = backend.get_worker_count().await {
                    metrics.update_worker_count(worker_count).await;
                }
            }

            debug!("Metrics collection stopped");
        });
    }

    /// Run as a worker node
    pub async fn run_worker<F, Fut>(&self, executor: F) -> Result<()>
    where
        F: Fn(Job) -> Fut + Send + Clone + 'static,
        Fut: std::future::Future<Output = Result<JobResult>> + Send + 'static,
    {
        info!("Starting worker node: {}", self.config.worker_id);

        // Mark worker as ready
        if let Some(mut worker) = self.worker_registry.get(&self.config.worker_id) {
            worker.mark_ready();
        }

        // Process jobs
        loop {
            let is_running = *self.running.read().await;
            if !is_running {
                break;
            }

            match self.claim_and_execute(|job| executor(job)).await {
                Ok(Some(_)) => {
                    // Job completed successfully
                }
                Ok(None) => {
                    // No jobs available, wait a bit
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!("Job execution error: {}", e);
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            }
        }

        info!("Worker node stopped: {}", self.config.worker_id);
        Ok(())
    }
}

/// Coordinator statistics
#[derive(Debug, Clone, Default)]
pub struct CoordinatorStats {
    /// Current queue length
    pub queue_length: usize,
    /// Total worker count
    pub worker_count: usize,
    /// Healthy worker count
    pub healthy_workers: usize,
    /// Available worker count
    pub available_workers: usize,
    /// Total jobs processed
    pub total_jobs_processed: u64,
    /// Total jobs failed
    pub total_jobs_failed: u64,
    /// Average load across workers
    pub average_load: f64,
}

impl fmt::Display for CoordinatorStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoordinatorStats {{ queue: {}, workers: {}/{} ({} available), jobs: {}/{} failed, load: {:.2}% }}",
            self.queue_length,
            self.healthy_workers,
            self.worker_count,
            self.available_workers,
            self.total_jobs_processed,
            self.total_jobs_failed,
            self.average_load * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform};

    #[test]
    fn test_backend_type_display() {
        assert_eq!(BackendType::Redis.to_string(), "redis");
        assert_eq!(BackendType::Nats.to_string(), "nats");
    }

    #[test]
    fn test_distribution_strategy() {
        let strategies = vec![
            JobDistributionStrategy::RoundRobin,
            JobDistributionStrategy::LeastLoaded,
            JobDistributionStrategy::Random,
            JobDistributionStrategy::MostCapacity,
            JobDistributionStrategy::PriorityBased,
        ];

        for strategy in strategies {
            let config = CoordinatorConfig::default().with_strategy(strategy);
            assert_eq!(config.distribution_strategy, strategy);
        }
    }

    #[test]
    fn test_coordinator_config() {
        let config = CoordinatorConfig::default()
            .with_backend(BackendType::Nats)
            .with_redis_url("redis://custom:6379")
            .with_worker_id("test-worker");

        assert_eq!(config.backend, BackendType::Nats);
        assert_eq!(config.redis_url, "redis://custom:6379");
        assert_eq!(config.worker_id, "test-worker");
    }

    #[test]
    fn test_coordinator_stats_display() {
        let stats = CoordinatorStats {
            queue_length: 10,
            worker_count: 5,
            healthy_workers: 4,
            available_workers: 3,
            total_jobs_processed: 100,
            total_jobs_failed: 5,
            average_load: 0.75,
        };

        let display = stats.to_string();
        assert!(display.contains("queue: 10"));
        assert!(display.contains("workers: 4/5"));
        assert!(display.contains("75%"));
    }
}
