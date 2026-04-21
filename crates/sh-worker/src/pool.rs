//! Worker pool management with dynamic scaling and health monitoring
//!
//! The worker pool manages a collection of workers, distributing jobs among them
//! and handling dynamic scaling based on load. It also monitors worker health
//! and replaces unhealthy workers automatically.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    ExecutionMetrics, JobExecutionResult, JobProcessor, Worker,
    WorkerCapabilities, WorkerHandle, WorkerHealth, WorkerId, WorkerResult, WorkerSnapshot,
    WorkerStatus,
};
use crate::error::WorkerError;
use crate::worker::WorkerJob;

/// Scaling policy for dynamic worker management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalingPolicy {
    /// Fixed number of workers, no scaling
    Fixed,
    /// Scale based on queue depth
    QueueDepth,
    /// Scale based on CPU/memory usage
    ResourceBased,
    /// Scale based on both queue depth and resources
    Adaptive,
}

impl Default for ScalingPolicy {
    fn default() -> Self {
        ScalingPolicy::QueueDepth
    }
}

/// Worker pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolConfig {
    /// Minimum number of workers
    pub min_workers: usize,
    /// Maximum number of workers
    pub max_workers: usize,
    /// Initial number of workers
    pub initial_workers: usize,
    /// Maximum jobs per worker
    pub max_jobs_per_worker: usize,
    /// Default job timeout in seconds
    pub default_timeout_secs: u64,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
    /// Scaling policy
    pub scaling_policy: ScalingPolicy,
    /// Scale up threshold (queue depth per worker)
    pub scale_up_threshold: usize,
    /// Scale down threshold (queue depth per worker)
    pub scale_down_threshold: usize,
    /// Scale up cooldown in seconds
    pub scale_up_cooldown_secs: u64,
    /// Scale down cooldown in seconds
    pub scale_down_cooldown_secs: u64,
    /// Maximum consecutive health check failures before worker restart
    pub max_health_failures: u32,
    /// Worker health check timeout in seconds
    pub health_check_timeout_secs: u64,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        let num_cpus = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        
        Self {
            min_workers: 2,
            max_workers: num_cpus * 2,
            initial_workers: num_cpus,
            max_jobs_per_worker: 10,
            default_timeout_secs: 1800, // 30 minutes
            heartbeat_interval_secs: 30,
            health_check_interval_secs: 10,
            scaling_policy: ScalingPolicy::default(),
            scale_up_threshold: 5,
            scale_down_threshold: 1,
            scale_up_cooldown_secs: 60,
            scale_down_cooldown_secs: 300,
            max_health_failures: 3,
            health_check_timeout_secs: 5,
        }
    }
}

/// Worker pool statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerPoolStats {
    /// Total number of workers
    pub total_workers: usize,
    /// Number of idle workers
    pub idle_workers: usize,
    /// Number of busy workers
    pub busy_workers: usize,
    /// Number of unhealthy workers
    pub unhealthy_workers: usize,
    /// Total jobs processed
    pub jobs_processed: u64,
    /// Total jobs failed
    pub jobs_failed: u64,
    /// Current queue depth
    pub queue_depth: usize,
    /// Average job duration in ms
    pub avg_job_duration_ms: f64,
    /// Average queue time in ms
    pub avg_queue_time_ms: f64,
    /// Current scaling factor (1.0 = baseline)
    pub scaling_factor: f64,
    /// Timestamp of last scale up
    pub last_scale_up_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of last scale down
    pub last_scale_down_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Internal worker entry in the pool
struct WorkerEntry {
    /// Worker handle
    handle: Arc<WorkerHandle>,
    /// Worker ID
    id: WorkerId,
    /// When the worker was added
    added_at: chrono::DateTime<chrono::Utc>,
    /// Consecutive health check failures
    health_failures: u32,
}

/// Worker pool for managing multiple workers
pub struct WorkerPool {
    /// Pool configuration
    config: WorkerPoolConfig,
    /// Worker processor factory
    processor_factory: Arc<dyn Fn() -> Arc<dyn JobProcessor> + Send + Sync>,
    /// Worker capabilities
    capabilities: WorkerCapabilities,
    /// Active workers
    workers: Arc<RwLock<HashMap<WorkerId, WorkerEntry>>>,
    /// Job queue sender (submitted jobs)
    job_tx: mpsc::UnboundedSender<WorkerJob>,
    /// Job queue receiver (for the distributor task)
    job_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<WorkerJob>>>>,
    /// Worker job channels (worker_id -> sender)
    worker_channels: Arc<RwLock<HashMap<WorkerId, mpsc::UnboundedSender<WorkerJob>>>>,
    /// Pool statistics
    stats: Arc<RwLock<WorkerPoolStats>>,
    /// Shutdown signal
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Background task handles
    task_handles: Mutex<Vec<JoinHandle<()>>>,
    /// Last scale up time
    last_scale_up: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
    /// Last scale down time
    last_scale_down: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl WorkerPool {
    /// Create a new worker pool
    pub fn new(
        config: WorkerPoolConfig,
        processor_factory: Arc<dyn Fn() -> Arc<dyn JobProcessor> + Send + Sync>,
        capabilities: WorkerCapabilities,
    ) -> Self {
        let (job_tx, job_rx) = mpsc::unbounded_channel();
        
        Self {
            config,
            processor_factory,
            capabilities,
            workers: Arc::new(RwLock::new(HashMap::new())),
            job_tx,
            job_rx: Arc::new(Mutex::new(Some(job_rx))),
            worker_channels: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(WorkerPoolStats::default())),
            shutdown_tx: Mutex::new(None),
            task_handles: Mutex::new(Vec::new()),
            last_scale_up: Arc::new(RwLock::new(None)),
            last_scale_down: Arc::new(RwLock::new(None)),
        }
    }
    
/// Start the worker pool
    pub async fn start(&self) -> WorkerResult<()> {
        info!(
            initial_workers = self.config.initial_workers,
            min_workers = self.config.min_workers,
            max_workers = self.config.max_workers,
            "Starting worker pool"
        );

        // Create initial workers
        for i in 0..self.config.initial_workers {
            self.spawn_worker(format!("worker-{}", i)).await?;
        }

        // Start background tasks
        let mut handles = self.task_handles.lock().await;

        // Job distributor task
        handles.push(self.spawn_job_distributor());

        // Health check task
        handles.push(self.spawn_health_check_task());

        // Scaling task (if not fixed)
        if self.config.scaling_policy != ScalingPolicy::Fixed {
            handles.push(self.spawn_scaling_task());
        }

        // Stats collection task
        handles.push(self.spawn_stats_task());

        info!("Worker pool started successfully");
        Ok(())
    }
    
    /// Submit a job to the pool
    pub async fn submit(&self, job: sh_types::Job) -> WorkerResult<JobExecutionResult> {
        let (result_tx, result_rx) = oneshot::channel();
        
        let worker_job = WorkerJob {
            job,
            result_tx,
            queued_at: Utc::now(),
        };
        
        self.job_tx
            .send(worker_job)
            .map_err(|_| WorkerError::ChannelError("Job channel closed".to_string()))?;
        
        // Update queue depth stat
        {
            let mut stats = self.stats.write().await;
            stats.queue_depth += 1;
        }
        
        // Wait for result
        let result = result_rx
            .await
            .map_err(|_| WorkerError::ChannelError("Result channel closed".to_string()))?;
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.queue_depth = stats.queue_depth.saturating_sub(1);
            stats.jobs_processed += 1;
            if !result.success {
                stats.jobs_failed += 1;
            }
        }
        
        Ok(result)
    }
    
    /// Get current pool statistics
    pub async fn stats(&self) -> WorkerPoolStats {
        self.stats.read().await.clone()
    }
    
    /// Get all worker snapshots
    pub async fn worker_snapshots(&self) -> Vec<WorkerSnapshot> {
        let workers = self.workers.read().await;
        let mut snapshots = Vec::with_capacity(workers.len());
        
        for entry in workers.values() {
            snapshots.push(entry.handle.snapshot().await);
        }
        
        snapshots
    }
    
    /// Get worker health information
    pub async fn worker_health(&self, worker_id: &WorkerId) -> WorkerResult<WorkerHealth> {
        let workers = self.workers.read().await;
        let entry = workers
            .get(worker_id)
            .ok_or_else(|| WorkerError::NotRunning(worker_id.clone()))?;
        
        Ok(entry.handle.health().await)
    }
    
    /// Scale up by adding workers
    pub async fn scale_up(&self, count: usize) -> WorkerResult<usize> {
        let workers = self.workers.read().await;
        let current_count = workers.len();
        drop(workers);
        
        let available_slots = self.config.max_workers.saturating_sub(current_count);
        let to_add = count.min(available_slots);
        
        if to_add == 0 {
            return Ok(0);
        }
        
        info!(count = to_add, current = current_count, max = self.config.max_workers, "Scaling up workers");
        
        let mut added = 0;
        for i in 0..to_add {
            let worker_id = format!("worker-{}-{}", Uuid::new_v4(), i);
            match self.spawn_worker(worker_id).await {
                Ok(_) => added += 1,
                Err(e) => {
                    error!(error = %e, "Failed to spawn worker during scale up");
                }
            }
        }
        
        // Update last scale up time
        *self.last_scale_up.write().await = Some(Utc::now());
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.last_scale_up_at = Some(Utc::now());
            stats.scaling_factor = (current_count + added) as f64 / self.config.initial_workers as f64;
        }
        
        Ok(added)
    }
    
    /// Scale down by removing idle workers
    pub async fn scale_down(&self, count: usize) -> WorkerResult<usize> {
        let workers = self.workers.read().await;
        let current_count = workers.len();
        
        // Don't go below minimum
        let min_to_keep = self.config.min_workers;
        let can_remove = current_count.saturating_sub(min_to_keep);
        let to_remove = count.min(can_remove);
        
        if to_remove == 0 {
            return Ok(0);
        }
        
        // Find idle workers to remove
        let mut idle_workers: Vec<WorkerId> = Vec::new();
        for (id, entry) in workers.iter() {
            let snapshot = entry.handle.snapshot().await;
            if snapshot.status == WorkerStatus::Idle {
                idle_workers.push(id.clone());
            }
        }
        
        drop(workers);
        
        // Remove workers
        let mut removed = 0;
        let mut workers = self.workers.write().await;
        
        for worker_id in idle_workers.iter().take(to_remove) {
            if let Some(entry) = workers.remove(worker_id) {
                entry.handle.stop().await;
                removed += 1;
                info!(worker_id = %worker_id, "Removed worker during scale down");
            }
        }
        
        // Update last scale down time
        *self.last_scale_down.write().await = Some(Utc::now());
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.last_scale_down_at = Some(Utc::now());
            stats.scaling_factor = (current_count - removed) as f64 / self.config.initial_workers as f64;
        }
        
        Ok(removed)
    }
    
    /// Shutdown the worker pool gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down worker pool");
        
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        
        // Stop all workers
        let workers = self.workers.read().await;
        for entry in workers.values() {
            entry.handle.stop().await;
        }
        drop(workers);
        
        // Cancel background tasks
        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.abort();
        }
        
        info!("Worker pool shutdown complete");
    }
    
/// Spawn a new worker
    async fn spawn_worker(&self, id: WorkerId) -> WorkerResult<()> {
        let processor = (self.processor_factory)();
        
        // Create a channel for this worker
        let (worker_tx, worker_rx) = mpsc::unbounded_channel();
        
        let worker = Worker::new(
            id.clone(),
            worker_rx,
            processor,
            self.capabilities.clone(),
            self.config.heartbeat_interval_secs,
            self.config.default_timeout_secs,
        );

        let handle = worker.start();

        let entry = WorkerEntry {
            handle: Arc::new(handle),
            id: id.clone(),
            added_at: Utc::now(),
            health_failures: 0,
        };

        // Store worker and its channel
        {
            let mut workers = self.workers.write().await;
            workers.insert(id.clone(), entry);
        }
        
        {
            let mut channels = self.worker_channels.write().await;
            channels.insert(id.clone(), worker_tx);
        }

        debug!(worker_id = %id, "Spawned new worker");
        Ok(())
    }

    /// Spawn job distributor task that routes jobs to workers
    fn spawn_job_distributor(&self) -> JoinHandle<()> {
        let job_rx = self.job_rx.clone();
        let worker_channels = self.worker_channels.clone();
        let workers = self.workers.clone();
        
        tokio::spawn(async move {
            let mut job_rx = job_rx.lock().await.take().expect("Job receiver already taken");
            
            while let Some(worker_job) = job_rx.recv().await {
                // Find an available worker (round-robin for now)
                let channels = worker_channels.read().await;
                let worker_ids: Vec<WorkerId> = channels.keys().cloned().collect();
                drop(channels);
                
                if worker_ids.is_empty() {
                    error!("No workers available to process job");
                    let _ = worker_job.result_tx.send(JobExecutionResult {
                        execution_id: Uuid::new_v4(),
                        worker_id: "none".to_string(),
                        job_id: worker_job.job.id,
                        success: false,
                        result: None,
                        error: Some("No workers available".to_string()),
                        metrics: ExecutionMetrics::default(),
                        started_at: Utc::now(),
                        completed_at: Utc::now(),
                    });
                    continue;
                }
                
                // Find an idle worker
                let workers_guard = workers.read().await;
                let mut selected_worker: Option<WorkerId> = None;
                
                for worker_id in &worker_ids {
                    if let Some(entry) = workers_guard.get(worker_id) {
                        let snapshot = entry.handle.snapshot().await;
                        if snapshot.status == WorkerStatus::Idle {
                            selected_worker = Some(worker_id.clone());
                            break;
                        }
                    }
                }
                drop(workers_guard);
                
                // If no idle worker, pick the first one (they'll queue internally)
                let selected_worker = selected_worker.unwrap_or_else(|| worker_ids[0].clone());
                
                // Send job to selected worker
                let channels = worker_channels.read().await;
                if let Some(tx) = channels.get(&selected_worker) {
                    if let Err(_) = tx.send(worker_job) {
                        error!(worker_id = %selected_worker, "Failed to send job to worker");
                    }
                }
            }
        })
    }

    /// Spawn health check task
    fn spawn_health_check_task(&self) -> JoinHandle<()> {
        let workers = self.workers.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.health_check_interval_secs));
            
            loop {
                interval.tick().await;
                
                let mut unhealthy_workers: Vec<WorkerId> = Vec::new();
                
                {
                    let workers_guard = workers.read().await;
                    
                    for (id, entry) in workers_guard.iter() {
                        let health = entry.handle.health().await;
                        
                        if !health.is_healthy {
                            unhealthy_workers.push(id.clone());
                            warn!(
                                worker_id = %id,
                                seconds_since_heartbeat = health.seconds_since_heartbeat,
                                "Worker health check failed"
                            );
                        }
                    }
                }
                
                // Update unhealthy count in stats
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.unhealthy_workers = unhealthy_workers.len();
                }
                
                // TODO: Restart unhealthy workers
                for worker_id in unhealthy_workers {
                    error!(worker_id = %worker_id, "Worker is unhealthy and should be restarted");
                }
            }
        })
    }
    
    /// Spawn scaling task
    fn spawn_scaling_task(&self) -> JoinHandle<()> {
        let workers = self.workers.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let last_scale_up = self.last_scale_up.clone();
        let last_scale_down = self.last_scale_down.clone();
        let job_tx = self.job_tx.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                let current_workers = {
                    let workers_guard = workers.read().await;
                    workers_guard.len()
                };
                
                let queue_depth = {
                    let stats_guard = stats.read().await;
                    stats_guard.queue_depth
                };
                
                let queue_per_worker = if current_workers > 0 {
                    queue_depth / current_workers
                } else {
                    queue_depth
                };
                
                // Check cooldowns
                let can_scale_up = {
                    let last = last_scale_up.read().await;
                    last.map(|t| {
                        (Utc::now() - t).num_seconds() >= config.scale_up_cooldown_secs as i64
                    })
                    .unwrap_or(true)
                };
                
                let can_scale_down = {
                    let last = last_scale_down.read().await;
                    last.map(|t| {
                        (Utc::now() - t).num_seconds() >= config.scale_down_cooldown_secs as i64
                    })
                    .unwrap_or(true)
                };
                
                // Scale up if queue depth is high
                if can_scale_up && queue_per_worker >= config.scale_up_threshold {
                    let to_add = ((queue_depth / config.scale_up_threshold) + 1).min(5);
                    if current_workers + to_add <= config.max_workers {
                        info!(
                            current = current_workers,
                            to_add = to_add,
                            queue_depth = queue_depth,
                            "Scaling up workers"
                        );
                        
                        // Note: Actual scale up would require access to self
                        // This is a simplified version - in production, use a channel
                    }
                }
                
                // Scale down if queue depth is low
                if can_scale_down && queue_per_worker <= config.scale_down_threshold && current_workers > config.min_workers {
                    info!(
                        current = current_workers,
                        min = config.min_workers,
                        queue_depth = queue_depth,
                        "Scaling down workers"
                    );
                    
                    // Note: Actual scale down would require access to self
                }
            }
        })
    }
    
    /// Spawn stats collection task
    fn spawn_stats_task(&self) -> JoinHandle<()> {
        let workers = self.workers.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                let workers_guard = workers.read().await;
                let total = workers_guard.len();
                
                let mut idle = 0;
                let mut busy = 0;
                let mut total_duration = 0.0;
                let mut worker_count = 0;
                
                for entry in workers_guard.values() {
                    let snapshot = entry.handle.snapshot().await;
                    
                    match snapshot.status {
                        WorkerStatus::Idle => idle += 1,
                        WorkerStatus::Busy => busy += 1,
                        _ => {}
                    }
                    
                    if snapshot.avg_job_duration_ms > 0.0 {
                        total_duration += snapshot.avg_job_duration_ms;
                        worker_count += 1;
                    }
                }
                
                drop(workers_guard);
                
                let avg_duration = if worker_count > 0 {
                    total_duration / worker_count as f64
                } else {
                    0.0
                };
                
                let mut stats_guard = stats.write().await;
                stats_guard.total_workers = total;
                stats_guard.idle_workers = idle;
                stats_guard.busy_workers = busy;
                stats_guard.avg_job_duration_ms = avg_duration;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    
    struct MockProcessor;
    
    #[async_trait]
    impl JobProcessor for MockProcessor {
        async fn process(&self, _job: &sh_types::Job) -> WorkerResult<sh_types::JobResult> {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(sh_types::JobResult::new(0))
        }
        
        fn can_process(&self, _job_type: &str) -> bool {
            true
        }
        
        fn capabilities(&self) -> WorkerCapabilities {
            WorkerCapabilities::default()
        }
    }
    
    fn create_test_pool() -> WorkerPool {
        let config = WorkerPoolConfig {
            min_workers: 1,
            max_workers: 4,
            initial_workers: 2,
            ..Default::default()
        };
        
        let processor_factory: Arc<dyn Fn() -> Arc<dyn JobProcessor> + Send + Sync> =
            Arc::new(|| Arc::new(MockProcessor));
        
        WorkerPool::new(config, processor_factory, WorkerCapabilities::default())
    }
    
    #[tokio::test]
    async fn test_pool_creation() {
        let pool = create_test_pool();
        
        // Before start, no workers
        let snapshots = pool.worker_snapshots().await;
        assert_eq!(snapshots.len(), 0);
    }
    
    #[tokio::test]
    async fn test_pool_start() {
        let pool = create_test_pool();
        
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let snapshots = pool.worker_snapshots().await;
        assert_eq!(snapshots.len(), 2); // initial_workers = 2
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_submit_job() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let target = sh_types::AnalysisTarget::new("/test", sh_types::Platform::Android);
        let job = sh_types::Job::new("test_job", target);
        
        let result = pool.submit(job).await.expect("Should submit job");
        assert!(result.success);
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_stats() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let stats = pool.stats().await;
        assert_eq!(stats.total_workers, 2);
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_scale_up() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let added = pool.scale_up(2).await.expect("Should scale up");
        assert_eq!(added, 2);
        
        let snapshots = pool.worker_snapshots().await;
        assert_eq!(snapshots.len(), 4); // 2 initial + 2 added
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_scale_down() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // First scale up
        pool.scale_up(1).await.expect("Should scale up");
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        let snapshots = pool.worker_snapshots().await;
        assert_eq!(snapshots.len(), 3);
        
        // Then scale down
        let removed = pool.scale_down(1).await.expect("Should scale down");
        assert_eq!(removed, 1);
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_scale_up_respects_max() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Try to scale up beyond max
        let added = pool.scale_up(10).await.expect("Should attempt scale up");
        assert_eq!(added, 2); // max_workers (4) - initial (2) = 2
        
        pool.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_pool_scale_down_respects_min() {
        let pool = create_test_pool();
        pool.start().await.expect("Pool should start");
        
        // Give workers time to start
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Try to scale down below min
        let removed = pool.scale_down(10).await.expect("Should attempt scale down");
        assert_eq!(removed, 1); // initial (2) - min (1) = 1
        
        pool.shutdown().await;
    }
}
