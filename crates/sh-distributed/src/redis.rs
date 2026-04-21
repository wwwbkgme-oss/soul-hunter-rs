//! Redis backend for distributed job queue

use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError, RedisResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::{DistributedError, Result};
use crate::worker::{WorkerInfo, WorkerRegistry, WorkerStatus};
use sh_types::{Job, JobId, JobPriority, JobResult, JobStatus};

/// Redis configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// Redis URL (e.g., "redis://localhost:6379")
    pub url: String,
    /// Connection pool size
    pub pool_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Key prefix for all keys
    pub key_prefix: String,
    /// Job queue key
    pub queue_key: String,
    /// Processing queue key
    pub processing_key: String,
    /// Dead letter queue key
    pub dlq_key: String,
    /// Worker registry key
    pub workers_key: String,
    /// Results key
    pub results_key: String,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Job visibility timeout in seconds (time before job is requeued)
    pub visibility_timeout_secs: u64,
    /// Enable cluster mode
    pub cluster_mode: bool,
    /// Cluster nodes (for cluster mode)
    pub cluster_nodes: Vec<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout_secs: 5,
            key_prefix: "sh:distributed".to_string(),
            queue_key: "jobs:queue".to_string(),
            processing_key: "jobs:processing".to_string(),
            dlq_key: "jobs:dlq".to_string(),
            workers_key: "workers".to_string(),
            results_key: "results".to_string(),
            heartbeat_interval_secs: 10,
            visibility_timeout_secs: 300,
            cluster_mode: false,
            cluster_nodes: vec![],
        }
    }
}

impl RedisConfig {
    /// Create new config with URL
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Set pool size
    pub fn with_pool_size(mut self, size: usize) -> Self {
        self.pool_size = size;
        self
    }

    /// Set key prefix
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Enable cluster mode
    pub fn with_cluster_mode(mut self, nodes: Vec<String>) -> Self {
        self.cluster_mode = true;
        self.cluster_nodes = nodes;
        self
    }

    /// Get full key with prefix
    fn full_key(&self, key: &str) -> String {
        format!("{}:{}", self.key_prefix, key)
    }
}

/// Redis job queue entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueueEntry {
    job: Job,
    enqueued_at: String,
    worker_id: Option<String>,
    visibility_timeout: Option<String>,
    retry_count: u32,
}

impl QueueEntry {
    fn new(job: Job) -> Self {
        Self {
            job,
            enqueued_at: Utc::now().to_rfc3339(),
            worker_id: None,
            visibility_timeout: None,
            retry_count: 0,
        }
    }
}

/// Redis backend for distributed execution
#[derive(Clone)]
pub struct RedisBackend {
    config: RedisConfig,
    connection: Arc<RwLock<ConnectionManager>>,
    worker_registry: WorkerRegistry,
    worker_id: String,
    running: Arc<RwLock<bool>>,
}

impl RedisBackend {
    /// Create a new Redis backend
    pub async fn new(config: RedisConfig, worker_id: impl Into<String>) -> Result<Self> {
        let worker_id = worker_id.into();
        info!("Connecting to Redis at {}", config.url);

        let client = redis::Client::open(config.url.as_str())
            .map_err(|e| DistributedError::Redis(format!("Failed to create client: {}", e)))?;

        let connection = client
            .get_connection_manager()
            .await
            .map_err(|e| DistributedError::Redis(format!("Failed to connect: {}", e)))?;

        info!("Connected to Redis successfully");

        Ok(Self {
            config,
            connection: Arc::new(RwLock::new(connection)),
            worker_registry: WorkerRegistry::new(),
            worker_id,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the backend
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = true;
        drop(running);

        // Register worker
        self.register_worker().await?;

        // Start heartbeat task
        self.start_heartbeat().await;

        // Start visibility timeout reaper
        self.start_reaper().await;

        info!("Redis backend started for worker {}", self.worker_id);
        Ok(())
    }

    /// Stop the backend
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = false;
        drop(running);

        // Unregister worker
        self.unregister_worker().await?;

        info!("Redis backend stopped for worker {}", self.worker_id);
        Ok(())
    }

    /// Submit a job to the queue
    pub async fn submit_job(&self, job: Job) -> Result<JobId> {
        let entry = QueueEntry::new(job.clone());
        let serialized =
            serde_json::to_string(&entry).map_err(|e| DistributedError::Serialization(e))?;

        let score = self.job_priority_to_score(&job);
        let queue_key = self.config.full_key(&self.config.queue_key);

        let mut conn = self.connection.write().await;
        conn.zadd(&queue_key, serialized, score)
            .await
            .map_err(|e| DistributedError::Redis(format!("Failed to submit job: {}", e)))?;

        info!("Submitted job {} to Redis queue", job.id);
        Ok(job.id)
    }

    /// Claim a job from the queue
    pub async fn claim_job(&self) -> Result<Option<Job>> {
        let queue_key = self.config.full_key(&self.config.queue_key);
        let processing_key = self.config.full_key(&self.config.processing_key);

        let mut conn = self.connection.write().await;

        // Get the highest priority job (lowest score)
        let result: RedisResult<Vec<(String, f64)>> = conn.zpopmin(&queue_key, 1).await;

        match result {
            Ok(entries) if !entries.is_empty() => {
                let (serialized, _score) = &entries[0];
                let mut entry: QueueEntry = serde_json::from_str(serialized)
                    .map_err(|e| DistributedError::Serialization(e))?;

                // Mark as processing
                entry.worker_id = Some(self.worker_id.clone());
                entry.visibility_timeout =
                    Some((Utc::now() + chrono::Duration::seconds(self.config.visibility_timeout_secs as i64)).to_rfc3339());

                let updated = serde_json::to_string(&entry)
                    .map_err(|e| DistributedError::Serialization(e))?;

                conn.hset(&processing_key, entry.job.id.to_string(), updated)
                    .await
                    .map_err(|e| DistributedError::Redis(format!("Failed to mark job processing: {}", e)))?;

                debug!("Claimed job {} from queue", entry.job.id);
                Ok(Some(entry.job))
            }
            _ => Ok(None),
        }
    }

    /// Complete a job
    pub async fn complete_job(&self, job_id: JobId, result: JobResult) -> Result<()> {
        let processing_key = self.config.full_key(&self.config.processing_key);
        let results_key = self.config.full_key(&self.config.results_key);

        let mut conn = self.connection.write().await;

        // Remove from processing
        let _: RedisResult<()> = conn.hdel(&processing_key, job_id.to_string()).await;

        // Store result
        let result_json = serde_json::to_string(&result)
            .map_err(|e| DistributedError::Serialization(e))?;

        conn.hset(&results_key, job_id.to_string(), result_json)
            .await
            .map_err(|e| DistributedError::Redis(format!("Failed to store result: {}", e)))?;

        // Update worker stats
        if let Some(mut worker) = self.worker_registry.get(&self.worker_id) {
            worker.record_success();
            self.update_worker_in_redis(&worker).await?;
        }

        info!("Completed job {}", job_id);
        Ok(())
    }

    /// Fail a job
    pub async fn fail_job(&self, job_id: JobId, error: impl Into<String>) -> Result<()> {
        let processing_key = self.config.full_key(&self.config.processing_key);
        let dlq_key = self.config.full_key(&self.config.dlq_key);

        let mut conn = self.connection.write().await;

        // Get job from processing
        let result: RedisResult<Option<String>> =
            conn.hget(&processing_key, job_id.to_string()).await;

        if let Ok(Some(serialized)) = result {
            let mut entry: QueueEntry = serde_json::from_str(&serialized)
                .map_err(|e| DistributedError::Serialization(e))?;

            // Remove from processing
            let _: RedisResult<()> = conn.hdel(&processing_key, job_id.to_string()).await;

            // Check if should retry
            entry.retry_count += 1;
            if entry.retry_count < entry.job.max_retries {
                // Requeue with delay
                let queue_key = self.config.full_key(&self.config.queue_key);
                let score = self.job_priority_to_score(&entry.job);
                let updated = serde_json::to_string(&entry)
                    .map_err(|e| DistributedError::Serialization(e))?;

                conn.zadd(&queue_key, updated, score + entry.retry_count as f64 * 1000.0)
                    .await
                    .map_err(|e| DistributedError::Redis(format!("Failed to requeue job: {}", e)))?;

                warn!("Requeued job {} for retry (attempt {})", job_id, entry.retry_count);
            } else {
                // Move to DLQ
                conn.hset(&dlq_key, job_id.to_string(), serialized)
                    .await
                    .map_err(|e| DistributedError::Redis(format!("Failed to move to DLQ: {}", e)))?;

                error!("Job {} moved to DLQ after {} retries", job_id, entry.retry_count);
            }
        }

        // Update worker stats
        if let Some(mut worker) = self.worker_registry.get(&self.worker_id) {
            worker.record_failure();
            self.update_worker_in_redis(&worker).await?;
        }

        Ok(())
    }

    /// Get job result
    pub async fn get_result(&self, job_id: JobId) -> Result<Option<JobResult>> {
        let results_key = self.config.full_key(&self.config.results_key);

        let mut conn = self.connection.write().await;
        let result: RedisResult<Option<String>> = conn.hget(&results_key, job_id.to_string()).await;

        match result {
            Ok(Some(serialized)) => {
                let job_result: JobResult = serde_json::from_str(&serialized)
                    .map_err(|e| DistributedError::Serialization(e))?;
                Ok(Some(job_result))
            }
            _ => Ok(None),
        }
    }

    /// Wait for job completion with timeout
    pub async fn wait_for_job(&self, job_id: JobId, timeout_secs: u64) -> Result<JobResult> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            if let Some(result) = self.get_result(job_id).await? {
                return Ok(result);
            }

            if start.elapsed() > timeout {
                return Err(DistributedError::Timeout(format!(
                    "Job {} did not complete within {} seconds",
                    job_id, timeout_secs
                )));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Get queue length
    pub async fn queue_length(&self) -> Result<usize> {
        let queue_key = self.config.full_key(&self.config.queue_key);

        let mut conn = self.connection.write().await;
        let len: RedisResult<i64> = conn.zcard(&queue_key).await;

        match len {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(DistributedError::Redis(format!("Failed to get queue length: {}", e))),
        }
    }

    /// Get processing count
    pub async fn processing_count(&self) -> Result<usize> {
        let processing_key = self.config.full_key(&self.config.processing_key);

        let mut conn = self.connection.write().await;
        let len: RedisResult<i64> = conn.hlen(&processing_key).await;

        match len {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(DistributedError::Redis(format!(
                "Failed to get processing count: {}",
                e
            ))),
        }
    }

    /// Get DLQ length
    pub async fn dlq_length(&self) -> Result<usize> {
        let dlq_key = self.config.full_key(&self.config.dlq_key);

        let mut conn = self.connection.write().await;
        let len: RedisResult<i64> = conn.hlen(&dlq_key).await;

        match len {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(DistributedError::Redis(format!("Failed to get DLQ length: {}", e))),
        }
    }

    /// Register worker in Redis
    async fn register_worker(&self) -> Result<()> {
        let workers_key = self.config.full_key(&self.config.workers_key);
        let worker = WorkerInfo::new(&self.worker_id, "127.0.0.1:0");

        let serialized = serde_json::to_string(&worker)
            .map_err(|e| DistributedError::Serialization(e))?;

        let mut conn = self.connection.write().await;
        conn.hset(&workers_key, &self.worker_id, serialized)
            .await
            .map_err(|e| DistributedError::WorkerRegistrationFailed(e.to_string()))?;

        self.worker_registry.register(worker)?;
        info!("Registered worker {} in Redis", self.worker_id);
        Ok(())
    }

    /// Unregister worker from Redis
    async fn unregister_worker(&self) -> Result<()> {
        let workers_key = self.config.full_key(&self.config.workers_key);

        let mut conn = self.connection.write().await;
        conn.hdel(&workers_key, &self.worker_id)
            .await
            .map_err(|e| DistributedError::Redis(format!("Failed to unregister worker: {}", e)))?;

        self.worker_registry.unregister(&self.worker_id)?;
        info!("Unregistered worker {} from Redis", self.worker_id);
        Ok(())
    }

    /// Update worker in Redis
    async fn update_worker_in_redis(&self, worker: &WorkerInfo) -> Result<()> {
        let workers_key = self.config.full_key(&self.config.workers_key);

        let serialized = serde_json::to_string(worker)
            .map_err(|e| DistributedError::Serialization(e))?;

        let mut conn = self.connection.write().await;
        conn.hset(&workers_key, &worker.id, serialized)
            .await
            .map_err(|e| DistributedError::Redis(format!("Failed to update worker: {}", e)))?;

        Ok(())
    }

    /// Start heartbeat task
    async fn start_heartbeat(&self) {
        let worker_id = self.worker_id.clone();
        let config = self.config.clone();
        let connection = self.connection.clone();
        let worker_registry = self.worker_registry.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.heartbeat_interval_secs));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Update heartbeat
                if let Some(mut worker) = worker_registry.get(&worker_id) {
                    worker.update_heartbeat();

                    let workers_key = config.full_key(&config.workers_key);
                    let serialized = match serde_json::to_string(&worker) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to serialize worker: {}", e);
                            continue;
                        }
                    };

                    let mut conn = connection.write().await;
                    if let Err(e) = conn.hset(&workers_key, &worker_id, serialized).await {
                        error!("Failed to send heartbeat: {}", e);
                    }
                }
            }

            debug!("Heartbeat task stopped for worker {}", worker_id);
        });
    }

    /// Start reaper task for visibility timeout
    async fn start_reaper(&self) {
        let config = self.config.clone();
        let connection = self.connection.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Reap timed out jobs
                if let Err(e) = Self::reap_timed_out_jobs(&config, &connection).await {
                    error!("Failed to reap timed out jobs: {}", e);
                }
            }

            debug!("Reaper task stopped");
        });
    }

    /// Reap jobs that have exceeded visibility timeout
    async fn reap_timed_out_jobs(
        config: &RedisConfig,
        connection: &Arc<RwLock<ConnectionManager>>,
    ) -> Result<()> {
        let processing_key = config.full_key(&config.processing_key);
        let queue_key = config.full_key(&config.queue_key);

        let mut conn = connection.write().await;

        // Get all processing jobs
        let entries: RedisResult<Vec<(String, String)>> = conn.hgetall(&processing_key).await;

        if let Ok(entries) = entries {
            let now = Utc::now();

            for (job_id, serialized) in entries {
                if let Ok(entry) = serde_json::from_str::<QueueEntry>(&serialized) {
                    if let Some(timeout_str) = entry.visibility_timeout {
                        if let Ok(timeout) = chrono::DateTime::parse_from_rfc3339(&timeout_str) {
                            let timeout = timeout.with_timezone(&Utc);
                            if now > timeout {
                                // Job has timed out, requeue it
                                warn!("Job {} visibility timeout exceeded, requeuing", job_id);

                                // Remove from processing
                                let _: RedisResult<()> =
                                    conn.hdel(&processing_key, &job_id).await;

                                // Requeue
                                let score = entry.job.priority as i32 as f64;
                                let _: RedisResult<()> =
                                    conn.zadd(&queue_key, serialized, score).await;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert job priority to Redis sorted set score
    fn job_priority_to_score(&self, job: &Job) -> f64 {
        // Higher priority = lower score (processed first)
        let base_score = match job.priority {
            JobPriority::Critical => 0.0,
            JobPriority::High => 25.0,
            JobPriority::Normal => 50.0,
            JobPriority::Low => 75.0,
            JobPriority::Lowest => 100.0,
        };

        // Add timestamp for FIFO within same priority
        let timestamp_factor = job.created_at.timestamp_millis() as f64 / 1e15;
        base_score + timestamp_factor
    }

    /// Get all workers from Redis
    pub async fn get_workers(&self) -> Result<Vec<WorkerInfo>> {
        let workers_key = self.config.full_key(&self.config.workers_key);

        let mut conn = self.connection.write().await;
        let entries: RedisResult<Vec<String>> = conn.hvals(&workers_key).await;

        match entries {
            Ok(workers) => {
                let mut result = Vec::new();
                for serialized in workers {
                    if let Ok(worker) = serde_json::from_str::<WorkerInfo>(&serialized) {
                        result.push(worker);
                    }
                }
                Ok(result)
            }
            Err(e) => Err(DistributedError::Redis(format!("Failed to get workers: {}", e))),
        }
    }

    /// Get worker count
    pub async fn get_worker_count(&self) -> Result<usize> {
        let workers_key = self.config.full_key(&self.config.workers_key);

        let mut conn = self.connection.write().await;
        let count: RedisResult<i64> = conn.hlen(&workers_key).await;

        match count {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(DistributedError::Redis(format!("Failed to get worker count: {}", e))),
        }
    }

    /// Clear all data (use with caution)
    pub async fn clear_all(&self) -> Result<()> {
        let mut conn = self.connection.write().await;

        // Get all keys with prefix
        let pattern = format!("{}:*", self.config.key_prefix);
        let keys: RedisResult<Vec<String>> = conn.keys(&pattern).await;

        if let Ok(keys) = keys {
            for key in keys {
                let _: RedisResult<()> = conn.del(&key).await;
            }
        }

        info!("Cleared all Redis data with prefix {}", self.config.key_prefix);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform};

    #[test]
    fn test_redis_config() {
        let config = RedisConfig::new("redis://localhost:6379").with_pool_size(20);
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.pool_size, 20);
        assert_eq!(config.full_key("test"), "sh:distributed:test");
    }

    #[test]
    fn test_queue_entry() {
        let target = AnalysisTarget::new("/test", Platform::Android);
        let job = Job::new("test", target);
        let entry = QueueEntry::new(job);
        assert!(entry.worker_id.is_none());
        assert_eq!(entry.retry_count, 0);
    }
}
