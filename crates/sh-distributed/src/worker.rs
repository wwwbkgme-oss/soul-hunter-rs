//! Worker registry and management for distributed execution

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::{DistributedError, Result};

/// Worker status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    /// Worker is starting up
    Starting,
    /// Worker is ready to accept jobs
    Ready,
    /// Worker is currently busy
    Busy,
    /// Worker is shutting down
    ShuttingDown,
    /// Worker is offline
    Offline,
    /// Worker has failed
    Failed,
}

impl Default for WorkerStatus {
    fn default() -> Self {
        WorkerStatus::Starting
    }
}

impl fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerStatus::Starting => write!(f, "starting"),
            WorkerStatus::Ready => write!(f, "ready"),
            WorkerStatus::Busy => write!(f, "busy"),
            WorkerStatus::ShuttingDown => write!(f, "shutting_down"),
            WorkerStatus::Offline => write!(f, "offline"),
            WorkerStatus::Failed => write!(f, "failed"),
        }
    }
}

use std::fmt;

/// Worker capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Supported job types
    pub job_types: Vec<String>,
    /// Supported platforms
    pub platforms: Vec<String>,
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: usize,
    /// Available memory in MB
    pub available_memory_mb: u64,
    /// Available CPU cores
    pub available_cpu_cores: u32,
    /// Custom capabilities
    pub custom: HashMap<String, String>,
}

impl WorkerCapabilities {
    /// Create new capabilities with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a supported job type
    pub fn with_job_type(mut self, job_type: impl Into<String>) -> Self {
        self.job_types.push(job_type.into());
        self
    }

    /// Add a supported platform
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platforms.push(platform.into());
        self
    }

    /// Set maximum concurrent jobs
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent_jobs = max;
        self
    }

    /// Check if worker supports a job type
    pub fn supports_job_type(&self, job_type: &str) -> bool {
        self.job_types.is_empty() || self.job_types.contains(&job_type.to_string())
    }

    /// Check if worker supports a platform
    pub fn supports_platform(&self, platform: &str) -> bool {
        self.platforms.is_empty() || self.platforms.contains(&platform.to_string())
    }
}

/// Worker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    /// Unique worker ID
    pub id: String,
    /// Worker hostname
    pub hostname: String,
    /// Worker address
    pub address: SocketAddr,
    /// Current status
    pub status: WorkerStatus,
    /// Worker capabilities
    pub capabilities: WorkerCapabilities,
    /// Current load (0.0 - 1.0)
    pub load: f64,
    /// Number of active jobs
    pub active_jobs: usize,
    /// Total jobs processed
    pub total_jobs_processed: u64,
    /// Total jobs failed
    pub total_jobs_failed: u64,
    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,
    /// Registration timestamp
    pub registered_at: DateTime<Utc>,
    /// Worker version
    pub version: String,
    /// Worker region/zone
    pub region: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl WorkerInfo {
    /// Create a new worker info
    pub fn new(id: impl Into<String>, address: impl Into<String>) -> Self {
        let id = id.into();
        let address_str = address.into();
        let address: SocketAddr = address_str
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());

        Self {
            id,
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string()),
            address,
            status: WorkerStatus::Starting,
            capabilities: WorkerCapabilities::default(),
            load: 0.0,
            active_jobs: 0,
            total_jobs_processed: 0,
            total_jobs_failed: 0,
            last_heartbeat: Utc::now(),
            registered_at: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            region: None,
            metadata: HashMap::new(),
        }
    }

    /// Set worker capabilities
    pub fn with_capabilities(mut self, capabilities: WorkerCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set worker region
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Update heartbeat
    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Utc::now();
    }

    /// Mark worker as ready
    pub fn mark_ready(&mut self) {
        self.status = WorkerStatus::Ready;
        self.update_heartbeat();
    }

    /// Mark worker as busy
    pub fn mark_busy(&mut self) {
        self.status = WorkerStatus::Busy;
    }

    /// Mark worker as shutting down
    pub fn mark_shutting_down(&mut self) {
        self.status = WorkerStatus::ShuttingDown;
    }

    /// Mark worker as offline
    pub fn mark_offline(&mut self) {
        self.status = WorkerStatus::Offline;
    }

    /// Mark worker as failed
    pub fn mark_failed(&mut self) {
        self.status = WorkerStatus::Failed;
    }

    /// Check if worker is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, WorkerStatus::Ready | WorkerStatus::Busy)
    }

    /// Check if worker is available for new jobs
    pub fn is_available(&self) -> bool {
        self.status == WorkerStatus::Ready
            && self.active_jobs < self.capabilities.max_concurrent_jobs
    }

    /// Increment active jobs
    pub fn increment_active(&mut self) {
        self.active_jobs += 1;
        if self.active_jobs >= self.capabilities.max_concurrent_jobs {
            self.status = WorkerStatus::Busy;
        }
    }

    /// Decrement active jobs
    pub fn decrement_active(&mut self) {
        if self.active_jobs > 0 {
            self.active_jobs -= 1;
        }
        if self.active_jobs < self.capabilities.max_concurrent_jobs {
            self.status = WorkerStatus::Ready;
        }
    }

    /// Record job completion
    pub fn record_success(&mut self) {
        self.total_jobs_processed += 1;
        self.decrement_active();
    }

    /// Record job failure
    pub fn record_failure(&mut self) {
        self.total_jobs_failed += 1;
        self.decrement_active();
    }

    /// Update load
    pub fn update_load(&mut self, load: f64) {
        self.load = load.clamp(0.0, 1.0);
    }

    /// Check if heartbeat is stale
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        let elapsed = Utc::now() - self.last_heartbeat;
        elapsed.num_seconds() > timeout_secs as i64
    }
}

/// Worker registry for tracking active workers
#[derive(Debug, Clone)]
pub struct WorkerRegistry {
    workers: Arc<DashMap<String, WorkerInfo>>,
    heartbeat_timeout_secs: u64,
}

impl WorkerRegistry {
    /// Create a new worker registry
    pub fn new() -> Self {
        Self::with_timeout(30)
    }

    /// Create a new registry with custom heartbeat timeout
    pub fn with_timeout(heartbeat_timeout_secs: u64) -> Self {
        Self {
            workers: Arc::new(DashMap::new()),
            heartbeat_timeout_secs,
        }
    }

    /// Register a new worker
    pub fn register(&self, worker: WorkerInfo) -> Result<()> {
        let id = worker.id.clone();
        info!("Registering worker: {} at {}", id, worker.address);
        self.workers.insert(id, worker);
        Ok(())
    }

    /// Unregister a worker
    pub fn unregister(&self, worker_id: &str) -> Result<()> {
        info!("Unregistering worker: {}", worker_id);
        self.workers.remove(worker_id);
        Ok(())
    }

    /// Update worker heartbeat
    pub fn heartbeat(&self, worker_id: &str) -> Result<()> {
        if let Some(mut entry) = self.workers.get_mut(worker_id) {
            entry.update_heartbeat();
            debug!("Updated heartbeat for worker: {}", worker_id);
            Ok(())
        } else {
            Err(DistributedError::WorkerNotFound(worker_id.to_string()))
        }
    }

    /// Get worker info
    pub fn get(&self, worker_id: &str) -> Option<WorkerInfo> {
        self.workers.get(worker_id).map(|w| w.clone())
    }

    /// Get all workers
    pub fn get_all(&self) -> Vec<WorkerInfo> {
        self.workers.iter().map(|w| w.clone()).collect()
    }

    /// Get healthy workers
    pub fn get_healthy(&self) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.is_healthy())
            .map(|w| w.clone())
            .collect()
    }

    /// Get available workers (ready to accept jobs)
    pub fn get_available(&self) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.is_available())
            .map(|w| w.clone())
            .collect()
    }

    /// Get workers by status
    pub fn get_by_status(&self, status: WorkerStatus) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.status == status)
            .map(|w| w.clone())
            .collect()
    }

    /// Get workers that support a specific job type
    pub fn get_by_job_type(&self, job_type: &str) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.capabilities.supports_job_type(job_type) && w.is_available())
            .map(|w| w.clone())
            .collect()
    }

    /// Get workers that support a specific platform
    pub fn get_by_platform(&self, platform: &str) -> Vec<WorkerInfo> {
        self.workers
            .iter()
            .filter(|w| w.capabilities.supports_platform(platform) && w.is_available())
            .map(|w| w.clone())
            .collect()
    }

    /// Update worker status
    pub fn update_status(&self, worker_id: &str, status: WorkerStatus) -> Result<()> {
        if let Some(mut entry) = self.workers.get_mut(worker_id) {
            entry.status = status;
            Ok(())
        } else {
            Err(DistributedError::WorkerNotFound(worker_id.to_string()))
        }
    }

    /// Update worker load
    pub fn update_load(&self, worker_id: &str, load: f64) -> Result<()> {
        if let Some(mut entry) = self.workers.get_mut(worker_id) {
            entry.update_load(load);
            Ok(())
        } else {
            Err(DistributedError::WorkerNotFound(worker_id.to_string()))
        }
    }

    /// Remove stale workers
    pub fn remove_stale(&self) -> Vec<String> {
        let stale_ids: Vec<String> = self
            .workers
            .iter()
            .filter(|w| w.is_stale(self.heartbeat_timeout_secs))
            .map(|w| w.id.clone())
            .collect();

        for id in &stale_ids {
            warn!("Removing stale worker: {}", id);
            self.workers.remove(id);
        }

        stale_ids
    }

    /// Get worker count
    pub fn count(&self) -> usize {
        self.workers.len()
    }

    /// Get healthy worker count
    pub fn healthy_count(&self) -> usize {
        self.workers.iter().filter(|w| w.is_healthy()).count()
    }

    /// Get available worker count
    pub fn available_count(&self) -> usize {
        self.workers.iter().filter(|w| w.is_available()).count()
    }

    /// Check if worker exists
    pub fn contains(&self, worker_id: &str) -> bool {
        self.workers.contains_key(worker_id)
    }

    /// Clear all workers
    pub fn clear(&self) {
        self.workers.clear();
    }

    /// Get total jobs processed across all workers
    pub fn total_jobs_processed(&self) -> u64 {
        self.workers
            .iter()
            .map(|w| w.total_jobs_processed)
            .sum()
    }

    /// Get total jobs failed across all workers
    pub fn total_jobs_failed(&self) -> u64 {
        self.workers
            .iter()
            .map(|w| w.total_jobs_failed)
            .sum()
    }

    /// Get average load across all workers
    pub fn average_load(&self) -> f64 {
        let count = self.workers.len() as f64;
        if count == 0.0 {
            return 0.0;
        }
        self.workers.iter().map(|w| w.load).sum::<f64>() / count
    }
}

impl Default for WorkerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Worker selector for choosing the best worker for a job
pub struct WorkerSelector;

impl WorkerSelector {
    /// Select the best worker using round-robin
    pub fn round_robin(workers: &[WorkerInfo], last_index: &mut usize) -> Option<WorkerInfo> {
        if workers.is_empty() {
            return None;
        }
        let idx = *last_index % workers.len();
        *last_index = (*last_index + 1) % workers.len();
        Some(workers[idx].clone())
    }

    /// Select the worker with lowest load
    pub fn least_loaded(workers: &[WorkerInfo]) -> Option<WorkerInfo> {
        workers
            .iter()
            .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
            .cloned()
    }

    /// Select a random worker
    pub fn random(workers: &[WorkerInfo]) -> Option<WorkerInfo> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        if workers.is_empty() {
            return None;
        }

        let mut hasher = DefaultHasher::new();
        Utc::now().timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        let idx = (hasher.finish() as usize) % workers.len();
        Some(workers[idx].clone())
    }

    /// Select worker with most capacity
    pub fn most_capacity(workers: &[WorkerInfo]) -> Option<WorkerInfo> {
        workers
            .iter()
            .max_by_key(|w| {
                w.capabilities.max_concurrent_jobs.saturating_sub(w.active_jobs)
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_info_lifecycle() {
        let mut worker = WorkerInfo::new("test-1", "127.0.0.1:8080");
        assert_eq!(worker.status, WorkerStatus::Starting);

        worker.mark_ready();
        assert_eq!(worker.status, WorkerStatus::Ready);
        assert!(worker.is_healthy());

        worker.increment_active();
        assert_eq!(worker.active_jobs, 1);

        worker.record_success();
        assert_eq!(worker.active_jobs, 0);
        assert_eq!(worker.total_jobs_processed, 1);
    }

    #[test]
    fn test_worker_capabilities() {
        let caps = WorkerCapabilities::new()
            .with_job_type("static_analysis")
            .with_platform("android")
            .with_max_concurrent(5);

        assert!(caps.supports_job_type("static_analysis"));
        assert!(!caps.supports_job_type("dynamic_analysis"));
        assert!(caps.supports_platform("android"));
        assert_eq!(caps.max_concurrent_jobs, 5);
    }

    #[test]
    fn test_worker_registry() {
        let registry = WorkerRegistry::new();

        let worker = WorkerInfo::new("test-1", "127.0.0.1:8080").mark_ready();
        registry.register(worker.clone()).unwrap();

        assert_eq!(registry.count(), 1);
        assert!(registry.contains("test-1"));

        let retrieved = registry.get("test-1").unwrap();
        assert_eq!(retrieved.id, "test-1");

        registry.unregister("test-1").unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_worker_selector() {
        let workers = vec![
            WorkerInfo::new("w1", "127.0.0.1:8081"),
            WorkerInfo::new("w2", "127.0.0.1:8082"),
            WorkerInfo::new("w3", "127.0.0.1:8083"),
        ];

        let mut idx = 0;
        let selected = WorkerSelector::round_robin(&workers, &mut idx);
        assert!(selected.is_some());

        let selected = WorkerSelector::random(&workers);
        assert!(selected.is_some());
    }
}
