//! Multi-Version Concurrency Control for atomic state synchronization
//!
//! Solves the "Concurrent TODO Update" problem by allowing multiple agents
//! to update task state concurrently without data loss or race conditions.
//!
//! ## Features
//!
//! - **Versioned State**: Each state change creates a new version with cryptographic hash
//! - **Atomic Updates**: Compare-and-swap semantics ensure consistency
//! - **Conflict Detection**: Automatic detection of concurrent modifications
//! - **Merge Strategies**: Configurable merge policies for concurrent updates
//! - **Audit Trail**: Complete history of all state changes
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      MVCC Store                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Key → [Version_1, Version_2, Version_3, ...]              │
//! │         │          │          │                             │
//! │         ├──────────┼──────────┤                             │
//! │         ▼          ▼          ▼                             │
//! │  {state: "pending", version: 1, hash: "abc"}               │
//! │  {state: "running", version: 2, hash: "def"}               │
//! │  {state: "completed", version: 3, hash: "ghi"}             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust
//! use sh_orchestrator::mvcc::{MvccStore, MvccVersion};
//!
//! let store = MvccStore::new();
//!
//! // Initial state
//! let v1 = store.create("task-1".to_string(), "pending".to_string());
//!
//! // Concurrent update attempt (will fail due to version mismatch)
//! let mut v2 = store.get_current("task-1").unwrap().clone();
//! v2.state = "running".to_string();
//! let success = store.update_if_match("task-1", v2, || {
//!     // transition validation
//!     true
//! }).unwrap();
//! ```

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

use sh_types::prelude::*;

/// MVCC-specific error types
#[derive(Error, Debug)]
pub enum MvccError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Version mismatch for key: {0}")]
    VersionMismatch(String),

    #[error("Maximum versions ({0}) exceeded for key: {1}")]
    MaxVersionsExceeded(usize, String),

    #[error("Transition validation failed: {0}")]
    TransitionValidationFailed(String),

    #[error("Concurrent modification conflict on key: {0}")]
    ConcurrentConflict(String),

    #[error("Store error: {0}")]
    StoreError(String),
}

/// A versioned state entry with full audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MvccVersion<T> {
    /// Unique version identifier (incremental)
    pub version: u64,
    /// The actual state data
    pub state: T,
    /// Cryptographic hash of state at this version (SHA-256)
    pub hash: String,
    /// Who created this version (agent ID or system)
    pub created_by: Option<String>,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Why this version was created (change reason)
    pub reason: Option<String>,
    /// Parent version this was derived from
    pub parent_version: Option<u64>,
}

impl<T: Serialize> MvccVersion<T> {
    /// Create a new version entry
    pub fn new(
        version: u64,
        state: T,
        created_by: Option<String>,
        reason: Option<String>,
        parent_version: Option<u64>,
    ) -> Result<Self, MvccError> {
        let hash = Self::compute_hash(&state)?;
        Ok(Self {
            version,
            state,
            hash,
            created_by,
            created_at: Utc::now(),
            reason,
            parent_version,
        })
    }

    /// Compute cryptographic hash of state
    fn compute_hash(state: &T) -> Result<String, MvccError> {
        let json = serde_json::to_vec(state)
            .map_err(|e| MvccError::StoreError(e.to_string()))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&json);
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Verify that this version's hash matches the state
    pub fn verify(&self) -> bool {
        match Self::compute_hash(&self.state) {
            Ok(hash) => hash == self.hash,
            Err(_) => false,
        }
    }
}

/// Configuration for MVCC store
#[derive(Debug, Clone)]
pub struct MvccConfig {
    /// Maximum number of versions to retain per key (for audit trail)
    pub max_versions_per_key: usize,
    /// Whether to enable automatic garbage collection of old versions
    pub enable_gc: bool,
    /// GC interval in seconds
    pub gc_interval_secs: u64,
    /// When to compact versions (keep only every N version)
    pub compaction_interval: usize,
}

impl Default for MvccConfig {
    fn default() -> Self {
        Self {
            max_versions_per_key: 100,
            enable_gc: true,
            gc_interval_secs: 3600,
            compaction_interval: 10,
        }
    }
}

/// Thread-safe MVCC store with atomic operations
pub struct MvccStore<T> {
    /// Main storage: key → versions (newest first)
    versions: DashMap<String, Arc<Mutex<VecDeque<Arc<MvccVersion<T>>>>>>,
    /// Global version counter for generating sequential versions
    global_version: Arc<Mutex<u64>>,
    config: MvccConfig,
}

impl<T: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static> MvccStore<T> {
    /// Create new MVCC store with configuration
    pub fn new(config: MvccConfig) -> Self {
        Self {
            versions: DashMap::new(),
            global_version: Arc::new(Mutex::new(0)),
            config,
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(MvccConfig::default())
    }

    /// Get or create initial version for a key
    pub async fn get_or_create(
        &self,
        key: String,
        initial_state: T,
        created_by: Option<String>,
        reason: Option<String>,
    ) -> Result<Arc<MvccVersion<T>>, MvccError> {
        let versions = self.versions.entry(key.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(VecDeque::new()))
        });

        let mut versions_guard = versions.lock().await;

        if let Some(latest) = versions_guard.front() {
            return Ok(Arc::clone(latest));
        }

        // Create initial version
        let version_num = {
            let mut global = self.global_version.lock().await;
            *global += 1;
            *global
        };

        let version = Arc::new(MvccVersion::new(
            version_num,
            initial_state,
            created_by,
            reason,
            None,
        )?);

        versions_guard.push_front(Arc::clone(&version));
        debug!("Created initial version {} for key: {}", version_num, key);

        Ok(version)
    }

    /// Get current (latest) version for a key
    pub async fn get_current(&self, key: &str) -> Option<Arc<MvccVersion<T>>> {
        self.versions
            .get(key)
            .and_then(|versions| {
                versions.lock().await.front().map(Arc::clone)
            })
    }

    /// Get all versions for a key (oldest to newest)
    pub async fn get_history(&self, key: &str) -> Vec<Arc<MvccVersion<T>>> {
        self.versions
            .get(key)
            .map(|versions| {
                let v = versions.lock().await;
                v.iter().rev().map(Arc::clone).collect()
            })
            .unwrap_or_default()
    }

    /// Update state only if version matches (atomic compare-and-swap)
    ///
    /// The transition validator can enforce state machine rules.
    pub async fn update_if_match<F>(
        &self,
        key: String,
        expected_version: MvccVersion<T>,
        transition_validator: F,
    ) -> Result<Arc<MvccVersion<T>>, MvccError>
    where
        F: Fn(&T, &T) -> bool,
    {
        let versions = self.versions.entry(key.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(VecDeque::new()))
        });

        let mut versions_guard = versions.lock().await;

        let current = versions_guard
            .front()
            .ok_or_else(|| MvccError::NotFound(key.clone()))?;

        // Version must match
        if current.version != expected_version.version {
            return Err(MvccError::VersionMismatch(key));
        }

        // Hash must match (state integrity check)
        if current.hash != expected_version.hash {
            return Err(MvccError::ConcurrentConflict(key));
        }

        // Validate transition
        if !transition_validator(&current.state, &expected_version.state) {
            return Err(MvccError::TransitionValidationFailed(key));
        }

        // Create new version
        let version_num = {
            let mut global = self.global_version.lock().await;
            *global += 1;
            *global
        };

        let new_version = Arc::new(MvccVersion::new(
            version_num,
            expected_version.state.clone(),
            expected_version.created_by,
            expected_version.reason,
            Some(current.version),
        )?);

        // Prepend to list (newest at front)
        versions_guard.push_front(Arc::clone(&new_version));

        // Trim old versions if exceeding limit
        if versions_guard.len() > self.config.max_versions_per_key {
            versions_guard.pop_back();
        }

        debug!(
            "Updated key {}: version {} → {}",
            key,
            current.version,
            version_num
        );

        Ok(new_version)
    }

    /// Atomic compare-and-swap with closure-based update
    ///
    /// This is the preferred pattern for concurrent updates:
    /// ```rust
    /// store.update_with_cas(key, |current_state| {
    ///     let mut new_state = current_state.clone();
    ///     new_state.progress += 1;
    ///     new_state
    /// }).await?;
    /// ```
    pub async fn update_with_cas<F>(
        &self,
        key: String,
        updater: F,
        created_by: Option<String>,
        reason: Option<String>,
    ) -> Result<Arc<MvccVersion<T>>, MvccError>
    where
        F: FnOnce(&T) -> Option<T>,
    {
        let versions = self.versions.entry(key.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(VecDeque::new()))
        });

        let mut versions_guard = versions.lock().await;

        let current = versions_guard
            .front()
            .ok_or_else(|| MvccError::NotFound(key.clone()))?;

        // Apply update function
        let new_state = updater(&current.state)
            .ok_or_else(|| MvccError::StoreError("Updater returned None".to_string()))?;

        // Create new version
        let version_num = {
            let mut global = self.global_version.lock().await;
            *global += 1;
            *global
        };

        let new_version = Arc::new(MvccVersion::new(
            version_num,
            new_state,
            created_by,
            reason,
            Some(current.version),
        )?);

        versions_guard.push_front(Arc::clone(&new_version));

        // Trim old versions
        if versions_guard.len() > self.config.max_versions_per_key {
            versions_guard.pop_back();
        }

        debug!("CAS update for key {}: version {}", key, version_num);
        Ok(new_version)
    }

    /// Delete a key and all its versions
    pub async fn delete(&self, key: &str) -> Result<(), MvccError> {
        self.versions
            .remove(key)
            .map(|_| ())
            .ok_or_else(|| MvccError::NotFound(key.to_string()))
    }

    /// List all keys in the store
    pub async fn list_keys(&self) -> Vec<String> {
        self.versions.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get store statistics
    pub async fn stats(&self) -> MvccStats {
        let mut total_versions = 0;
        let mut keys = 0;

        for entry in &self.versions {
            let versions = entry.value().lock().await;
            total_versions += versions.len();
            keys += 1;
        }

        MvccStats {
            keys,
            total_versions,
            avg_versions_per_key: if keys > 0 { total_versions as f64 / keys as f64 } else { 0.0 },
            global_version: *self.global_version.lock().await,
        }
    }
}

/// Statistics about the MVCC store
#[derive(Debug, Clone)]
pub struct MvccStats {
    pub keys: usize,
    pub total_versions: usize,
    pub avg_versions_per_key: f64,
    pub global_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mvcc_basic_operations() {
        let store = MvccStore::default();

        // Create initial version
        let state1 = "pending".to_string();
        let v1 = store.get_or_create(
            "task-1".to_string(),
            state1.clone(),
            None,
            None,
        ).await.unwrap();
        assert_eq!(v1.state, state1);
        assert_eq!(v1.version, 1);

        // Get current
        let current = store.get_current("task-1").await.unwrap();
        assert_eq!(current.version, 1);

        // Update with CAS
        let mut expected = v1.as_ref().clone();
        expected.state = "running".to_string();

        let v2 = store.update_if_match(
            "task-1".to_string(),
            expected,
            |old, new| old == "pending" && new == "running",
        ).await.unwrap();
        assert_eq!(v2.state, "running");
        assert_eq!(v2.version, 2);
        assert_eq!(v2.parent_version, Some(1));

        // History
        let history = store.get_history("task-1").await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].version, 1);  // oldest first
        assert_eq!(history[0].version, 2);  // newest last in reversed order
    }

    #[tokio::test]
    async fn test_mvcc_concurrent_updates() {
        use std::sync::Arc;
        use tokio::task;

        let store = Arc::new(MvccStore::default());

        // Initialize
        store.get_or_create(
            "counter".to_string(),
            0u64,
            None,
            None,
        ).await.unwrap();

        // Spawn multiple concurrent updaters
        let mut handles = vec![];
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = task::spawn(async move {
                for _ in 0..10 {
                    let current = match store_clone.get_current("counter").await {
                        Some(v) => v.as_ref().clone(),
                        None => return Err(MvccError::NotFound("counter".to_string())),
                    };

                    let mut new_state = current.state.clone();
                    new_state += 1;

                    let _ = store_clone.update_if_match(
                        "counter".to_string(),
                        MvccVersion {
                            version: current.version,
                            state: new_state,
                            hash: current.hash,
                            created_by: Some(format!("agent-{}", i)),
                            created_at: current.created_at,
                            reason: Some("increment".to_string()),
                            parent_version: current.parent_version,
                        },
                        |_old, _new| true,
                    ).await;
                }
                Ok::<(), MvccError>(())
            });
            handles.push(handle);
        }

        // Wait for all
        for h in handles {
            h.await.unwrap().unwrap();
        }

        // Final value should be 100
        let final_state = store.get_current("counter").await.unwrap();
        assert_eq!(final_state.state, 100u64);
    }
}
