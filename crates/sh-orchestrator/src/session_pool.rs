//! Session Pool with Isolation and Auto-Compaction
//!
//! Manages isolated execution contexts (sessions) with automatic cleanup
//! and resource pressure awareness.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
thiserror::Error;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, warn};

use sh_types::prelude::*;

/// Session pool configuration
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Session idle timeout before compaction
    pub session_ttl_secs: u64,
    /// How often to run garbage collection (seconds)
    pub gc_interval_secs: u64,
    /// Maximum sessions in LRU cache before eviction
    pub lru_cache_size: usize,
    /// Whether to warm up sessions on startup
    pub warmup: bool,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            session_ttl_secs: 1800,  // 30 minutes
            gc_interval_secs: 300,   // 5 minutes
            lru_cache_size: 50,
            warmup: false,
        }
    }
}

/// An isolated execution session
pub struct Session {
    /// Unique session ID
    pub id: String,
    /// Assessment/task this session is for
    pub assessment_id: String,
    /// Session creation time
    pub created_at: Instant,
    /// Last access time
    pub last_accessed: Arc<Mutex<Instant>>,
    /// Session state (arbitrary data)
    pub state: Arc<tokio::sync::RwLock<HashMap<String, serde_json::Value>>>,
    /// Whether session is currently active
    pub active: Arc<Mutex<bool>>,
    /// Session token for cleanup
    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) _token: Option<Arc<Semaphore>>,
}

impl Session {
    pub fn new(id: String, assessment_id: String) -> Self {
        Self {
            id,
            assessment_id,
            created_at: Instant::now(),
            last_accessed: Arc::new(Mutex::new(Instant::now())),
            state: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            active: Arc::new(Mutex::new(true)),
            #[cfg(test)]
            _token: None,
        }
    }

    /// Touch session to update last accessed time
    pub async fn touch(&self) {
        *self.last_accessed.lock().await = Instant::now();
    }

    /// Check if session is expired
    pub async fn is_expired(&self, ttl_secs: u64) -> bool {
        let last_accessed = *self.last_accessed.lock().await;
        last_accessed.elapsed() > Duration::from_secs(ttl_secs)
    }

    /// Set state value
    pub async fn set_state(&self, key: impl Into<String>, value: impl Serialize) -> Result<(), SessionError> {
        let json = serde_json::to_value(value)
            .map_err(|e| SessionError::StateError(e.to_string()))?;
        self.state.write().await.insert(key.into(), json);
        Ok(())
    }

    /// Get state value
    pub async fn get_state(&self, key: &str) -> Option<serde_json::Value> {
        self.state.read().await.get(key).cloned()
    }

    /// Mark session as inactive
    pub async fn deactivate(&self) {
        *self.active.lock().await = false;
    }

    /// Check if session is active
    pub async fn is_active(&self) -> bool {
        *self.active.lock().await
    }
}

/// Session pool errors
#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Pool exhausted: max sessions ({0}) reached")]
    PoolExhausted(usize),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid session state: {0}")]
    InvalidState(String),

    #[error("Session already active: {0}")]
    AlreadyActive(String),
}

/// Thread-safe session pool with LRU eviction and auto-compaction
pub struct SessionPool {
    config: SessionPoolConfig,
    /// Active sessions by ID
    sessions: DashMap<String, Arc<Session>>,
    /// Access order for LRU (most recent at back)
    access_order: Arc<Mutex<VecDeque<String>>>,
    /// Semaphore to limit concurrent sessions
    permits: Arc<Semaphore>,
    /// GC task handle
    #[allow(dead_code)]
    gc_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SessionPool {
    pub fn new(config: SessionPoolConfig) -> Self {
        let pool = Self {
            config,
            sessions: DashMap::new(),
            access_order: Arc::new(Mutex::new(VecDeque::new())),
            permits: Arc::new(Semaphore::new(config.max_sessions)),
            gc_handle: None,
        };

        // Start GC task if enabled
        if pool.config.gc_interval_secs > 0 {
            pool.start_gc_task();
        }

        pool
    }

    /// Start background garbage collection task
    fn start_gc_task(&self) {
        let sessions = Arc::clone(&self.sessions);
        let access_order = Arc::clone(&self.access_order);
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.gc_interval_secs));

            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut expired = Vec::new();

                // Find expired sessions
                for entry in &sessions {
                    let session = entry.value();
                    if session.is_expired(config.session_ttl_secs).await && !session.is_active().await {
                        expired.push(entry.key().clone());
                    }
                }

                // Remove expired sessions
                for id in expired {
                    if let Some((_, session)) = sessions.remove(&id) {
                        debug!("GC: Removed expired session {}", id);
                        // Release permit
                        drop(session);
                    }
                }

                // LRU eviction if over limit
                let current_count = sessions.len();
                let target = config.lru_cache_size;

                if current_count > target {
                    let mut order = access_order.lock().await;
                    let to_evict = current_count - target;

                    for _ in 0..to_evict {
                        if let Some(oldest) = order.pop_front() {
                            if sessions.remove(&oldest).is_some() {
                                debug!("GC: LRU evicted session {}", oldest);
                            }
                        }
                    }
                }

                let remaining = sessions.len();
                if remaining > 0 {
                    debug!("GC completed: {} sessions remain", remaining);
                }
            }
        });

        // Store handle (would need interior mutability for real Drop)
        // For now we leak it intentionally
        std::mem::forget(handle);
    }

    /// Acquire a new session
    pub async fn acquire(&self, assessment_id: impl Into<String>) -> Result<Arc<Session>, SessionError> {
        let assessment_id = assessment_id.into();

        // Try to acquire permit
        let permit = match self.permits.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                // Check if we have an existing session for this assessment
                for entry in &self.sessions {
                    if entry.value().assessment_id == assessment_id {
                        let session = entry.value().clone();
                        session.touch().await;
                        return Ok(session);
                    }
                }
                return Err(SessionError::PoolExhausted(self.config.max_sessions));
            }
        };

        // Create new session
        let session_id = format!("session-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
        let session = Arc::new(Session::new(
            session_id.clone(),
            assessment_id.clone(),
        ));

        // Store session
        self.sessions.insert(session_id.clone(), session.clone());
        self.update_access_order(&session_id).await;

        debug!("Acquired session {} for assessment {}", session_id, assessment_id);
        Ok(session)
    }

    /// Get existing session by ID
    pub fn get(&self, session_id: &str) -> Option<Arc<Session>> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    /// Release session back to pool
    pub async fn release(&self, session_id: &str) -> Result<(), SessionError> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            session.deactivate().await;
            // Drop the permit implicitly when Arc is dropped
            debug!("Released session {}", session_id);
            Ok(())
        } else {
            Err(SessionError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Update LRU access order
    async fn update_access_order(&self, session_id: &str) {
        let mut order = self.access_order.lock().await;

        // Remove if exists
        order.retain(|id| id != session_id);

        // Add to end (most recent)
        order.push_back(session_id.to_string());

        // Trim if too long
        if order.len() > self.config.lru_cache_size * 2 {
            order.drain(..order.len() - self.config.lru_cache_size);
        }
    }

    /// Get session count
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Get available permits
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// List all session IDs
    pub fn list_sessions(&self) -> Vec<String> {
        self.sessions.iter().map(|s| s.key().clone()).collect()
    }

    /// Force cleanup of all sessions
    pub async fn force_cleanup(&self) -> usize {
        let mut count = 0;
        let mut to_remove = Vec::new();

        for entry in &self.sessions {
            let session = entry.value();
            let is_active = session.is_active().await;
            if !is_active {
                to_remove.push(entry.key().clone());
            }
        }

        for id in to_remove {
            if self.sessions.remove(&id).is_some() {
                count += 1;
            }
        }

        debug!("Force cleanup removed {} sessions", count);
        count
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        // The gc_handle is leaked in current implementation
        // In production we'd want proper cancellation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_pool_basic() {
        let pool = SessionPool::new(SessionPoolConfig {
            max_sessions: 5,
            session_ttl_secs: 1,  // Very short for test
            gc_interval_secs: 60,
            lru_cache_size: 10,
            warmup: false,
        });

        // Acquire session
        let session = pool.acquire("assessment-1").await.unwrap();
        assert_eq!(session.assessment_id, "assessment-1");
        assert!(session.is_active().await);

        // Get same session again should return existing
        let sessions = pool.list_sessions();
        assert_eq!(sessions.len(), 1);

        // Release session
        pool.release(&session.id).await.unwrap();
        assert!(session.is_active().await);  // Still active object-wise
    }

    #[tokio::test]
    async fn test_session_pool_exhaustion() {
        let pool = SessionPool::new(SessionPoolConfig {
            max_sessions: 2,
            ..Default::default()
        });

        // Acquire max sessions
        let _s1 = pool.acquire("assessment-1").await.unwrap();
        let _s2 = pool.acquire("assessment-1").await.unwrap();

        // Third should fail
        let result = pool.acquire("assessment-2").await;
        assert!(matches!(result, Err(SessionError::PoolExhausted(2))));
    }
}
