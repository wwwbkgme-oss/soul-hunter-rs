//! Circuit Breaker for Fault Tolerance
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! and enable automatic recovery from transient errors.
//!
//! ## States
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Failures count exceeded, requests fail immediately
//! - **Half-Open**: Testing if service recovered, limited requests allowed
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐    Success      ┌─────────────┐
//! │   Closed    │ ──────────────► │   Closed    │
//! │  (Normal)   │ ◄──────────────┤  (Normal)   │
//! └──────┬──────┘    Fail count   └─────────────┘
//!        │ exceeds threshold
//!        ▼
//! ┌─────────────┐    Timeout     ┌─────────────┐
//! │    Open     │ ◄──────────────┤ Half-Open   │
//! │  (Failing)  │ ◄──────────────┤ (Testing)   │
//! └─────────────┘  Success count └─────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Circuit breaker error
#[derive(Error, Debug)]
pub enum BreakerError {
    #[error("Circuit is open, request rejected")]
    OpenCircuit,

    #[error("Circuit in half-open state, not ready yet")]
    HalfOpen,

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation, requests pass through
    Closed,
    /// Circuit is open, requests fail immediately
    Open,
    /// Testing if service recovered
    HalfOpen,
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: usize,
    /// Number of successes in half-open to close circuit
    pub success_threshold: usize,
    /// Time in seconds before attempting half-open from open
    pub open_timeout_secs: u64,
    /// Timeout for individual operations
    pub operation_timeout: Duration,
    /// Whether to record metrics
    pub enable_metrics: bool,
    /// Minimum requests before evaluating state (to avoid noise)
    pub minimum_requests: usize,
    /// Sliding window size for failure rate calculation
    pub window_size: usize,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_timeout_secs: 60,
            operation_timeout: Duration::from_secs(30),
            enable_metrics: true,
            minimum_requests: 10,
            window_size: 100,
        }
    }
}

/// Circuit breaker with sliding window failure detection
pub struct CircuitBreaker {
    name: String,
    config: BreakerConfig,
    state: Arc<Mutex<CircuitState>>,
    /// Sliding window of recent outcomes (true = success)
    outcomes: Arc<Mutex<VecDeque<bool>>>,
    /// Consecutive failures in current state
    consecutive_failures: Arc<Mutex<usize>>,
    /// Consecutive successes in half-open
    consecutive_successes: Arc<Mutex<usize>>,
    /// When circuit opened
    opened_at: Arc<Mutex<Option<Instant>>>,
    /// Total statistics
    stats: Arc<Mutex<BreakerStats>>,
}

impl CircuitBreaker {
    /// Create new circuit breaker
    pub fn new(name: impl Into<String>, config: BreakerConfig) -> Self {
        Self {
            name: name.into(),
            config: config.clone(),
            state: Arc::new(Mutex::new(CircuitState::Closed)),
            outcomes: Arc::new(Mutex::new(VecDeque::with_capacity(config.window_size))),
            consecutive_failures: Arc::new(Mutex::new(0)),
            consecutive_successes: Arc::new(Mutex::new(0)),
            opened_at: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(BreakerStats::default())),
        }
    }

    /// Execute operation with circuit breaker protection
    pub async fn execute<F, Fut, T>(&self, operation: F) -> Result<T, BreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, anyhow::Error>> + Send,
    {
        // Check state first
        let current_state = *self.state.lock().await;

        match current_state {
            CircuitState::Open => {
                // Check if timeout elapsed
                if let Some(opened_at) = *self.opened_at.lock().await {
                    if opened_at.elapsed() >= Duration::from_secs(self.config.open_timeout_secs) {
                        // Transition to half-open
                        *self.state.lock().await = CircuitState::HalfOpen;
                        info!("Circuit '{}': Open → HalfOpen (timeout elapsed)", self.name);
                    } else {
                        return Err(BreakerError::OpenCircuit);
                    }
                }
            }
            CircuitState::HalfOpen => {
                // In half-open, allow limited requests (implicit via success threshold)
            }
            CircuitState::Closed => {
                // Continue
            }
        }

        // Execute with timeout
        let result = tokio::time::timeout(
            self.config.operation_timeout,
            operation()
        ).await;

        let outcome = match result {
            Ok(Ok(res)) => {
                // Success
                self.record_success().await;
                Ok(res)
            }
            Ok(Err(e)) => {
                // Operation failed
                self.record_failure().await;
                Err(BreakerError::HealthCheckFailed(e.to_string()))
            }
            Err(_) => {
                // Timeout
                self.record_failure().await;
                Err(BreakerError::HealthCheckFailed("operation timeout".to_string()))
            }
        };

        // Check if we should transition state
        self.evaluate_state().await;

        outcome
    }

    /// Record successful operation
    async fn record_success(&self) {
        {
            let mut failures = self.consecutive_failures.lock().await;
            *failures = 0;
        }

        let state = *self.state.lock().await;
        if matches!(state, CircuitState::HalfOpen) {
            let mut successes = self.consecutive_successes.lock().await;
            *successes += 1;
        }

        // Add to sliding window
        {
            let mut outcomes = self.outcomes.lock().await;
            outcomes.push_back(true);
            if outcomes.len() > self.config.window_size {
                outcomes.pop_front();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.total_successes += 1;
        }
    }

    /// Record failed operation
    async fn record_failure(&self) {
        let mut failures = self.consecutive_failures.lock().await;
        *failures += 1;

        let mut successes = self.consecutive_successes.lock().await;
        *successes = 0;

        // Add to sliding window
        {
            let mut outcomes = self.outcomes.lock().await;
            outcomes.push_back(false);
            if outcomes.len() > self.config.window_size {
                outcomes.pop_front();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.total_failures += 1;
        }
    }

    /// Evaluate whether to change circuit state
    async fn evaluate_state(&self) {
        let current_state = *self.state.lock().await;
        let outcomes = self.outcomes.lock().await;

        // Need minimum requests before evaluating
        if outcomes.len() < self.config.minimum_requests {
            return;
        }

        match current_state {
            CircuitState::Closed => {
                // Check failure rate in window
                let failures = outcomes.iter().filter(|&&success| !success).count();
                let failure_rate = failures as f64 / outcomes.len() as f64;

                if failures >= self.config.failure_threshold || failure_rate > 0.5 {
                    *self.state.lock().await = CircuitState::Open;
                    *self.opened_at.lock().await = Some(Instant::now());
                    warn!("Circuit '{}': Closed → Open (failures: {}/{})",
                        self.name, failures, outcomes.len());
                }
            }
            CircuitState::HalfOpen => {
                let successes = *self.consecutive_successes.lock().await;
                if successes >= self.config.success_threshold {
                    *self.state.lock().await = CircuitState::Closed;
                    info!("Circuit '{}': HalfOpen → Closed ({} consecutive successes)",
                        self.name, successes);
                } else if failures >= self.config.failure_threshold {
                    *self.state.lock().await = CircuitState::Open;
                    *self.opened_at.lock().await = Some(Instant::now());
                    warn!("Circuit '{}': HalfOpen → Open (failures threshold reached)", self.name);
                }
            }
            CircuitState::Open => {
                // Timer-based transition handled in execute()
            }
        }
    }

    /// Get current state
    pub async fn state(&self) -> CircuitState {
        *self.state.lock().await
    }

    /// Force open circuit
    pub async fn force_open(&self) {
        *self.state.lock().await = CircuitState::Open;
        *self.opened_at.lock().await = Some(Instant::now());
        warn!("Circuit '{}': manually forced Open", self.name);
    }

    /// Reset circuit to closed state
    pub async fn reset(&self) {
        *self.state.lock().await = CircuitState::Closed;
        *self.consecutive_failures.lock().await = 0;
        *self.consecutive_successes.lock().await = 0;
        *self.opened_at.lock().await = None;
        self.outcomes.lock().await.clear();
        info!("Circuit '{}': manually reset", self.name);
    }

    /// Get statistics
    pub async fn stats(&self) -> BreakerStats {
        self.stats.lock().await.clone()
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakerStats {
    pub total_requests: usize,
    pub total_successes: usize,
    pub total_failures: usize,
    pub state_changes: usize,
    pub last_state_transition: Option<Instant>,
    pub current_state: CircuitState,
    pub failure_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closed_to_open() {
        let breaker = CircuitBreaker::new("test", BreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            open_timeout_secs: 60,
            minimum_requests: 1,
            ..Default::default()
        });

        // Simulate failures
        for _ in 0..3 {
            let _ = breaker.execute(|| async { Err(anyhow::anyhow!("failed")) }).await;
        }

        assert_eq!(breaker.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_open() {
        let breaker = CircuitBreaker::new("test", BreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            open_timeout_secs: 1,  // Short for test
            minimum_requests: 1,
            ..Default::default()
        });

        // Fail once to open
       let _ = breaker.execute(|| async { Err(anyhow::anyhow!("failed")) }).await;
        assert_eq!(breaker.state().await, CircuitState::Open);

        // Next should be rejected immediately
        let result = breaker.execute(|| async { Ok(()) }).await;
        assert!(matches!(result, Err(BreakerError::OpenCircuit)));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open() {
        let breaker = Arc::new(CircuitBreaker::new("test", BreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            open_timeout_secs: 0,  // Immediate half-open (override for test)
            minimum_requests: 1,
            ..Default::default()
        }));

        // Fail to open
       let _ = breaker.execute(|| async { Err(anyhow::anyhow!("failed")) }).await;
        assert_eq!(breaker.state().await, CircuitState::Open);

        // Manually set opened_at to past to trigger half-open
        {
            *breaker.opened_at.lock().await = Some(Instant::now() - Duration::from_secs(1));
        }

        // Should now be half-open (but we need to trigger evaluate_state)
        // Actually execute will check
        let result = breaker.execute(|| async { Ok::<_, anyhow::Error>(42) }).await;
        assert!(result.is_ok());

        // Success should close circuit
        assert_eq!(breaker.state().await, CircuitState::Closed);
    }
}
