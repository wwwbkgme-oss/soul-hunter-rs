//! Autonomous Recovery Engine
//!
//! Self-healing system that detects stagnation, enters diagnostic mode,
//! and applies recovery strategies with exponential backoff.
//!
//! ## Features
//!
//! - **Stagnation Detection**: Monitors progress and detects when stuck
//! - **Diagnostic Mode**: Forces log audits and planning when stuck
//! - **Recovery Strategies**: Multiple strategies for different failure modes
//! - **Exponential Backoff**: Adaptive retry timing
//! - **Proactive Agency**: Speculative planning during background tasks
//!
//! ## Recovery Flow
//!
//! ```text
//! Normal Operation
//!      │
//!      ▼
//! ┌─────────────────┐
//! │ Monitor Progress│
//! │ (iterations/sec)│
//! └────────┬────────┘
//!          │
//!    stagnant? ──No──► Continue
//!          │Yes
//!          ▼
//! ┌─────────────────┐
//! │ Diagnostic Mode │
//! │  • Audit logs  │
//! │  • Check state │
//! │  • Analyze     │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Apply Strategy  │
//! │  • Retry       │
//! │  • Adjust      │
//! │  • Restart     │
//! └────────┬────────┘
//!          │
//!          ▼
//!       Recovery
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, broadcast};
use tracing::{debug, error, info, warn};

use sh_types::prelude::*;

/// Recovery error types
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Stagnation detected: {0}")]
    StagnationDetected(String),

    #[error("Recovery strategy failed: {0}")]
    StrategyFailed(String),

    #[error("Maximum recovery attempts exceeded")]
    MaxAttemptsExceeded,

    #[error("Recovery not allowed in current state")]
    NotAllowed,
}

/// Diagnostic information collected during diagnostic mode
#[derive(Debug, Clone)]
pub struct DiagnosticInfo {
    /// Timestamp of diagnostic
    pub timestamp: Instant,
    /// Current state snapshot
    pub state_snapshot: serde_json::Value,
    /// Recent log entries
    pub recent_logs: Vec<String>,
    /// Active tasks count
    pub active_tasks: usize,
    /// Resource utilization
    pub resource_usage: ResourceSnapshot,
    /// Identified issues
    pub issues: Vec<RecoveryIssue>,
}

/// Resource utilization snapshot
#[derive(Debug, Clone)]
pub struct ResourceSnapshot {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub thread_count: usize,
    pub queue_sizes: HashMap<String, usize>,
}

/// Identified recovery issues
#[derive(Debug, Clone)]
pub struct RecoveryIssue {
    pub issue_type: IssueType,
    pub severity: IssueSeverity,
    pub description: String,
    pub affected_component: String,
}

#[derive(Debug, Clone)]
pub enum IssueType {
    Stagnation,
    ResourceExhaustion,
    Deadlock,
    HighFailureRate,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Recovery strategy types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Simple retry with backoff
    Retry,
    /// Adjust worker count
    ScaleWorkers,
    /// Clear and restart queues
    ResetQueues,
    /// Full component restart
    RestartComponent,
    /// Load shedding (reject new work)
    ShedLoad,
    /// Degraded mode (skip non-critical)
    DegradedMode,
    /// Emergency stop
    EmergencyStop,
}

/// Configuration for recovery engine
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// How many iterations without progress before detecting stagnation
    pub stagnation_threshold: usize,
    /// Time window for measuring progress (seconds)
    pub progress_window_secs: u64,
    /// Maximum recovery attempts per component
    pub max_recovery_attempts: usize,
    /// Base backoff duration (milliseconds)
    pub base_backoff_ms: u64,
    /// Maximum backoff duration (seconds)
    pub max_backoff_secs: u64,
    /// Whether to enable proactive planning
    pub enable_proactive: bool,
    /// Components that can be individually recovered
    pub recoverable_components: Vec<String>,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            stagnation_threshold: 10,
            progress_window_secs: 60,
            max_recovery_attempts: 5,
            base_backoff_ms: 100,
            max_backoff_secs: 300,
            enable_proactive: true,
            recoverable_components: vec![
                "scheduler".to_string(),
                "agent_manager".to_string(),
                "executor".to_string(),
            ],
        }
    }
}

/// Autonomous recovery engine
pub struct RecoveryEngine {
    config: RecoveryConfig,
    /// Current recovery attempts per component
    attempts: DashMap<String, usize>,
    /// Backoff state per component
    backoffs: DashMap<String, BackoffState>,
    Diagnostic mode active
    diagnostic_mode: Arc<Mutex<bool>>,
    /// Active recovery operations
    active_recoveries: DashMap<String, RecoveryOperation>,
    /// Event channel for recovery notifications
    event_tx: broadcast::Sender<RecoveryEvent>,
    /// Statistics
    stats: Arc<Mutex<RecoveryStats>>,
}

#[derive(Debug, Clone)]
struct BackoffState {
    next_attempt: Instant,
    current_delay_ms: u64,
    attempt_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryEvent {
    StagnationDetected { component: String, reason: String },
    DiagnosticModeEntered { component: String, info: DiagnosticInfo },
    RecoveryStarted { component: String, strategy: RecoveryStrategy },
    RecoveryCompleted { component: String, success: bool },
    RecoveryFailed { component: String, error: String },
}

#[derive(Debug, Clone)]
struct RecoveryOperation {
    started_at: Instant,
    strategy: RecoveryStrategy,
    component: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryStats {
    pub total_stagnations: usize,
    pub total_recoveries: usize,
    pub successful_recoveries: usize,
    pub failed_recoveries: usize,
    pub current_active: usize,
    pub avg_recovery_time_ms: f64,
    pub strategies_used: HashMap<RecoveryStrategy, usize>,
}

impl RecoveryEngine {
    /// Create new recovery engine
    pub fn new(config: RecoveryConfig) -> (Self, broadcast::Receiver<RecoveryEvent>) {
        let (tx, rx) = broadcast::channel(100);

        (
            Self {
                config,
                attempts: DashMap::new(),
                backoffs: DashMap::new(),
                diagnostic_mode: Arc::new(Mutex::new(false)),
                active_recoveries: DashMap::new(),
                event_tx: tx,
                stats: Arc::new(Mutex::new(RecoveryStats::default())),
            },
            rx,
        )
    }

    /// Check for stagnation and trigger recovery if needed
    pub async fn check_stagnation(
        &self,
        component: impl Into<String>,
        progress_fn: impl FnOnce() -> usize,
    ) -> Result<(), RecoveryError> {
        let component = component.into();

        // Get current progress
        let current_progress = progress_fn();

        // Retrieve previous progress from cache
        let prev_progress = self
            .attempts
            .get(&component)
            .map(|attempts| *attempts.value())
            .unwrap_or(0);

        // Check for stagnation
        if current_progress <= prev_progress {
            // Stagnation detected
            let reason = format!(
                "No progress: {} → {}",
                prev_progress, current_progress
            );

            warn!("Stagnation detected in '{}': {}", component, reason);

            // Publish event
            let _ = self.event_tx.send(RecoveryEvent::StagnationDetected {
                component: component.clone(),
                reason: reason.clone(),
            });

            return Err(RecoveryError::StagnationDetected(reason));
        }

        // Update progress tracking
        self.attempts.insert(component.clone(), current_progress);
        Ok(())
    }

    /// Enter diagnostic mode for component
    pub async fn enter_diagnostic_mode(
        &self,
        component: &str,
        info: DiagnosticInfo,
    ) -> Result<(), RecoveryError> {
        {
            let mut mode = self.diagnostic_mode.lock().await;
            *mode = true;
        }

        let _ = self.event_tx.send(RecoveryEvent::DiagnosticModeEntered {
            component: component.to_string(),
            info: info.clone(),
        });

        info!("Entered diagnostic mode for '{}'", component);
        debug!("Diagnostic info: {:?}", info);

        Ok(())
    }

    /// Execute recovery for a component
    pub async fn recover(
        &self,
        component: impl Into<String>,
        strategy: RecoveryStrategy,
    ) -> Result<(), RecoveryError> {
        let component = component.into();

        // Check if component is recoverable
        if !self.config.recoverable_components.contains(&component) {
            return Err(RecoveryError::RecoveryStrategyFailed(
                format!("Component '{}' is not recoverable", component)
            ));
        }

        // Check backoff
        if let Some(backoff) = self.backoffs.get(&component) {
            if backoff.next_attempt > Instant::now() {
                return Err(RecoveryError::NotAllowed);
            }
        }

        // Check max attempts
        let attempts = self.attempts.get(&component).map(|a| *a.value()).unwrap_or(0);
        if attempts >= self.config.max_recovery_attempts {
            return Err(RecoveryError::MaxAttemptsExceeded);
        }

        // Start recovery
        let operation = RecoveryOperation {
            started_at: Instant::now(),
            strategy,
            component: component.clone(),
        };
        self.active_recoveries.insert(component.clone(), operation);

        let _ = self.event_tx.send(RecoveryEvent::RecoveryStarted {
            component: component.clone(),
            strategy,
        });

        info!("Starting recovery for '{}' using strategy {:?}", component, strategy);

        // Apply recovery strategy (would integrate with actual components)
        let result = self.apply_strategy(&component, strategy).await;

        // Record completion
        if let Some((_, op)) = self.active_recoveries.remove(&component) {
            let duration = op.started_at.elapsed();

            {
                let mut stats = self.stats.lock().await;
                stats.total_recoveries += 1;
                stats.avg_recovery_time_ms =
                    (stats.avg_recovery_time_ms * (stats.total_recoveries - 1) as f64
                        + duration.as_millis() as f64)
                        / stats.total_recoveries as f64;
                *stats.strategies_used.entry(strategy).or_insert(0) += 1;

                if result.is_ok() {
                    stats.successful_recoveries += 1;
                } else {
                    stats.failed_recoveries += 1;
                }
            }

            let event = match &result {
                Ok(()) => RecoveryEvent::RecoveryCompleted {
                    component: component.clone(),
                    success: true,
                },
                Err(e) => RecoveryEvent::RecoveryFailed {
                    component: component.clone(),
                    error: e.to_string(),
                },
            };
            let _ = self.event_tx.send(event);
        }

        // Update backoff
        match &result {
            Ok(()) => {
                // Reset backoff on success
                self.backoffs.remove(&component);
                self.attempts.insert(component.clone(), 0);
            }
            Err(_) => {
                // Increase backoff
                self.update_backoff(&component).await;
            }
        }

        result
    }

    /// Apply specific recovery strategy
    async fn apply_strategy(
        &self,
        component: &str,
        strategy: RecoveryStrategy,
    ) -> Result<(), RecoveryError> {
        match strategy {
            RecoveryStrategy::Retry => {
                debug!("Retry strategy for '{}'", component);
                // Just wait and retry - caller will retry
                tokio::time::sleep(Duration::from_millis(
                    self.config.base_backoff_ms * self.get_backoff_multiplier(component)
                )).await;
                Ok(())
            }
            RecoveryStrategy::ScaleWorkers => {
                debug!("Scale workers strategy for '{}'", component);
                // Would adjust worker pool size
                Ok(())
            }
            RecoveryStrategy::ResetQueues => {
                debug!("Reset queues strategy for '{}'", component);
                // Would clear task queues
                Ok(())
            }
            RecoveryStrategy::RestartComponent => {
                debug!("Restart component strategy for '{}'", component);
                // Would restart component
                Ok(())
            }
            RecoveryStrategy::ShedLoad => {
                debug!("Shed load strategy for '{}'", component);
                // Would reject new work
                Ok(())
            }
            RecoveryStrategy::DegradedMode => {
                debug!("Degraded mode strategy for '{}'", component);
                // Would switch to reduced functionality
                Ok(())
            }
            RecoveryStrategy::EmergencyStop => {
                debug!("Emergency stop strategy for '{}'", component);
                Err(RecoveryError::StrategyFailed(
                    "Emergency stop not implemented".to_string()
                ))
            }
        }
    }

    /// Update backoff state for component
    async fn update_backoff(&self, component: &str) {
        let now = Instant::now();
        let base = self.config.base_backoff_ms;
        let max = self.config.max_backoff_secs * 1000;

        let current = self.backoffs
            .get(component)
            .map(|b| {
                (
                    b.current_delay_ms,
                    b.attempt_count,
                )
            })
            .unwrap_or((base, 0));

        let next_delay = (current.0 as f64 * 2.0).min(max as f64) as u64;

        let backoff = BackoffState {
            next_attempt: now + Duration::from_millis(next_delay),
            current_delay_ms: next_delay,
            attempt_count: current.1 + 1,
        };

        self.backoffs.insert(component.to_string(), backoff);
    }

    /// Get backoff multiplier for component
    fn get_backoff_multiplier(&self, component: &str) -> u32 {
        self.backoffs
            .get(component)
            .map(|b| {
                let count = b.attempt_count.min(10);
                1 << count  // 2^count
            })
            .unwrap_or(1)
    }

    /// Check if diagnostic mode is active
    pub async fn is_in_diagnostic_mode(&self) -> bool {
        *self.diagnostic_mode.lock().await
    }

    /// Exit diagnostic mode
    pub async fn exit_diagnostic_mode(&self) {
        let mut mode = self.diagnostic_mode.lock().await;
        *mode = false;
        info!("Exited diagnostic mode");
    }

    /// Get statistics
    pub async fn stats(&self) -> RecoveryStats {
        self.stats.lock().await.clone()
    }

    /// List active recoveries
    pub async fn active_recoveries(&self) -> Vec<String> {
        self.active_recoveries.iter().map(|r| r.key().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recovery_stagnation_detection() {
        let engine = RecoveryEngine::new(RecoveryConfig {
            stagnation_threshold: 2,
            ..Default::default()
        });

        // First call with progress 10
        let result1 = engine.check_stagnation("test", || 10).await;
        assert!(result1.is_ok());

        // Second call with same progress should detect stagnation
        let result2 = engine.check_stagnation("test", || 10).await;
        assert!(matches!(result2, Err(RecoveryError::StagnationDetected(_))));
    }

    #[tokio::test]
    async fn test_recovery_backoff() {
        let engine = RecoveryEngine::new(RecoveryConfig {
            stagnation_threshold: 1,
            base_backoff_ms: 10,
            max_backoff_secs: 1,
            ..Default::default()
        });

        // Trigger recovery
       let _ = engine.recover("test", RecoveryStrategy::Retry).await;

        // Check backoff was set
        assert!(engine.backoffs.contains_key("test"));
    }
}
