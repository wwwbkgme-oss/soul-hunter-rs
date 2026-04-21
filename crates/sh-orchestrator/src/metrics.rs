//! Orchestration Metrics and Monitoring
//!
//! Comprehensive metrics collection for all orchestration components.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

/// Overall orchestration metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationMetrics {
    /// Work-stealing statistics
    pub work_steal: WorkStealStats,
    /// MVCC statistics
    pub mvcc: MvccStats,
    /// Hook system statistics
    pub hooks: HookStats,
    /// Session pool statistics
    pub sessions: SessionStats,
    /// Circuit breaker statistics
    pub circuit_breakers: HashMap<String, BreakerStats>,
    /// Recovery engine statistics
    pub recovery: RecoveryStats,
    /// Overall throughput
    pub throughput: ThroughputStats,
}

/// Work-stealing metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkStealStats {
    pub total_pushes: usize,
    pub total_pops: usize,
    pub total_steals: usize,
    pub steal_success_rate: f64,
    pub owner_efficiency: f64,
    pub avg_steal_latency_ns: f64,
    pub contention_count: usize,
}

/// Session pool metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub active_sessions: usize,
    pub idle_sessions: usize,
    pool_size: usize,
    pub acquisition_rate_per_sec: f64,
    pub avg_session_lifetime_secs: f64,
}

/// Hook system metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookStats {
    pub total_hooks: usize,
    pub hooks_executed: usize,
    pub avg_execution_time_ms: f64,
    pub failed_hooks: usize,
    pub dependency_resolution_time_ms: f64,
}

/// Throughput statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputStats {
    pub tasks_per_second: f64,
    pub avg_task_duration_ms: f64,
    pub peak_concurrent_tasks: usize,
    pub total_tasks_completed: usize,
    pub queue_depth: usize,
}

/// Metrics collector that aggregates from all components
pub struct MetricsCollector {
    work_steal_queue: Option<Arc<WorkStealingQueue<crate::worksteal::WorkItem<()>>>>,
    mvcc_store: Option<Arc<crate::mvcc::MvccStore<()>>>,
    hook_registry: Option<Arc<crate::hooks::HookRegistry>>,
    session_pool: Option<Arc<crate::session_pool::SessionPool>>,
    circuit_breakers: DashMap<String, Arc<CircuitBreaker>>,
    recovery_engine: Option<Arc<RecoveryEngine>>,
    /// Internal counters
    counters: Arc<Mutex<Counters>>,
    /// Start time
    start_time: Instant,
}

#[derive(Debug, Default)]
struct Counters {
    tasks_started: usize,
    tasks_completed: usize,
    total_execution_time_ms: f64,
    last_second_tasks: usize,
    peak_concurrent: usize,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            work_steal_queue: None,
            mvcc_store: None,
            hook_registry: None,
            session_pool: None,
            circuit_breakers: DashMap::new(),
            recovery_engine: None,
            counters: Arc::new(Mutex::new(Counters::default())),
            start_time: Instant::now(),
        }
    }

    /// Register work-stealing queue
    pub fn with_work_steal(mut self, queue: Arc<WorkStealingQueue<crate::worksteal::WorkItem<()>>>) -> Self {
        self.work_steal_queue = Some(queue);
        self
    }

    /// Register MVCC store
    pub fn with_mvcc(mut self, store: Arc<crate::mvcc::MvccStore<()>>) -> Self {
        self.mvcc_store = Some(store);
        self
    }

    /// Register hook registry
    pub fn with_hooks(mut self, registry: Arc<crate::hooks::HookRegistry>) -> Self {
        self.hook_registry = Some(registry);
        self
    }

    /// Register session pool
    pub fn with_sessions(mut self, pool: Arc<crate::session_pool::SessionPool>) -> Self {
        self.session_pool = Some(pool);
        self
    }

    /// Register circuit breaker
    pub fn register_circuit_breaker(&self, name: String, breaker: Arc<CircuitBreaker>) {
        self.circuit_breakers.insert(name, breaker);
    }

    /// Register recovery engine
    pub fn with_recovery(mut self, engine: Arc<RecoveryEngine>) -> Self {
        self.recovery_engine = Some(engine);
        self
    }

    /// Record task completion
    pub async fn record_task_completion(&self, duration: Duration) {
        let mut counters = self.counters.lock().await;
        counters.tasks_completed += 1;
        counters.total_execution_time_ms += duration.as_secs_f64() * 1000.0;
        counters.last_second_tasks += 1;
    }

    /// Collect all metrics
    pub async fn collect(&self) -> OrchestrationMetrics {
        let counters = self.counters.lock().await;
        let elapsed = self.start_time.elapsed().as_secs_f64();

        let throughput = ThroughputStats {
            tasks_per_second: counters.tasks_completed as f64 / elapsed.max(1.0),
            avg_task_duration_ms: if counters.tasks_completed > 0 {
                counters.total_execution_time_ms / counters.tasks_completed as f64
            } else {
                0.0
            },
            peak_concurrent_tasks: counters.peak_concurrent,
            total_tasks_completed: counters.tasks_completed,
            queue_depth: self.work_steal_queue
                .as_ref()
                .map(|q| q.num_workers() * 2)  // Approximate
                .unwrap_or(0),
        };

        OrchestrationMetrics {
            work_steal: self.work_steal_queue
                .as_ref()
                .map(|q| q.stats().await)
                .unwrap_or_default(),
            mvcc: self.mvcc_store
                .as_ref()
                .map(|s| s.stats().await)
                .unwrap_or_default(),
            hooks: HookStats {
                total_hooks: self.hook_registry.as_ref().map(|r| r.len()).unwrap_or(0),
                ..Default::default()
            },
            sessions: SessionStats {
                active_sessions: self.session_pool.as_ref().map(|p| p.count()).unwrap_or(0),
                ..Default::default()
            },
            circuit_breakers: self.circuit_breakers
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().stats().await))
                .collect(),
            recovery: self.recovery_engine
                .as_ref()
                .map(|e| e.stats().await)
                .unwrap_or_default(),
            throughput,
        }
    }

    /// Get human-readable metrics report
    pub async fn format_report(&self) -> String {
        let metrics = self.collect().await;

        format!(
            r#"Orchestration Metrics
====================
System Uptime: {:.2}s

Throughput:
  Tasks/sec: {:.2}
  Avg task time: {:.2}ms
  Total completed: {}

Work-Stealing:
  Success rate: {:.1}%
  Owner efficiency: {:.1}%
  Steal latency: {:.0}ns avg

MVCC:
  Keys: {}
  Total versions: {}
  Avg versions/key: {:.2}

Sessions:
  Active: {}
  Pool size: {}

Recovery:
  Total recoveries: {}
  Success rate: {:.1}%
  Active now: {}

Circuit Breakers:
  {}
"#,
            metrics.throughput.peak_concurrent_tasks,
            metrics.throughput.tasks_per_second,
            metrics.throughput.avg_task_duration_ms,
            metrics.throughput.total_tasks_completed,
            metrics.work_steal.steal_success_rate * 100.0,
            metrics.work_steal.owner_efficiency * 100.0,
            metrics.work_steal.avg_steal_latency_ns,
            metrics.mvcc.keys,
            metrics.mvcc.total_versions,
            metrics.mvcc.avg_versions_per_key,
            metrics.sessions.active_sessions,
            metrics.sessions.pool_size,
            metrics.recovery.total_recoveries,
            if metrics.recovery.total_recoveries > 0 {
                (metrics.recovery.successful_recoveries as f64 / metrics.recovery.total_recoveries as f64) * 100.0
            } else {
                0.0
            },
            metrics.recovery.current_active,
            self.format_circuit_breakers(&metrics.circuit_breakers)
        )
    }

    fn format_circuit_breakers(&self, breakers: &HashMap<String, BreakerStats>) -> String {
        if breakers.is_empty() {
            "  None".to_string()
        } else {
            breakers.iter()
                .map(|(name, stats)| {
                    format!("  {}: {} ({} failures)",
                        name,
                        if stats.current_state == CircuitState::Closed { "CLOSED" } else { "OPEN" },
                        stats.total_failures)
                })
                .collect::<Vec<_>>()
                .join("\n  ")
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export for convenience
pub use crate::circuit_breaker::BreakerStats;
pub use crate::mvcc::MvccStats;
pub use crate::recovery::RecoveryStats;
pub use crate::worksteal::WorkStealStats;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();
        let report = collector.format_report().await;
        assert!(report.len() > 0);
        assert!(report.contains("Orchestration Metrics"));
    }
}
