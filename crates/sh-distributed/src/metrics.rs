//! Metrics collection for distributed execution

use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::error::Result;

/// Metric value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter value
    Counter(u64),
    /// Gauge value
    Gauge(f64),
    /// Histogram value
    Histogram(Vec<f64>),
    /// Timer value in milliseconds
    Timer(u64),
}

/// Metric record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// Metric name
    pub name: String,
    /// Metric value
    pub value: MetricValue,
    /// Timestamp
    pub timestamp: String,
    /// Tags
    pub tags: HashMap<String, String>,
    /// Worker ID
    pub worker_id: Option<String>,
}

impl Metric {
    /// Create a new counter metric
    pub fn counter(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value: MetricValue::Counter(value),
            timestamp: Utc::now().to_rfc3339(),
            tags: HashMap::new(),
            worker_id: None,
        }
    }

    /// Create a new gauge metric
    pub fn gauge(name: impl Into<String>, value: f64) -> Self {
        Self {
            name: name.into(),
            value: MetricValue::Gauge(value),
            timestamp: Utc::now().to_rfc3339(),
            tags: HashMap::new(),
            worker_id: None,
        }
    }

    /// Create a new timer metric
    pub fn timer(name: impl Into<String>, value_ms: u64) -> Self {
        Self {
            name: name.into(),
            value: MetricValue::Timer(value_ms),
            timestamp: Utc::now().to_rfc3339(),
            tags: HashMap::new(),
            worker_id: None,
        }
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Set worker ID
    pub fn with_worker_id(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }
}

/// Distributed metrics collector
#[derive(Clone)]
pub struct DistributedMetrics {
    counters: Arc<DashMap<String, u64>>,
    gauges: Arc<DashMap<String, f64>>,
    timers: Arc<DashMap<String, Vec<u64>>>,
    metrics_history: Arc<RwLock<Vec<Metric>>>,
    max_history_size: usize,
}

impl DistributedMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self::with_history_size(10000)
    }

    /// Create with custom history size
    pub fn with_history_size(max_history_size: usize) -> Self {
        Self {
            counters: Arc::new(DashMap::new()),
            gauges: Arc::new(DashMap::new()),
            timers: Arc::new(DashMap::new()),
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            max_history_size,
        }
    }

    /// Increment a counter
    pub async fn increment_counter(&self, name: impl Into<String>) {
        let name = name.into();
        let mut entry = self.counters.entry(name.clone()).or_insert(0);
        *entry += 1;
        debug!("Counter {} incremented to {}", name, *entry);
    }

    /// Add to a counter
    pub async fn add_counter(&self, name: impl Into<String>, value: u64) {
        let name = name.into();
        let mut entry = self.counters.entry(name.clone()).or_insert(0);
        *entry += value;
    }

    /// Get counter value
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters.get(name).map(|v| *v).unwrap_or(0)
    }

    /// Set a gauge
    pub async fn set_gauge(&self, name: impl Into<String>, value: f64) {
        let name = name.into();
        self.gauges.insert(name.clone(), value);
        debug!("Gauge {} set to {}", name, value);
    }

    /// Get gauge value
    pub fn get_gauge(&self, name: &str) -> Option<f64> {
        self.gauges.get(name).map(|v| *v)
    }

    /// Record a timer
    pub async fn record_timer(&self, name: impl Into<String>, value_ms: u64) {
        let name = name.into();
        let mut entry = self.timers.entry(name.clone()).or_insert_with(Vec::new);
        entry.push(value_ms);

        // Keep only last 1000 values
        if entry.len() > 1000 {
            entry.remove(0);
        }

        debug!("Timer {} recorded: {}ms", name, value_ms);
    }

    /// Get timer statistics
    pub fn get_timer_stats(&self, name: &str) -> Option<TimerStats> {
        self.timers.get(name).map(|values| {
            let values: Vec<u64> = values.clone();
            TimerStats::from_values(&values)
        })
    }

    /// Record a metric
    pub async fn record(&self, metric: Metric) {
        let mut history = self.metrics_history.write().await;
        history.push(metric);

        // Trim history if needed
        if history.len() > self.max_history_size {
            let excess = history.len() - self.max_history_size;
            history.drain(0..excess);
        }
    }

    /// Get metrics history
    pub async fn get_history(&self) -> Vec<Metric> {
        self.metrics_history.read().await.clone()
    }

    /// Get all counters
    pub fn get_all_counters(&self) -> HashMap<String, u64> {
        self.counters
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }

    /// Get all gauges
    pub fn get_all_gauges(&self) -> HashMap<String, f64> {
        self.gauges
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }

    /// Clear all metrics
    pub async fn clear(&self) {
        self.counters.clear();
        self.gauges.clear();
        self.timers.clear();
        self.metrics_history.write().await.clear();
    }

    /// Record job submitted
    pub async fn record_job_submitted(&self) {
        self.increment_counter("jobs_submitted").await;
        self.increment_counter("jobs_pending").await;
    }

    /// Record job completed
    pub async fn record_job_completed(&self, duration: Duration) {
        self.increment_counter("jobs_completed").await;
        self.add_counter("jobs_pending", u64::MAX).await; // Decrement
        self.record_timer("job_execution_time", duration.as_millis() as u64)
            .await;
    }

    /// Record job failed
    pub async fn record_job_failed(&self) {
        self.increment_counter("jobs_failed").await;
        self.add_counter("jobs_pending", u64::MAX).await; // Decrement
    }

    /// Update queue length gauge
    pub async fn update_queue_length(&self, length: usize) {
        self.set_gauge("queue_length", length as f64).await;
    }

    /// Update worker count gauge
    pub async fn update_worker_count(&self, count: usize) {
        self.set_gauge("worker_count", count as f64).await;
    }

    /// Update worker load gauge
    pub async fn update_worker_load(&self, worker_id: impl Into<String>, load: f64) {
        let name = format!("worker_load_{}", worker_id.into());
        self.set_gauge(name, load).await;
    }

    /// Get summary
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            counters: self.get_all_counters(),
            gauges: self.get_all_gauges(),
            timer_stats: self
                .timers
                .iter()
                .map(|entry| {
                    let values: Vec<u64> = entry.value().clone();
                    (entry.key().clone(), TimerStats::from_values(&values))
                })
                .collect(),
        }
    }
}

impl Default for DistributedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimerStats {
    /// Number of samples
    pub count: usize,
    /// Minimum value
    pub min: u64,
    /// Maximum value
    pub max: u64,
    /// Mean value
    pub mean: f64,
    /// 50th percentile
    pub p50: u64,
    /// 95th percentile
    pub p95: u64,
    /// 99th percentile
    pub p99: u64,
}

impl TimerStats {
    /// Calculate statistics from values
    pub fn from_values(values: &[u64]) -> Self {
        if values.is_empty() {
            return Self {
                count: 0,
                min: 0,
                max: 0,
                mean: 0.0,
                p50: 0,
                p95: 0,
                p99: 0,
            };
        }

        let count = values.len();
        let min = *values.iter().min().unwrap();
        let max = *values.iter().max().unwrap();
        let mean = values.iter().sum::<u64>() as f64 / count as f64;

        let mut sorted = values.to_vec();
        sorted.sort_unstable();

        let p50 = sorted[count * 50 / 100];
        let p95 = sorted[count * 95 / 100.min(count - 1)];
        let p99 = sorted[count * 99 / 100.min(count - 1)];

        Self {
            count,
            min,
            max,
            mean,
            p50,
            p95,
            p99,
        }
    }
}

/// Metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// All counters
    pub counters: HashMap<String, u64>,
    /// All gauges
    pub gauges: HashMap<String, f64>,
    /// Timer statistics
    pub timer_stats: HashMap<String, TimerStats>,
}

/// Metrics collector trait
#[async_trait::async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Record a metric
    async fn record_metric(&self, metric: Metric);
    /// Flush metrics
    async fn flush(&self) -> Result<()>;
    /// Get metrics
    async fn get_metrics(&self) -> Vec<Metric>;
}

/// Console metrics collector
pub struct ConsoleMetricsCollector;

#[async_trait::async_trait]
impl MetricsCollector for ConsoleMetricsCollector {
    async fn record_metric(&self, metric: Metric) {
        info!("METRIC: {:?}", metric);
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }

    async fn get_metrics(&self) -> Vec<Metric> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_creation() {
        let counter = Metric::counter("test_counter", 5);
        assert_eq!(counter.name, "test_counter");
        assert!(matches!(counter.value, MetricValue::Counter(5)));

        let gauge = Metric::gauge("test_gauge", 3.14);
        assert!(matches!(gauge.value, MetricValue::Gauge(v) if (v - 3.14).abs() < 0.001));

        let timer = Metric::timer("test_timer", 100);
        assert!(matches!(timer.value, MetricValue::Timer(100)));
    }

    #[test]
    fn test_timer_stats() {
        let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let stats = TimerStats::from_values(&values);

        assert_eq!(stats.count, 10);
        assert_eq!(stats.min, 10);
        assert_eq!(stats.max, 100);
        assert_eq!(stats.mean, 55.0);
        assert_eq!(stats.p50, 50);
    }

    #[tokio::test]
    async fn test_distributed_metrics() {
        let metrics = DistributedMetrics::new();

        metrics.increment_counter("test").await;
        metrics.increment_counter("test").await;
        assert_eq!(metrics.get_counter("test"), 2);

        metrics.set_gauge("load", 0.75).await;
        assert_eq!(metrics.get_gauge("load"), Some(0.75));

        metrics.record_timer("duration", 100).await;
        metrics.record_timer("duration", 200).await;
        let stats = metrics.get_timer_stats("duration").unwrap();
        assert_eq!(stats.count, 2);
    }

    #[test]
    fn test_timer_stats_empty() {
        let stats = TimerStats::from_values(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 0);
    }
}
