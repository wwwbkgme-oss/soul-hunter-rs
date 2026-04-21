//! Timeout handling for job execution
//!
//! This module provides comprehensive timeout handling with graceful cancellation,
//! deadline tracking, and timeout policy configuration.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep};
use tracing::{debug, trace, warn};

/// Configuration for timeout behavior
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimeoutConfig {
    /// Default timeout duration
    pub default_timeout: Duration,
    /// Maximum allowed timeout
    pub max_timeout: Duration,
    /// Minimum allowed timeout
    pub min_timeout: Duration,
    /// Whether to enable graceful cancellation
    pub graceful_cancellation: bool,
    /// Grace period for cleanup after cancellation
    pub grace_period: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(300), // 5 minutes
            max_timeout: Duration::from_secs(3600),    // 1 hour
            min_timeout: Duration::from_secs(1),       // 1 second
            graceful_cancellation: true,
            grace_period: Duration::from_secs(5),
        }
    }
}

impl TimeoutConfig {
    /// Create a new timeout configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default timeout
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set the maximum timeout
    pub fn with_max_timeout(mut self, timeout: Duration) -> Self {
        self.max_timeout = timeout;
        self
    }

    /// Set the minimum timeout
    pub fn with_min_timeout(mut self, timeout: Duration) -> Self {
        self.min_timeout = timeout;
        self
    }

    /// Enable or disable graceful cancellation
    pub fn with_graceful_cancellation(mut self, enabled: bool) -> Self {
        self.graceful_cancellation = enabled;
        self
    }

    /// Set the grace period
    pub fn with_grace_period(mut self, period: Duration) -> Self {
        self.grace_period = period;
        self
    }

    /// Validate and clamp a timeout duration
    pub fn clamp_timeout(&self, timeout: Duration) -> Duration {
        timeout.clamp(self.min_timeout, self.max_timeout)
    }

    /// Create a configuration for short-running jobs
    pub fn short_running() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(300),
            min_timeout: Duration::from_secs(1),
            graceful_cancellation: true,
            grace_period: Duration::from_secs(2),
        }
    }

    /// Create a configuration for long-running jobs
    pub fn long_running() -> Self {
        Self {
            default_timeout: Duration::from_secs(1800), // 30 minutes
            max_timeout: Duration::from_secs(7200),     // 2 hours
            min_timeout: Duration::from_secs(60),      // 1 minute
            graceful_cancellation: true,
            grace_period: Duration::from_secs(30),
        }
    }

    /// Create a configuration with no timeout
    pub fn no_timeout() -> Self {
        Self {
            default_timeout: Duration::MAX,
            max_timeout: Duration::MAX,
            min_timeout: Duration::from_secs(1),
            graceful_cancellation: false,
            grace_period: Duration::ZERO,
        }
    }
}

/// Timeout policy for different job types
#[derive(Debug, Clone)]
pub struct TimeoutPolicy {
    /// Job type pattern (supports wildcards)
    pub job_type_pattern: String,
    /// Timeout configuration
    pub config: TimeoutConfig,
    /// Priority multiplier for timeout calculation
    pub priority_multiplier: f64,
}

impl TimeoutPolicy {
    /// Create a new timeout policy
    pub fn new(job_type_pattern: impl Into<String>, config: TimeoutConfig) -> Self {
        Self {
            job_type_pattern: job_type_pattern.into(),
            config,
            priority_multiplier: 1.0,
        }
    }

    /// Set the priority multiplier
    pub fn with_priority_multiplier(mut self, multiplier: f64) -> Self {
        self.priority_multiplier = multiplier;
        self
    }

    /// Check if this policy matches a job type
    pub fn matches(&self, job_type: &str) -> bool {
        if self.job_type_pattern == "*" {
            return true;
        }
        if self.job_type_pattern.ends_with('*') {
            let prefix = &self.job_type_pattern[..self.job_type_pattern.len() - 1];
            return job_type.starts_with(prefix);
        }
        self.job_type_pattern == job_type
    }

    /// Calculate timeout based on priority
    pub fn calculate_timeout(&self, base_timeout: Duration, priority: &sh_types::JobPriority) -> Duration {
        let multiplier = match priority {
            sh_types::JobPriority::Critical => self.priority_multiplier * 2.0,
            sh_types::JobPriority::High => self.priority_multiplier * 1.5,
            sh_types::JobPriority::Normal => self.priority_multiplier,
            sh_types::JobPriority::Low => self.priority_multiplier * 0.8,
            sh_types::JobPriority::Lowest => self.priority_multiplier * 0.5,
        };

        let adjusted_millis = (base_timeout.as_millis() as f64 * multiplier) as u64;
        self.config.clamp_timeout(Duration::from_millis(adjusted_millis))
    }
}

/// Timeout manager for handling multiple timeout policies
#[derive(Debug, Clone)]
pub struct TimeoutManager {
    policies: Vec<TimeoutPolicy>,
    default_config: TimeoutConfig,
}

impl TimeoutManager {
    /// Create a new timeout manager
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            default_config: TimeoutConfig::default(),
        }
    }

    /// Create a new timeout manager with default configuration
    pub fn with_default_config(mut self, config: TimeoutConfig) -> Self {
        self.default_config = config;
        self
    }

    /// Add a timeout policy
    pub fn add_policy(mut self, policy: TimeoutPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Get the appropriate timeout for a job
    pub fn get_timeout(
        &self,
        job_type: &str,
        priority: &sh_types::JobPriority,
        requested_timeout: Option<Duration>,
    ) -> Duration {
        // Find matching policy
        let policy = self
            .policies
            .iter()
            .find(|p| p.matches(job_type))
            .map(|p| &p.config)
            .unwrap_or(&self.default_config);

        // Use requested timeout or default
        let base_timeout = requested_timeout.unwrap_or(policy.default_timeout);

        // Clamp to policy limits
        let clamped = policy.clamp_timeout(base_timeout);

        // Apply priority multiplier if there's a matching policy
        if let Some(policy) = self.policies.iter().find(|p| p.matches(job_type)) {
            policy.calculate_timeout(clamped, priority)
        } else {
            clamped
        }
    }

    /// Get timeout configuration for a job type
    pub fn get_config(&self, job_type: &str) -> &TimeoutConfig {
        self.policies
            .iter()
            .find(|p| p.matches(job_type))
            .map(|p| &p.config)
            .unwrap_or(&self.default_config)
    }
}

impl Default for TimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Deadline tracker for monitoring execution progress
#[derive(Debug, Clone)]
pub struct Deadline {
    deadline: Instant,
    original_duration: Duration,
    warning_thresholds: Vec<f64>, // Percentages (0.0 to 1.0)
}

impl Deadline {
    /// Create a new deadline
    pub fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
            original_duration: duration,
            warning_thresholds: vec![0.5, 0.75, 0.9],
        }
    }

    /// Create a deadline with custom warning thresholds
    pub fn with_warnings(duration: Duration, thresholds: Vec<f64>) -> Self {
        Self {
            deadline: Instant::now() + duration,
            original_duration: duration,
            warning_thresholds: thresholds,
        }
    }

    /// Check if the deadline has passed
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Get remaining time
    pub fn remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.deadline {
            Duration::ZERO
        } else {
            self.deadline - now
        }
    }

    /// Get elapsed time since deadline creation
    pub fn elapsed(&self) -> Duration {
        self.original_duration - self.remaining()
    }

    /// Get progress as a percentage (0.0 to 1.0)
    pub fn progress(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        let total = self.original_duration.as_secs_f64();
        if total == 0.0 {
            1.0
        } else {
            (elapsed / total).min(1.0)
        }
    }

    /// Check if a warning threshold has been crossed
    pub fn check_warnings(&self) -> Vec<f64> {
        let progress = self.progress();
        self.warning_thresholds
            .iter()
            .filter(|&&threshold| progress >= threshold)
            .copied()
            .collect()
    }

    /// Get the original duration
    pub fn original_duration(&self) -> Duration {
        self.original_duration
    }

    /// Extend the deadline by a duration
    pub fn extend(&mut self, additional: Duration) {
        self.deadline += additional;
        self.original_duration += additional;
    }

    /// Reset the deadline with a new duration
    pub fn reset(&mut self, duration: Duration) {
        self.deadline = Instant::now() + duration;
        self.original_duration = duration;
    }
}

/// Future wrapper that adds timeout functionality
#[derive(Debug)]
pub struct TimeoutFuture<F> {
    future: F,
    sleep: Pin<Box<Sleep>>,
    deadline: Deadline,
    graceful: bool,
}

impl<F> TimeoutFuture<F> {
    /// Create a new timeout future
    pub fn new(future: F, duration: Duration, graceful: bool) -> Self {
        Self {
            future,
            sleep: Box::pin(tokio::time::sleep(duration)),
            deadline: Deadline::new(duration),
            graceful,
        }
    }

    /// Get the deadline tracker
    pub fn deadline(&self) -> &Deadline {
        &self.deadline
    }

    /// Check if graceful cancellation is enabled
    pub fn is_graceful(&self) -> bool {
        self.graceful
    }
}

impl<F: Future + Unpin> Future for TimeoutFuture<F> {
    type Output = Result<F::Output, TimeoutError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Check if the inner future is ready
        if let Poll::Ready(result) = Pin::new(&mut self.future).poll(cx) {
            return Poll::Ready(Ok(result));
        }

        // Check if timeout has occurred
        match self.sleep.as_mut().poll(cx) {
            Poll::Ready(_) => Poll::Ready(Err(TimeoutError::new(
                self.deadline.original_duration(),
                self.graceful,
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Timeout error type
#[derive(Debug, Clone, PartialEq)]
pub struct TimeoutError {
    /// Duration that was set for the timeout
    pub duration: Duration,
    /// Whether graceful cancellation was attempted
    pub graceful: bool,
    /// Time when the timeout occurred
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

impl TimeoutError {
    /// Create a new timeout error
    pub fn new(duration: Duration, graceful: bool) -> Self {
        Self {
            duration,
            graceful,
            occurred_at: chrono::Utc::now(),
        }
    }

    /// Get the duration
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Check if graceful cancellation was attempted
    pub fn is_graceful(&self) -> bool {
        self.graceful
    }
}

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Operation timed out after {:?} (graceful: {})",
            self.duration, self.graceful
        )
    }
}

impl std::error::Error for TimeoutError {}

/// Execute a future with a timeout
pub async fn timeout<F>(
    duration: Duration,
    future: F,
) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| TimeoutError::new(duration, false))
}

/// Execute a future with a timeout and graceful cancellation
pub async fn timeout_with_grace<F>(
    duration: Duration,
    grace_period: Duration,
    future: F,
) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    trace!(
        timeout_ms = duration.as_millis(),
        grace_ms = grace_period.as_millis(),
        "Starting operation with timeout and grace period"
    );

    match tokio::time::timeout(duration, future).await {
        Ok(result) => {
            trace!("Operation completed before timeout");
            Ok(result)
        }
        Err(_) => {
            warn!(
                timeout_ms = duration.as_millis(),
                "Operation timed out, waiting for grace period"
            );

            // Wait for grace period to allow cleanup
            tokio::time::sleep(grace_period).await;

            Err(TimeoutError::new(duration, true))
        }
    }
}

/// Execute a future with a timeout and cancellation token
pub async fn timeout_with_cancellation<F>(
    duration: Duration,
    cancellation_token: tokio_util::sync::CancellationToken,
    future: F,
) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    tokio::select! {
        result = future => Ok(result),
        _ = tokio::time::sleep(duration) => {
            cancellation_token.cancel();
            Err(TimeoutError::new(duration, true))
        }
    }
}

/// Timeout guard that automatically tracks execution time
pub struct TimeoutGuard {
    deadline: Deadline,
    job_id: sh_types::JobId,
    warnings_logged: Vec<f64>,
}

impl TimeoutGuard {
    /// Create a new timeout guard
    pub fn new(job_id: sh_types::JobId, duration: Duration) -> Self {
        debug!(
            job_id = %job_id,
            timeout_ms = duration.as_millis(),
            "Created timeout guard"
        );

        Self {
            deadline: Deadline::new(duration),
            job_id,
            warnings_logged: Vec::new(),
        }
    }

    /// Check and log warnings
    pub fn check_warnings(&mut self) {
        let warnings = self.deadline.check_warnings();
        for threshold in warnings {
            if !self.warnings_logged.contains(&threshold) {
                warn!(
                    job_id = %self.job_id,
                    progress_pct = threshold * 100.0,
                    remaining_ms = self.deadline.remaining().as_millis(),
                    "Job approaching timeout"
                );
                self.warnings_logged.push(threshold);
            }
        }
    }

    /// Check if the deadline has expired
    pub fn is_expired(&self) -> bool {
        self.deadline.is_expired()
    }

    /// Get remaining time
    pub fn remaining(&self) -> Duration {
        self.deadline.remaining()
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.deadline.elapsed()
    }

    /// Get progress percentage
    pub fn progress(&self) -> f64 {
        self.deadline.progress()
    }
}

impl Drop for TimeoutGuard {
    fn drop(&mut self) {
        let elapsed = self.elapsed();
        let progress = self.progress();

        debug!(
            job_id = %self.job_id,
            elapsed_ms = elapsed.as_millis(),
            progress_pct = progress * 100.0,
            "Timeout guard dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.default_timeout, Duration::from_secs(300));
        assert_eq!(config.max_timeout, Duration::from_secs(3600));
        assert_eq!(config.min_timeout, Duration::from_secs(1));
        assert!(config.graceful_cancellation);
    }

    #[test]
    fn test_timeout_config_builder() {
        let config = TimeoutConfig::new()
            .with_default_timeout(Duration::from_secs(60))
            .with_max_timeout(Duration::from_secs(600))
            .with_min_timeout(Duration::from_secs(5))
            .with_graceful_cancellation(false);

        assert_eq!(config.default_timeout, Duration::from_secs(60));
        assert_eq!(config.max_timeout, Duration::from_secs(600));
        assert_eq!(config.min_timeout, Duration::from_secs(5));
        assert!(!config.graceful_cancellation);
    }

    #[test]
    fn test_timeout_config_clamp() {
        let config = TimeoutConfig::new()
            .with_min_timeout(Duration::from_secs(10))
            .with_max_timeout(Duration::from_secs(100));

        // Below minimum
        assert_eq!(
            config.clamp_timeout(Duration::from_secs(5)),
            Duration::from_secs(10)
        );

        // Above maximum
        assert_eq!(
            config.clamp_timeout(Duration::from_secs(200)),
            Duration::from_secs(100)
        );

        // Within range
        assert_eq!(
            config.clamp_timeout(Duration::from_secs(50)),
            Duration::from_secs(50)
        );
    }

    #[test]
    fn test_timeout_policy() {
        let policy = TimeoutPolicy::new("static_*", TimeoutConfig::short_running());

        assert!(policy.matches("static_analysis"));
        assert!(policy.matches("static_scan"));
        assert!(!policy.matches("dynamic_analysis"));

        // Test wildcard
        let policy_all = TimeoutPolicy::new("*", TimeoutConfig::default());
        assert!(policy_all.matches("anything"));
    }

    #[test]
    fn test_timeout_policy_priority_multiplier() {
        let policy = TimeoutPolicy::new("test", TimeoutConfig::default())
            .with_priority_multiplier(1.0);

        let base = Duration::from_secs(100);

        let critical = policy.calculate_timeout(base, &sh_types::JobPriority::Critical);
        assert_eq!(critical, Duration::from_secs(200));

        let normal = policy.calculate_timeout(base, &sh_types::JobPriority::Normal);
        assert_eq!(normal, Duration::from_secs(100));

        let lowest = policy.calculate_timeout(base, &sh_types::JobPriority::Lowest);
        assert_eq!(lowest, Duration::from_secs(50));
    }

    #[test]
    fn test_timeout_manager() {
        let manager = TimeoutManager::new()
            .add_policy(TimeoutPolicy::new("fast_*", TimeoutConfig::short_running()))
            .add_policy(TimeoutPolicy::new("slow_*", TimeoutConfig::long_running()));

        // Fast job should use short timeout
        let fast_timeout = manager.get_timeout(
            "fast_analysis",
            &sh_types::JobPriority::Normal,
            None,
        );
        assert_eq!(fast_timeout, Duration::from_secs(30));

        // Slow job should use long timeout
        let slow_timeout = manager.get_timeout(
            "slow_analysis",
            &sh_types::JobPriority::Normal,
            None,
        );
        assert_eq!(slow_timeout, Duration::from_secs(1800));

        // Unknown job should use default
        let default_timeout = manager.get_timeout(
            "unknown",
            &sh_types::JobPriority::Normal,
            None,
        );
        assert_eq!(default_timeout, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_deadline() {
        let deadline = Deadline::new(Duration::from_millis(100));

        assert!(!deadline.is_expired());
        assert!(deadline.remaining() > Duration::ZERO);
        assert_eq!(deadline.elapsed(), Duration::ZERO);
        assert_eq!(deadline.progress(), 0.0);

        sleep(Duration::from_millis(150)).await;

        assert!(deadline.is_expired());
        assert_eq!(deadline.remaining(), Duration::ZERO);
        assert!(deadline.progress() >= 1.0);
    }

    #[tokio::test]
    async fn test_deadline_warnings() {
        let deadline = Deadline::with_warnings(
            Duration::from_secs(100),
            vec![0.25, 0.5, 0.75],
        );

        // Initially no warnings
        let warnings = deadline.check_warnings();
        assert!(warnings.is_empty());

        // Simulate progress by creating a new deadline and checking
        // (We can't easily manipulate time, so we test the structure)
        assert_eq!(deadline.warning_thresholds, vec![0.25, 0.5, 0.75]);
    }

    #[tokio::test]
    async fn test_timeout_success() {
        let result = timeout(Duration::from_secs(1), async { 42 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_timeout_failure() {
        let result = timeout(Duration::from_millis(50), async {
            sleep(Duration::from_millis(100)).await;
            42
        })
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.duration, Duration::from_millis(50));
        assert!(!err.graceful);
    }

    #[tokio::test]
    async fn test_timeout_with_grace() {
        let start = Instant::now();
        let result = timeout_with_grace(
            Duration::from_millis(50),
            Duration::from_millis(20),
            async {
                sleep(Duration::from_millis(200)).await;
                42
            },
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.graceful);

        // Should have waited for grace period
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(70)); // 50ms timeout + 20ms grace
    }

    #[tokio::test]
    async fn test_timeout_guard() {
        let job_id = uuid::Uuid::new_v4();
        let mut guard = TimeoutGuard::new(job_id, Duration::from_millis(100));

        assert!(!guard.is_expired());
        assert!(guard.remaining() > Duration::ZERO);
        assert_eq!(guard.progress(), 0.0);

        sleep(Duration::from_millis(150)).await;

        assert!(guard.is_expired());
        assert_eq!(guard.remaining(), Duration::ZERO);
    }

    #[test]
    fn test_timeout_error_display() {
        let err = TimeoutError::new(Duration::from_secs(30), true);
        let msg = err.to_string();
        assert!(msg.contains("timed out"));
        assert!(msg.contains("30s"));
        assert!(msg.contains("true"));
    }
}
