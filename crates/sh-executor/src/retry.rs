//! Retry strategies for job execution
//!
//! This module provides various retry strategies with exponential backoff,
//! jitter, and configurable parameters for resilient job execution.

use rand::Rng;
use std::time::Duration;
use tracing::{debug, trace};

/// Configuration for retry behavior
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Backoff multiplier (e.g., 2.0 for exponential)
    pub backoff_multiplier: f64,
    /// Whether to add jitter to delays
    pub use_jitter: bool,
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            use_jitter: true,
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of retries
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set the initial delay
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set the maximum delay
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set the backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Enable or disable jitter
    pub fn with_jitter(mut self, enabled: bool) -> Self {
        self.use_jitter = enabled;
        self
    }

    /// Set the jitter factor
    pub fn with_jitter_factor(mut self, factor: f64) -> Self {
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// Create a configuration with no retries
    pub fn no_retries() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create a configuration with aggressive retry (fast, many retries)
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 1.5,
            use_jitter: true,
            jitter_factor: 0.2,
        }
    }

    /// Create a configuration with conservative retry (slow, fewer retries)
    pub fn conservative() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(300),
            backoff_multiplier: 2.0,
            use_jitter: true,
            jitter_factor: 0.1,
        }
    }

    /// Create a configuration with linear backoff
    pub fn linear() -> Self {
        Self {
            backoff_multiplier: 1.0,
            ..Default::default()
        }
    }

    /// Create a configuration with fixed delay (no backoff)
    pub fn fixed(delay: Duration) -> Self {
        Self {
            initial_delay: delay,
            max_delay: delay,
            backoff_multiplier: 1.0,
            ..Default::default()
        }
    }
}

/// Retry strategy trait for calculating delays
pub trait RetryStrategy: Send + Sync {
    /// Calculate the delay for a specific retry attempt
    fn calculate_delay(&self, attempt: u32) -> Duration;

    /// Check if another retry should be attempted
    fn should_retry(&self, attempt: u32) -> bool;

    /// Get the maximum number of retries
    fn max_retries(&self) -> u32;
}

/// Exponential backoff retry strategy
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    config: RetryConfig,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff strategy with default configuration
    pub fn new() -> Self {
        Self {
            config: RetryConfig::default(),
        }
    }

    /// Create a new exponential backoff strategy with custom configuration
    pub fn with_config(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Calculate delay with optional jitter
    fn calculate_delay_with_jitter(&self, attempt: u32) -> Duration {
        let base_delay = self.calculate_base_delay(attempt);

        if !self.config.use_jitter {
            return base_delay;
        }

        // Add random jitter to prevent thundering herd
        let jitter_range = base_delay.as_millis() as f64 * self.config.jitter_factor;
        let jitter = if jitter_range > 0.0 {
            let random_jitter = rand::random::<f64>() * jitter_range * 2.0 - jitter_range;
            Duration::from_millis(random_jitter.abs() as u64)
        } else {
            Duration::ZERO
        };

        base_delay + jitter
    }

    /// Calculate base delay without jitter
    fn calculate_base_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let multiplier = self.config.backoff_multiplier.powi(attempt as i32 - 1);
        let delay_millis = (self.config.initial_delay.as_millis() as f64 * multiplier) as u64;
        let delay = Duration::from_millis(delay_millis);

        delay.min(self.config.max_delay)
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryStrategy for ExponentialBackoff {
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let delay = self.calculate_delay_with_jitter(attempt);
        trace!(
            attempt = attempt,
            delay_ms = delay.as_millis(),
            "Calculated retry delay"
        );
        delay
    }

    fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_retries
    }

    fn max_retries(&self) -> u32 {
        self.config.max_retries
    }
}

/// Linear backoff retry strategy (fixed increment)
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    config: RetryConfig,
    increment: Duration,
}

impl LinearBackoff {
    /// Create a new linear backoff strategy
    pub fn new(increment: Duration) -> Self {
        Self {
            config: RetryConfig::default(),
            increment,
        }
    }

    /// Create a new linear backoff strategy with custom configuration
    pub fn with_config(config: RetryConfig, increment: Duration) -> Self {
        Self { config, increment }
    }
}

impl RetryStrategy for LinearBackoff {
    fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let delay = self.config.initial_delay + self.increment * (attempt - 1);
        delay.min(self.config.max_delay)
    }

    fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_retries
    }

    fn max_retries(&self) -> u32 {
        self.config.max_retries
    }
}

/// Fixed delay retry strategy (no backoff)
#[derive(Debug, Clone)]
pub struct FixedDelay {
    config: RetryConfig,
}

impl FixedDelay {
    /// Create a new fixed delay strategy
    pub fn new(delay: Duration) -> Self {
        Self {
            config: RetryConfig::fixed(delay),
        }
    }
}

impl RetryStrategy for FixedDelay {
    fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            Duration::ZERO
        } else {
            self.config.initial_delay
        }
    }

    fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_retries
    }

    fn max_retries(&self) -> u32 {
        self.config.max_retries
    }
}

/// Circuit breaker retry strategy
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    config: RetryConfig,
    failure_threshold: u32,
    reset_timeout: Duration,
    consecutive_failures: std::sync::Arc<tokio::sync::RwLock<u32>>,
    last_failure_time: std::sync::Arc<tokio::sync::RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker strategy
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            config: RetryConfig::default(),
            failure_threshold,
            reset_timeout,
            consecutive_failures: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
            last_failure_time: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Record a failure
    pub async fn record_failure(&self) {
        let mut failures = self.consecutive_failures.write().await;
        *failures += 1;
        let mut last_time = self.last_failure_time.write().await;
        *last_time = Some(chrono::Utc::now());
        debug!(
            consecutive_failures = *failures,
            threshold = self.failure_threshold,
            "Recorded failure in circuit breaker"
        );
    }

    /// Record a success
    pub async fn record_success(&self) {
        let mut failures = self.consecutive_failures.write().await;
        if *failures > 0 {
            debug!(
                previous_failures = *failures,
                "Resetting circuit breaker after success"
            );
            *failures = 0;
        }
        let mut last_time = self.last_failure_time.write().await;
        *last_time = None;
    }

    /// Check if the circuit is open (too many failures)
    pub async fn is_open(&self) -> bool {
        let failures = *self.consecutive_failures.read().await;
        if failures < self.failure_threshold {
            return false;
        }

        // Check if enough time has passed to try again
        let last_time = *self.last_failure_time.read().await;
        if let Some(last) = last_time {
            let elapsed = chrono::Utc::now() - last;
            elapsed.num_milliseconds() as u64 > self.reset_timeout.as_millis() as u64
        } else {
            false
        }
    }
}

impl RetryStrategy for CircuitBreaker {
    fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        // Use exponential backoff for delays
        let multiplier = self.config.backoff_multiplier.powi(attempt as i32 - 1);
        let delay_millis = (self.config.initial_delay.as_millis() as f64 * multiplier) as u64;
        Duration::from_millis(delay_millis).min(self.config.max_delay)
    }

    fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_retries
    }

    fn max_retries(&self) -> u32 {
        self.config.max_retries
    }
}

/// Retry state for tracking attempts
#[derive(Debug, Clone)]
pub struct RetryState {
    /// Current retry attempt (0 = first attempt)
    pub attempt: u32,
    /// Total time spent retrying
    pub total_delay: Duration,
    /// Last error message
    pub last_error: Option<String>,
}

impl RetryState {
    /// Create a new retry state
    pub fn new() -> Self {
        Self {
            attempt: 0,
            total_delay: Duration::ZERO,
            last_error: None,
        }
    }

    /// Increment the attempt counter
    pub fn increment_attempt(&mut self) {
        self.attempt += 1;
    }

    /// Add delay to total
    pub fn add_delay(&mut self, delay: Duration) {
        self.total_delay += delay;
    }

    /// Set the last error
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    /// Check if retries are exhausted
    pub fn is_exhausted(&self, max_retries: u32) -> bool {
        self.attempt >= max_retries
    }
}

impl Default for RetryState {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to execute with retry
pub async fn execute_with_retry<F, Fut, T, E>(
    operation: F,
    strategy: &dyn RetryStrategy,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut state = RetryState::new();

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                state.set_error(e.to_string());

                if !strategy.should_retry(state.attempt) {
                    return Err(e);
                }

                let delay = strategy.calculate_delay(state.attempt + 1);
                state.increment_attempt();
                state.add_delay(delay);

                debug!(
                    attempt = state.attempt,
                    delay_ms = delay.as_millis(),
                    error = %e,
                    "Retrying operation"
                );

                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(60));
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.use_jitter);
    }

    #[test]
    fn test_retry_config_builder() {
        let config = RetryConfig::new()
            .with_max_retries(5)
            .with_initial_delay(Duration::from_millis(500))
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert_eq!(config.backoff_multiplier, 1.5);
        assert!(!config.use_jitter);
    }

    #[test]
    fn test_exponential_backoff() {
        let strategy = ExponentialBackoff::new();

        // First attempt has no delay
        assert_eq!(strategy.calculate_delay(0), Duration::ZERO);

        // Subsequent attempts follow exponential backoff
        let delay1 = strategy.calculate_delay(1);
        assert!(delay1 >= Duration::from_secs(1));
        assert!(delay1 <= Duration::from_secs(2)); // With jitter

        let delay2 = strategy.calculate_delay(2);
        assert!(delay2 >= Duration::from_secs(2));

        let delay3 = strategy.calculate_delay(3);
        assert!(delay3 >= Duration::from_secs(4));

        // Should respect max delay
        let delay10 = strategy.calculate_delay(10);
        assert!(delay10 <= Duration::from_secs(60));
    }

    #[test]
    fn test_linear_backoff() {
        let strategy = LinearBackoff::new(Duration::from_secs(1));

        assert_eq!(strategy.calculate_delay(0), Duration::ZERO);
        assert_eq!(strategy.calculate_delay(1), Duration::from_secs(1));
        assert_eq!(strategy.calculate_delay(2), Duration::from_secs(2));
        assert_eq!(strategy.calculate_delay(3), Duration::from_secs(3));
    }

    #[test]
    fn test_fixed_delay() {
        let strategy = FixedDelay::new(Duration::from_secs(5));

        assert_eq!(strategy.calculate_delay(0), Duration::ZERO);
        assert_eq!(strategy.calculate_delay(1), Duration::from_secs(5));
        assert_eq!(strategy.calculate_delay(2), Duration::from_secs(5));
        assert_eq!(strategy.calculate_delay(3), Duration::from_secs(5));
    }

    #[test]
    fn test_should_retry() {
        let strategy = ExponentialBackoff::with_config(RetryConfig::new().with_max_retries(3));

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(1));
        assert!(strategy.should_retry(2));
        assert!(!strategy.should_retry(3));
        assert!(!strategy.should_retry(4));
    }

    #[test]
    fn test_retry_state() {
        let mut state = RetryState::new();
        assert_eq!(state.attempt, 0);
        assert!(!state.is_exhausted(3));

        state.increment_attempt();
        assert_eq!(state.attempt, 1);

        state.add_delay(Duration::from_secs(1));
        assert_eq!(state.total_delay, Duration::from_secs(1));

        state.set_error("test error");
        assert_eq!(state.last_error, Some("test error".to_string()));

        state.attempt = 3;
        assert!(state.is_exhausted(3));
    }

    #[tokio::test]
    async fn test_execute_with_retry_success() {
        let mut counter = 0;
        let operation = || async {
            counter += 1;
            if counter < 3 {
                Err::<i32, &str>("not yet")
            } else {
                Ok(42)
            }
        };

        let strategy = ExponentialBackoff::with_config(
            RetryConfig::new().with_max_retries(5).with_jitter(false),
        );

        let result = execute_with_retry(operation, &strategy).await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter, 3);
    }

    #[tokio::test]
    async fn test_execute_with_retry_exhausted() {
        let strategy =
            ExponentialBackoff::with_config(RetryConfig::new().with_max_retries(2).with_jitter(false));

        let operation = || async { Err::<i32, &str>("always fails") };
        let result = execute_with_retry(operation, &strategy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(1));

        // Initially closed
        assert!(!cb.is_open().await);

        // Record failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert!(!cb.is_open().await);

        cb.record_failure().await;
        // Circuit should be open now
        assert!(cb.is_open().await);

        // Record success to reset
        cb.record_success().await;
        assert!(!cb.is_open().await);
    }
}
