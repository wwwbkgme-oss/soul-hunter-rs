//! Utility functions and traits for sh-orchestrator

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

/// Convert Duration to milliseconds
pub fn duration_to_ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// Convert Duration to seconds with fraction
pub fn duration_to_secs_f64(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// Calculate exponential backoff
pub fn exponential_backoff(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let delay = (base_ms as f64 * 2.0_f64.powf(attempt as f64)).min(max_ms as f64) as u64;
    Duration::from_millis(delay)
}

/// Rate limiter using token bucket algorithm
pub struct TokenBucket {
    rate: f64,  // tokens per second
    capacity: u32,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, capacity: u32) -> Self {
        Self {
            rate: rate_per_sec,
            capacity,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity as f64);
        self.last_refill = now;
    }
}

/// Retry policy builder
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: usize,
    base_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f64,
}

impl RetryPolicy {
    pub fn new() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }

    pub fn with_max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts;
        self
    }

    pub fn with_backoff(mut self, base: Duration, multiplier: f64) -> Self {
        self.base_delay = base;
        self.backoff_multiplier = multiplier;
        self
    }

    pub fn next_delay(&self, attempt: usize) -> Duration {
        if attempt >= self.max_attempts {
            return Duration::ZERO;
        }
        let delay = self.base_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32);
        std::cmp::min(delay as u64, self.max_delay.as_millis() as u64) as u64
            .milliseconds()
    }
}

/// Async retry helper
pub async fn retry<F, Fut, T, E>(
    policy: &RetryPolicy,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last_error = None;

    for attempt in 0..=policy.max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < policy.max_attempts {
                    let delay = policy.next_delay(attempt);
                    debug!("Retry attempt {} after {:?}", attempt + 1, delay);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let d1 = exponential_backoff(0, 100, 10000);
        let d2 = exponential_backoff(1, 100, 10000);
        let d3 = exponential_backoff(2, 100, 10000);

        assert_eq!(d1, Duration::from_millis(100));
        assert_eq!(d2, Duration::from_millis(200));
        assert_eq!(d3, Duration::from_millis(400));
    }

    #[tokio::test]
    async fn test_retry_policy() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let mut attempt = 0;

        let result: Result<(), ()> = retry(&policy, || async move {
            attempt += 1;
            if attempt < 3 {
                Err(())
            } else {
                Ok(())
            }
        }).await;

        assert!(result.is_ok());
        assert_eq!(attempt, 3);
    }
}
