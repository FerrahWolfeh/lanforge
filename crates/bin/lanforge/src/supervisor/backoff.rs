//! Pure exponential backoff and healthy uptime calculation.

use lanforge_core::service::RestartPolicy;
use std::time::Duration;

/// Decision on whether to retry and with what delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffDecision {
    /// Wait for the specified duration before retrying.
    RetryIn(Duration),
    /// Maximum retries exceeded. Do not retry.
    Exhausted,
}

/// Evaluates if a service was running long enough to be considered healthy.
#[must_use]
pub fn is_healthy(uptime: Duration, policy: &RestartPolicy) -> bool {
    uptime >= policy.healthy_uptime
}

/// Calculates the next backoff duration based on consecutive failure count.
///
/// If `policy.max_retries > 0` and `failures > policy.max_retries`, returns `BackoffDecision::Exhausted`.
/// Otherwise computes `base_backoff * 2^(failures - 1)` capped at `max_backoff`.
#[must_use]
pub fn calculate_backoff(policy: &RestartPolicy, failures: u32) -> BackoffDecision {
    if failures == 0 {
        return BackoffDecision::RetryIn(Duration::ZERO);
    }

    if policy.max_retries > 0 && failures >= policy.max_retries {
        return BackoffDecision::Exhausted;
    }

    let exponent = failures.saturating_sub(1).min(30);
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);

    let delay = policy
        .base_backoff
        .saturating_mul(multiplier.try_into().unwrap_or(u32::MAX))
        .min(policy.max_backoff);

    BackoffDecision::RetryIn(delay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_uptime() {
        let policy = RestartPolicy {
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
            max_retries: 3,
            healthy_uptime: Duration::from_secs(30),
        };

        assert!(!is_healthy(Duration::from_secs(29), &policy));
        assert!(is_healthy(Duration::from_secs(30), &policy));
        assert!(is_healthy(Duration::from_secs(100), &policy));
    }

    #[test]
    fn test_exponential_backoff_progression() {
        let policy = RestartPolicy {
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            max_retries: 5,
            healthy_uptime: Duration::from_secs(30),
        };

        assert_eq!(
            calculate_backoff(&policy, 1),
            BackoffDecision::RetryIn(Duration::from_secs(2))
        );
        assert_eq!(
            calculate_backoff(&policy, 2),
            BackoffDecision::RetryIn(Duration::from_secs(4))
        );
        assert_eq!(
            calculate_backoff(&policy, 3),
            BackoffDecision::RetryIn(Duration::from_secs(8))
        );
        assert_eq!(
            calculate_backoff(&policy, 4),
            BackoffDecision::RetryIn(Duration::from_secs(16))
        );
        // Exceeded max_retries (failures = 5 >= max_retries = 5)
        assert_eq!(calculate_backoff(&policy, 5), BackoffDecision::Exhausted);
    }

    #[test]
    fn test_unlimited_retries_when_max_retries_zero() {
        let policy = RestartPolicy {
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(16),
            max_retries: 0,
            healthy_uptime: Duration::from_secs(30),
        };

        assert_eq!(
            calculate_backoff(&policy, 1),
            BackoffDecision::RetryIn(Duration::from_secs(1))
        );
        assert_eq!(
            calculate_backoff(&policy, 100),
            BackoffDecision::RetryIn(Duration::from_secs(16))
        );
    }
}
