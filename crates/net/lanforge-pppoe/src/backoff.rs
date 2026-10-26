//! Reconnect pacing for the `PPPoE` client.
//!
//! ISPs rate-limit (or flag) accounts that reconnect in tight loops, and a concentrator that is
//! failing keeps failing for a while. Invariants:
//! - Consecutive failures double the wait from `base`, capped at [`MAX_DELAY`], with ±20% jitter so
//!   restarts across a neighbourhood do not synchronise.
//! - An explicit credential reject waits at least [`REJECT_FLOOR`]: retrying fast cannot fix it.
//! - Only a session that stayed up for [`HEALTHY_UPTIME`] clears the failure count; one that drops
//!   seconds after coming up counts as a failure (a concentrator kicking us in a loop).
//! - Admin restarts and config changes bypass pacing ([`ReconnectBackoff::reset`]).

use std::time::Duration;

/// Longest wait between attempts.
pub const MAX_DELAY: Duration = Duration::from_secs(300);
/// Minimum wait after the concentrator explicitly rejected the credentials.
pub const REJECT_FLOOR: Duration = Duration::from_secs(60);
/// Uptime after which a session counts as healthy and clears the failure count.
pub const HEALTHY_UPTIME: Duration = Duration::from_secs(120);

/// How the previous attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnd {
    /// Time the session was up, `None` if it never came up.
    pub uptime: Option<Duration>,
    /// The concentrator explicitly rejected the credentials.
    pub rejected: bool,
}

#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    base: Duration,
    failures: u32,
}

impl ReconnectBackoff {
    #[must_use]
    pub const fn new(base: Duration) -> Self {
        Self { base, failures: 0 }
    }

    /// Consecutive failed attempts since the last healthy session or reset.
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    pub const fn set_base(&mut self, base: Duration) {
        self.base = base;
    }

    pub const fn reset(&mut self) {
        self.failures = 0;
    }

    /// Records how the attempt ended and returns how long to wait before the next one.
    /// `jitter` is a factor in `[0.8, 1.2]`.
    pub fn next_delay(&mut self, end: SessionEnd, jitter: f64) -> Duration {
        if end.uptime.is_some_and(|u| u >= HEALTHY_UPTIME) {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);

        let exp = self.failures.saturating_sub(1).min(16);
        let raw = self.base.saturating_mul(1 << exp).min(MAX_DELAY);
        let mut delay = raw.mul_f64(jitter.clamp(0.8, 1.2)).min(MAX_DELAY);
        if end.rejected {
            delay = delay.max(REJECT_FLOOR);
        }
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILED: SessionEnd = SessionEnd {
        uptime: None,
        rejected: false,
    };

    fn secs(d: Duration) -> u64 {
        d.as_secs()
    }

    #[test]
    fn failures_double_up_to_the_cap() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        let seq: Vec<u64> = (0..8).map(|_| secs(b.next_delay(FAILED, 1.0))).collect();
        assert_eq!(seq, [10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(b.failures(), 8);
    }

    #[test]
    fn an_hour_of_failures_is_a_handful_of_attempts() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        let (mut elapsed, mut attempts) = (Duration::ZERO, 0);
        while elapsed < Duration::from_secs(3600) {
            elapsed += b.next_delay(FAILED, 1.0);
            attempts += 1;
        }
        // A fixed 10 s retry would make ~360 attempts.
        assert!(attempts <= 20, "{attempts} attempts in an hour");
    }

    #[test]
    fn a_short_lived_session_still_counts_as_a_failure() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        let flap = SessionEnd {
            uptime: Some(Duration::from_secs(3)),
            rejected: false,
        };
        let seq: Vec<u64> = (0..4).map(|_| secs(b.next_delay(flap, 1.0))).collect();
        assert_eq!(seq, [10, 20, 40, 80]);
    }

    #[test]
    fn a_healthy_session_clears_the_failure_count() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        for _ in 0..5 {
            b.next_delay(FAILED, 1.0);
        }
        let healthy = SessionEnd {
            uptime: Some(HEALTHY_UPTIME),
            rejected: false,
        };
        assert_eq!(secs(b.next_delay(healthy, 1.0)), 10);
        assert_eq!(b.failures(), 1);
    }

    #[test]
    fn an_explicit_reject_waits_at_least_the_floor_and_a_timeout_does_not() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        let rejected = SessionEnd {
            uptime: None,
            rejected: true,
        };
        assert_eq!(b.next_delay(rejected, 1.0), REJECT_FLOOR);
        b.reset();
        assert_eq!(secs(b.next_delay(FAILED, 1.0)), 10);
    }

    #[test]
    fn jitter_stays_within_bounds_and_never_exceeds_the_cap() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(10));
        assert_eq!(secs(b.next_delay(FAILED, 0.8)), 8);
        assert_eq!(secs(b.next_delay(FAILED, 1.2)), 24);
        for _ in 0..10 {
            b.next_delay(FAILED, 1.0);
        }
        assert_eq!(b.next_delay(FAILED, 1.2), MAX_DELAY);
        assert_eq!(secs(b.next_delay(FAILED, 5.0)), 300, "jitter is clamped");
    }
}
