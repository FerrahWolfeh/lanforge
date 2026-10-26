pub use lanforge_types::network::dns::{UpstreamHealthSnapshot, UpstreamStatus};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exponential Moving Average alpha factor.
const RTT_ALPHA: f32 = 0.3;

/// Atomic performance counters for a single upstream target.
#[derive(Default)]
pub struct UpstreamHealth {
    pub rtt_ewma_us: AtomicU32,
    pub last_rtt_us: AtomicU32,
    pub total_queries: AtomicU64,
    pub total_successes: AtomicU64,
    pub total_failures: AtomicU64,
    pub consecutive_failures: AtomicU8,
    pub last_success_ts: AtomicU64,
    pub last_failure_ts: AtomicU64,
}

impl UpstreamHealth {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rtt_ewma_us: AtomicU32::new(0),
            last_rtt_us: AtomicU32::new(0),
            total_queries: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            consecutive_failures: AtomicU8::new(0),
            last_success_ts: AtomicU64::new(0),
            last_failure_ts: AtomicU64::new(0),
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn record_success(&self, rtt_us: u32) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_rtt_us.store(rtt_us, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_success_ts.store(now, Ordering::Relaxed);

        self.rtt_ewma_us
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                if old == 0 {
                    Some(rtt_us)
                } else {
                    let new = RTT_ALPHA.mul_add(rtt_us as f32, (1.0 - RTT_ALPHA) * old as f32);
                    Some(new as u32)
                }
            })
            .ok();
    }

    pub fn record_failure(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .consecutive_failures
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_ts.store(now, Ordering::Relaxed);
    }

    pub fn status(&self) -> UpstreamStatus {
        if self.consecutive_failures.load(Ordering::Relaxed) >= 5 {
            return UpstreamStatus::Degraded;
        }
        UpstreamStatus::Healthy
    }

    pub fn is_eligible_for_probing(&self) -> bool {
        if self.consecutive_failures.load(Ordering::Relaxed) >= 5 {
            let last_fail = self.last_failure_ts.load(Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(last_fail) >= 30
        } else {
            false
        }
    }

    pub fn snapshot(
        &self,
        target: std::net::SocketAddr,
        protocol: lanforge_types::network::dns::upstream::UpstreamProtocol,
        domain: Option<String>,
    ) -> UpstreamHealthSnapshot {
        UpstreamHealthSnapshot {
            target,
            protocol,
            rtt_ewma_us: self.rtt_ewma_us.load(Ordering::Relaxed),
            last_rtt_us: self.last_rtt_us.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            total_successes: self.total_successes.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            status: self.status(),
            last_success_secs_ago: {
                let ts = self.last_success_ts.load(Ordering::Relaxed);
                if ts == 0 {
                    None
                } else {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    Some(now.saturating_sub(ts))
                }
            },
            domain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consecutive_failures_saturation_never_overflows() {
        let health = UpstreamHealth::new();
        assert_eq!(health.status(), UpstreamStatus::Healthy);

        // Record 300 failures (greater than u8::MAX = 255)
        for _ in 0..300 {
            health.record_failure();
        }

        assert_eq!(health.consecutive_failures.load(Ordering::Relaxed), u8::MAX);
        assert_eq!(health.status(), UpstreamStatus::Degraded);
        assert_eq!(health.total_failures.load(Ordering::Relaxed), 300);

        // Success resets consecutive failures to 0 and recovers status to Healthy
        health.record_success(1500);
        assert_eq!(health.consecutive_failures.load(Ordering::Relaxed), 0);
        assert_eq!(health.status(), UpstreamStatus::Healthy);
    }
}
