use lanforge_core::types::UpstreamHealthSnapshot;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exponential Moving Average alpha factor.
/// 0.3 means we weigh the new sample by 30% and the historical average by 70%.
const RTT_ALPHA: f32 = 0.3;

/// Status of an upstream resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamStatus {
    /// Responding normally.
    Healthy,
    /// Recently failed multiple queries.
    Degraded,
    /// Explicitly disabled.
    Disabled,
}

/// Atomic performance counters for a single upstream target.
///
/// Tracks round-trip time (RTT) and success/failure rates for
/// strategy selection and observability.
#[derive(Default)]
pub struct UpstreamHealth {
    /// EWMA of round-trip time in microseconds.
    pub rtt_ewma_us: AtomicU32,
    /// Last measured RTT in microseconds.
    pub last_rtt_us: AtomicU32,
    /// Total queries forwarded to this upstream.
    pub total_queries: AtomicU64,
    /// Total successful responses.
    pub total_successes: AtomicU64,
    /// Total failures (timeouts, errors).
    pub total_failures: AtomicU64,
    /// Consecutive failures (reset on success).
    pub consecutive_failures: AtomicU8,
    /// Unix timestamp of last successful response.
    pub last_success_ts: AtomicU64,
    /// Unix timestamp of last failed response.
    pub last_failure_ts: AtomicU64,
}

impl UpstreamHealth {
    /// Creates a new health tracker with initial state.
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

    /// Records a successful response and updates RTT EWMA.
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

        // Update EWMA
        self.rtt_ewma_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                if old == 0 {
                    Some(rtt_us)
                } else {
                    let new = RTT_ALPHA.mul_add(rtt_us as f32, (1.0 - RTT_ALPHA) * old as f32);
                    Some(new as u32)
                }
            })
            .ok();
    }

    /// Records a failed query (timeout or protocol error).
    pub fn record_failure(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_ts.store(now, Ordering::Relaxed);
    }

    /// Returns the current status based on consecutive failures.
    pub fn status(&self) -> UpstreamStatus {
        if self.consecutive_failures.load(Ordering::Relaxed) >= 5 {
            let last_fail = self.last_failure_ts.load(Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now.saturating_sub(last_fail) < 30 {
                return UpstreamStatus::Degraded;
            }
        }
        UpstreamStatus::Healthy
    }

    /// Returns a serializable snapshot of the health metrics.
    pub fn snapshot(&self, target: String, protocol: String) -> UpstreamHealthSnapshot {
        UpstreamHealthSnapshot {
            target,
            protocol,
            rtt_ewma_us: self.rtt_ewma_us.load(Ordering::Relaxed),
            last_rtt_us: self.last_rtt_us.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            total_successes: self.total_successes.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            status: format!("{:?}", self.status()),
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
        }
    }
}
