use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use lanforge_types::network::snapshot::TransportSnapshot;

/// Trait for transport types exposing point-in-time metrics snapshots.
pub trait TransportStats: Send + Sync {
    /// Captures a point-in-time snapshot of low-level transport metrics.
    fn snapshot(&self) -> TransportSnapshot;
}

/// Transparent, lock-free traffic counters for network transports.
#[derive(Debug, Default)]
pub struct TransportMetrics {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    dropped_packets: AtomicU64,
    rate_limited_packets: AtomicU64,
    errors: AtomicU64,
    last_error_timestamp: AtomicU64,
}

impl TransportMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            rate_limited_packets: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error_timestamp: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_drop(&self) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_rate_limited(&self) {
        self.rate_limited_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_error_timestamp.store(now, Ordering::Relaxed);
    }

    #[must_use]
    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rate_limited_packets(&self) -> u64 {
        self.rate_limited_packets.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn last_error_age_secs(&self) -> Option<u64> {
        let ts = self.last_error_timestamp.load(Ordering::Relaxed);
        if ts == 0 {
            None
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(now.saturating_sub(ts))
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            rx_packets: self.rx_packets(),
            rx_bytes: self.rx_bytes(),
            tx_packets: self.tx_packets(),
            tx_bytes: self.tx_bytes(),
            dropped: self.dropped_packets(),
            rate_limited: self.rate_limited_packets(),
            errors: self.errors(),
            last_error_age_secs: self.last_error_age_secs(),
        }
    }

    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.dropped_packets.store(0, Ordering::Relaxed);
        self.rate_limited_packets.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.last_error_timestamp.store(0, Ordering::Relaxed);
    }
}

impl TransportStats for TransportMetrics {
    fn snapshot(&self) -> TransportSnapshot {
        self.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn should_initialize_all_counters_to_zero() {
        let metrics = TransportMetrics::new();
        assert_eq!(metrics.rx_packets(), 0);
        assert_eq!(metrics.rx_bytes(), 0);
        assert_eq!(metrics.tx_packets(), 0);
        assert_eq!(metrics.tx_bytes(), 0);
        assert_eq!(metrics.dropped_packets(), 0);
    }

    #[test]
    fn should_record_rx_bytes_and_packets() {
        let metrics = TransportMetrics::new();
        metrics.record_rx(64);
        metrics.record_rx(128);

        assert_eq!(metrics.rx_packets(), 2);
        assert_eq!(metrics.rx_bytes(), 192);
        assert_eq!(metrics.tx_packets(), 0);
    }

    #[test]
    fn should_record_tx_bytes_and_packets() {
        let metrics = TransportMetrics::new();
        metrics.record_tx(256);
        metrics.record_tx(512);

        assert_eq!(metrics.tx_packets(), 2);
        assert_eq!(metrics.tx_bytes(), 768);
        assert_eq!(metrics.rx_packets(), 0);
    }

    #[test]
    fn should_record_packet_drops() {
        let metrics = TransportMetrics::new();
        metrics.record_drop();
        metrics.record_drop();
        metrics.record_drop();

        assert_eq!(metrics.dropped_packets(), 3);
    }

    #[test]
    fn should_reset_all_counters_to_zero() {
        let metrics = TransportMetrics::new();
        metrics.record_rx(100);
        metrics.record_tx(200);
        metrics.record_drop();

        metrics.reset();

        assert_eq!(metrics.rx_packets(), 0);
        assert_eq!(metrics.rx_bytes(), 0);
        assert_eq!(metrics.tx_packets(), 0);
        assert_eq!(metrics.tx_bytes(), 0);
        assert_eq!(metrics.dropped_packets(), 0);
    }

    #[test]
    fn should_handle_concurrent_metric_increments() {
        let metrics = Arc::new(TransportMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..10 {
            let m = Arc::clone(&metrics);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    m.record_rx(10);
                    m.record_tx(20);
                    m.record_drop();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(metrics.rx_packets(), 1000);
        assert_eq!(metrics.rx_bytes(), 10_000);
        assert_eq!(metrics.tx_packets(), 1000);
        assert_eq!(metrics.tx_bytes(), 20_000);
        assert_eq!(metrics.dropped_packets(), 1000);
    }
}
