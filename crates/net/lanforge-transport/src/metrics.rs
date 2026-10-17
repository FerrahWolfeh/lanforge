use std::sync::atomic::{AtomicU64, Ordering};

/// Transparent, lock-free traffic counters for network transports.
#[derive(Debug, Default)]
pub struct TransportMetrics {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    dropped_packets: AtomicU64,
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

    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.dropped_packets.store(0, Ordering::Relaxed);
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
