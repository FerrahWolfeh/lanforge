pub use lanforge_types::network::snapshot::{TransportMetrics, TransportSnapshot};

/// Trait for transport types exposing point-in-time metrics snapshots.
pub trait TransportStats: Send + Sync {
    /// Captures a point-in-time snapshot of low-level transport metrics.
    fn snapshot(&self) -> TransportSnapshot;
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
