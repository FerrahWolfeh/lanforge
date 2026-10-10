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
