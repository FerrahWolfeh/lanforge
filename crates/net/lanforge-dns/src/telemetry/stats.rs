//! DNS service statistics using atomic counters.

use lanforge_types::network::dns::{DnsLifetimeStats, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for DNS service metrics.
#[derive(Debug)]
pub struct DnsStats {
    pub requests_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub auth_queries: AtomicU64,
    pub recursions: AtomicU64,
    pub resolved_total: AtomicU64,
    pub failed_total: AtomicU64,
    #[cfg(feature = "adblock")]
    pub blocked_queries: AtomicU64,
    pub cache_entries: AtomicU64,
    pub cache_capacity: AtomicU64,
    pub cache_evictions: AtomicU64,
    // Protocol distribution
    pub proto_udp: AtomicU64,
    pub proto_tcp: AtomicU64,
    pub proto_dot: AtomicU64,
    pub proto_doq: AtomicU64,
    pub proto_doh: AtomicU64,
}

impl DnsStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_lifetime(lifetime: &DnsLifetimeStats) -> Self {
        Self {
            requests_total: AtomicU64::new(lifetime.total_requests),
            cache_hits: AtomicU64::new(lifetime.cache_hits),
            cache_misses: AtomicU64::new(lifetime.cache_misses),
            upstream_errors: AtomicU64::new(lifetime.upstream_errors),
            auth_queries: AtomicU64::new(lifetime.auth_queries),
            recursions: AtomicU64::new(lifetime.recursions),
            resolved_total: AtomicU64::new(lifetime.resolved_total),
            failed_total: AtomicU64::new(lifetime.failed_total),
            #[cfg(feature = "adblock")]
            blocked_queries: AtomicU64::new(lifetime.blocked_queries),
            cache_entries: AtomicU64::new(0),
            cache_capacity: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            proto_udp: AtomicU64::new(lifetime.proto_udp),
            proto_tcp: AtomicU64::new(lifetime.proto_tcp),
            proto_dot: AtomicU64::new(lifetime.proto_dot),
            proto_doq: AtomicU64::new(lifetime.proto_doq),
            proto_doh: AtomicU64::new(lifetime.proto_doh),
        }
    }

    pub fn lifetime_snapshot(&self) -> DnsLifetimeStats {
        DnsLifetimeStats {
            total_requests: self.requests_total.load(Ordering::Relaxed),
            #[cfg(feature = "adblock")]
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            #[cfg(not(feature = "adblock"))]
            blocked_queries: 0,
            resolved_total: self.resolved_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            auth_queries: self.auth_queries.load(Ordering::Relaxed),
            recursions: self.recursions.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            proto_udp: self.proto_udp.load(Ordering::Relaxed),
            proto_tcp: self.proto_tcp.load(Ordering::Relaxed),
            proto_dot: self.proto_dot.load(Ordering::Relaxed),
            proto_doq: self.proto_doq.load(Ordering::Relaxed),
            proto_doh: self.proto_doh.load(Ordering::Relaxed),
        }
    }

    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth(&self) {
        self.auth_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recursive(&self) {
        self.recursions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_resolved(&self) {
        self.resolved_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_failed(&self) {
        self.failed_total.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "adblock")]
    pub fn inc_blocked(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_protocol(&self, proto: TransportProtocol) {
        match proto {
            TransportProtocol::Udp => self.proto_udp.fetch_add(1, Ordering::Relaxed),
            TransportProtocol::Tcp => self.proto_tcp.fetch_add(1, Ordering::Relaxed),
            TransportProtocol::Tls => self.proto_dot.fetch_add(1, Ordering::Relaxed),
            TransportProtocol::Quic => self.proto_doq.fetch_add(1, Ordering::Relaxed),
            TransportProtocol::Https => self.proto_doh.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn inc_cache_eviction(&self) {
        self.cache_evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            auth_queries: self.auth_queries.load(Ordering::Relaxed),
            recursions: self.recursions.load(Ordering::Relaxed),
            resolved_total: self.resolved_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            #[cfg(feature = "adblock")]
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            cache_entries: self.cache_entries.load(Ordering::Relaxed),
            cache_capacity: self.cache_capacity.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            proto_udp: self.proto_udp.load(Ordering::Relaxed),
            proto_tcp: self.proto_tcp.load(Ordering::Relaxed),
            proto_dot: self.proto_dot.load(Ordering::Relaxed),
            proto_doq: self.proto_doq.load(Ordering::Relaxed),
            proto_doh: self.proto_doh.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStatsSnapshot {
    pub requests_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_errors: u64,
    pub auth_queries: u64,
    pub recursions: u64,
    pub resolved_total: u64,
    pub failed_total: u64,
    #[cfg(feature = "adblock")]
    pub blocked_queries: u64,
    pub cache_entries: u64,
    pub cache_capacity: u64,
    pub cache_evictions: u64,
    pub proto_udp: u64,
    pub proto_tcp: u64,
    pub proto_dot: u64,
    pub proto_doq: u64,
    pub proto_doh: u64,
}

impl Default for DnsStats {
    fn default() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            auth_queries: AtomicU64::new(0),
            recursions: AtomicU64::new(0),
            resolved_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            #[cfg(feature = "adblock")]
            blocked_queries: AtomicU64::new(0),
            cache_entries: AtomicU64::new(0),
            cache_capacity: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            proto_udp: AtomicU64::new(0),
            proto_tcp: AtomicU64::new(0),
            proto_dot: AtomicU64::new(0),
            proto_doq: AtomicU64::new(0),
            proto_doh: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_initialize_with_lifetime_and_record_metrics() {
        let lifetime = DnsLifetimeStats {
            total_requests: 100,
            upstream_errors: 5,
            auth_queries: 20,
            recursions: 80,
            resolved_total: 95,
            failed_total: 5,
            #[cfg(feature = "adblock")]
            blocked_queries: 12,
            cache_hits: 40,
            cache_misses: 20,
            proto_udp: 90,
            proto_tcp: 10,
            proto_dot: 0,
            proto_doq: 0,
            proto_doh: 0,
        };

        let stats = DnsStats::with_lifetime(&lifetime);
        stats.inc_protocol(TransportProtocol::Udp);
        stats.cache_hits.fetch_add(3, Ordering::Relaxed);
        stats.cache_misses.fetch_add(2, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.requests_total, 100);
        assert_eq!(snap.proto_udp, 91);
        assert_eq!(snap.cache_hits, 43);
        assert_eq!(snap.cache_misses, 22);

        let snap_lifetime = stats.lifetime_snapshot();
        assert_eq!(snap_lifetime.cache_hits, 43);
        assert_eq!(snap_lifetime.cache_misses, 22);
    }
}

