use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for DNS service metrics, designed for zero-lock hot path performance.
#[derive(Debug)]
pub struct DnsStats {
    pub requests_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub auth_queries: AtomicU64,
    pub recursions: AtomicU64,
}

impl DnsStats {
    pub fn new() -> Self {
        Self::default()
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

    pub fn snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            auth_queries: self.auth_queries.load(Ordering::Relaxed),
            recursions: self.recursions.load(Ordering::Relaxed),
        }
    }
}

/// A non-atomic snapshot of DNS statistics for reporting.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStatsSnapshot {
    pub requests_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_errors: u64,
    pub auth_queries: u64,
    pub recursions: u64,
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
        }
    }
}
