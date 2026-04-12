//! DNS service statistics using atomic counters.
//!
//! Provides lock-free counters for tracking requests, cache hits/misses,
//! upstream errors, authoritative queries, and recursive forwarding.
//! Designed for zero-lock performance in the DNS hot path.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for DNS service metrics.
///
/// All counters use `Relaxed` ordering since exact precision is not required
/// for statistics — only eventual consistency matters.
#[derive(Debug)]
pub struct DnsStats {
    /// Total number of DNS queries received.
    pub requests_total: AtomicU64,
    /// Number of queries answered from the upstream cache.
    pub cache_hits: AtomicU64,
    /// Number of queries that required upstream forwarding.
    pub cache_misses: AtomicU64,
    /// Number of errors returned from the upstream resolver.
    pub upstream_errors: AtomicU64,
    /// Number of queries answered authoritatively from local state.
    pub auth_queries: AtomicU64,
    /// Number of queries forwarded recursively to upstream.
    pub recursions: AtomicU64,
}

impl DnsStats {
    /// Creates a new stats instance with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the total request counter.
    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the cache hit counter.
    pub fn inc_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the cache miss counter.
    pub fn inc_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the upstream error counter.
    pub fn inc_upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the authoritative query counter.
    pub fn inc_auth(&self) {
        self.auth_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the recursive forwarding counter.
    pub fn inc_recursive(&self) {
        self.recursions.fetch_add(1, Ordering::Relaxed);
    }

    /// Captures a point-in-time snapshot of all counters.
    ///
    /// The returned `DnsStatsSnapshot` is safe to serialize and report
    /// via the API or CLI.
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
///
/// Suitable for JSON serialization via the API/CLI.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStatsSnapshot {
    /// Total number of DNS queries received.
    pub requests_total: u64,
    /// Number of queries answered from the upstream cache.
    pub cache_hits: u64,
    /// Number of queries that required upstream forwarding.
    pub cache_misses: u64,
    /// Number of errors from the upstream resolver.
    pub upstream_errors: u64,
    /// Number of queries answered authoritatively from local state.
    pub auth_queries: u64,
    /// Number of queries forwarded recursively.
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
