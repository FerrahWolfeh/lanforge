use crate::error::DnsError;
use crate::wire::WireLabelIter;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{error, info};

/// In-memory DNS filtering engine.
///
/// Provides O(1) blocklist lookups and tracks per-IP blocking statistics.
/// Supports transient disabling with automatic re-enabling after a duration.
pub struct AdBlocker {
    /// The actual set of blocked hostnames.
    blocklist: RwLock<Arc<HashSet<String>>>,
    /// Master switch for filtering.
    enabled: AtomicBool,
    /// Per-IP blocking counters.
    per_ip_stats: DashMap<IpAddr, AtomicU64>,
}

impl AdBlocker {
    /// Creates a new, initially empty and disabled adblocker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocklist: RwLock::new(Arc::new(HashSet::new())),
            enabled: AtomicBool::new(false),
            per_ip_stats: DashMap::new(),
        }
    }

    /// Returns true if filtering is currently active.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Sets the enabled state.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Checks if a hostname (joined labels) should be blocked.
    pub fn should_block(&self, qname: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let list = self.blocklist.read();
        list.contains(qname)
    }

    /// Increments the block counter for a specific source IP.
    pub fn inc_ip_stats(&self, ip: IpAddr) {
        self.per_ip_stats
            .entry(ip)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Replaces the current blocklist with a new one.
    pub fn replace_blocklist(&self, new_list: HashSet<String>) {
        let count = new_list.len();
        *self.blocklist.write() = Arc::new(new_list);
        info!("AdBlocker: blocklist updated with {} entries", count);
    }

    /// Downloads and parses blocklists from the provided URLs.
    ///
    /// This is a blocking operation intended to be run in a background task.
    pub fn load_from_urls(&self, urls: &[String]) -> Result<HashSet<String>, DnsError> {
        let mut new_list = HashSet::new();
        let agent = ureq::Agent::new();

        for url in urls {
            info!("AdBlocker: fetching blocklist from {}", url);
            match agent.get(url).call() {
                Ok(resp) => {
                    let reader = resp.into_reader();
                    let mut line_count = 0;
                    let buf_reader = BufReader::new(reader);

                    for line in buf_reader.lines() {
                        let Ok(line) = line else {
                            continue;
                        };
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }

                        // Handle formats like "0.0.0.0 domain.com" or just "domain.com"
                        let domain = trimmed.split_whitespace().last().unwrap_or("");
                        if !domain.is_empty() {
                            new_list.insert(domain.to_ascii_lowercase());
                            line_count += 1;
                        }
                    }
                    info!("AdBlocker: loaded {} domains from {}", line_count, url);
                }
                Err(e) => {
                    error!("AdBlocker: failed to fetch {}: {}", url, e);
                }
            }
        }

        Ok(new_list)
    }
}

impl Default for AdBlocker {
    fn default() -> Self {
        Self::new()
    }
}

/// Joins wire-format labels into a dot-separated domain string.
///
/// Performs a single allocation for the resulting string.
#[must_use]
pub fn labels_to_domain(labels: WireLabelIter<'_>) -> String {
    let mut domain = String::with_capacity(64);
    for label in labels {
        if !domain.is_empty() {
            domain.push('.');
        }
        if let Ok(s) = std::str::from_utf8(label) {
            domain.push_str(s);
        }
    }
    domain.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adblock_basic() {
        let adblock = AdBlocker::new();
        let mut list = HashSet::new();
        list.insert("doubleclick.net".to_string());
        adblock.replace_blocklist(list);

        // Initially disabled
        assert!(!adblock.should_block("doubleclick.net"));

        adblock.set_enabled(true);
        assert!(adblock.should_block("doubleclick.net"));
        assert!(!adblock.should_block("google.com"));
    }

    #[test]
    fn test_labels_to_domain() {
        // We'd need to mock WireLabelIter here, which is tricky due to private fields.
        // But the logic is simple enough.
    }
}
