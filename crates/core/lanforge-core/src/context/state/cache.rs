use dashmap::DashMap;
use lanforge_types::identifiers::{Duid, MacAddr};
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

/// Global discovery store for volatile/ephemeral network observations.
///
/// Uses concurrent sharded maps ([`DashMap`]) so that high-frequency discovery
/// traffic (such as NDP and link-local observations) does not acquire the central
/// authoritative state lock or invalidate CPU cache lines for DNS resolvers.
#[derive(Debug, Default)]
pub struct DiscoveryStore {
    /// NDP (Neighbor Discovery Protocol) cache for IPv6 link-local observations.
    pub ndp_cache: DashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// IPv6 leases that haven't been resolved to a MAC yet.
    pub orphaned_v6: DashMap<Ipv6Addr, (Duid, u32, SystemTime)>,
}

/// Legacy type alias for backwards compatibility.
pub type DiscoveryCache = DiscoveryStore;

impl DiscoveryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears both the NDP cache and orphaned IPv6 leases.
    pub fn clear(&self) {
        self.ndp_cache.clear();
        self.orphaned_v6.clear();
    }

    /// Retrieves a MAC address from the NDP cache for the given IPv6 address.
    #[must_use]
    pub fn get_mac(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|entry| entry.0)
    }

    /// Inserts or updates an NDP cache entry with the current timestamp.
    pub fn insert_ndp(&self, ip: Ipv6Addr, mac: MacAddr) {
        self.ndp_cache.insert(ip, (mac, SystemTime::now()));
    }

    /// Removes an NDP cache entry.
    #[must_use]
    pub fn remove_ndp(&self, ip: &Ipv6Addr) -> Option<(MacAddr, SystemTime)> {
        self.ndp_cache.remove(ip).map(|(_, v)| v)
    }

    /// Inserts an orphaned IPv6 lease.
    pub fn insert_orphan(&self, ip: Ipv6Addr, duid: Duid, iaid: u32, expires: SystemTime) {
        self.orphaned_v6.insert(ip, (duid, iaid, expires));
    }

    /// Removes an orphaned IPv6 lease by IP.
    #[must_use]
    pub fn remove_orphan(&self, ip: &Ipv6Addr) -> Option<(Duid, u32, SystemTime)> {
        self.orphaned_v6.remove(ip).map(|(_, v)| v)
    }

    /// Removes all orphaned IPv6 leases associated with a specific DUID.
    #[must_use]
    pub fn remove_orphans_by_duid(&self, duid: &Duid) -> Vec<(Ipv6Addr, (Duid, u32, SystemTime))> {
        let matching: Vec<Ipv6Addr> = self
            .orphaned_v6
            .iter()
            .filter(|entry| &entry.value().0 == duid)
            .map(|entry| *entry.key())
            .collect();

        let mut results = Vec::with_capacity(matching.len());
        for ip in matching {
            if let Some((_, val)) = self.orphaned_v6.remove(&ip) {
                results.push((ip, val));
            }
        }
        results
    }

    /// Prunes stale entries older than `max_age`.
    pub fn prune_stale(&self, max_age: Duration) {
        let now = SystemTime::now();
        self.ndp_cache
            .retain(|_, (_, time)| now.duration_since(*time).is_ok_and(|d| d < max_age));
        self.orphaned_v6
            .retain(|_, (_, _, time)| now.duration_since(*time).is_ok_and(|d| d < max_age));
    }
}
