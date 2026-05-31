//! IPv4 address pool with dynamic allocation and quarantine.
//!
//! Uses a `RoaringBitmap` for efficient IP tracking (O(1) insert/remove,
//! O(log n) random selection). Supports sticky leases, static reservations,
//! and DECLINE quarantine (2-hour timeout for conflicted IPs).
//!
//! ## Allocation Strategy
//!
//! ```mermaid
//! flowchart TD
//!     START["allocate called for MAC"] --> STATIC{"Static/Dynamic in ctx?"}
//!     STATIC -->|Yes| RETURN["Return existing IP"]
//!     STATIC -->|No| REQUESTED{"Requested IP free?"}
//!     REQUESTED -->|Yes| ASSIGN["Assign requested IP"]
//!     REQUESTED -->|No| RANDOM["Random from available pool"]
//!     RANDOM --> EXHAUSTED{"Pool empty?"}
//!     EXHAUSTED -->|Yes| GC["Garbage collect expired leases"]
//!     EXHAUSTED -->|No| RETURN
//!     GC --> SECOND["Second random pass"]
//!     SECOND --> STILL_EMPTY{"Still empty?"}
//!     STILL_EMPTY -->|Yes| DECLINE["Recover DECLINEd IPs"]
//!     STILL_EMPTY -->|No| RETURN
//!     DECLINE --> RETURN
//! ```
//!
//! ## Quarantine
//!
//! IPs rejected via DHCP DECLINE (client detected IP conflict) are quarantined
//! for 2 hours before being returned to the pool. If the pool is fully exhausted,
//! quarantine is bypassed as an emergency fallback.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::traits::DhcpPool;
use lanforge_types::device::IPv4State;
use lanforge_types::identifiers::MacAddr;

use lanforge_core::context::LanforgeContext;

use roaring::RoaringBitmap;

use super::config::Dhcpv4PoolConfig;

/// Dynamic IPv4 address pool backed by a roaring bitmap.
///
/// # Allocation Guarantees
///
/// - Never assigns an IP already owned by another MAC (checked via `LanforgeContext`)
/// - Respects static reservations by removing them from the available set
/// - Quarantines `DECLINEd` IPs for 2 hours to avoid conflict storms
pub struct IpPool {
    /// Configured pools (ranges).
    pools: Vec<Dhcpv4PoolConfig>,
    /// IPs rejected via DECLINE with quarantine timestamp.
    declined: HashMap<Ipv4Addr, Instant>,
    /// Bitmap of free IPs — efficient O(1) insert/remove, O(log n) select.
    available: RoaringBitmap,
}

impl IpPool {
    /// Creates a new pool from a list of range configurations.
    #[must_use]
    pub fn new(pools: Vec<Dhcpv4PoolConfig>) -> Self {
        let mut available = RoaringBitmap::new();
        for pool in &pools {
            if pool.range_start <= pool.range_end {
                available.insert_range(u32::from(pool.range_start)..=u32::from(pool.range_end));
            } else {
                tracing::warn!(
                    "[DHCPv4] Invalid pool range: start {} is greater than end {}",
                    pool.range_start,
                    pool.range_end
                );
            }
        }

        Self {
            pools,
            declined: HashMap::new(),
            available,
        }
    }

    /// Cleans up quarantine IPs.
    pub fn cleanup_quarantine(&mut self, now: Instant) {
        // Cleanup Quarantine (DECLINEs) - Recover IPs after 2 hours
        let quarantine_timeout = Duration::from_hours(2);
        let recovered_ips: Vec<Ipv4Addr> = self
            .declined
            .iter()
            .filter(|(_, time)| now.duration_since(**time) >= quarantine_timeout)
            .map(|(&ip, _)| ip)
            .collect();

        for ip in recovered_ips {
            tracing::info!("[DHCPv4] Recovering IP {ip} from DECLINE quarantine.");
            self.declined.remove(&ip);
            if self.is_in_range(ip) {
                self.add_to_available(ip);
            }
        }
    }

    /// Returns the live pool utilization statistics.
    /// Returns: (total, used, available, `utilization_percent`)
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn stats(&self) -> (u32, u32, u32, f32) {
        let total = self.total_pool_size();
        let available = u32::try_from(self.available.len()).unwrap_or(0);
        let used = total.saturating_sub(available);
        let utilization_percent = if total > 0 {
            (used as f32 / total as f32) * 100.0
        } else {
            0.0
        };
        (total, used, available, utilization_percent)
    }

    fn total_pool_size(&self) -> u32 {
        self.pools
            .iter()
            .map(|p| {
                if p.range_start <= p.range_end {
                    u32::from(p.range_end).saturating_sub(u32::from(p.range_start)) + 1
                } else {
                    0
                }
            })
            .sum()
    }

    /// Allocates an IP for a MAC address.
    pub fn allocate(
        &mut self,
        ctx: &LanforgeContext,
        mac: MacAddr,
        requested: Option<Ipv4Addr>,
    ) -> Option<Ipv4Addr> {
        // 1. Sticky / Static: already has allocation in global table
        if let Some(dev) = ctx.get_device(&mac) {
            match &dev.v4 {
                IPv4State::Static(ip) => {
                    self.remove_from_available(*ip);
                    return Some(*ip);
                }
                IPv4State::Dynamic(lease) => {
                    self.remove_from_available(lease.ip);
                    return Some(lease.ip);
                }
                IPv4State::None => {}
            }
        }

        // 2. Try the requested IP if it's free and in range
        if let Some(req) = requested
            && self.is_in_range(req)
        {
            if ctx.get_mac_by_ip(IpAddr::V4(req)).is_none() && !self.declined.contains_key(&req) {
                self.remove_from_available(req);
                return Some(req);
            }
            // Not actually free according to single source of truth, sync
            self.remove_from_available(req);
        }

        // 3. Fallback: Pick from available pool (O(log n))
        while !self.available.is_empty() {
            let rank =
                rand::random_range(0..u32::try_from(self.available.len()).unwrap_or(u32::MAX));
            let ip_u32 = self.available.select(rank).unwrap(); // Safe due to rank check
            let ip = Ipv4Addr::from(ip_u32);

            self.remove_from_available(ip);
            if ctx.get_mac_by_ip(IpAddr::V4(ip)).is_none() {
                return Some(ip);
            }
        }

        // 3.5. Garbage Collection: If pool is empty, scan for naturally expired leases
        let mut recovered = RoaringBitmap::new();
        for pool in &self.pools {
            if pool.range_start <= pool.range_end {
                recovered.insert_range(u32::from(pool.range_start)..=u32::from(pool.range_end));
            }
        }

        let mut active_ips = RoaringBitmap::new();
        ctx.with_state(|state| {
            for dev in state.devices.values() {
                if let Some(ip) = dev.v4.ip() {
                    active_ips.insert(u32::from(ip));
                }
            }
        });

        recovered -= active_ips;

        for ip in self.declined.keys() {
            recovered.remove(u32::from(*ip));
        }

        self.available = recovered;

        // Second pass after GC
        while !self.available.is_empty() {
            let rank =
                rand::random_range(0..u32::try_from(self.available.len()).unwrap_or(u32::MAX));
            let ip_u32 = self.available.select(rank).unwrap();
            let ip = Ipv4Addr::from(ip_u32);

            self.remove_from_available(ip);
            if ctx.get_mac_by_ip(IpAddr::V4(ip)).is_none() {
                return Some(ip);
            }
        }

        // 4. Emergency fallback: DECLINEs
        if !self.declined.is_empty() {
            tracing::warn!("[DHCPv4] Pool exhausted! Recovering IPs from DECLINE quarantine...");
            let declined_list: Vec<Ipv4Addr> = self.declined.keys().copied().collect();
            self.declined.clear();
            for ip in declined_list {
                self.add_to_available(ip);
            }

            while !self.available.is_empty() {
                let rank =
                    rand::random_range(0..u32::try_from(self.available.len()).unwrap_or(u32::MAX));
                let ip_u32 = self.available.select(rank).unwrap();
                let ip = Ipv4Addr::from(ip_u32);

                self.remove_from_available(ip);
                if ctx.get_mac_by_ip(IpAddr::V4(ip)).is_none() {
                    return Some(ip);
                }
            }
        }

        None
    }

    fn add_to_available(&mut self, ip: Ipv4Addr) {
        self.available.insert(u32::from(ip));
    }

    fn remove_from_available(&mut self, ip: Ipv4Addr) {
        self.available.remove(u32::from(ip));
    }
}

impl DhcpPool<Ipv4Addr> for IpPool {
    fn reserve_statics(&mut self, ips: impl IntoIterator<Item = Ipv4Addr>) {
        for ip in ips {
            if self.is_in_range(ip) {
                self.remove_from_available(ip);
            }
        }
    }

    fn release(&mut self, ip: &Ipv4Addr) {
        if self.is_in_range(*ip) {
            self.add_to_available(*ip);
        }
    }

    fn decline(&mut self, ip: Ipv4Addr) {
        self.remove_from_available(ip);
        self.declined.insert(ip, Instant::now());
    }
}

impl IpPool {
    /// Check if an IP is within any of the configured dynamic ranges.
    #[must_use]
    pub fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        self.pools
            .iter()
            .any(|p| ip >= p.range_start && ip <= p.range_end)
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {

    use lanforge_types::{
        device::Origin,
        update::{CliHostUpdate, DeviceUpdate, FieldUpdate},
    };

    use super::*;
    use std::time::{Duration, SystemTime};

    use crate::{test_utils::init_test_context, v4::config::Dhcpv4PoolConfig};

    fn pool() -> (IpPool, LanforgeContext) {
        let ctx = init_test_context();
        (
            IpPool::new(vec![Dhcpv4PoolConfig {
                range_start: Ipv4Addr::new(192, 168, 0, 100),
                range_end: Ipv4Addr::new(192, 168, 0, 105),
            }]),
            ctx,
        )
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
    }

    #[test]
    fn allocates_within_range() {
        let (mut p, ctx) = pool();
        let ip = p.allocate(&ctx, mac(1), None).unwrap();
        assert!(
            p.is_in_range(ip),
            "The randomly allocated IP must respect the range"
        );
    }

    #[test]
    fn sticky_returns_same_ip() {
        let (mut p, ctx) = pool();

        let ip1 = p.allocate(&ctx, mac(1), None).unwrap();
        // Simulate allocation in LanforgeContext
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac(1),
            ip: ip1,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        let ip2 = p.allocate(&ctx, mac(1), None).unwrap();
        assert_eq!(ip1, ip2, "Same MAC must receive the same IP (Sticky)");
    }

    #[test]
    fn respects_requested_ip() {
        let (mut p, ctx) = pool();
        let requested = Ipv4Addr::new(192, 168, 0, 103);
        let ip = p.allocate(&ctx, mac(1), Some(requested)).unwrap();
        assert_eq!(ip, requested, "Must respect Requested IP if it is free");
    }

    #[test]
    fn skips_reserved_and_declined_ips() {
        let (mut p, ctx) = pool(); // Range of 6 IPs (.100 to .105)

        let reserved_ip = Ipv4Addr::new(192, 168, 0, 100);
        let declined_ip = Ipv4Addr::new(192, 168, 0, 101);

        // Simulate reserved IP in global context
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(99),
            update: CliHostUpdate {
                hostname: FieldUpdate::Set("test".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::Set(reserved_ip),
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            },
        });

        p.decline(declined_ip);

        // Request IPs
        let expiry = SystemTime::now() + Duration::from_hours(1);
        for i in 0..4 {
            if let Some(ip) = p.allocate(&ctx, mac(i), None) {
                // Register each one so it's not picked again
                let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
                    mac: mac(i),
                    ip,
                    expires: expiry,
                });
                assert_ne!(ip, reserved_ip, "Must not allocate reserved IP");
                assert_ne!(
                    ip, declined_ip,
                    "Must not allocate quarantined IP (DECLINE)"
                );
            }
        }
    }

    #[test]
    fn clears_quarantine_if_pool_exhausted() {
        let (mut p, ctx) = pool(); // Range of 6 IPs (.100 to .105)

        // Put all 6 IPs in quarantine simulating a problematic network
        for i in 100..=105 {
            p.decline(Ipv4Addr::new(192, 168, 0, i));
        }

        let rescued_ip = p.allocate(&ctx, mac(1), None).unwrap();
        assert!(p.is_in_range(rescued_ip));
        assert!(
            p.declined.is_empty(),
            "Quarantine must have been emptied as an emergency"
        );
    }

    #[test]
    fn test_cleanup_declined_quarantine() {
        let _ctx = init_test_context();
        let mut p = IpPool::new(vec![Dhcpv4PoolConfig {
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 100),
        }]);
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        // 1. Mark as declined
        p.decline(ip);
        assert!(p.available.is_empty());
        assert_eq!(p.declined.len(), 1);

        // 2. Try to clean now (should not recover as timeout is 2h)
        p.cleanup_quarantine(Instant::now());
        assert!(p.available.is_empty());

        // 3. Simulate 3 hours in the future
        let three_hours_later = Instant::now() + Duration::from_hours(3);
        p.cleanup_quarantine(three_hours_later);

        // 4. Should have recovered the IP
        assert_eq!(p.available.len(), 1);
        assert_eq!(Ipv4Addr::from(p.available.select(0).unwrap()), ip);
        assert!(p.declined.is_empty());
    }

    #[test]
    fn test_pool_stats() {
        let (mut p, ctx) = pool(); // Range of 6 IPs (.100 to .105)
        let (total, used, available, util) = p.stats();
        assert_eq!(total, 6);
        assert_eq!(used, 0);
        assert_eq!(available, 6);
        assert_eq!(util, 0.0);

        // Allocate one
        let ip = p.allocate(&ctx, mac(1), None).unwrap();
        // Register it in context so it's not picked again
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac(1),
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        let (total, used, available, util) = p.stats();
        assert_eq!(total, 6);
        assert_eq!(used, 1);
        assert_eq!(available, 5);
        assert_eq!(util, (1.0 / 6.0) * 100.0);
    }
}
