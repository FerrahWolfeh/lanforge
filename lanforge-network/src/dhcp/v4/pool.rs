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

use lanforge_core::device::IPv4State;

use lanforge_core::identifiers::MacAddr;

use lanforge_core::context::LanforgeContext;

use roaring::RoaringBitmap;

/// Dynamic IPv4 address pool backed by a roaring bitmap.
///
/// # Allocation Guarantees
///
/// - Never assigns an IP already owned by another MAC (checked via `LanforgeContext`)
/// - Respects static reservations by removing them from the available set
/// - Quarantines `DECLINEd` IPs for 2 hours to avoid conflict storms
pub struct IpPool {
    /// Range start (inclusive), as `u32` in network byte order.
    start: u32,
    /// Range end (inclusive), as `u32` in network byte order.
    end: u32,
    /// IPs rejected via DECLINE with quarantine timestamp.
    declined: HashMap<Ipv4Addr, Instant>,
    /// Bitmap of free IPs — efficient O(1) insert/remove, O(log n) select.
    available: RoaringBitmap,
}

impl IpPool {
    /// Creates a new pool with all IPs in `[start, end]` marked as available.
    #[must_use]
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let s = u32::from(start);
        let e = u32::from(end);

        let mut available = RoaringBitmap::new();
        available.insert_range(s..=e);

        Self {
            start: s,
            end: e,
            declined: HashMap::new(),
            available,
        }
    }

    /// Isolates a problematic IP reported via DECLINE.
    pub fn mark_declined(&mut self, ip: Ipv4Addr) {
        self.remove_from_available(ip);
        self.declined.insert(ip, Instant::now());
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
            && self.is_available_in_pool(req)
        {
            if ctx.get_mac_by_ip(IpAddr::V4(req)).is_none() {
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
        for i in self.start..=self.end {
            let ip = Ipv4Addr::from(i);
            if ctx.get_mac_by_ip(IpAddr::V4(ip)).is_none() && !self.declined.contains_key(&ip) {
                self.add_to_available(ip);
            }
        }

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

    /// Return an IP to the available pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        if self.is_in_range(ip) {
            self.add_to_available(ip);
        }
    }

    fn add_to_available(&mut self, ip: Ipv4Addr) {
        self.available.insert(u32::from(ip));
    }

    fn remove_from_available(&mut self, ip: Ipv4Addr) {
        self.available.remove(u32::from(ip));
    }

    /// Reserves a batch of static addresses by removing them from the available pool.
    /// This prevents dynamic allocation collisions on startup.
    pub fn reserve_statics(&mut self, ips: impl IntoIterator<Item = Ipv4Addr>) {
        for ip in ips {
            if self.is_in_range(ip) {
                self.remove_from_available(ip);
            }
        }
    }

    /// Check if an IP is in the dynamic available pool.
    fn is_available_in_pool(&self, ip: Ipv4Addr) -> bool {
        self.available.contains(u32::from(ip))
    }

    /// Check if an IP is within the dynamic range.
    #[must_use]
    pub fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        raw >= self.start && raw <= self.end
    }
}

#[cfg(test)]
mod tests {
    use lanforge_core::{
        context::state::{DeviceUpdate, FieldUpdate},
        device::Origin,
    };

    use super::*;
    use std::time::{Duration, SystemTime};

    use crate::test_utils::init_test_context;

    fn pool() -> (IpPool, LanforgeContext) {
        let ctx = init_test_context();
        (
            IpPool::new(
                Ipv4Addr::new(192, 168, 0, 100),
                Ipv4Addr::new(192, 168, 0, 105),
            ),
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
            "O IP alocado randomicamente deve respeitar o range"
        );
    }

    #[test]
    fn sticky_returns_same_ip() {
        let (mut p, ctx) = pool();

        let ip1 = p.allocate(&ctx, mac(1), None).unwrap();
        // Simular o LanforgeContext alocando
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac(1),
            ip: ip1,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        let ip2 = p.allocate(&ctx, mac(1), None).unwrap();
        assert_eq!(ip1, ip2, "Mesmo MAC deve receber o mesmo IP (Sticky)");
    }

    #[test]
    fn respects_requested_ip() {
        let (mut p, ctx) = pool();
        let requested = Ipv4Addr::new(192, 168, 0, 103);
        let ip = p.allocate(&ctx, mac(1), Some(requested)).unwrap();
        assert_eq!(
            ip, requested,
            "Deve respeitar o Requested IP se estiver livre"
        );
    }

    #[test]
    fn skips_reserved_and_declined_ips() {
        let (mut p, ctx) = pool(); // Range de 6 IPs (.100 a .105)

        let reserved_ip = Ipv4Addr::new(192, 168, 0, 100);
        let declined_ip = Ipv4Addr::new(192, 168, 0, 101);

        // Simulamos IP reservado no contexto global
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(99),
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set(reserved_ip),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Cli,
            boot_file: FieldUpdate::NoChange,
        });

        p.mark_declined(declined_ip);

        // Pedimos IPs
        let expiry = SystemTime::now() + Duration::from_hours(1);
        for i in 0..4 {
            if let Some(ip) = p.allocate(&ctx, mac(i), None) {
                // Registrar cada um para que NÂO seja pego de novo
                let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
                    mac: mac(i),
                    ip,
                    expires: expiry,
                });
                assert_ne!(ip, reserved_ip, "Não deve alocar IP reservado");
                assert_ne!(
                    ip, declined_ip,
                    "Não deve alocar IP de quarentena (DECLINE)"
                );
            }
        }
    }

    #[test]
    fn clears_quarantine_if_pool_exhausted() {
        let (mut p, ctx) = pool(); // Range de 6 IPs (.100 a .105)

        // Colocamos os 6 IPs em quarentena simulando uma rede problemática
        for i in 100..=105 {
            p.mark_declined(Ipv4Addr::new(192, 168, 0, i));
        }

        let rescued_ip = p.allocate(&ctx, mac(1), None).unwrap();
        assert!(p.is_in_range(rescued_ip));
        assert!(
            p.declined.is_empty(),
            "A quarentena deve ter sido esvaziada por emergência"
        );
    }

    #[test]
    fn test_cleanup_declined_quarantine() {
        let _ctx = init_test_context();
        let mut p = IpPool::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        // 1. Marca como declined
        p.mark_declined(ip);
        assert!(p.available.is_empty());
        assert_eq!(p.declined.len(), 1);

        // 2. Tenta limpar agora (não deve recuperar pois o timeout é 2h)
        p.cleanup_quarantine(Instant::now());
        assert!(p.available.is_empty());

        // 3. Simula 3 horas no futuro
        let three_hours_later = Instant::now() + Duration::from_hours(3);
        p.cleanup_quarantine(three_hours_later);

        // 4. Deve ter recuperado o IP
        assert_eq!(p.available.len(), 1);
        assert_eq!(Ipv4Addr::from(p.available.select(0).unwrap()), ip);
        assert!(p.declined.is_empty());
    }
}
