use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use rand::seq::SliceRandom;

use lanforge_core::identifiers::MacAddr;

use lanforge_core::context::LanforgeContext;

/// IPv4 address pool with dynamic allocation.
pub struct IpPool {
    /// Range start (inclusive).
    start: u32,
    /// Range end (inclusive).
    end: u32,
    /// IPs rejected via DECLINE (Quarantine with timestamp).
    declined: HashMap<Ipv4Addr, SystemTime>,
    /// Pool of free IPs for circular/fast O(1) allocation.
    available_ips: Vec<Ipv4Addr>,
    /// Maps IP to its position in `available_ips` for O(1) removal.
    ip_to_index: HashMap<Ipv4Addr, usize>,
}

impl IpPool {
    #[must_use]
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let s = u32::from(start);
        let e = u32::from(end);
        let raw_size = u64::from(e) - u64::from(s) + 1;
        let size = usize::try_from(raw_size).expect("Pool size exceeds usize capacity");

        let mut available_ips = Vec::with_capacity(size);

        for i in 0..size {
            let offset = u32::try_from(i).expect("Index exceeds u32 capacity");
            let ip = Ipv4Addr::from(s + offset);
            available_ips.push(ip);
        }

        // Shuffle so allocation order is random (Fisher-Yates)
        available_ips.shuffle(&mut rand::rng());

        // Build index AFTER shuffle so positions match
        let ip_to_index: HashMap<Ipv4Addr, usize> = available_ips
            .iter()
            .enumerate()
            .map(|(i, &ip)| (ip, i))
            .collect();

        Self {
            start: s,
            end: e,
            declined: HashMap::new(),
            available_ips,
            ip_to_index,
        }
    }

    /// Isolates a problematic IP reported via DECLINE.
    pub fn mark_declined(&mut self, ip: Ipv4Addr) {
        self.remove_from_available(ip);
        self.declined.insert(ip, SystemTime::now());
    }

    /// Cleans up quarantine IPs.
    pub fn cleanup_quarantine(&mut self, now: SystemTime) {
        // Cleanup Quarantine (DECLINEs) - Recover IPs after 2 hours
        let quarantine_timeout = std::time::Duration::from_secs(7200);
        let recovered_ips: Vec<Ipv4Addr> = self
            .declined
            .iter()
            .filter(|(_, time)| {
                now.duration_since(**time).unwrap_or_default() >= quarantine_timeout
            })
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
        mac: MacAddr,
        requested: Option<Ipv4Addr>,
        _expiry: SystemTime,
    ) -> Option<Ipv4Addr> {
        let t = LanforgeContext::table();
        let table = t.read();

        // 1. Sticky / Static: already has allocation in global table
        if let Some(dev) = table.get_device(&mac) {
            match dev.v4 {
                lanforge_core::device::IPv4State::Static(ip) => {
                    self.remove_from_available(ip);
                    return Some(ip);
                }
                lanforge_core::device::IPv4State::Dynamic(ref lease) => {
                    self.remove_from_available(lease.ip);
                    return Some(lease.ip);
                }
                lanforge_core::device::IPv4State::None => {}
            }
        }

        // 2. Try the requested IP if it's free and in range
        if let Some(req) = requested
            && self.is_in_range(req)
            && self.is_available_in_pool(req)
        {
            if table.get_mac_by_ip(std::net::IpAddr::V4(req)).is_none() {
                return Some(req);
            }
            // Not actually free according to single source of truth, sync
            self.remove_from_available(req);
        }

        // 3. Fallback: Pick from available pool (O(1))
        while let Some(ip) = self.available_ips.last().copied() {
            self.remove_from_available(ip);
            if table.get_mac_by_ip(std::net::IpAddr::V4(ip)).is_none() {
                return Some(ip);
            }
        }

        // 3.5. Garbage Collection: If pool is empty, scan for naturally expired leases
        for i in self.start..=self.end {
            let ip = Ipv4Addr::from(i);
            if table.get_mac_by_ip(std::net::IpAddr::V4(ip)).is_none()
                && !self.declined.contains_key(&ip)
            {
                self.add_to_available(ip);
            }
        }

        // Second pass after GC
        while let Some(ip) = self.available_ips.last().copied() {
            self.remove_from_available(ip);
            if table.get_mac_by_ip(std::net::IpAddr::V4(ip)).is_none() {
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

            while let Some(ip) = self.available_ips.last().copied() {
                self.remove_from_available(ip);
                if table.get_mac_by_ip(std::net::IpAddr::V4(ip)).is_none() {
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
        if !self.ip_to_index.contains_key(&ip) {
            let idx = self.available_ips.len();
            self.available_ips.push(ip);
            self.ip_to_index.insert(ip, idx);
        }
    }

    fn remove_from_available(&mut self, ip: Ipv4Addr) {
        if let Some(idx) = self.ip_to_index.remove(&ip) {
            // Swap-remove to maintain O(1) performance
            let last_idx = self.available_ips.len() - 1;
            if idx != last_idx {
                let swapped_ip = self.available_ips[last_idx];
                self.available_ips.swap(idx, last_idx);
                self.ip_to_index.insert(swapped_ip, idx);
            }
            self.available_ips.pop();
        }
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
        self.ip_to_index.contains_key(&ip)
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
    use super::*;
    use std::time::Duration;

    use lanforge_core::bus::{EventBus, ManagedTable};
    use std::sync::Arc;

    static INIT: std::sync::Once = std::sync::Once::new();
    fn init_context() {
        INIT.call_once(|| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let bus = Arc::new(EventBus::new());
                let table = Arc::new(ManagedTable::from_table(
                    bus.clone(),
                    lanforge_core::state::DeviceTable::new(),
                    None,
                ));
                LanforgeContext::init(bus, table);
            }));
        });

        // Clear the state before each test runs to avoid cross-contamination
        let binding = LanforgeContext::table();
        let mut w = binding.write();
        *w = lanforge_core::state::DeviceTable::new();
    }

    fn pool() -> IpPool {
        init_context();
        IpPool::new(
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 105),
        )
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
    }

    #[test]
    fn allocates_within_range() {
        init_context();
        let mut p = pool();
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let ip = p.allocate(mac(1), None, expiry).unwrap();
        assert!(
            p.is_in_range(ip),
            "O IP alocado randomicamente deve respeitar o range"
        );
    }

    #[test]
    fn sticky_returns_same_ip() {
        init_context();
        let mut p = pool();
        let expiry = SystemTime::now() + Duration::from_secs(3600);

        let ip1 = p.allocate(mac(1), None, expiry).unwrap();
        // Simular o LanforgeContext alocando
        let _ = LanforgeContext::table().update(
            &lanforge_core::state::update::DeviceUpdate::V4LeaseGranted {
                mac: mac(1),
                ip: ip1,
                expires: expiry,
            },
        );

        let ip2 = p.allocate(mac(1), None, expiry).unwrap();
        assert_eq!(ip1, ip2, "Mesmo MAC deve receber o mesmo IP (Sticky)");
    }

    #[test]
    fn respects_requested_ip() {
        init_context();
        let mut p = pool();
        let requested = Ipv4Addr::new(192, 168, 0, 103);
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let ip = p.allocate(mac(1), Some(requested), expiry).unwrap();
        assert_eq!(
            ip, requested,
            "Deve respeitar o Requested IP se estiver livre"
        );
    }

    #[test]
    fn skips_reserved_and_declined_ips() {
        init_context();
        let mut p = pool(); // Range de 6 IPs (.100 a .105)

        let reserved_ip = Ipv4Addr::new(192, 168, 0, 100);
        let declined_ip = Ipv4Addr::new(192, 168, 0, 101);

        // Simulamos IP reservado no contexto global
        let binding = LanforgeContext::table();
        let mut w = binding.write();
        w.add_static_device(mac(99), "test".to_string(), Some(reserved_ip), None);
        drop(w);

        p.mark_declined(declined_ip);

        // Pedimos IPs
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        for i in 0..4 {
            if let Some(ip) = p.allocate(mac(i), None, expiry) {
                // Registrar cada um para que NÂO seja pego de novo
                let _ = LanforgeContext::table().update(
                    &lanforge_core::state::update::DeviceUpdate::V4LeaseGranted {
                        mac: mac(i),
                        ip,
                        expires: expiry,
                    },
                );
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
        init_context();
        let mut p = pool(); // Range de 6 IPs (.100 a .105)

        // Colocamos os 6 IPs em quarentena simulando uma rede problemática
        for i in 100..=105 {
            p.mark_declined(Ipv4Addr::new(192, 168, 0, i));
        }

        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let rescued_ip = p.allocate(mac(1), None, expiry).unwrap();
        assert!(p.is_in_range(rescued_ip));
        assert!(
            p.declined.is_empty(),
            "A quarentena deve ter sido esvaziada por emergência"
        );
    }

    #[test]
    fn test_cleanup_declined_quarantine() {
        init_context();
        let mut p = IpPool::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 100),
        );
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        // 1. Marca como declined
        p.mark_declined(ip);
        assert!(p.available_ips.is_empty());
        assert_eq!(p.declined.len(), 1);

        // 2. Tenta limpar agora (não deve recuperar pois o timeout é 2h)
        p.cleanup_quarantine(SystemTime::now());
        assert!(p.available_ips.is_empty());

        // 3. Simula 3 horas no futuro
        let three_hours_later = SystemTime::now() + Duration::from_secs(3 * 3600);
        p.cleanup_quarantine(three_hours_later);

        // 4. Deve ter recuperado o IP
        assert_eq!(p.available_ips.len(), 1);
        assert_eq!(p.available_ips[0], ip);
        assert!(p.declined.is_empty());
    }
}
