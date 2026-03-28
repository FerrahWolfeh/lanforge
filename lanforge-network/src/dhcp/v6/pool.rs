use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::SystemTime;

use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;

/// Key for identifying a lease, strictly following RFC 8415 (DUID + IAID).
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct LeaseKey {
    pub duid: Vec<u8>,
    pub iaid: u32,
}

#[allow(dead_code)]
pub struct Ipv6Pool {
    pub range_start: Option<Ipv6Addr>,
    pub range_end: Option<Ipv6Addr>,
    ula_prefix: Option<Ipv6Addr>,
    pub ula_prefix_len: u8,
    /// Active leases indexed by DUID + IAID.
    active: HashMap<LeaseKey, Ipv6Addr>,
    /// Reverse index (IP → LeaseKey) for fast reverse lookups.
    ip_to_lease: HashMap<Ipv6Addr, LeaseKey>,
    /// Static reservations mapped by MAC (Device-centric).
    reserved: HashMap<Ipv6Addr, MacAddr>,
    /// IPs in quarantine (e.g., after declining due to DAD failure).
    blacklisted: HashMap<Ipv6Addr, SystemTime>,
    /// Delegated prefixes (IA_PD).
    prefix_active: HashMap<LeaseKey, (Ipv6Addr, u8)>,
}

impl Ipv6Pool {
    pub fn new(
        range_start: Option<Ipv6Addr>,
        range_end: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
        ula_prefix_len: u8,
    ) -> Self {
        Self {
            range_start,
            range_end,
            ula_prefix,
            ula_prefix_len,
            active: HashMap::new(),
            ip_to_lease: HashMap::new(),
            reserved: HashMap::new(),
            blacklisted: HashMap::new(),
            prefix_active: HashMap::new(),
        }
    }

    /// Add a static reservation directly to the pool
    #[allow(dead_code)]
    pub fn add_reservation(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.reserved.insert(ip, mac);
    }

    /// Remove a static reservation for a MAC.
    pub fn remove_reservation(&mut self, mac: MacAddr) {
        self.reserved.retain(|_, m| *m != mac);
    }

    /// Constructs a static IPv6 address given a device's configured suffix and the network's ULA prefix.
    #[allow(dead_code)]
    pub fn construct_static_ula(&self, suffix: &Ipv6AddrOrSuffix) -> Option<Ipv6Addr> {
        let ula = self.ula_prefix?;
        match suffix {
            Ipv6AddrOrSuffix::Full(ip) => Some(*ip),
            Ipv6AddrOrSuffix::Suffix(s) => {
                let ula_segs = ula.segments();
                let combined = [
                    ula_segs[0],
                    ula_segs[1],
                    ula_segs[2],
                    ula_segs[3],
                    u16::from_be_bytes([s[0], s[1]]),
                    u16::from_be_bytes([s[2], s[3]]),
                    u16::from_be_bytes([s[4], s[5]]),
                    u16::from_be_bytes([s[6], s[7]]),
                ];
                Some(Ipv6Addr::from(combined))
            }
        }
    }

    /// Allocates an IPv6 address for the given DUID+IAID.
    pub fn allocate(
        &mut self,
        duid: &[u8],
        iaid: u32,
        mac: Option<MacAddr>,
        requested: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        let lease_key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };

        // 1. Sticky IP: Does a lease for this DUID+IAID already exist? (Highest priority)
        if let Some(ip) = self.active.get(&lease_key) {
            return Some(*ip);
        }

        // 2. Static Reservation check (configured in TOML / Device-centric)
        // If we know the MAC and it has an unused reservation, return it.
        if let Some(known_mac) = mac {
            let reserved_ip = self
                .reserved
                .iter()
                .find(|(ip, res_mac)| **res_mac == known_mac && self.is_available(ip))
                .map(|(ip, _)| *ip);

            if let Some(ip) = reserved_ip {
                self.mark_used(ip, lease_key);
                return Some(ip);
            }
        }

        // 3. Restricted Dynamic Pool (Sequential/Ranged) - If range_start and range_end exist
        if let (Some(start), Some(end)) = (self.range_start, self.range_end) {
            let start_int = u128::from_be_bytes(start.octets());
            let end_int = u128::from_be_bytes(end.octets());

            // Try the requested IP first, respecting range and availability
            if let Some(req) = requested {
                let req_int = u128::from_be_bytes(req.octets());
                if req_int >= start_int && req_int <= end_int && self.is_available(&req) {
                    self.mark_used(req, lease_key);
                    return Some(req);
                }
            }

            // Random-offset allocation with linear probing (wrap-around)
            let range_size = end_int - start_int + 1;
            let offset = rand::random::<u128>() % range_size;

            for i in 0..range_size {
                let raw = start_int + (offset + i) % range_size;
                let ip = Ipv6Addr::from(raw.to_be_bytes());
                if self.is_available(&ip) {
                    self.mark_used(ip, lease_key);
                    return Some(ip);
                }
            }
        }
        // 4. Opaque / Randomized IID (RFC 7943) - Used if no range is defined but ULA exists
        else if let Some(ula) = self.ula_prefix {
            // Did the client request a specific IP? If it matches our ULA prefix and is free, accept it.
            if let Some(req) = requested
                && self.is_on_link(&req)
                && self.is_available(&req)
            {
                self.mark_used(req, lease_key);
                return Some(req);
            }

            // Generate a random Interface Identifier (IID) suffix.
            let ula_int = u128::from_be_bytes(ula.octets());
            let mask = !0u128 >> self.ula_prefix_len;

            for _ in 0..20 {
                let random_suffix: u128 = rand::random::<u128>() & mask;
                let ip = Ipv6Addr::from((ula_int | random_suffix).to_be_bytes());

                if self.is_available(&ip) {
                    self.mark_used(ip, lease_key);
                    return Some(ip);
                }
            }
        }

        // Pool exhausted or prefix omitted in configuration
        None
    }

    /// Allocates an IPv6 prefix for the given DUID+IAID (Prefix Delegation).
    pub fn allocate_prefix(
        &mut self,
        duid: &[u8],
        iaid: u32,
        _requested: Option<(Ipv6Addr, u8)>,
    ) -> Option<(Ipv6Addr, u8)> {
        let lease_key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };

        if let Some(res) = self.prefix_active.get(&lease_key) {
            return Some(*res);
        }

        // If the ULA prefix is /64 or smaller, we cannot delegate /64 sub-prefixes.
        if self.ula_prefix_len >= 64 {
            return None;
        }

        let ula = self.ula_prefix?;
        let ula_int = u128::from_be_bytes(ula.octets());

        // Search for a free /64 within the ULA prefix.
        let step = 1u128 << (128 - 64);
        let start = ula_int;
        let end = ula_int | (!0u128 >> self.ula_prefix_len);

        // Skip the first /64 (reserved for LAN IA_NA usage)
        let mut curr = start + step;
        while curr < end {
            let prefix_addr = Ipv6Addr::from(curr.to_be_bytes());
            if self.is_prefix_available(&prefix_addr, 64) {
                self.prefix_active.insert(lease_key, (prefix_addr, 64));
                return Some((prefix_addr, 64));
            }
            curr += step;
        }

        None
    }
    pub fn has_binding(&self, duid: &[u8], iaid: u32) -> bool {
        let lease_key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };
        self.active.contains_key(&lease_key)
    }

    pub fn has_prefix_binding(&self, duid: &[u8], iaid: u32) -> bool {
        let lease_key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };
        self.prefix_active.contains_key(&lease_key)
    }

    pub fn is_on_link(&self, ip: &Ipv6Addr) -> bool {
        let ula = match self.ula_prefix {
            Some(u) => u,
            None => return false,
        };
        let ula_int = u128::from_be_bytes(ula.octets());
        let ip_int = u128::from_be_bytes(ip.octets());
        let mask = !0u128 << (128 - self.ula_prefix_len);
        (ip_int & mask) == (ula_int & mask)
    }

    fn is_prefix_available(&self, addr: &Ipv6Addr, len: u8) -> bool {
        // Check for conflicts with delegated prefixes
        for (a, l) in self.prefix_active.values() {
            if *a == *addr && *l == len {
                return false;
            }
        }
        // Check for conflicts with individual LAN IPs
        // (Simplification: ideally prefixes and IPs reside in separate pools)
        true
    }

    pub fn decline(&mut self, ip: Ipv6Addr) {
        self.release(&ip);
        self.blacklisted.insert(ip, SystemTime::now());
    }

    fn is_available(&self, ip: &Ipv6Addr) -> bool {
        // An IP is free if not granted, reserved, or blacklisted.
        if self.ip_to_lease.contains_key(ip) {
            return false;
        }
        if let Some(ts) = self.blacklisted.get(ip) {
            // Quarantine for 24 hours.
            if ts.elapsed().unwrap_or_default().as_secs() < 86400 {
                return false;
            }
        }
        true
    }

    pub fn release(&mut self, ip: &Ipv6Addr) {
        if let Some(key) = self.ip_to_lease.remove(ip) {
            self.active.remove(&key);
        }
    }

    pub fn release_mac(&mut self, mac: MacAddr) {
        // Find IPs associated with this MAC through reservations or active leases.
        // Note: in interface-centric IPv6, a single MAC can hold multiple IAIDs.
        // If forcing release by MAC, we clear the reservations.
        self.remove_reservation(mac);
    }

    fn mark_used(&mut self, ip: Ipv6Addr, key: LeaseKey) {
        // If this IP was already in use by another key, remove the old one
        if let Some(old_key) = self.ip_to_lease.remove(&ip) {
            self.active.remove(&old_key);
        }
        self.active.insert(key.clone(), ip);
        self.ip_to_lease.insert(ip, key);
    }

    pub fn lookup(&self, duid: &[u8], iaid: u32) -> Option<Ipv6Addr> {
        let key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };
        self.active.get(&key).copied()
    }

    pub fn lookup_prefix(&self, duid: &[u8], iaid: u32) -> Option<(Ipv6Addr, u8)> {
        let key = LeaseKey {
            duid: duid.to_vec(),
            iaid,
        };
        self.prefix_active.get(&key).copied()
    }

    /// Legacy version for compatibility with Managers that only identified via MAC.
    pub fn lookup_by_mac_legacy(&self, mac: MacAddr) -> Option<Ipv6Addr> {
        for (ip, res_mac) in &self.reserved {
            if *res_mac == mac {
                return Some(*ip);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use lanforge_core::device::Ipv6AddrOrSuffix;

    use super::*;

    // Função auxiliar para gerar MACs nos testes
    fn mac(last_byte: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte])
    }

    fn duid(last_byte: u8) -> Vec<u8> {
        vec![0, 3, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte]
    }

    #[test]
    fn test_construct_static_ula() {
        let ula = "fd12:3456:7890:abcd::".parse().ok();
        let pool = Ipv6Pool::new(None, None, ula, 64);

        let suf1 = Ipv6AddrOrSuffix::parse("::1111:2222:3333:4444").unwrap();
        let res = pool.construct_static_ula(&suf1).unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        let suf2 = Ipv6AddrOrSuffix::parse("::cafe:babe").unwrap();
        let res2 = pool.construct_static_ula(&suf2).unwrap();
        assert_eq!(res2.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_dynamic_allocation_ranged() {
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        let ip1 = pool.allocate(&duid(1), 1, Some(mac(1)), None).unwrap();
        let ip2 = pool.allocate(&duid(2), 1, Some(mac(2)), None).unwrap();
        let ip3 = pool.allocate(&duid(3), 1, Some(mac(3)), None).unwrap();

        // All IPs must be within range
        for ip in [ip1, ip2, ip3] {
            let raw = u128::from_be_bytes(ip.octets());
            assert!(raw >= start_int && raw <= end_int, "IP {ip} out of range");
        }

        // All IPs must be unique
        assert_ne!(ip1, ip2);
        assert_ne!(ip2, ip3);
        assert_ne!(ip1, ip3);

        // Pool esgotado
        assert!(pool.allocate(&duid(4), 1, Some(mac(4)), None).is_none());
    }

    #[test]
    fn test_dynamic_allocation_opaque_random() {
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        // Sem limites de range definidos, apenas o ULA
        let mut pool = Ipv6Pool::new(None, None, Some(ula), 64);

        let ip1 = pool.allocate(&duid(1), 1, Some(mac(1)), None).unwrap();
        let ip2 = pool.allocate(&duid(2), 1, Some(mac(2)), None).unwrap();

        // Garante que a rede /64 está correta
        let ula_segs = ula.segments();
        assert_eq!(ip1.segments()[0..4], ula_segs[0..4]);
        assert_eq!(ip2.segments()[0..4], ula_segs[0..4]);

        // A chance de colisão nos 64 bits de host é estatisticamente nula
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_requested_ip_ranged() {
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::200".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Pedido válido dentro do range
        let requested = "fd00::150".parse().unwrap();
        let ip = pool
            .allocate(&duid(1), 1, Some(mac(1)), Some(requested))
            .unwrap();
        assert_eq!(ip, requested);

        // Pedido fora do range: ignora o request e aloca qualquer IP livre do range
        let out_of_bounds = "fd00::250".parse().unwrap();
        let ip2 = pool
            .allocate(&duid(2), 1, Some(mac(2)), Some(out_of_bounds))
            .unwrap();
        let raw = u128::from_be_bytes(ip2.octets());
        assert!(
            raw >= start_int && raw <= end_int,
            "Fallback IP {ip2} out of range"
        );
        assert_ne!(
            ip2, requested,
            "Fallback must not collide with already-assigned IP"
        );
    }

    #[test]
    fn test_requested_ip_opaque() {
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula), 64);

        // Cliente envia hint de um IP opaco que ele já usou
        let requested = "fd97:f00d:cafe:3731:1234:5678:9abc:def0".parse().unwrap();
        let ip = pool
            .allocate(&duid(1), 1, Some(mac(1)), Some(requested))
            .unwrap();
        assert_eq!(ip, requested);

        // Cliente pede um IP de outra rede (ex: GUA antigo) -> ignora e gera um novo random
        let wrong_net: Ipv6Addr = "2001:db8::1234".parse().unwrap();
        let ip2 = pool
            .allocate(&duid(2), 1, Some(mac(2)), Some(wrong_net))
            .unwrap();
        assert_ne!(ip2, wrong_net);
        assert_eq!(ip2.segments()[0..4], ula.segments()[0..4]);
    }

    #[test]
    fn test_sticky_allocation() {
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula), 64);

        let ip1 = pool.allocate(&duid(1), 1, Some(mac(1)), None).unwrap();
        let ip2 = pool.allocate(&duid(1), 1, Some(mac(1)), None).unwrap(); // Mesmo MAC pedindo de novo

        // Deve retornar exatamente o mesmo IP
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_static_reservation() {
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula), 64);

        let static_ip = "fd00::cafe".parse().unwrap();
        pool.add_reservation(static_ip, mac(1));

        // Cliente pode até pedir outra coisa, mas o estático prevalece
        let requested = "fd00::babe".parse().unwrap();
        let ip = pool
            .allocate(&duid(1), 1, Some(mac(1)), Some(requested))
            .unwrap();
        assert_eq!(ip, static_ip);
    }

    #[test]
    fn test_release() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::100".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None, 64);

        let ip1 = pool.allocate(&duid(1), 1, Some(mac(1)), None).unwrap();
        assert!(pool.allocate(&duid(2), 1, Some(mac(2)), None).is_none()); // Esgotado

        pool.release(&ip1);

        let ip2 = pool.allocate(&duid(2), 1, Some(mac(2)), None).unwrap(); // Liberou, o MAC 2 consegue pegar
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_add_remove_reservation() {
        let ula = "fd00::".parse().unwrap();
        let mut p = Ipv6Pool::new(None, None, Some(ula), 64);
        let mac = mac(1);
        let ip = "fd00::cafe".parse().unwrap();

        p.add_reservation(ip, mac);
        assert_eq!(p.lookup_by_mac_legacy(mac), Some(ip));

        p.remove_reservation(mac);
        assert_eq!(p.lookup_by_mac_legacy(mac), None);
    }
    #[test]
    fn test_random_allocation_fills_and_releases() {
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Fill the pool (3 IPs)
        let ip1 = pool.allocate(&duid(1), 1, None, None).unwrap();
        let ip2 = pool.allocate(&duid(2), 1, None, None).unwrap();
        let ip3 = pool.allocate(&duid(3), 1, None, None).unwrap();

        // All must be unique and in range
        let ips = [ip1, ip2, ip3];
        for ip in &ips {
            let raw = u128::from_be_bytes(ip.octets());
            assert!(raw >= start_int && raw <= end_int);
        }
        assert_ne!(ip1, ip2);
        assert_ne!(ip2, ip3);
        assert_ne!(ip1, ip3);

        // Pool exhausted
        assert!(pool.allocate(&duid(4), 1, None, None).is_none());

        // Release one and allocate again — the freed IP should be reused
        pool.release(&ip1);
        let ip4 = pool.allocate(&duid(4), 1, None, None).unwrap();
        assert_eq!(ip4, ip1, "Released IP should be reusable");
    }
}
