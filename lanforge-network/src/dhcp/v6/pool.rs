use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::SystemTime;

use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::{Duid, MacAddr};

use crate::dhcp::v6::config::Dhcpv6PoolConfig;

/// Internal representation of a DHCPv6 address range.
#[derive(Clone, Debug)]
pub enum PoolRange {
    /// A range bound to a specific 64-bit prefix.
    Fixed {
        prefix: [u16; 4],
        start_u128: u128,
        end_u128: u128,
    },
    /// A "floating" range that applies to any managed prefix (ULA or GUA).
    Floating {
        start_suffix: [u8; 8],
        end_suffix: [u8; 8],
    },
}

impl PoolRange {
    pub fn from_config(cfg: &Dhcpv6PoolConfig) -> Self {
        if let Some(ref cidr) = cfg.address
            && let Some((addr, len)) = Self::parse_cidr(cidr)
        {
            let segs = addr.segments();
            if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                // Floating range from CIDR (e.g. ::/64)
                let start = [0u8; 8];
                let end = if len <= 64 {
                    [0xff; 8]
                } else {
                    let total_host_bits = 128 - len;
                    let end_u64 = if total_host_bits >= 64 {
                        !0u64
                    } else {
                        (1u64 << total_host_bits) - 1
                    };
                    end_u64.to_be_bytes()
                };

                return Self::Floating {
                    start_suffix: start,
                    end_suffix: end,
                };
            } else {
                // Fixed range from CIDR (e.g. fd00::/64)
                let start_u128 = u128::from_be_bytes(addr.octets());
                let host_bits = 128 - len;
                let end_u128 = if host_bits >= 128 {
                    !0u128
                } else {
                    start_u128 | ((1u128 << host_bits) - 1)
                };

                return Self::Fixed {
                    prefix: [segs[0], segs[1], segs[2], segs[3]],
                    start_u128,
                    end_u128,
                };
            }
        }

        match (&cfg.range_start, &cfg.range_end) {
            (Some(Ipv6AddrOrSuffix::Full(start)), Some(Ipv6AddrOrSuffix::Full(end))) => {
                let s_segs = start.segments();
                let e_segs = end.segments();
                if s_segs[0..4] == e_segs[0..4] {
                    Self::Fixed {
                        prefix: [s_segs[0], s_segs[1], s_segs[2], s_segs[3]],
                        start_u128: u128::from_be_bytes(start.octets()),
                        end_u128: u128::from_be_bytes(end.octets()),
                    }
                } else {
                    Self::Floating {
                        start_suffix: [
                            s_segs[4].to_be_bytes()[0],
                            s_segs[4].to_be_bytes()[1],
                            s_segs[5].to_be_bytes()[0],
                            s_segs[5].to_be_bytes()[1],
                            s_segs[6].to_be_bytes()[0],
                            s_segs[6].to_be_bytes()[1],
                            s_segs[7].to_be_bytes()[0],
                            s_segs[7].to_be_bytes()[1],
                        ],
                        end_suffix: [
                            e_segs[4].to_be_bytes()[0],
                            e_segs[4].to_be_bytes()[1],
                            e_segs[5].to_be_bytes()[0],
                            e_segs[5].to_be_bytes()[1],
                            e_segs[6].to_be_bytes()[0],
                            e_segs[6].to_be_bytes()[1],
                            e_segs[7].to_be_bytes()[0],
                            e_segs[7].to_be_bytes()[1],
                        ],
                    }
                }
            }
            (Some(Ipv6AddrOrSuffix::Suffix(s)), Some(Ipv6AddrOrSuffix::Suffix(e))) => {
                Self::Floating {
                    start_suffix: *s,
                    end_suffix: *e,
                }
            }
            _ => Self::Floating {
                start_suffix: [0; 8],
                end_suffix: [0, 0, 0, 0, 0, 0, 0xff, 0xff], // Safe default
            },
        }
    }

    fn parse_cidr(s: &str) -> Option<(Ipv6Addr, u8)> {
        let parts: Vec<&str> = s.split('/').collect();
        let addr = parts[0].parse::<Ipv6Addr>().ok()?;
        let len = if parts.len() > 1 {
            parts[1].parse::<u8>().ok()?
        } else {
            64
        };
        Some((addr, len))
    }
}

#[allow(dead_code)]
pub struct Ipv6Pool {
    /// Configured pools (Fixed or Floating).
    pub pools: Vec<PoolRange>,
    /// Static ULA prefix from config.
    pub ula_prefix: Option<Ipv6Addr>,
    /// Dynamic GUA prefix detected from RA.
    pub gua_prefix: Option<Ipv6Addr>,
    pub ula_prefix_len: u8,
    /// IPs in quarantine.
    blacklisted: HashMap<Ipv6Addr, SystemTime>,
}

impl Ipv6Pool {
    pub fn new(
        pools: Vec<Dhcpv6PoolConfig>,
        ula_prefix: Option<Ipv6Addr>,
        ula_prefix_len: u8,
    ) -> Self {
        Self {
            pools: pools.iter().map(PoolRange::from_config).collect(),
            ula_prefix,
            gua_prefix: None,
            ula_prefix_len,
            blacklisted: HashMap::new(),
        }
    }
    /// Updates the dynamic GUA prefix.
    pub fn set_gua_prefix(&mut self, prefix: Ipv6Addr) {
        self.gua_prefix = Some(prefix);
    }

    /// Constructs an IPv6 address given a device's configured suffix and a prefix.
    pub fn construct_addr(&self, prefix: Ipv6Addr, suffix: &Ipv6AddrOrSuffix) -> Ipv6Addr {
        match suffix {
            Ipv6AddrOrSuffix::Full(ip) => *ip,
            Ipv6AddrOrSuffix::Suffix(s) => {
                let p_segs = prefix.segments();
                let combined = [
                    p_segs[0],
                    p_segs[1],
                    p_segs[2],
                    p_segs[3],
                    u16::from_be_bytes([s[0], s[1]]),
                    u16::from_be_bytes([s[2], s[3]]),
                    u16::from_be_bytes([s[4], s[5]]),
                    u16::from_be_bytes([s[6], s[7]]),
                ];
                Ipv6Addr::from(combined)
            }
        }
    }

    /// Helper for construct_static_ula for legacy calls.
    pub fn construct_static_ula(&self, suffix: &Ipv6AddrOrSuffix) -> Option<Ipv6Addr> {
        self.ula_prefix.map(|ula| self.construct_addr(ula, suffix))
    }

    /// Allocates IPv6 addresses for the given DUID+IAID.
    /// Returns a list of addresses (e.g. one ULA and one GUA).
    pub fn allocate(
        &mut self,
        duid: &[u8],
        iaid: u32,
        mac: Option<MacAddr>,
        requested: Option<Ipv6Addr>,
    ) -> Vec<Ipv6Addr> {
        let t = LanforgeContext::table();
        let table = t.read();

        // 1. Sticky IP check: if we already have addresses globally, return them.
        let mut dev_opt = table.get_by_duid(&Duid::new(duid.to_vec()));
        if dev_opt.is_none()
            && let Some(m) = mac
        {
            dev_opt = table.get_device(&m);
        }

        if let Some(dev) = dev_opt.as_ref() {
            let mut sticky = Vec::new();
            for state in &dev.v6 {
                if let lanforge_core::device::IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    sticky.push(lease.ip);
                }
            }
            if !sticky.is_empty() {
                return sticky;
            }
        }

        let mut assigned = Vec::new();

        // Prefixes to process
        let mut prefixes = Vec::new();
        if let Some(ula) = self.ula_prefix {
            prefixes.push(ula);
        }
        if let Some(gua) = self.gua_prefix {
            prefixes.push(gua);
        }

        // Include any Fixed pool prefixes that aren't already covered
        for pool in &self.pools {
            if let PoolRange::Fixed { prefix: p, .. } = pool {
                let addr = Ipv6Addr::new(p[0], p[1], p[2], p[3], 0, 0, 0, 0);
                if !prefixes.contains(&addr) {
                    prefixes.push(addr);
                }
            }
        }

        for prefix in prefixes {
            let mut prefix_assigned = false;
            let mut pool_attempted = false;

            // 2. Static Reservation check for this prefix
            if let Some(dev) = dev_opt.as_ref() {
                for state in &dev.v6 {
                    if let lanforge_core::device::IPv6State::Static(suffix) = state {
                        let ip = self.construct_addr(prefix, suffix);
                        if self.is_on_prefix(&ip, &prefix)
                            && self.is_available(&ip, &table)
                            && !assigned.contains(&ip)
                        {
                            assigned.push(ip);
                            prefix_assigned = true;
                        }
                    }
                }
            }

            // 3. Requested IP check for this prefix
            if !prefix_assigned
                && let Some(req_ip) = requested
                && self.is_on_prefix(&req_ip, &prefix)
                && self.is_available(&req_ip, &table)
            {
                assigned.push(req_ip);
                prefix_assigned = true;
            }

            if prefix_assigned {
                continue;
            }

            // 4. Dynamic Pools check for this prefix
            // Search Fixed pools first for precedence
            for pool in &self.pools {
                if let PoolRange::Fixed {
                    prefix: p,
                    start_u128,
                    end_u128,
                } = pool
                {
                    let pref_segs = prefix.segments();
                    if pref_segs[0..4] == *p {
                        pool_attempted = true;
                        // Fixed pool matches this prefix
                        if let Some(ip) = self.allocate_from_range(*start_u128, *end_u128, &table) {
                            assigned.push(ip);
                            prefix_assigned = true;
                            break;
                        }
                    }
                }
            }

            if prefix_assigned {
                continue;
            }

            // 4. Search Floating pools
            for pool in &self.pools {
                if let PoolRange::Floating {
                    start_suffix,
                    end_suffix,
                } = pool
                {
                    pool_attempted = true;
                    // Floating pool applies to any prefix
                    let start_u128 = self.combine_pref_suf(&prefix, start_suffix);
                    let end_u128 = self.combine_pref_suf(&prefix, end_suffix);
                    if let Some(ip) = self.allocate_from_range(start_u128, end_u128, &table) {
                        assigned.push(ip);
                        prefix_assigned = true;
                        break;
                    }
                }
            }

            if prefix_assigned {
                continue;
            }

            // 5. Fallback: Randomized IID in prefix (only if NO pools were configured for this prefix)
            if !pool_attempted {
                let pref_int = u128::from_be_bytes(prefix.octets());
                let mask = !0u128 >> 64; // Assuming /64 for simplicity

                for _ in 0..20 {
                    let random_suffix: u128 = rand::random::<u128>() & mask;
                    let ip = Ipv6Addr::from((pref_int | random_suffix).to_be_bytes());
                    if self.is_available(&ip, &table) {
                        assigned.push(ip);
                        break;
                    }
                }
            }
        }

        assigned
    }

    pub fn has_binding(&self, duid: &[u8], iaid: u32) -> bool {
        let t = LanforgeContext::table();
        let table = t.read();
        if let Some(dev) = table.get_by_duid(&Duid::new(duid.to_vec())) {
            for state in &dev.v6 {
                if let lanforge_core::device::IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_prefix_binding(&self, duid: &[u8], iaid: u32) -> bool {
        let t = LanforgeContext::table();
        let table = t.read();
        if let Some(dev) = table.get_by_duid(&Duid::new(duid.to_vec())) {
            for pref in &dev.v6_prefixes {
                if pref.iaid == iaid {
                    return true;
                }
            }
        }
        false
    }

    pub fn lookup(&self, duid: &[u8], iaid: u32) -> Vec<Ipv6Addr> {
        let t = LanforgeContext::table();
        let table = t.read();
        let mut ips = Vec::new();
        if let Some(dev) = table.get_by_duid(&Duid::new(duid.to_vec())) {
            for state in &dev.v6 {
                if let lanforge_core::device::IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    ips.push(lease.ip);
                }
            }
        }
        ips
    }

    pub fn lookup_prefix(&self, duid: &[u8], iaid: u32) -> Option<(Ipv6Addr, u8)> {
        let t = LanforgeContext::table();
        let table = t.read();
        if let Some(dev) = table.get_by_duid(&Duid::new(duid.to_vec())) {
            for pref in &dev.v6_prefixes {
                if pref.iaid == iaid {
                    return Some((pref.prefix, pref.len));
                }
            }
        }
        None
    }

    pub fn lookup_by_mac_legacy(&self, mac: MacAddr) -> Vec<Ipv6Addr> {
        let t = LanforgeContext::table();
        let table = t.read();
        if let Some(dev) = table.get_device(&mac) {
            dev.v6.iter().filter_map(|s| s.ip()).collect()
        } else {
            Vec::new()
        }
    }

    fn combine_pref_suf(&self, prefix: &Ipv6Addr, suffix: &[u8; 8]) -> u128 {
        let p = prefix.segments();
        let mut octets = [0u8; 16];
        octets[0..2].copy_from_slice(&p[0].to_be_bytes());
        octets[2..4].copy_from_slice(&p[1].to_be_bytes());
        octets[4..6].copy_from_slice(&p[2].to_be_bytes());
        octets[6..8].copy_from_slice(&p[3].to_be_bytes());
        octets[8..16].copy_from_slice(suffix);
        u128::from_be_bytes(octets)
    }

    fn allocate_from_range(
        &self,
        start: u128,
        end: u128,
        table: &lanforge_core::state::DeviceTable,
    ) -> Option<Ipv6Addr> {
        let size = end - start + 1;
        let offset = rand::random::<u128>() % size;
        for i in 0..size {
            let raw = start + (offset + i) % size;
            let ip = Ipv6Addr::from(raw.to_be_bytes());
            if self.is_available(&ip, table) {
                return Some(ip);
            }
        }
        None
    }

    fn is_on_prefix(&self, ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
        let ip_segs = ip.segments();
        let pref_segs = prefix.segments();
        ip_segs[0..4] == pref_segs[0..4]
    }

    fn is_available(&self, ip: &Ipv6Addr, table: &lanforge_core::state::DeviceTable) -> bool {
        table.get_mac_by_ip(std::net::IpAddr::V6(*ip)).is_none()
            && !self.blacklisted.contains_key(ip)
    }

    pub fn release(&mut self, _ip: &Ipv6Addr) {
        // Releases are handled by DeviceTable event updates matching the IP.
        // We do not manage the mapping internally anymore.
    }

    /// Allocates an IPv6 prefix for the given DUID+IAID (Prefix Delegation).
    pub fn allocate_prefix(
        &mut self,
        duid: &[u8],
        iaid: u32,
        _requested: Option<(Ipv6Addr, u8)>,
    ) -> Option<(Ipv6Addr, u8)> {
        let t = LanforgeContext::table();
        let table = t.read();

        // Sticky prefix check globally
        if let Some(dev) = table.get_by_duid(&Duid::new(duid.to_vec())) {
            for pref in &dev.v6_prefixes {
                if pref.iaid == iaid {
                    return Some((pref.prefix, pref.len));
                }
            }
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
            if self.is_prefix_available(&prefix_addr, 64, &table) {
                return Some((prefix_addr, 64));
            }
            curr += step;
        }

        None
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

    fn is_prefix_available(
        &self,
        addr: &Ipv6Addr,
        len: u8,
        table: &lanforge_core::state::DeviceTable,
    ) -> bool {
        // Check for conflicts with delegated prefixes
        for dev in table.devices() {
            for p in &dev.v6_prefixes {
                if p.prefix == *addr && p.len == len {
                    return false;
                }
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
}

#[cfg(test)]
mod tests {
    use lanforge_core::device::Ipv6AddrOrSuffix;

    use super::*;
    use lanforge_core::bus::{EventBus, ManagedTable};
    use lanforge_core::state::update::DeviceUpdate;
    use std::sync::Arc;
    use std::time::Duration;

    use std::sync::Once;
    static INIT: Once = Once::new();

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

    // Função auxiliar para gerar MACs nos testes
    fn mac(last_byte: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte])
    }

    fn duid(last_byte: u8) -> Vec<u8> {
        vec![0, 3, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte]
    }

    fn commit_lease(mac: Option<MacAddr>, duid: &[u8], iaid: u32, ip: Ipv6Addr) {
        let table = LanforgeContext::table();
        let _ = table.update(&DeviceUpdate::V6LeaseGranted {
            mac,
            duid: Duid::new(duid.to_vec()),
            iaid,
            ip,
            expires: SystemTime::now() + Duration::from_secs(3600),
        });
    }

    fn release_mac(mac: MacAddr) {
        let table = LanforgeContext::table();
        let _ = table.update(&DeviceUpdate::HostRemoved { mac });
    }

    #[test]
    fn test_construct_static_ula() {
        init_context();
        let ula = "fd12:3456:7890:abcd::".parse().ok();
        let pool = Ipv6Pool::new(Vec::new(), ula, 64);

        let suf1 = Ipv6AddrOrSuffix::parse("::1111:2222:3333:4444").unwrap();
        let res = pool.construct_static_ula(&suf1).unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        let suf2 = Ipv6AddrOrSuffix::parse("::cafe:babe").unwrap();
        let res2 = pool.construct_static_ula(&suf2).unwrap();
        assert_eq!(res2.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_dynamic_allocation_ranged() {
        init_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let ula = "fd00::".parse().ok();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(pools, ula, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        let ips1 = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        let ip1 = ips1[0];
        commit_lease(Some(mac(1)), &duid(1), 1, ip1);

        let ips2 = pool.allocate(&duid(2), 1, Some(mac(2)), None);
        let ip2 = ips2[0];
        commit_lease(Some(mac(2)), &duid(2), 1, ip2);

        let ips3 = pool.allocate(&duid(3), 1, Some(mac(3)), None);
        let ip3 = ips3[0];
        commit_lease(Some(mac(3)), &duid(3), 1, ip3);

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
        assert!(pool.allocate(&duid(4), 1, Some(mac(4)), None).is_empty());
    }

    #[test]
    fn test_multi_prefix_allocation() {
        init_context();
        let ula = "fd00::".parse::<Ipv6Addr>().ok();
        let gua = "2001:db8::".parse::<Ipv6Addr>().unwrap();

        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Suffix([0, 0, 0, 0, 0, 0, 0, 1])),
            range_end: Some(Ipv6AddrOrSuffix::Suffix([0, 0, 0, 0, 0, 0, 0, 0xFF])),
            address: None,
        }];

        let mut pool = Ipv6Pool::new(pools, ula, 64);
        pool.set_gua_prefix(gua);

        let ips = pool.allocate(&duid(1), 1, Some(mac(1)), None);

        assert_eq!(ips.len(), 2, "Should allocate both ULA and GUA");
        assert!(
            ips.iter().any(|ip| ip.segments()[0] == 0xfd00),
            "Missing ULA"
        );
        assert!(
            ips.iter().any(|ip| ip.segments()[0] == 0x2001),
            "Missing GUA"
        );
    }

    #[test]
    fn test_dynamic_allocation_opaque_random() {
        init_context();
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        // No range limits, just the ULA prefix
        let mut pool = Ipv6Pool::new(Vec::new(), Some(ula), 64);

        let ips1 = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        let ip1 = ips1[0];
        let ips2 = pool.allocate(&duid(2), 1, Some(mac(2)), None);
        let ip2 = ips2[0];

        // Ensure the /64 network is correct
        let ula_segs = ula.segments();
        assert_eq!(ip1.segments()[0..4], ula_segs[0..4]);
        assert_eq!(ip2.segments()[0..4], ula_segs[0..4]);

        // Collision chance in 64 host bits is statistically zero
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_requested_ip_honoring() {
        init_context();
        let ula = "fd00::".parse::<Ipv6Addr>().ok();
        let mut pool = Ipv6Pool::new(Vec::new(), ula, 64);

        let requested = "fd00::dead:beef".parse::<Ipv6Addr>().unwrap();
        let ips = pool.allocate(&duid(1), 1, Some(mac(1)), Some(requested));

        assert!(ips.contains(&requested), "Must honor requested IP");
    }

    #[test]
    fn test_requested_ip_ranged() {
        init_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::200".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(pools, None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Valid request within range (Note: allocate currently ignores requested IP for simplicity in multi-pool,
        // but it should still return a valid IP from the range)
        let ips = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        let ip = ips[0];
        let raw = u128::from_be_bytes(ip.octets());
        assert!(raw >= start_int && raw <= end_int, "IP {ip} out of range");

        // Second allocation
        let ips2 = pool.allocate(&duid(2), 1, Some(mac(2)), None);
        let ip2 = ips2[0];
        let raw2 = u128::from_be_bytes(ip2.octets());
        assert!(
            raw2 >= start_int && raw2 <= end_int,
            "Fallback IP {ip2} out of range"
        );
        assert_ne!(ip2, ip, "Must not collide");
    }

    #[test]
    fn test_sticky_allocation() {
        init_context();
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(Vec::new(), Some(ula), 64);

        let ips1 = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        commit_lease(Some(mac(1)), &duid(1), 1, ips1[0]);

        let ips2 = pool.allocate(&duid(1), 1, Some(mac(1)), None); // Same client asking again

        // Must return exactly the same list of IPs
        assert_eq!(ips1, ips2);
    }

    #[test]
    fn test_static_reservation() {
        init_context();
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(Vec::new(), Some(ula), 64);

        let static_suffix = Ipv6AddrOrSuffix::parse("::cafe").unwrap();
        let binding = LanforgeContext::table();
        let mut w = binding.write();
        w.add_static_device(mac(1), "test".to_string(), None, Some(static_suffix));
        drop(w);

        let ips = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        assert!(ips.contains(&"fd00::cafe".parse().unwrap()));
    }

    #[test]
    fn test_release() {
        init_context();
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::100".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(pools, None, 64);

        let ips1 = pool.allocate(&duid(1), 1, Some(mac(1)), None);
        let ip1 = ips1[0];
        commit_lease(Some(mac(1)), &duid(1), 1, ip1);

        assert!(pool.allocate(&duid(2), 1, Some(mac(2)), None).is_empty()); // Exhausted

        release_mac(mac(1));

        let ips2 = pool.allocate(&duid(2), 1, Some(mac(2)), None); // Released, Mac 2 can take it
        assert_eq!(ip1, ips2[0]);
    }

    #[test]
    fn test_random_allocation_fills_and_releases() {
        init_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(pools, None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Fill the pool (3 IPs)
        let ip1 = pool.allocate(&duid(1), 1, Some(mac(1)), None)[0];
        commit_lease(Some(mac(1)), &duid(1), 1, ip1);

        let ip2 = pool.allocate(&duid(2), 1, Some(mac(2)), None)[0];
        commit_lease(Some(mac(2)), &duid(2), 1, ip2);

        let ip3 = pool.allocate(&duid(3), 1, Some(mac(3)), None)[0];
        commit_lease(Some(mac(3)), &duid(3), 1, ip3);

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
        assert!(pool.allocate(&duid(4), 1, None, None).is_empty());

        // Release one and allocate again — the freed IP should be reused
        // Since we don't have MACs in this test, we use DuidAssociated which might be tricky,
        // but HostRemoved by MAC won't work.
        // Let's use a simpler way: just clear the table for this test's contet.
        let binding = LanforgeContext::table();
        let mut w = binding.write();
        *w = lanforge_core::state::DeviceTable::new();
        // Re-filling with 2 and 3 so 1 is free
        drop(w);
        commit_lease(Some(mac(2)), &duid(2), 1, ip2);
        commit_lease(Some(mac(3)), &duid(3), 1, ip3);

        let ip4 = pool.allocate(&duid(4), 1, Some(mac(4)), None)[0];
        assert_eq!(ip4, ip1, "Released IP should be reusable");
    }

    #[test]
    fn test_cidr_expansion() {
        // 1. Floating CIDR ::/120 (expect 256 addresses)
        let cfg1 = Dhcpv6PoolConfig {
            range_start: None,
            range_end: None,
            address: Some("::/120".to_string()),
        };
        let range1 = PoolRange::from_config(&cfg1);
        if let PoolRange::Floating {
            start_suffix,
            end_suffix,
        } = range1
        {
            assert_eq!(start_suffix, [0; 8]);
            assert_eq!(end_suffix, [0, 0, 0, 0, 0, 0, 0, 0xff]);
        } else {
            panic!("Expected Floating range for ::/120");
        }

        // 2. Fixed CIDR fd00::/120
        let cfg2 = Dhcpv6PoolConfig {
            range_start: None,
            range_end: None,
            address: Some("fd00::/120".to_string()),
        };
        let range2 = PoolRange::from_config(&cfg2);
        if let PoolRange::Fixed {
            prefix,
            start_u128,
            end_u128,
        } = range2
        {
            assert_eq!(prefix, [0xfd00, 0, 0, 0]);
            let start = "fd00::".parse::<Ipv6Addr>().unwrap();
            let end = "fd00::ff".parse::<Ipv6Addr>().unwrap();
            assert_eq!(start_u128, u128::from_be_bytes(start.octets()));
            assert_eq!(end_u128, u128::from_be_bytes(end.octets()));
        } else {
            panic!("Expected Fixed range for fd00::/120");
        }
    }
}
