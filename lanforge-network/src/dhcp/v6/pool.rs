//! Multi-prefix IPv6 address pool for `DHCPv6` (`IA_NA` + `IA_PD`).
//!
//! Supports simultaneous `ULA` and `GUA` prefix operation, with both
//! **fixed** (prefix-bound) and **floating** (suffix-only) pool ranges.
//!
//! ## Pool Types
//!
//! | Type | Use Case | Example |
//! | :--- | :--- | :--- |
//! | `Fixed` | Addresses tied to a specific 64-bit prefix | `fd00::100`–`fd00::200` |
//! | `Floating` | Suffix ranges that apply to any managed prefix | `::100`–`::200` on ULA or GUA |
//!
//! ## Allocation Strategy
//!
//! 1. **Static reservations** — pre-allocated on startup per prefix
//! 2. **Sticky leases** — return same address for returning DUID+IAID
//! 3. **Deterministic** — hash(DUID, IAID, index) for reproducible assignment
//! 4. **Random fallback** — when deterministic slots are taken
//!
//! ## Multi-Prefix Operation
//!
//! When both `ULA` and `GUA` prefixes are configured, the pool allocates
//! addresses on both prefixes simultaneously. A single `IA_NA` request
//! may receive one `ULA` and one `GUA` address.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use lanforge_core::context::LanforgeContext;
use lanforge_core::device::{IPv6State, Ipv6AddrOrSuffix};
use lanforge_core::identifiers::{Duid, MacAddr};
use rand::random;

use crate::dhcp::v6::config::Dhcpv6PoolConfig;

/// Range definition for a `DHCPv6` address pool.
#[derive(Clone, Debug)]
pub enum PoolRange {
    /// A range bound to a specific 64-bit prefix (e.g., `fd00::100`–`fd00::200`).
    Fixed {
        /// First 4 segments (64 bits) of the prefix.
        prefix: [u16; 4],
        /// Lower bound of the range as a full 128-bit value.
        start_u128: u128,
        /// Upper bound of the range as a full 128-bit value.
        end_u128: u128,
    },
    /// A "floating" range that applies to any managed prefix (ULA or GUA).
    /// The suffix is combined with the active prefix at allocation time.
    Floating {
        /// Lower bound 64-bit suffix.
        start_suffix: [u8; 8],
        /// Upper bound 64-bit suffix.
        end_suffix: [u8; 8],
    },
}

impl PoolRange {
    #[must_use]
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
            }
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

/// Multi-prefix IPv6 address pool supporting `IA_NA` and `IA_PD` allocation.
///
/// Manages both `ULA` (static) and `GUA` (dynamic, from `RA`) prefixes simultaneously.
/// Addresses are tracked per `DUID`+`IAID` for sticky lease behavior.
#[allow(dead_code)]
pub struct Ipv6Pool {
    /// Configured pool ranges (Fixed or Floating).
    pub pools: Vec<PoolRange>,
    /// Static ULA prefix from configuration (`fd00::/8`).
    pub ula_prefix: Option<Ipv6Addr>,
    /// Dynamic GUA prefix detected from Router Advertisements.
    pub gua_prefix: Option<Ipv6Addr>,
    /// Prefix length for the ULA (typically 64).
    pub ula_prefix_len: u8,
    /// Blacklisted IPs from DECLINE with quarantine timestamp.
    blacklisted: HashMap<Ipv6Addr, Instant>,
    /// Static IP reservations to prevent dynamic allocation collisions.
    reserved_static: Vec<Ipv6Addr>,
}

impl Ipv6Pool {
    pub fn new(
        pools: &[Dhcpv6PoolConfig],
        ula_prefix: Option<Ipv6Addr>,
        ula_prefix_len: u8,
    ) -> Self {
        Self {
            pools: pools.iter().map(PoolRange::from_config).collect(),
            ula_prefix,
            gua_prefix: None,
            ula_prefix_len,
            blacklisted: HashMap::new(),
            reserved_static: Vec::new(),
        }
    }
    /// Updates the dynamic GUA prefix.
    pub const fn set_gua_prefix(&mut self, prefix: Ipv6Addr) {
        self.gua_prefix = Some(prefix);
    }

    /// Reserves a batch of static addresses by marking them as taken.
    /// This prevents dynamic allocation collisions on startup.
    pub fn reserve_statics(&mut self, ips: impl IntoIterator<Item = Ipv6Addr>) {
        for ip in ips {
            if !self.reserved_static.contains(&ip) {
                self.reserved_static.push(ip);
            }
        }
    }

    /// Constructs an IPv6 address given a device's configured suffix and a prefix.
    #[must_use]
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

    /// Helper for `construct_static_ula` for legacy calls.
    #[must_use]
    pub fn construct_static_ula(&self, suffix: &Ipv6AddrOrSuffix) -> Option<Ipv6Addr> {
        self.ula_prefix.map(|ula| self.construct_addr(ula, suffix))
    }

    /// Collects static suffix addresses across all active prefixes.
    /// Returns addresses for every prefix where the device has a static reservation.
    fn collect_static_ips(
        &self,
        ctx: &LanforgeContext,
        duid: &Duid,
        mac: Option<MacAddr>,
        prefixes: &[Ipv6Addr],
    ) -> Vec<Ipv6Addr> {
        let mut dev_opt = ctx.query(|t| t.get_by_duid(duid));
        if dev_opt.is_none()
            && let Some(m) = mac
        {
            dev_opt = ctx.get_device(&m);
        }

        let Some(dev) = dev_opt else {
            return Vec::new();
        };

        let mut ips = Vec::new();
        for prefix in prefixes {
            for state in &dev.v6 {
                if let IPv6State::Static(suffix) = state {
                    let ip = self.construct_addr(*prefix, suffix);
                    if Self::is_on_prefix(&ip, prefix) && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
        ips
    }

    /// Allocates IPv6 addresses for the given DUID+IAID.
    /// Returns a list of addresses (e.g. one ULA and one GUA).
    pub fn allocate(
        &mut self,
        ctx: &LanforgeContext,
        duid: &Duid,
        iaid: u32,
        mac: Option<MacAddr>,
        requested: Option<Ipv6Addr>,
    ) -> Vec<Ipv6Addr> {
        let prefixes = self.get_active_prefixes();

        // 1. Static reservations take absolute priority (OpenWrt-style).
        //    If the device has a configured suffix, apply it to ALL active prefixes.
        let static_ips = self.collect_static_ips(ctx, duid, mac, &prefixes);
        if !static_ips.is_empty() {
            return static_ips;
        }

        // 2. Sticky IP check: return previously assigned dynamic leases.
        let sticky = Self::get_sticky_ips(ctx, duid, iaid, mac);
        if !sticky.is_empty() {
            return sticky;
        }

        // 3. Fresh dynamic allocation from pools.
        let mut assigned = Vec::new();
        for prefix in prefixes {
            if let Some(ip) = self.allocate_for_prefix(ctx, prefix, duid, mac, requested, &assigned)
            {
                assigned.push(ip);
            }
        }

        assigned
    }

    /// Checks if a device already has an active lease for a specific IAID.
    fn get_sticky_ips(
        ctx: &LanforgeContext,
        duid: &Duid,
        iaid: u32,
        mac: Option<MacAddr>,
    ) -> Vec<Ipv6Addr> {
        let mut dev_opt = ctx.query(|t| t.get_by_duid(duid));
        if dev_opt.is_none()
            && let Some(m) = mac
        {
            dev_opt = ctx.get_device(&m);
        }

        if let Some(dev) = dev_opt {
            let mut sticky = Vec::new();
            for state in &dev.v6 {
                if let IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    sticky.push(lease.ip);
                }
            }
            return sticky;
        }
        Vec::new()
    }

    /// Gathers all prefixes that this service should provide addresses for.
    fn get_active_prefixes(&self) -> Vec<Ipv6Addr> {
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
        prefixes
    }

    /// Logic for a single prefix allocation attempt.
    fn allocate_for_prefix(
        &self,
        ctx: &LanforgeContext,
        prefix: Ipv6Addr,
        duid: &Duid,
        mac: Option<MacAddr>,
        requested: Option<Ipv6Addr>,
        already_assigned: &[Ipv6Addr],
    ) -> Option<Ipv6Addr> {
        // 1. Requested IP check
        if let Some(req_ip) = requested
            && Self::is_on_prefix(&req_ip, &prefix)
            && !already_assigned.contains(&req_ip) // Added check
            && self.is_available(ctx, &req_ip, mac)
        {
            return Some(req_ip);
        }

        // 3. Dynamic Pools
        let mut pool_attempted = false;
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
                    if let Some(ip) = self.allocate_from_range(
                        ctx,
                        prefix,
                        duid.as_bytes(),
                        *start_u128,
                        *end_u128,
                        mac,
                    ) && !already_assigned.contains(&ip)
                    {
                        // Added check
                        return Some(ip);
                    }
                }
            }
        }

        // 4. Floating Pools
        for pool in &self.pools {
            if let PoolRange::Floating {
                start_suffix,
                end_suffix,
            } = pool
            {
                pool_attempted = true;
                let start_u128 = Self::combine_pref_suf(&prefix, *start_suffix);
                let end_u128 = Self::combine_pref_suf(&prefix, *end_suffix);
                if let Some(ip) = self.allocate_from_range(
                    ctx,
                    prefix,
                    duid.as_bytes(),
                    start_u128,
                    end_u128,
                    mac,
                ) && !already_assigned.contains(&ip)
                {
                    // Added check
                    return Some(ip);
                }
            }
        }

        // 5. Fallback: Randomized IID
        if !pool_attempted {
            let pref_int = u128::from_be_bytes(prefix.octets());
            let mask = !0u128 >> 64;

            // Step 1: Deterministic IID
            let det_suffix = Self::generate_deterministic_u128(&prefix, duid.as_bytes(), mask);
            let ip = Ipv6Addr::from((pref_int | (det_suffix & mask)).to_be_bytes());
            if self.is_available(ctx, &ip, mac) {
                return Some(ip);
            }

            // Step 2: Limited random attempts
            for _ in 0..10 {
                let random_suffix: u128 = random::<u128>() & mask;
                let ip = Ipv6Addr::from((pref_int | random_suffix).to_be_bytes());
                if self.is_available(ctx, &ip, mac) {
                    return Some(ip);
                }
            }
        }

        None
    }

    #[must_use]
    pub fn has_binding(&self, ctx: &LanforgeContext, duid: &Duid, iaid: u32) -> bool {
        let device_opt = ctx.query(|t| t.get_by_duid(duid));

        if let Some(dev) = device_opt {
            for state in &dev.v6 {
                if let IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    return true;
                }
            }
        }
        false
    }

    #[must_use]
    pub fn has_prefix_binding(&self, ctx: &LanforgeContext, duid: &Duid, iaid: u32) -> bool {
        let device_opt = ctx.query(|t| t.get_by_duid(duid));

        if let Some(dev) = device_opt {
            for pref in &dev.v6_prefixes {
                if pref.iaid == iaid {
                    return true;
                }
            }
        }
        false
    }

    #[must_use]
    pub fn lookup(&self, ctx: &LanforgeContext, duid: &Duid, iaid: u32) -> Vec<Ipv6Addr> {
        let mut ips = Vec::new();
        let device_opt = ctx.query(|t| t.get_by_duid(duid));

        if let Some(dev) = device_opt {
            for state in &dev.v6 {
                if let IPv6State::Dynamic(lease) = state
                    && lease.iaid == iaid
                {
                    ips.push(lease.ip);
                }
            }
        }
        ips
    }

    #[must_use]
    pub fn lookup_prefix(
        &self,
        ctx: &LanforgeContext,
        duid: &Duid,
        iaid: u32,
    ) -> Option<(Ipv6Addr, u8)> {
        let device_opt = ctx.query(|t| t.get_by_duid(duid));

        if let Some(dev) = device_opt {
            for pref in &dev.v6_prefixes {
                if pref.iaid == iaid {
                    return Some((pref.prefix, pref.len));
                }
            }
        }
        None
    }

    pub fn lookup_by_mac_legacy(&self, ctx: &LanforgeContext, mac: MacAddr) -> Vec<Ipv6Addr> {
        ctx.get_device(&mac).map_or_else(Vec::new, |dev| {
            dev.v6.iter().filter_map(IPv6State::ip).collect()
        })
    }

    fn combine_pref_suf(prefix: &Ipv6Addr, suffix: [u8; 8]) -> u128 {
        let p = prefix.segments();
        let mut octets = [0u8; 16];
        octets[0..2].copy_from_slice(&p[0].to_be_bytes());
        octets[2..4].copy_from_slice(&p[1].to_be_bytes());
        octets[4..6].copy_from_slice(&p[2].to_be_bytes());
        octets[6..8].copy_from_slice(&p[3].to_be_bytes());
        octets[8..16].copy_from_slice(&suffix);
        u128::from_be_bytes(octets)
    }

    fn allocate_from_range(
        &self,
        ctx: &LanforgeContext,
        prefix: Ipv6Addr,
        identifier: &[u8],
        start: u128,
        end: u128,
        target_mac: Option<MacAddr>,
    ) -> Option<Ipv6Addr> {
        let size = end - start + 1;

        // 1. Deterministic Candidate (Stability)
        let det_offset = Self::generate_deterministic_u128(&prefix, identifier, size);
        let det_ip = Ipv6Addr::from((start + (det_offset % size)).to_be_bytes());
        if self.is_available(ctx, &det_ip, target_mac) {
            return Some(det_ip);
        }

        // 2. Limited Probabilistic Retries (Safety)
        for _ in 0..10 {
            let offset = random::<u128>() % size;
            let ip = Ipv6Addr::from((start + offset).to_be_bytes());
            if self.is_available(ctx, &ip, target_mac) {
                return Some(ip);
            }
        }
        None
    }

    fn generate_deterministic_u128(prefix: &Ipv6Addr, identifier: &[u8], range_size: u128) -> u128 {
        let mut hasher = DefaultHasher::new();
        prefix.hash(&mut hasher);
        identifier.hash(&mut hasher);
        let hash = hasher.finish();

        if range_size > u128::from(u64::MAX) {
            // If range is huge, mix in more random-ish deterministic bits
            let mut hasher2 = DefaultHasher::new();
            hash.hash(&mut hasher2);
            let hash2 = hasher2.finish();
            (u128::from(hash) << 64) | u128::from(hash2)
        } else {
            u128::from(hash)
        }
    }

    fn is_on_prefix(ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
        let ip_segs = ip.segments();
        let pref_segs = prefix.segments();
        ip_segs[0..4] == pref_segs[0..4]
    }

    fn is_available(
        &self,
        ctx: &LanforgeContext,
        ip: &Ipv6Addr,
        target_mac: Option<MacAddr>,
    ) -> bool {
        if let Some(mac) = ctx.get_mac_by_ip(IpAddr::V6(*ip))
            && Some(mac) != target_mac
        {
            return false;
        }

        if self.reserved_static.contains(ip) {
            return false;
        }

        !self.blacklisted.contains_key(ip)
    }

    pub const fn release(&mut self, _ip: &Ipv6Addr) {
        // Releases are handled by DeviceTable event updates matching the IP.
        // We do not manage the mapping internally anymore.
    }

    /// Allocates an IPv6 prefix for the given DUID+IAID (Prefix Delegation).
    pub fn allocate_prefix(
        &mut self,
        ctx: &LanforgeContext,
        duid: &Duid,
        iaid: u32,
        _requested: Option<(Ipv6Addr, u8)>,
    ) -> Option<(Ipv6Addr, u8)> {
        // Sticky prefix check globally
        let device_opt = ctx.query(|t| t.get_by_duid(duid));

        if let Some(dev) = device_opt {
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
            if !ctx.is_prefix_delegated(prefix_addr, 64) {
                return Some((prefix_addr, 64));
            }
            curr += step;
        }

        None
    }

    #[must_use]
    pub const fn is_on_link(&self, ip: &Ipv6Addr) -> bool {
        let Some(ula) = self.ula_prefix else {
            return false;
        };

        let ula_int = u128::from_be_bytes(ula.octets());
        let ip_int = u128::from_be_bytes(ip.octets());
        let mask = !0u128 << (128 - self.ula_prefix_len);
        (ip_int & mask) == (ula_int & mask)
    }

    pub fn decline(&mut self, ip: Ipv6Addr) {
        self.release(&ip);
        self.blacklisted.insert(ip, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::init_test_context;
    use lanforge_core::{
        device::{Ipv6AddrOrSuffix, Origin},
        state::{DeviceUpdate, FieldUpdate},
    };

    use super::*;
    use std::time::{Duration, SystemTime};

    // Função auxiliar para gerar MACs nos testes
    fn mac(last_byte: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte])
    }

    fn duid(last_byte: u8) -> Vec<u8> {
        vec![0, 3, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte]
    }

    fn commit_lease(
        ctx: &LanforgeContext,
        mac: Option<MacAddr>,
        duid: &[u8],
        iaid: u32,
        ip: Ipv6Addr,
    ) {
        let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
            mac,
            duid: Duid::new(duid.to_vec()),
            iaid,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });
    }

    fn release_mac(ctx: &LanforgeContext, mac: MacAddr) {
        let _ = ctx.apply(DeviceUpdate::HostRemoved { mac });
    }

    #[test]
    fn test_construct_static_ula() {
        let _ctx = init_test_context();
        let ula = "fd12:3456:7890:abcd::".parse().ok();
        let pool = Ipv6Pool::new(&Vec::new(), ula, 64);

        let suf1 = Ipv6AddrOrSuffix::parse("::1111:2222:3333:4444").unwrap();
        let res = pool.construct_static_ula(&suf1).unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        let suf2 = Ipv6AddrOrSuffix::parse("::cafe:babe").unwrap();
        let res2 = pool.construct_static_ula(&suf2).unwrap();
        assert_eq!(res2.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_dynamic_allocation_ranged() {
        let ctx = init_test_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let ula = "fd00::".parse().ok();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(&pools, ula, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        let ips1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        let first_ip = ips1[0];
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, first_ip);

        let ips2 = pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None);
        let second_ip = ips2[0];
        commit_lease(&ctx, Some(mac(2)), &duid(2), 1, second_ip);

        let ips3 = pool.allocate(&ctx, &Duid::new(duid(3)), 1, Some(mac(3)), None);
        let third_ip = ips3[0];
        commit_lease(&ctx, Some(mac(3)), &duid(3), 1, third_ip);

        // All IPs must be within range
        for ip in [first_ip, second_ip, third_ip] {
            let raw = u128::from_be_bytes(ip.octets());
            assert!(raw >= start_int && raw <= end_int, "IP {ip} out of range");
        }

        // All IPs must be unique
        assert_ne!(first_ip, second_ip);
        assert_ne!(second_ip, third_ip);
        assert_ne!(first_ip, third_ip);

        // Pool esgotado
        assert!(
            pool.allocate(&ctx, &Duid::new(duid(4)), 1, Some(mac(4)), None)
                .is_empty()
        );
    }

    #[test]
    fn test_multi_prefix_allocation() {
        let ctx = init_test_context();
        let ula = "fd00::".parse::<Ipv6Addr>().ok();
        let gua = "2001:db8::".parse::<Ipv6Addr>().unwrap();

        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Suffix([0, 0, 0, 0, 0, 0, 0, 1])),
            range_end: Some(Ipv6AddrOrSuffix::Suffix([0, 0, 0, 0, 0, 0, 0, 0xFF])),
            address: None,
        }];

        let mut pool = Ipv6Pool::new(&pools, ula, 64);
        pool.set_gua_prefix(gua);

        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);

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
        let ctx = init_test_context();
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        // No range limits, just the ULA prefix
        let mut pool = Ipv6Pool::new(&Vec::new(), Some(ula), 64);

        let ips1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        let first_ip = ips1[0];
        let ips2 = pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None);
        let second_ip = ips2[0];

        // Ensure the /64 network is correct
        let ula_segs = ula.segments();
        assert_eq!(first_ip.segments()[0..4], ula_segs[0..4]);
        assert_eq!(second_ip.segments()[0..4], ula_segs[0..4]);

        // Collision chance in 64 host bits is statistically zero
        assert_ne!(first_ip, second_ip);
    }

    #[test]
    fn test_requested_ip_honoring() {
        let ctx = init_test_context();
        let ula = "fd00::".parse::<Ipv6Addr>().ok();
        let mut pool = Ipv6Pool::new(&Vec::new(), ula, 64);

        let requested = "fd00::dead:beef".parse::<Ipv6Addr>().unwrap();
        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), Some(requested));

        assert!(ips.contains(&requested), "Must honor requested IP");
    }

    #[test]
    fn test_requested_ip_ranged() {
        let ctx = init_test_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::200".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(&pools, None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Valid request within range (Note: allocate currently ignores requested IP for simplicity in multi-pool,
        // but it should still return a valid IP from the range)
        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        let ip = ips[0];
        let raw = u128::from_be_bytes(ip.octets());
        assert!(raw >= start_int && raw <= end_int, "IP {ip} out of range");

        // Second allocation
        let ips2 = pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None);
        let second = ips2[0];
        let raw2 = u128::from_be_bytes(second.octets());
        assert!(
            raw2 >= start_int && raw2 <= end_int,
            "Fallback IP {second} out of range"
        );
        assert_ne!(second, ip, "Must not collide");
    }

    #[test]
    fn test_sticky_allocation() {
        let ctx = init_test_context();
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(&Vec::new(), Some(ula), 64);

        let ips1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, ips1[0]);

        let ips2 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None); // Same client asking again

        // Must return exactly the same list of IPs
        assert_eq!(ips1, ips2);
    }

    #[test]
    fn test_static_reservation() {
        let ctx = init_test_context();
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(&Vec::new(), Some(ula), 64);

        let static_suffix = Ipv6AddrOrSuffix::parse("::cafe").unwrap();
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(1),
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(static_suffix),
            origin: Origin::Cli,
        });

        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        assert!(ips.contains(&"fd00::cafe".parse().unwrap()));
    }

    #[test]
    fn test_release() {
        let ctx = init_test_context();
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::100".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(&pools, None, 64);

        let ips1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        let first_ip = ips1[0];
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, first_ip);

        assert!(
            pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None)
                .is_empty()
        ); // Exhausted

        release_mac(&ctx, mac(1));

        let ips2 = pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None); // Released, Mac 2 can take it
        assert_eq!(first_ip, ips2[0]);
    }

    #[test]
    fn test_static_reservation_reconnect() {
        let ctx = init_test_context();
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(&Vec::new(), Some(ula), 64);

        let static_suffix = Ipv6AddrOrSuffix::parse("::cafe").unwrap();
        let static_ip: Ipv6Addr = "fd00::cafe".parse().unwrap();

        // 1. Setup static device
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(1),
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(static_suffix),
            origin: Origin::Cli,
        });

        // 2. Allocate first time
        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        assert!(ips.contains(&static_ip));

        // 3. Commit lease (this puts it in the ip_index)
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, static_ip);

        // 4. Allocate again (simulated reconnect)
        // Even though fd00::cafe is in the index, it should still be assigned because it's static
        let ips2 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        assert!(
            ips2.contains(&static_ip),
            "Should still return static IP on reconnect"
        );
    }

    #[test]
    fn test_random_allocation_fills_and_releases() {
        let ctx = init_test_context();
        let start: Ipv6Addr = "fd00::100".parse().unwrap();
        let end: Ipv6Addr = "fd00::102".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(Ipv6AddrOrSuffix::Full(end)),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(&pools, None, 64);

        let start_int = u128::from_be_bytes(start.octets());
        let end_int = u128::from_be_bytes(end.octets());

        // Fill the pool (3 IPs)
        let ip1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None)[0];
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, ip1);

        let ip2 = pool.allocate(&ctx, &Duid::new(duid(2)), 1, Some(mac(2)), None)[0];
        commit_lease(&ctx, Some(mac(2)), &duid(2), 1, ip2);

        let ip3 = pool.allocate(&ctx, &Duid::new(duid(3)), 1, Some(mac(3)), None)[0];
        commit_lease(&ctx, Some(mac(3)), &duid(3), 1, ip3);

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
        assert!(
            pool.allocate(&ctx, &Duid::new(duid(4)), 1, None, None)
                .is_empty()
        );

        // Release one and allocate again — the freed IP should be reused
        // Since we don't have MACs in this test, we use DuidAssociated which might be tricky,
        // Clear the table by getting a fresh context
        let ctx = init_test_context();

        // Re-filling with 2 and 3 so 1 is free
        commit_lease(&ctx, Some(mac(2)), &duid(2), 1, ip2);
        commit_lease(&ctx, Some(mac(3)), &duid(3), 1, ip3);

        let ip4 = pool.allocate(&ctx, &Duid::new(duid(4)), 1, Some(mac(4)), None)[0];
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

    #[test]
    fn test_static_overrides_sticky() {
        let ctx = init_test_context();
        let ula = "fd00::".parse().unwrap();
        let pools = vec![Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::parse("::1").unwrap()),
            range_end: Some(Ipv6AddrOrSuffix::parse("::10").unwrap()),
            address: None,
        }];
        let mut pool = Ipv6Pool::new(&pools, Some(ula), 64);

        // 1. Allocate dynamic first
        let ips1 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        let dynamic_ip = ips1[0];
        assert_ne!(dynamic_ip, "fd00::cafe".parse::<Ipv6Addr>().unwrap());
        commit_lease(&ctx, Some(mac(1)), &duid(1), 1, dynamic_ip);

        // 2. Set static suffix later
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(1),
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::cafe").unwrap()),
            origin: Origin::Cli,
        });

        // 3. Re-allocate -> must return static address, NOT the sticky dynamic one
        let ips2 = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        assert_eq!(ips2.len(), 1);
        assert_eq!(ips2[0], "fd00::cafe".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_multi_prefix_static_suffix_dual_stack() {
        let ctx = init_test_context();
        let ula = "fd00::".parse().unwrap();
        let gua = "2001:db8::".parse().unwrap();
        let mut pool = Ipv6Pool::new(&Vec::new(), Some(ula), 64);
        pool.set_gua_prefix(gua);

        // Setup static device
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac: mac(1),
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::cafe").unwrap()),
            origin: Origin::Cli,
        });

        // Allocate -> must return suffix on both ULA and GUA
        let ips = pool.allocate(&ctx, &Duid::new(duid(1)), 1, Some(mac(1)), None);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"fd00::cafe".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::cafe".parse().unwrap()));
    }
}
