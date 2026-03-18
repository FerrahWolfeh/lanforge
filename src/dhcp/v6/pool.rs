use crate::state::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;

#[allow(dead_code)]
pub struct Ipv6Pool {
    dynamic_prefixes: Vec<Ipv6Addr>, // Example: [fd97:f00d:cafe:3731::]
    ula_prefix: Option<Ipv6Addr>,    // Prefix to use when formatting static [::xxxx] suffixes
    active: HashMap<MacAddr, Ipv6Addr>,
    ip_to_mac: HashMap<Ipv6Addr, MacAddr>,
    reserved: HashMap<Ipv6Addr, MacAddr>,
}

impl Ipv6Pool {
    pub fn new(dynamic_prefixes: Vec<Ipv6Addr>, ula_prefix: Option<Ipv6Addr>) -> Self {
        Self {
            dynamic_prefixes,
            ula_prefix,
            active: HashMap::new(),
            ip_to_mac: HashMap::new(),
            reserved: HashMap::new(),
        }
    }

    /// Add a static reservation directly to the pool
    #[allow(dead_code)]
    pub fn add_reservation(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.reserved.insert(ip, mac);
    }

    /// Constructs a static IPv6 address given a device's configured suffix and the network's ULA prefix.
    /// E.g. prefix `fd12:3456::` + suffix `::abcd` = `fd12:3456::abcd`.
    #[allow(dead_code)]
    pub fn construct_static_ula(&self, suffix: &str) -> Option<Ipv6Addr> {
        let ula = self.ula_prefix?;

        // Ensure suffix starts with ::
        let clean_suffix = if let Some(stripped) = suffix.strip_prefix("::") {
            stripped
        } else {
            suffix
        };

        // ULA prefix is typically /64 (first 4 segments)
        let ula_segs = ula.segments();

        // Parse the simulated suffix as a full IP to extract its segments easily
        let suffix_ip: Ipv6Addr = format!("::{}", clean_suffix).parse().ok()?;
        let suf_segs = suffix_ip.segments();

        // Combine: First 4 from ULA, last 4 from suffix
        let combined = [
            ula_segs[0],
            ula_segs[1],
            ula_segs[2],
            ula_segs[3],
            suf_segs[4],
            suf_segs[5],
            suf_segs[6],
            suf_segs[7],
        ];

        Some(Ipv6Addr::from(combined))
    }

    /// Allocates an IPv6 address for the given MAC.
    /// Priority:
    /// 1. Static reservation
    /// 2. Sticky dynamic IP
    /// 3. New dynamic EUI-64 IP
    pub fn allocate(&mut self, mac: MacAddr, _requested: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        // 1. Check static reservation
        for (ip, res_mac) in &self.reserved {
            if *res_mac == mac {
                return Some(*ip);
            }
        }

        // 2. Sticky: already has a dynamic allocation
        if let Some(ip) = self.active.get(&mac) {
            return Some(*ip);
        }

        // 3. New dynamic allocation
        if let Some(ip) = self.allocate_dynamic(&mac) {
            self.mark_used(ip, mac);
            return Some(ip);
        }

        None
    }

    /// Allocates a dynamic IPv6 address for the given MAC using EUI-64 algorithm.
    pub fn allocate_dynamic(&self, mac: &MacAddr) -> Option<Ipv6Addr> {
        let prefix = self.dynamic_prefixes.first()?;
        let segs = prefix.segments();
        let m = mac.0;

        // EUI-64 algorithm: insert fffe in the middle, flip 7th bit of first byte
        let eui = [m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]];

        let combined = [
            segs[0],
            segs[1],
            segs[2],
            segs[3],
            u16::from_be_bytes([eui[0], eui[1]]),
            u16::from_be_bytes([eui[2], eui[3]]),
            u16::from_be_bytes([eui[4], eui[5]]),
            u16::from_be_bytes([eui[6], eui[7]]),
        ];

        Some(Ipv6Addr::from(combined))
    }

    /// Releases a dynamic allocation by IP.
    pub fn release(&mut self, ip: &Ipv6Addr) {
        if let Some(mac) = self.ip_to_mac.remove(ip) {
            self.active.remove(&mac);
        }
    }

    /// Releases all dynamic allocations for a MAC.
    pub fn release_mac(&mut self, mac: &MacAddr) {
        if let Some(ip) = self.active.remove(mac) {
            self.ip_to_mac.remove(&ip);
        }
    }

    fn mark_used(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.release_mac(&mac);
        self.active.insert(mac, ip);
        self.ip_to_mac.insert(ip, mac);
    }

    /// Get the IP currently assigned to a MAC (static or dynamic).
    pub fn lookup(&self, mac: &MacAddr) -> Option<Ipv6Addr> {
        for (ip, res_mac) in &self.reserved {
            if res_mac == mac {
                return Some(*ip);
            }
        }
        self.active.get(mac).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_static_ula() {
        let ula = "fd12:3456:7890:abcd::".parse().ok();
        let pool = Ipv6Pool::new(vec![], ula);

        // suffix with standard ::
        let res = pool.construct_static_ula("::1111:2222:3333:4444").unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        // suffix without ::
        let res = pool.construct_static_ula("::cafe:babe").unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_allocate_dynamic_eui64() {
        let dyn_pfx = "2001:db8:1:2::".parse().unwrap();
        let pool = Ipv6Pool::new(vec![dyn_pfx], None);

        let mac = MacAddr::parse("3c:0a:7a:d8:11:78").unwrap();

        let res = pool.allocate_dynamic(&mac).unwrap();

        assert_eq!(res.to_string(), "2001:db8:1:2:3e0a:7aff:fed8:1178");
    }

    #[test]
    fn test_stateful_allocation() {
        let dyn_pfx = "2001:db8:1:2::".parse().unwrap();
        let mut pool = Ipv6Pool::new(vec![dyn_pfx], None);
        let mac = MacAddr::parse("3c:0a:7a:d8:11:78").unwrap();

        let ip = pool.allocate(mac, None).unwrap();
        assert_eq!(ip.to_string(), "2001:db8:1:2:3e0a:7aff:fed8:1178");
        
        // Sticky check
        let ip2 = pool.allocate(mac, None).unwrap();
        assert_eq!(ip, ip2);
        
        pool.release(&ip);
        assert!(pool.lookup(&mac).is_none());
    }
}
