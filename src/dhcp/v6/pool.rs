use crate::state::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;

#[allow(dead_code)]
pub struct Ipv6Pool {
    pub range_start: Option<Ipv6Addr>,
    pub range_end: Option<Ipv6Addr>,
    ula_prefix: Option<Ipv6Addr>,
    active: HashMap<MacAddr, Ipv6Addr>,
    ip_to_mac: HashMap<Ipv6Addr, MacAddr>,
    reserved: HashMap<Ipv6Addr, MacAddr>,
}

impl Ipv6Pool {
    pub fn new(
        range_start: Option<Ipv6Addr>,
        range_end: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            range_start,
            range_end,
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
    #[allow(dead_code)]
    pub fn construct_static_ula(&self, suffix: &str) -> Option<Ipv6Addr> {
        let ula = self.ula_prefix?;
        let clean_suffix = suffix.strip_prefix("::").unwrap_or(suffix);
        let ula_segs = ula.segments();
        let suffix_ip: Ipv6Addr = format!("::{}", clean_suffix).parse().ok()?;
        let suf_segs = suffix_ip.segments();

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
    pub fn allocate(&mut self, mac: MacAddr, requested: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        // 1. Static reservation
        for (ip, res_mac) in &self.reserved {
            if *res_mac == mac {
                return Some(*ip);
            }
        }

        // 2. Sticky: already has a dynamic allocation
        if let Some(ip) = self.active.get(&mac) {
            return Some(*ip);
        }

        // 3. New dynamic allocation within the configured bounds (u128 arithmetic)
        if let (Some(start), Some(end)) = (self.range_start, self.range_end) {
            let start_int = u128::from_be_bytes(start.octets());
            let end_int = u128::from_be_bytes(end.octets());

            // Tenta o IP requisitado pelo cliente primeiro
            if let Some(req) = requested {
                let req_int = u128::from_be_bytes(req.octets());
                if req_int >= start_int && req_int <= end_int && self.is_available(&req) {
                    self.mark_used(req, mac);
                    return Some(req);
                }
            }

            // Busca o primeiro IP livre no range
            for raw in start_int..=end_int {
                let ip = Ipv6Addr::from(raw.to_be_bytes());
                if self.is_available(&ip) {
                    self.mark_used(ip, mac);
                    return Some(ip);
                }
            }
        }

        None
    }

    fn is_available(&self, ip: &Ipv6Addr) -> bool {
        !self.reserved.contains_key(ip) && !self.ip_to_mac.contains_key(ip)
    }

    pub fn release(&mut self, ip: &Ipv6Addr) {
        if let Some(mac) = self.ip_to_mac.remove(ip) {
            self.active.remove(&mac);
        }
    }

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
        let pool = Ipv6Pool::new(None, None, ula);

        // suffix com :: padrão
        let res = pool.construct_static_ula("::1111:2222:3333:4444").unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        // suffix sem ::
        let res = pool.construct_static_ula("::cafe:babe").unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_dynamic_allocation_range() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::102".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None);

        let mac1 = MacAddr::parse("aa:bb:cc:dd:ee:01").unwrap();
        let mac2 = MacAddr::parse("aa:bb:cc:dd:ee:02").unwrap();
        let mac3 = MacAddr::parse("aa:bb:cc:dd:ee:03").unwrap();
        let mac4 = MacAddr::parse("aa:bb:cc:dd:ee:04").unwrap();

        assert_eq!(pool.allocate(mac1, None).unwrap().to_string(), "fd00::100");
        assert_eq!(pool.allocate(mac2, None).unwrap().to_string(), "fd00::101");
        assert_eq!(pool.allocate(mac3, None).unwrap().to_string(), "fd00::102");

        // Pool esgotado (end é 102)
        assert!(pool.allocate(mac4, None).is_none());
    }

    #[test]
    fn test_sticky_allocation() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::100".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None);
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:01").unwrap();

        let ip1 = pool.allocate(mac, None).unwrap();
        let ip2 = pool.allocate(mac, None).unwrap(); // Deve retornar o mesmo IP
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_static_reservation() {
        let mut pool = Ipv6Pool::new(None, None, None);
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:01").unwrap();
        let static_ip = "fd00::cafe".parse().unwrap();

        pool.add_reservation(static_ip, mac);

        // Mesmo pedindo sem IP preferencial, a reserva estática tem prioridade
        let allocated = pool.allocate(mac, None).unwrap();
        assert_eq!(allocated, static_ip);
    }
}
