//! Alocador de endereços IP para o pool dinâmico DHCPv4.
//!
//! Gerencia o range configurável excluindo reservas estáticas.
//! Prioriza reutilizar o IP anteriormente atribuído ao mesmo MAC (sticky).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::state::MacAddr;

/// Pool de endereços IPv4 com alocação dinâmica.
pub struct IpPool {
    /// Range start (inclusive).
    start: u32,
    /// Range end (inclusive).
    end: u32,
    /// MAC → IP: alocações ativas (dinâmicas).
    active: HashMap<MacAddr, Ipv4Addr>,
    /// IP → MAC: índice reverso para lookup rápido.
    ip_to_mac: HashMap<Ipv4Addr, MacAddr>,
    /// IPs reservados (estáticos) — excluídos do pool dinâmico.
    reserved: HashMap<Ipv4Addr, MacAddr>,
}

impl IpPool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        IpPool {
            start: u32::from(start),
            end: u32::from(end),
            active: HashMap::new(),
            ip_to_mac: HashMap::new(),
            reserved: HashMap::new(),
        }
    }

    /// Reserve a static IP for a MAC (excluded from dynamic allocation).
    pub fn add_reservation(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.reserved.insert(ip, mac);
    }

    /// Allocate an IP for a MAC address.
    ///
    /// Priority:
    /// 1. Static reservation for this MAC → return reserved IP
    /// 2. Previously-assigned dynamic IP for this MAC (sticky) → return same
    /// 3. Requested IP (if available and in range) → return requested
    /// 4. Next free IP in range → return it
    /// 5. No IPs available → None
    pub fn allocate(&mut self, mac: MacAddr, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
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

        // 3. Try the requested IP if it's free and in range
        if let Some(req) = requested
            && self.is_in_range(req)
            && self.is_available(req)
        {
            self.mark_used(req, mac);
            return Some(req);
        }

        // 4. Scan for next free IP
        for raw in self.start..=self.end {
            let ip = Ipv4Addr::from(raw);
            if self.is_available(ip) {
                self.mark_used(ip, mac);
                return Some(ip);
            }
        }

        // 5. Pool exhausted
        None
    }

    /// Release a dynamic allocation.
    pub fn release(&mut self, ip: Ipv4Addr) {
        if let Some(mac) = self.ip_to_mac.remove(&ip) {
            self.active.remove(&mac);
        }
    }

    /// Release all allocations for a MAC.
    pub fn release_mac(&mut self, mac: &MacAddr) {
        if let Some(ip) = self.active.remove(mac) {
            self.ip_to_mac.remove(&ip);
        }
    }

    /// Check if an IP is available (not in active use and not reserved).
    fn is_available(&self, ip: Ipv4Addr) -> bool {
        !self.ip_to_mac.contains_key(&ip) && !self.reserved.contains_key(&ip)
    }

    /// Check if an IP is within the dynamic range.
    fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        raw >= self.start && raw <= self.end
    }

    /// Mark an IP as used by a MAC.
    fn mark_used(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        // Release any previous allocation for this MAC
        self.release_mac(&mac);
        self.active.insert(mac, ip);
        self.ip_to_mac.insert(ip, mac);
    }

    /// Get the IP currently assigned to a MAC (if any — static or dynamic).
    pub fn lookup(&self, mac: &MacAddr) -> Option<Ipv4Addr> {
        // Check static first
        for (ip, res_mac) in &self.reserved {
            if res_mac == mac {
                return Some(*ip);
            }
        }
        self.active.get(mac).copied()
    }

    /// Total number of active dynamic allocations.
    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> IpPool {
        IpPool::new(
            Ipv4Addr::new(192, 168, 0, 100),
            Ipv4Addr::new(192, 168, 0, 105),
        )
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
    }

    #[test]
    fn allocates_first_available() {
        let mut p = pool();
        let ip = p.allocate(mac(1), None).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 100));
    }

    #[test]
    fn sticky_returns_same_ip() {
        let mut p = pool();
        let ip1 = p.allocate(mac(1), None).unwrap();
        let ip2 = p.allocate(mac(1), None).unwrap();
        assert_eq!(ip1, ip2, "same MAC should get same IP");
    }

    #[test]
    fn respects_requested_ip() {
        let mut p = pool();
        let requested = Ipv4Addr::new(192, 168, 0, 103);
        let ip = p.allocate(mac(1), Some(requested)).unwrap();
        assert_eq!(ip, requested);
    }

    #[test]
    fn skips_reserved_ips() {
        let mut p = pool();
        p.add_reservation(Ipv4Addr::new(192, 168, 0, 100), mac(99));
        let ip = p.allocate(mac(1), None).unwrap();
        assert_eq!(
            ip,
            Ipv4Addr::new(192, 168, 0, 101),
            "should skip reserved IP"
        );
    }

    #[test]
    fn static_reservation_wins() {
        let mut p = pool();
        let reserved_ip = Ipv4Addr::new(192, 168, 0, 2); // outside range
        p.add_reservation(reserved_ip, mac(5));
        let ip = p.allocate(mac(5), None).unwrap();
        assert_eq!(ip, reserved_ip, "static reservation should be returned");
    }

    #[test]
    fn release_frees_ip() {
        let mut p = pool();
        let ip = p.allocate(mac(1), None).unwrap();
        p.release(ip);
        let ip2 = p.allocate(mac(2), None).unwrap();
        assert_eq!(ip, ip2, "released IP should be reusable");
    }

    #[test]
    fn pool_exhaustion() {
        let mut p = pool(); // 6 IPs: .100-.105
        for i in 0..6 {
            assert!(p.allocate(mac(i), None).is_some());
        }
        assert!(
            p.allocate(mac(99), None).is_none(),
            "pool should be exhausted"
        );
    }
}
