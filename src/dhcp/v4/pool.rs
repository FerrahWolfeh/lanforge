//! Alocador de endereços IP para o pool dinâmico DHCPv4.
//!
//! Gerencia o range configurável excluindo reservas estáticas.
//! Prioriza reutilizar o IP anteriormente atribuído ao mesmo MAC (sticky).

use std::collections::{HashMap, HashSet};
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
    /// IPs rejeitados por DECLINE (Quarentena para evitar loops infinitos)
    declined: HashSet<Ipv4Addr>,
}

impl IpPool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        IpPool {
            start: u32::from(start),
            end: u32::from(end),
            active: HashMap::new(),
            ip_to_mac: HashMap::new(),
            reserved: HashMap::new(),
            declined: HashSet::new(),
        }
    }

    /// Reserve a static IP for a MAC (excluded from dynamic allocation).
    pub fn add_reservation(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.reserved.insert(ip, mac);
    }

    /// Isola um IP problemático reportado via DECLINE.
    pub fn mark_declined(&mut self, ip: Ipv4Addr) {
        self.release(ip);
        self.declined.insert(ip);
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

        // 4. Scan Randomizado: escolhe um ponto de partida aleatório e varre o range de forma circular
        let size = self.end.saturating_sub(self.start) + 1;
        let start_offset = rand::random::<u32>() % size;

        for i in 0..size {
            let raw = self.start + ((start_offset + i) % size);
            let ip = Ipv4Addr::from(raw);
            if self.is_available(ip) {
                self.mark_used(ip, mac);
                return Some(ip);
            }
        }

        // 5. Fallback de emergência: Se o pool estiver esgotado mas a quarentena estiver cheia,
        // limpamos a quarentena e tentamos mais uma vez (alguém pode ter desligado o aparelho conflitante).
        if !self.declined.is_empty() {
            tracing::warn!(
                "[DHCPv4] Pool esgotado! Limpando quarentena de DECLINEs para tentar recuperar IPs..."
            );
            self.declined.clear();

            for i in 0..size {
                let raw = self.start + ((start_offset + i) % size);
                let ip = Ipv4Addr::from(raw);
                if self.is_available(ip) {
                    self.mark_used(ip, mac);
                    return Some(ip);
                }
            }
        }

        // 6. Pool realmente esgotado
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
        !self.ip_to_mac.contains_key(&ip)
            && !self.reserved.contains_key(&ip)
            && !self.declined.contains(&ip) // Não entrega IP de quarentena
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
    fn allocates_within_range() {
        let mut p = pool();
        let ip = p.allocate(mac(1), None).unwrap();
        assert!(
            p.is_in_range(ip),
            "O IP alocado randomicamente deve respeitar o range"
        );
    }

    #[test]
    fn sticky_returns_same_ip() {
        let mut p = pool();
        let ip1 = p.allocate(mac(1), None).unwrap();
        let ip2 = p.allocate(mac(1), None).unwrap();
        assert_eq!(ip1, ip2, "Mesmo MAC deve receber o mesmo IP (Sticky)");
    }

    #[test]
    fn respects_requested_ip() {
        let mut p = pool();
        let requested = Ipv4Addr::new(192, 168, 0, 103);
        let ip = p.allocate(mac(1), Some(requested)).unwrap();
        assert_eq!(
            ip, requested,
            "Deve respeitar o Requested IP se estiver livre"
        );
    }

    #[test]
    fn skips_reserved_and_declined_ips() {
        let mut p = pool(); // Range de 6 IPs (.100 a .105)

        let reserved_ip = Ipv4Addr::new(192, 168, 0, 100);
        let declined_ip = Ipv4Addr::new(192, 168, 0, 101);

        p.add_reservation(reserved_ip, mac(99));
        p.mark_declined(declined_ip);

        // Pedimos apenas 4 IPs (exatamente a quantidade de IPs realmente livres)
        // para não engatilhar o fallback de emergência de pool esgotado.
        for i in 0..4 {
            if let Some(ip) = p.allocate(mac(i), None) {
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
        let mut p = pool(); // Range de 6 IPs (.100 a .105)

        // Colocamos os 6 IPs em quarentena simulando uma rede problemática
        for i in 100..=105 {
            p.mark_declined(Ipv4Addr::new(192, 168, 0, i));
        }

        // O pool vai tentar achar um livre, ver que estão todos rejeitados,
        // limpar a quarentena e devolver o IP mesmo assim
        let rescued_ip = p.allocate(mac(1), None).unwrap();
        assert!(p.is_in_range(rescued_ip));
        assert!(
            p.declined.is_empty(),
            "A quarentena deve ter sido esvaziada por emergência"
        );
    }
}
