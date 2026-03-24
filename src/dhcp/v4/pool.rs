use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::state::MacAddr;

/// Representação de uma alocação ativa.
#[derive(Debug, Clone)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub expiry: SystemTime,
}

/// Pool de endereços IPv4 com alocação dinâmica.
pub struct IpPool {
    /// Range start (inclusive).
    start: u32,
    /// Range end (inclusive).
    end: u32,
    /// MAC → Lease: alocações ativas (dinâmicas).
    active: HashMap<MacAddr, Lease>,
    /// IP → MAC: índice reverso para lookup rápido de alocações dinâmicas.
    ip_to_mac: HashMap<Ipv4Addr, MacAddr>,
    /// IPs reservados (estáticos) — excluídos do pool dinâmico.
    reserved: HashMap<Ipv4Addr, MacAddr>,
    /// MAC → IP: índice para lookup O(1) de reservas por MAC.
    mac_to_reserved: HashMap<MacAddr, Ipv4Addr>,
    /// IPs rejeitados por DECLINE (Quarentena com timestamp)
    declined: HashMap<Ipv4Addr, SystemTime>,
    /// Pool de IPs livres para alocação circular/rápida O(1).
    available_ips: Vec<Ipv4Addr>,
    /// Mapeia o IP para sua posição no vetor available_ips pra remoção O(1).
    ip_to_index: HashMap<Ipv4Addr, usize>,
}

impl IpPool {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let s = u32::from(start);
        let e = u32::from(end);
        let size = (u64::from(e) - u64::from(s) + 1) as usize;

        let mut available_ips = Vec::with_capacity(size);
        let mut ip_to_index = HashMap::with_capacity(size);

        for i in 0..size {
            let ip = Ipv4Addr::from(s + i as u32);
            available_ips.push(ip);
            ip_to_index.insert(ip, i);
        }

        Self {
            start: s,
            end: e,
            active: HashMap::new(),
            ip_to_mac: HashMap::new(),
            reserved: HashMap::new(),
            mac_to_reserved: HashMap::new(),
            declined: HashMap::new(),
            available_ips,
            ip_to_index,
        }
    }

    /// Reserve a static IP for a MAC (excluded from dynamic allocation).
    pub fn add_reservation(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if let Some(old_mac) = self.ip_to_mac.get(&ip).copied() {
            self.active.remove(&old_mac);
        }
        self.ip_to_mac.insert(ip, mac); // Atualiza índice pro novo dono

        self.reserved.insert(ip, mac);
        self.mac_to_reserved.insert(mac, ip);
        self.remove_from_available(ip);
    }

    /// Remove a static reservation for a MAC.
    pub fn remove_reservation(&mut self, mac: MacAddr) {
        if let Some(ip) = self.mac_to_reserved.remove(&mac) {
            self.reserved.remove(&ip);
            // IP agora pode voltar ao pool dinâmico, se for do range
            if self.is_in_range(ip) {
                self.add_to_available(ip);
            }
        }
    }

    /// Isola um IP problemático reportado via DECLINE.
    pub fn mark_declined(&mut self, ip: Ipv4Addr) {
        self.release(ip);
        self.declined.insert(ip, SystemTime::now());
        self.remove_from_available(ip);
    }

    /// Limpa leases e quarentenas que expiraram.
    pub fn cleanup_expired_leases(&mut self, now: SystemTime) {
        // 1. Cleanup Leases
        let expired_leases: Vec<Ipv4Addr> = self
            .active
            .values()
            .filter(|l| l.expiry <= now)
            .map(|l| l.ip)
            .collect();

        for ip in expired_leases {
            tracing::info!("[DHCPv4] Lease for {ip} expired, returning to pool.");
            self.release(ip);
        }

        // 2. Cleanup Quarantine (DECLINEs) - Recupera IPs após 2 horas
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
            if self.is_in_range(ip) && !self.reserved.contains_key(&ip) {
                self.add_to_available(ip);
            }
        }
    }

    /// Allocate an IP for a MAC address.
    pub fn allocate(
        &mut self,
        mac: MacAddr,
        requested: Option<Ipv4Addr>,
        expiry: SystemTime,
    ) -> Option<Ipv4Addr> {
        // 1. Check static reservation (O(1))
        if let Some(ip) = self.mac_to_reserved.get(&mac) {
            return Some(*ip);
        }

        // 2. Sticky: already has a dynamic allocation
        if let Some(lease) = self.active.get_mut(&mac) {
            lease.expiry = expiry; // Estende o lease
            return Some(lease.ip);
        }

        // 3. Try the requested IP if it's free and in range
        if let Some(req) = requested
            && self.is_in_range(req)
            && self.is_available_in_pool(req)
        {
            self.mark_used(req, mac, expiry);
            return Some(req);
        }

        // 4. Fallback: Pick from available pool (O(1))
        if let Some(ip) = self.available_ips.last().copied() {
            self.mark_used(ip, mac, expiry);
            return Some(ip);
        }

        // 5. Pool esgotado: Tentamos limpar expired leases agora mesmo pra ver se libera algo
        self.cleanup_expired_leases(SystemTime::now());
        if let Some(ip) = self.available_ips.last().copied() {
            self.mark_used(ip, mac, expiry);
            return Some(ip);
        }

        // 6. Fallback de emergência: DECLINEs
        if !self.declined.is_empty() {
            tracing::warn!("[DHCPv4] Pool esgotado! Recuperando IPs de quarentena (DECLINEs)...");
            let declined_list: Vec<Ipv4Addr> = self.declined.keys().copied().collect();
            self.declined.clear();
            for ip in declined_list {
                self.add_to_available(ip);
            }

            if let Some(ip) = self.available_ips.last().copied() {
                self.mark_used(ip, mac, expiry);
                return Some(ip);
            }
        }

        None
    }

    /// Release a dynamic allocation.
    pub fn release(&mut self, ip: Ipv4Addr) {
        if let Some(mac) = self.ip_to_mac.remove(&ip) {
            self.active.remove(&mac);
            if self.is_in_range(ip) && !self.reserved.contains_key(&ip) {
                self.add_to_available(ip);
            }
        }
    }

    /// Release all allocations and reservations for a MAC.
    pub fn release_mac(&mut self, mac: MacAddr) {
        if let Some(lease) = self.active.remove(&mac) {
            self.ip_to_mac.remove(&lease.ip);
            if self.is_in_range(lease.ip) && !self.reserved.contains_key(&lease.ip) {
                self.add_to_available(lease.ip);
            }
        }
        self.remove_reservation(mac);
    }

    /// Check if an IP is in the dynamic available pool.
    fn is_available_in_pool(&self, ip: Ipv4Addr) -> bool {
        self.ip_to_index.contains_key(&ip)
    }

    /// Check if an IP is within the dynamic range.
    fn is_in_range(&self, ip: Ipv4Addr) -> bool {
        let raw = u32::from(ip);
        raw >= self.start && raw <= self.end
    }

    /// Mark an IP as used by a MAC.
    fn mark_used(&mut self, ip: Ipv4Addr, mac: MacAddr, expiry: SystemTime) {
        self.remove_from_available(ip);
        self.active.insert(mac, Lease { ip, expiry });
        self.ip_to_mac.insert(ip, mac);
    }

    /// Get the IP currently assigned to a MAC (if any — static or dynamic).
    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.mac_to_reserved
            .get(&mac)
            .copied()
            .or_else(|| self.active.get(&mac).map(|l| l.ip))
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
            // Swap-remove para manter O(1)
            let last_idx = self.available_ips.len() - 1;
            if idx != last_idx {
                let swapped_ip = self.available_ips[last_idx];
                self.available_ips.swap(idx, last_idx);
                self.ip_to_index.insert(swapped_ip, idx);
            }
            self.available_ips.pop();
        }
    }

    /// Total number of active dynamic allocations.
    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let ip = p.allocate(mac(1), None, expiry).unwrap();
        assert!(
            p.is_in_range(ip),
            "O IP alocado randomicamente deve respeitar o range"
        );
    }

    #[test]
    fn sticky_returns_same_ip() {
        let mut p = pool();
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let ip1 = p.allocate(mac(1), None, expiry).unwrap();
        let ip2 = p.allocate(mac(1), None, expiry).unwrap();
        assert_eq!(ip1, ip2, "Mesmo MAC deve receber o mesmo IP (Sticky)");
    }

    #[test]
    fn respects_requested_ip() {
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
        let mut p = pool(); // Range de 6 IPs (.100 a .105)

        let reserved_ip = Ipv4Addr::new(192, 168, 0, 100);
        let declined_ip = Ipv4Addr::new(192, 168, 0, 101);

        p.add_reservation(reserved_ip, mac(99));
        p.mark_declined(declined_ip);

        // Pedimos apenas 4 IPs (exatamente a quantidade de IPs realmente livres)
        // para não engatilhar o fallback de emergência de pool esgotado.
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        for i in 0..4 {
            if let Some(ip) = p.allocate(mac(i), None, expiry) {
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
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        let rescued_ip = p.allocate(mac(1), None, expiry).unwrap();
        assert!(p.is_in_range(rescued_ip));
        assert!(
            p.declined.is_empty(),
            "A quarentena deve ter sido esvaziada por emergência"
        );
    }

    #[test]
    fn test_add_remove_reservation() {
        let mut p = pool();
        let mac = mac(1);
        let ip = Ipv4Addr::new(192, 168, 0, 100);

        p.add_reservation(ip, mac);
        assert_eq!(p.lookup(mac), Some(ip));

        p.remove_reservation(mac);
        assert_eq!(p.lookup(mac), None);
    }
    #[test]
    fn test_cleanup_expired_leases() {
        let mut p = pool();
        let mac = mac(1);
        let expiry = SystemTime::now() - Duration::from_secs(10); // Já expirado
        p.allocate(mac, None, expiry).unwrap();
        assert_eq!(p.active_count(), 1);

        p.cleanup_expired_leases(SystemTime::now());
        assert_eq!(p.active_count(), 0);
    }

    #[test]
    fn test_cleanup_declined_quarantine() {
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
        p.cleanup_expired_leases(SystemTime::now());
        assert!(p.available_ips.is_empty());

        // 3. Simula 3 horas no futuro
        let three_hours_later = SystemTime::now() + Duration::from_secs(3 * 3600);
        p.cleanup_expired_leases(three_hours_later);

        // 4. Deve ter recuperado o IP
        assert_eq!(p.available_ips.len(), 1);
        assert_eq!(p.available_ips[0], ip);
        assert!(p.declined.is_empty());
    }
}
