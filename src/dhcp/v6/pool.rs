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

    /// Remove a static reservation for a MAC.
    pub fn remove_reservation(&mut self, mac: MacAddr) {
        self.reserved.retain(|_, m| *m != mac);
    }

    /// Constructs a static IPv6 address given a device's configured suffix and the network's ULA prefix.
    #[allow(dead_code)]
    pub fn construct_static_ula(&self, suffix: &str) -> Option<Ipv6Addr> {
        let ula = self.ula_prefix?;
        let clean_suffix = suffix.strip_prefix("::").unwrap_or(suffix);
        let ula_segs = ula.segments();
        let suffix_ip: Ipv6Addr = format!("::{clean_suffix}").parse().ok()?;
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
        // 1. Verificação de reserva estática (Configurada no TOML)
        for (ip, res_mac) in &self.reserved {
            if *res_mac == mac {
                return Some(*ip);
            }
        }

        // 2. IP "Sticky" (Reutiliza a alocação ativa atual para este MAC)
        if let Some(ip) = self.active.get(&mac) {
            return Some(*ip);
        }

        // 3. Pool Dinâmico Restrito (Sequencial) - Se range_start e range_end existirem
        if let (Some(start), Some(end)) = (self.range_start, self.range_end) {
            let start_int = u128::from_be_bytes(start.octets());
            let end_int = u128::from_be_bytes(end.octets());

            // Tenta o IP requisitado primeiro, respeitando os limites e a disponibilidade
            if let Some(req) = requested {
                let req_int = u128::from_be_bytes(req.octets());
                if req_int >= start_int && req_int <= end_int && self.is_available(&req) {
                    self.mark_used(req, mac);
                    return Some(req);
                }
            }

            // Alocação sequencial
            for raw in start_int..=end_int {
                let ip = Ipv6Addr::from(raw.to_be_bytes());
                if self.is_available(&ip) {
                    self.mark_used(ip, mac);
                    return Some(ip);
                }
            }
        }
        // 4. Opaque / Randomized IID (RFC 7943) - Se o range for omitido mas tivermos um ULA
        else if let Some(ula) = self.ula_prefix {
            let ula_segs = ula.segments();

            // O cliente pediu um IP específico? Se bater com o /64 do nosso ULA e estiver livre, aceitamos.
            if let Some(req) = requested {
                let req_segs = req.segments();
                if req_segs[0..4] == ula_segs[0..4] && self.is_available(&req) {
                    self.mark_used(req, mac);
                    return Some(req);
                }
            }

            // Gera um sufixo IID (Interface Identifier) de 64 bits de forma puramente aleatória.
            // Executamos num laço de até 10 tentativas para garantir que, na chance astronomicamente
            // remota de colisão no cache, o event-loop não trave tentando infinitamente.
            for _ in 0..10 {
                let ip = Ipv6Addr::new(
                    ula_segs[0],
                    ula_segs[1],
                    ula_segs[2],
                    ula_segs[3], // Mantém a rede
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(), // Sorteia o host
                );

                if self.is_available(&ip) {
                    self.mark_used(ip, mac);
                    return Some(ip);
                }
            }
        }

        // Pool esgotado ou prefixo omitido nas configurações
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

    pub fn release_mac(&mut self, mac: MacAddr) {
        if let Some(ip) = self.active.remove(&mac) {
            self.ip_to_mac.remove(&ip);
        }
        self.remove_reservation(mac);
    }

    fn mark_used(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.release_mac(mac);
        self.active.insert(mac, ip);
        self.ip_to_mac.insert(ip, mac);
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv6Addr> {
        for (ip, res_mac) in &self.reserved {
            if *res_mac == mac {
                return Some(*ip);
            }
        }
        self.active.get(&mac).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Função auxiliar para gerar MACs nos testes
    fn mac(last_byte: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last_byte])
    }

    #[test]
    fn test_construct_static_ula() {
        let ula = "fd12:3456:7890:abcd::".parse().ok();
        let pool = Ipv6Pool::new(None, None, ula);

        let res = pool.construct_static_ula("::1111:2222:3333:4444").unwrap();
        assert_eq!(res.to_string(), "fd12:3456:7890:abcd:1111:2222:3333:4444");

        let res2 = pool.construct_static_ula("::cafe:babe").unwrap();
        assert_eq!(res2.to_string(), "fd12:3456:7890:abcd::cafe:babe");
    }

    #[test]
    fn test_dynamic_allocation_sequential() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::102".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None);

        assert_eq!(
            pool.allocate(mac(1), None).unwrap().to_string(),
            "fd00::100"
        );
        assert_eq!(
            pool.allocate(mac(2), None).unwrap().to_string(),
            "fd00::101"
        );
        assert_eq!(
            pool.allocate(mac(3), None).unwrap().to_string(),
            "fd00::102"
        );

        // Pool esgotado
        assert!(pool.allocate(mac(4), None).is_none());
    }

    #[test]
    fn test_dynamic_allocation_opaque_random() {
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        // Sem limites de range definidos, apenas o ULA
        let mut pool = Ipv6Pool::new(None, None, Some(ula));

        let ip1 = pool.allocate(mac(1), None).unwrap();
        let ip2 = pool.allocate(mac(2), None).unwrap();

        // Garante que a rede /64 está correta
        let ula_segs = ula.segments();
        assert_eq!(ip1.segments()[0..4], ula_segs[0..4]);
        assert_eq!(ip2.segments()[0..4], ula_segs[0..4]);

        // A chance de colisão nos 64 bits de host é estatisticamente nula
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_requested_ip_sequential() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::200".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None);

        // Pedido válido dentro do range
        let requested = "fd00::150".parse().unwrap();
        let ip = pool.allocate(mac(1), Some(requested)).unwrap();
        assert_eq!(ip, requested);

        // Pedido fora do range ignora o request e pega o primeiro livre
        let out_of_bounds = "fd00::250".parse().unwrap();
        let ip2 = pool.allocate(mac(2), Some(out_of_bounds)).unwrap();
        assert_eq!(ip2.to_string(), "fd00::100");
    }

    #[test]
    fn test_requested_ip_opaque() {
        let ula: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula));

        // Cliente envia hint de um IP opaco que ele já usou
        let requested = "fd97:f00d:cafe:3731:1234:5678:9abc:def0".parse().unwrap();
        let ip = pool.allocate(mac(1), Some(requested)).unwrap();
        assert_eq!(ip, requested);

        // Cliente pede um IP de outra rede (ex: GUA antigo) -> ignora e gera um novo random
        let wrong_net: Ipv6Addr = "2001:db8::1234".parse().unwrap();
        let ip2 = pool.allocate(mac(2), Some(wrong_net)).unwrap();
        assert_ne!(ip2, wrong_net);
        assert_eq!(ip2.segments()[0..4], ula.segments()[0..4]);
    }

    #[test]
    fn test_sticky_allocation() {
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula));

        let ip1 = pool.allocate(mac(1), None).unwrap();
        let ip2 = pool.allocate(mac(1), None).unwrap(); // Mesmo MAC pedindo de novo

        // Deve retornar exatamente o mesmo IP
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_static_reservation() {
        let ula = "fd00::".parse().unwrap();
        let mut pool = Ipv6Pool::new(None, None, Some(ula));

        let static_ip = "fd00::cafe".parse().unwrap();
        pool.add_reservation(static_ip, mac(1));

        // Cliente pode até pedir outra coisa, mas o estático prevalece
        let requested = "fd00::babe".parse().unwrap();
        let ip = pool.allocate(mac(1), Some(requested)).unwrap();
        assert_eq!(ip, static_ip);
    }

    #[test]
    fn test_release() {
        let start = "fd00::100".parse().unwrap();
        let end = "fd00::100".parse().unwrap();
        let mut pool = Ipv6Pool::new(Some(start), Some(end), None);

        let ip1 = pool.allocate(mac(1), None).unwrap();
        assert!(pool.allocate(mac(2), None).is_none()); // Esgotado

        pool.release(&ip1);

        let ip2 = pool.allocate(mac(2), None).unwrap(); // Liberou, o MAC 2 consegue pegar
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_add_remove_reservation() {
        let ula = "fd00::".parse().unwrap();
        let mut p = Ipv6Pool::new(None, None, Some(ula));
        let mac = mac(1);
        let ip = "fd00::cafe".parse().unwrap();

        p.add_reservation(ip, mac);
        assert_eq!(p.lookup(mac), Some(ip));

        p.remove_reservation(mac);
        assert_eq!(p.lookup(mac), None);
    }
}
