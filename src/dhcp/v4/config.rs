//! Configuração do servidor DHCPv4.

use std::net::Ipv4Addr;

/// Configuração do servidor DHCPv4 — construída a partir do TOML `[dhcp.v4]`.
#[derive(Debug, Clone)]
pub struct Dhcpv4Config {
    /// Interface LAN para escutar.
    pub iface: String,
    /// IP do servidor (nosso endereço na LAN — usado como server_id e siaddr).
    pub server_id: Ipv4Addr,
    /// Início do range dinâmico.
    pub range_start: Ipv4Addr,
    /// Fim do range dinâmico (inclusive).
    pub range_end: Ipv4Addr,
    /// Lease time em segundos.
    pub lease_time: u32,
    /// Default gateway anunciado aos clientes.
    pub router: Ipv4Addr,
    /// Servidores DNS anunciados.
    pub dns: Vec<Ipv4Addr>,
    /// Máscara de rede (default 255.255.255.0).
    pub subnet_mask: Ipv4Addr,
    /// Nome de domínio (opcional).
    pub domain_name: Option<String>,
}

impl Default for Dhcpv4Config {
    fn default() -> Self {
        Dhcpv4Config {
            iface: "end0".into(),
            server_id: Ipv4Addr::new(192, 168, 0, 1),
            range_start: Ipv4Addr::new(192, 168, 0, 100),
            range_end: Ipv4Addr::new(192, 168, 0, 254),
            lease_time: 86400,
            router: Ipv4Addr::new(192, 168, 0, 1),
            dns: vec![Ipv4Addr::new(192, 168, 0, 1)],
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            domain_name: None,
        }
    }
}
