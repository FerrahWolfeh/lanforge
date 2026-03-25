use std::net::{Ipv6Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Upstream resolver (ex: Unbound em 127.0.0.1:5335).
    /// Se `None`, queries não-locais retornam REFUSED.
    pub upstream: Option<SocketAddr>,
    pub search_domain: String,
    pub ula_prefix: Option<Ipv6Addr>,
    pub ttl: u32,
    pub search_labels: Vec<Vec<u8>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "0.0.0.0:53".parse().unwrap(),
            upstream: None,
            search_domain: "lan".into(),
            ula_prefix: None,
            ttl: 60,
            search_labels: vec!["lan".into()],
        }
    }
}
