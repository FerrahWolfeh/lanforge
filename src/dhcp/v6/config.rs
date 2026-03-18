use std::net::Ipv6Addr;

#[derive(Clone, Debug)]
pub struct Dhcpv6Config {
    pub enabled: bool,
    pub iface: String,
    pub lease_time: u32,
    pub ula_prefix: Option<Ipv6Addr>,
}
