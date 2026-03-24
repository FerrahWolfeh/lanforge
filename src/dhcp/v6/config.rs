use std::net::Ipv6Addr;

#[derive(Clone, Debug)]
pub struct Dhcpv6Config {
    pub enabled: bool,
    pub iface: String,
    pub lease_time: u32,
    pub ula_prefix: Option<Ipv6Addr>,
    pub ula_prefix_len: u8,
    pub range_start: Option<Ipv6Addr>,
    pub range_end: Option<Ipv6Addr>,
}
