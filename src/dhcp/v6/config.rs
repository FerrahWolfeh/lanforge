#[derive(Clone, Debug)]
pub struct Dhcpv6Config {
    pub enabled: bool,
    pub iface: String,
    pub lease_time: u32,
    // Note: dnsmasq ULA configuration is mostly statically handled per-device
    // dynamic allocation range will be extracted from RA auto_gua or ula configs
}
