//! A static host: the part of a device the admin configures in `[hosts]`.

use std::net::Ipv4Addr;

use crate::device::{Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};
use crate::identifiers::MacAddr;

/// What `[hosts]` reserves for a device: its name, addresses and boot file. Everything else the
/// device table holds (leases, status, DUID, the `WebUI`'s DNS log settings, class) is not part
/// of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHost {
    pub mac: MacAddr,
    pub hostname: String,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6AddrOrSuffix>,
    pub boot_file: Option<String>,
}

impl Device {
    /// This device's reservation, if it is a static host.
    #[must_use]
    pub fn static_host(&self) -> Option<StaticHost> {
        (self.origin == Origin::Static).then(|| StaticHost {
            mac: self.mac,
            hostname: self.hostname.name.clone(),
            v4: match self.v4 {
                IPv4State::Static(ip) => Some(ip),
                _ => None,
            },
            v6: self.v6.iter().find_map(|s| match s {
                IPv6State::Static(v6, _) => Some(*v6),
                _ => None,
            }),
            boot_file: self.boot_file.clone(),
        })
    }
}
