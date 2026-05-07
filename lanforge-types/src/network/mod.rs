mod hostname;
mod ip;
mod neighbor;

pub use hostname::{Hostname, HostnameOrigin};
pub use ip::{
    classify_ip, classify_ipv6, is_ula, IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix,
};
pub use neighbor::NeighborEvent;
