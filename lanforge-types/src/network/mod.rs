mod dns;
mod hostname;
mod ip;
mod neighbor;

pub use dns::{DnsRecordEntry, UpstreamHealthSnapshot};
pub use hostname::{Hostname, HostnameOrigin};
pub use ip::{IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix, classify_ip, classify_ipv6, is_ula};
pub use neighbor::NeighborEvent;
