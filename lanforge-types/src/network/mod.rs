pub mod dns;
mod hostname;
mod ip;
mod neighbor;
pub mod subnet;

pub use dns::{
    DnsClass, DnsHeader, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordEntry,
    DnsRecordType, DnsResponseCode, QueryLogEntry, QueryResult, UpstreamHealthSnapshot,
};
pub use hostname::{Hostname, HostnameOrigin};
pub use ip::{IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix, classify_ip, classify_ipv6, is_ula};
pub use neighbor::NeighborEvent;
pub use subnet::{DnsReverseResolver, IpSubnet};
