pub mod device;
pub mod events;
pub mod identifiers;
pub mod network;
pub mod update;
pub mod utils;

// Compatibility aliases
pub use network as ndp;
pub use update as updates;

// Re-exports for convenience
pub use crate::device::{
    Device, DeviceClass, IPv4State, IPv6State, LearningMethod, Origin, TopologyInfo, V4Lease,
    V6Lease, V6ObservationOrigin, V6PrefixLease,
};
pub use crate::events::{
    DeviceChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType, DnsEvent, LanforgeEvent,
    NetworkEvent, StorageEvent, SystemEvent, TimedEvent,
};
pub use crate::identifiers::{Duid, MacAddr};
pub use crate::network::{
    DnsRecordEntry, Hostname, HostnameOrigin, IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix,
    NeighborEvent, UpstreamHealthSnapshot, classify_ip, classify_ipv6,
};
pub use crate::update::{CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget};
pub use crate::utils::network::{
    compute_eui64_ip, ip_matches_prefix, is_slaac_iid, mac_from_eui64_link_local,
};
