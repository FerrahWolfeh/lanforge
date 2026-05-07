pub mod device;
pub mod events;
pub mod identifiers;
pub mod ndp;
pub mod updates;
pub mod utils;

// Re-exports for convenience
pub use crate::device::{
    Device, DeviceClass, Hostname, HostnameOrigin, IPv4State, IPv6State, IpClassification,
    Ipv6AddrOrSuffix, LearningMethod, Origin, V6ObservationOrigin, classify_ip, classify_ipv6,
};
pub use crate::events::{
    DeviceChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType, DnsEvent, LanforgeEvent,
    NetworkEvent, StorageEvent, SystemEvent, TimedEvent,
};
pub use crate::identifiers::{Duid, MacAddr};
pub use crate::updates::{CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget};
