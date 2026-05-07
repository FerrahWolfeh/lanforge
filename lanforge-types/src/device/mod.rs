mod core;
mod state;
mod topology;

pub use core::{Device, DeviceClass, LearningMethod, Origin};
pub use state::{IPv4State, IPv6State, V4Lease, V6Lease, V6ObservationOrigin, V6PrefixLease};
pub use topology::TopologyInfo;

// Re-exports for backward compatibility
pub use crate::network::{
    Hostname, HostnameOrigin, IpClassification, Ipv6AddrOrSuffix, classify_ip, classify_ipv6,
};
