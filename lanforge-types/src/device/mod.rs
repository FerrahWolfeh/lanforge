pub mod core;
pub mod history;
pub mod state;
pub mod topology;

pub use history::{LeaseAction, LeaseHistoryEntry, LeaseKind};

pub use core::{Device, DeviceClass, LearningMethod, Origin};
pub use state::{IPv4State, IPv6State, V4Lease, V6Lease, V6ObservationOrigin, V6PrefixLease};
pub use topology::TopologyInfo;

// Re-exports for backward compatibility
pub use crate::network::{
    Hostname, HostnameOrigin, IpClassification, Ipv6AddrOrSuffix, classify_ip, classify_ipv6,
};
