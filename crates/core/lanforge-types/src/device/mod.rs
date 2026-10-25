pub mod core;
pub mod identity;
pub mod state;
pub mod transient;

pub use core::{Device, DeviceClass, DeviceStatus, LearningMethod, Origin};
pub use identity::DeviceIdentity;
pub use state::{
    IPv4State, IPv6State, LeaseKind, V4Lease, V6Kind, V6Lease, V6ObservationOrigin, V6PrefixLease,
};
pub use transient::{TransientHost, TransientOrigin};

// Re-exports for backward compatibility
pub use crate::network::{
    Hostname, HostnameOrigin, IpClassification, Ipv6AddrOrSuffix, Ipv6Suffix, classify_ip,
    classify_ipv6,
};
