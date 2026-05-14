use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::time::SystemTime;

pub mod device;
pub mod dns;
pub mod network;
pub mod storage;
pub mod system;

pub use self::device::{DeviceChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType};
pub use self::dns::DnsEvent;
pub use self::network::NetworkEvent;
pub use self::storage::StorageEvent;
pub use self::system::SystemEvent;

/// Reusable event collection that avoids heap allocation for the common case (up to 8 events).
pub type EventVec = SmallVec<[LanforgeEvent; 8]>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    pub event: LanforgeEvent,
    pub timestamp: SystemTime,
}

impl TimedEvent {
    #[must_use]
    pub fn new(event: LanforgeEvent) -> Self {
        Self {
            event,
            timestamp: SystemTime::now(),
        }
    }

    #[must_use]
    pub const fn is_loggable(&self) -> bool {
        match &self.event {
            LanforgeEvent::Device(e) => match e {
                DeviceEvent::Discovered { .. }
                | DeviceEvent::Updated { .. }
                | DeviceEvent::Expired { .. }
                | DeviceEvent::Purged { .. }
                | DeviceEvent::LeaseRelease { .. }
                | DeviceEvent::LeaseRenew { .. }
                | DeviceEvent::DhcpV4Transaction { .. }
                | DeviceEvent::DhcpV6Transaction { .. }
                | DeviceEvent::NeighborBatchSummary { .. } => true,
            },
            LanforgeEvent::Network(e) => match e {
                NetworkEvent::PrefixChanged { .. }
                | NetworkEvent::InterfaceUpdated { .. }
                | NetworkEvent::WolTriggered { .. }
                | NetworkEvent::RsReceived { .. }
                | NetworkEvent::ScanRequested
                | NetworkEvent::NeighborScanRequested
                | NetworkEvent::SubnetScanStarted { .. }
                | NetworkEvent::LeaseRenewRequested { .. }
                | NetworkEvent::LeaseReleaseRequested { .. } => true,
            },
            LanforgeEvent::System(e) => matches!(
                e,
                SystemEvent::ReloadConfig
                    | SystemEvent::ServiceReady { .. }
                    | SystemEvent::SystemReady
                    | SystemEvent::ConfigUpdate { .. }
            ),
            LanforgeEvent::Storage(e) => matches!(
                e,
                StorageEvent::DbVacuum | StorageEvent::DbLogClean | StorageEvent::DbPrune
            ),
            LanforgeEvent::Dns(e) => match e {
                #[cfg(feature = "adblock")]
                DnsEvent::AdblockToggle { .. } | DnsEvent::AdblockReload => true,
                DnsEvent::QueryResolved(_) => true,
                _ => false,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    Device(DeviceEvent),
    Network(NetworkEvent),
    System(SystemEvent),
    Storage(StorageEvent),
    Dns(DnsEvent),
}
