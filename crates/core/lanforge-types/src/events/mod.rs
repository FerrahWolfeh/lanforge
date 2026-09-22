use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::time::SystemTime;

pub mod device;
pub mod dns;
pub mod firewall;
pub mod network;
pub mod pppoe;
pub mod storage;
pub mod system;
pub mod traffic;

pub use self::device::{
    AdminChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType, NetworkChange,
};
pub use self::dns::DnsEvent;
pub use self::firewall::{FirewallAppliedSummary, FirewallEvent};
pub use self::network::{NetworkEvent, PrefixChangeDetails};
pub use self::pppoe::{PppoeEvent, PppoeSessionUp};
pub use self::storage::StorageEvent;
pub use self::system::SystemEvent;
pub use self::traffic::TrafficEvent;

/// Reusable event collection that avoids heap allocation for the common case (up to 4 events).
pub type EventVec = SmallVec<[LanforgeEvent; 4]>;

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
                | DeviceEvent::NetworkUpdate { .. }
                | DeviceEvent::AdminUpdate { .. }
                | DeviceEvent::Expired { .. }
                | DeviceEvent::Purged { .. }
                | DeviceEvent::LeaseRelease { .. }
                | DeviceEvent::LeaseRenew { .. }
                | DeviceEvent::DhcpV4Transaction { .. }
                | DeviceEvent::DhcpV6Transaction { .. }
                | DeviceEvent::NeighborBatchSummary { .. } => true,
                DeviceEvent::NetworkActivity { .. } => false,
            },
            LanforgeEvent::Network(e) => match e {
                NetworkEvent::PrefixChanged(..)
                | NetworkEvent::InterfaceUpdated { .. }
                | NetworkEvent::WolTriggered { .. }
                | NetworkEvent::RsReceived { .. }
                | NetworkEvent::LeaseRenewRequested { .. }
                | NetworkEvent::LeaseReleaseRequested { .. }
                | NetworkEvent::RaTriggerRequested => true,

            },
            LanforgeEvent::System(e) => matches!(
                e,
                SystemEvent::ReloadConfig
                    | SystemEvent::ServiceReady { .. }
                    | SystemEvent::SystemReady
                    | SystemEvent::ConfigUpdate { .. }
                    | SystemEvent::ServiceStatusBanner(..)
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
            LanforgeEvent::Pppoe(_) | LanforgeEvent::Firewall(_) | LanforgeEvent::Traffic(_) => true,
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
    Pppoe(PppoeEvent),
    Firewall(FirewallEvent),
    Traffic(Box<TrafficEvent>),
}
