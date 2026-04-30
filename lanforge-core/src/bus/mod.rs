//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.

pub mod device;
pub mod dns;
pub mod network;
pub mod storage;
pub mod system;
#[cfg(test)]
pub mod tests;

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self, Receiver};

pub use self::device::{DeviceChange, DeviceEvent};
pub use self::dns::DnsEvent;
pub use self::network::NetworkEvent;
pub use self::storage::StorageEvent;
pub use self::system::SystemEvent;

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    Device(DeviceEvent),
    Network(NetworkEvent),
    System(SystemEvent),
    Storage(StorageEvent),
    Dns(DnsEvent),
}

impl TimedEvent {
    #[must_use]
    pub const fn is_loggable(&self) -> bool {
        match &self.event {
            LanforgeEvent::Device(e) => match e {
                DeviceEvent::Discovered { .. }
                | DeviceEvent::Updated { .. }
                | DeviceEvent::Expired { .. }
                | DeviceEvent::Purged { .. }
                | DeviceEvent::LeaseRelease { .. }
                | DeviceEvent::LeaseRenew { .. } => true,
            },
            LanforgeEvent::Network(e) => match e {
                NetworkEvent::PrefixChanged { .. }
                | NetworkEvent::InterfaceUpdated { .. }
                | NetworkEvent::WolTriggered { .. }
                | NetworkEvent::RsReceived { .. }
                | NetworkEvent::ScanRequested
                | NetworkEvent::NeighborScanRequested
                | NetworkEvent::SubnetScanStarted { .. } => true,
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
                _ => false,
            },
        }
    }
}

pub struct EventBus {
    tx: broadcast::Sender<TimedEvent>,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { tx }
    }

    #[must_use]
    pub fn subscribe(&self) -> Receiver<TimedEvent> {
        self.tx.subscribe()
    }

    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.tx.send(TimedEvent::new(event)).unwrap_or(0)
    }

    #[must_use]
    pub fn publish_timed(&self, event: TimedEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
