//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.

#[cfg(test)]
pub mod tests;

pub use lanforge_types::events::{LanforgeEvent, TimedEvent};
use tokio::sync::broadcast::{self, Receiver};

pub use lanforge_types::events::{
    NetworkChange, AdminChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType, DnsEvent, EventVec,
    NetworkEvent, StorageEvent, SystemEvent,
};

pub struct EventBus {
    tx: broadcast::Sender<TimedEvent>,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    #[must_use]
    pub fn subscribe(&self) -> Receiver<TimedEvent> {
        self.tx.subscribe()
    }

    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        #[cfg(feature = "hotpath")]
        {
            #[allow(clippy::cast_precision_loss)]
            hotpath::gauge!("event_bus_receivers").set(self.tx.receiver_count() as f64);
        }
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
