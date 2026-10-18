//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.

#[cfg(test)]
pub mod tests;

pub use lanforge_types::events::{LanforgeEvent, TimedEvent};
use tokio::sync::broadcast::{self, Receiver};

pub use lanforge_types::events::{
    AdminChange, DeviceEvent, DhcpV4MessageType, DhcpV6MessageType, DnsEvent, EventVec,
    FirewallEvent, NetworkChange, NetworkEvent, PppoeEvent, PrefixChangeDetails, StorageEvent,
    SystemEvent, TrafficEvent,
};

/// Domain-specific event topics for isolated subscriber channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum EventTopic {
    System = 0,
    Network = 1,
    Device = 2,
    Dns = 3,
    Storage = 4,
    Pppoe = 5,
    Firewall = 6,
    Traffic = 7,
}

impl EventTopic {
    pub const COUNT: usize = 8;
    pub const ALL: [Self; Self::COUNT] = [
        Self::System,
        Self::Network,
        Self::Device,
        Self::Dns,
        Self::Storage,
        Self::Pppoe,
        Self::Firewall,
        Self::Traffic,
    ];

    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

pub struct EventBus {
    global: broadcast::Sender<TimedEvent>,
    topics: [broadcast::Sender<TimedEvent>; EventTopic::COUNT],
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        let (global, _) = broadcast::channel(1024);
        let topics = [
            broadcast::channel(256).0, // System
            broadcast::channel(256).0, // Network
            broadcast::channel(512).0, // Device
            broadcast::channel(512).0, // Dns
            broadcast::channel(128).0, // Storage
            broadcast::channel(128).0, // Pppoe
            broadcast::channel(128).0, // Firewall
            broadcast::channel(128).0, // Traffic
        ];
        Self { global, topics }
    }

    /// Subscribes to the global event stream (receives all system events).
    #[must_use]
    pub fn subscribe(&self) -> Receiver<TimedEvent> {
        self.global.subscribe()
    }

    /// Subscribes to an explicit domain topic.
    #[must_use]
    pub fn subscribe_topic(&self, topic: EventTopic) -> Receiver<TimedEvent> {
        self.topics[topic.index()].subscribe()
    }

    /// Subscribes exclusively to system lifecycle and ready events.
    #[must_use]
    pub fn subscribe_system(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::System)
    }

    /// Subscribes exclusively to network interface, prefix, and discovery trigger events.
    #[must_use]
    pub fn subscribe_network(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Network)
    }

    /// Subscribes exclusively to host device mutations and DHCP transactions.
    #[must_use]
    pub fn subscribe_device(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Device)
    }

    /// Subscribes exclusively to DNS resolution, cache, and adblock events.
    #[must_use]
    pub fn subscribe_dns(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Dns)
    }

    /// Subscribes exclusively to storage and database lifecycle events.
    #[must_use]
    pub fn subscribe_storage(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Storage)
    }

    /// Subscribes exclusively to `PPPoE` connection and keepalive events.
    #[must_use]
    pub fn subscribe_pppoe(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Pppoe)
    }

    /// Subscribes exclusively to firewall ruleset and dynamic port events.
    #[must_use]
    pub fn subscribe_firewall(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Firewall)
    }

    /// Subscribes exclusively to traffic, NIC tuning, and SQM events.
    #[must_use]
    pub fn subscribe_traffic(&self) -> Receiver<TimedEvent> {
        self.subscribe_topic(EventTopic::Traffic)
    }

    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        #[cfg(feature = "hotpath")]
        {
            #[allow(clippy::cast_precision_loss)]
            hotpath::gauge!("event_bus_receivers").set(self.global.receiver_count() as f64);
        }
        self.publish_timed(TimedEvent::new(event))
    }

    #[inline]
    fn send_if_subscribed(tx: &broadcast::Sender<TimedEvent>, event: &TimedEvent) {
        if tx.receiver_count() > 0 {
            let _ = tx.send(event.clone());
        }
    }

    #[inline]
    fn send_topic(&self, topic: EventTopic, event: &TimedEvent) {
        Self::send_if_subscribed(&self.topics[topic.index()], event);
    }

    #[must_use]
    pub fn publish_timed(&self, event: TimedEvent) -> usize {
        // Dispatch to domain topic channel only when receivers exist
        match &event.event {
            LanforgeEvent::System(SystemEvent::Shutdown) => {
                for topic in EventTopic::ALL {
                    self.send_topic(topic, &event);
                }
            }
            LanforgeEvent::System(SystemEvent::ConfigRaChanged) => {
                self.send_topic(EventTopic::System, &event);
                self.send_topic(EventTopic::Network, &event);
            }
            LanforgeEvent::System(
                SystemEvent::ConfigDhcpV4Changed
                | SystemEvent::ConfigDhcpV6Changed
                | SystemEvent::ConfigDhcpOptionsChanged,
            ) => {
                self.send_topic(EventTopic::System, &event);
                self.send_topic(EventTopic::Device, &event);
            }
            LanforgeEvent::System(_) => {
                self.send_topic(EventTopic::System, &event);
            }
            LanforgeEvent::Network(_) => {
                self.send_topic(EventTopic::Network, &event);
            }
            LanforgeEvent::Device(_) => {
                self.send_topic(EventTopic::Device, &event);
            }
            LanforgeEvent::Dns(_) => {
                self.send_topic(EventTopic::Dns, &event);
            }
            LanforgeEvent::Storage(_) => {
                self.send_topic(EventTopic::Storage, &event);
            }
            LanforgeEvent::Pppoe(_) => {
                self.send_topic(EventTopic::Pppoe, &event);
                self.send_topic(EventTopic::Dns, &event);
            }
            LanforgeEvent::Firewall(_) => {
                self.send_topic(EventTopic::Firewall, &event);
            }
            LanforgeEvent::Traffic(_) => {
                self.send_topic(EventTopic::Traffic, &event);
            }
        }

        if self.global.receiver_count() > 0 {
            self.global.send(event).unwrap_or(0)
        } else {
            0
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
