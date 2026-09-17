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

pub struct EventBus {
    global: broadcast::Sender<TimedEvent>,
    system: broadcast::Sender<TimedEvent>,
    network: broadcast::Sender<TimedEvent>,
    device: broadcast::Sender<TimedEvent>,
    dns: broadcast::Sender<TimedEvent>,
    storage: broadcast::Sender<TimedEvent>,
    pppoe: broadcast::Sender<TimedEvent>,
    firewall: broadcast::Sender<TimedEvent>,
    traffic: broadcast::Sender<TimedEvent>,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        let (global, _) = broadcast::channel(1024);
        let (system, _) = broadcast::channel(256);
        let (network, _) = broadcast::channel(256);
        let (device, _) = broadcast::channel(512);
        let (dns, _) = broadcast::channel(512);
        let (storage, _) = broadcast::channel(128);
        let (pppoe, _) = broadcast::channel(128);
        let (firewall, _) = broadcast::channel(128);
        let (traffic, _) = broadcast::channel(128);
        Self {
            global,
            system,
            network,
            device,
            dns,
            storage,
            pppoe,
            firewall,
            traffic,
        }
    }

    /// Subscribes to the global event stream (receives all system events).
    #[must_use]
    pub fn subscribe(&self) -> Receiver<TimedEvent> {
        self.global.subscribe()
    }

    /// Subscribes exclusively to system lifecycle and ready events.
    #[must_use]
    pub fn subscribe_system(&self) -> Receiver<TimedEvent> {
        self.system.subscribe()
    }

    /// Subscribes exclusively to network interface, prefix, and discovery trigger events.
    #[must_use]
    pub fn subscribe_network(&self) -> Receiver<TimedEvent> {
        self.network.subscribe()
    }

    /// Subscribes exclusively to host device mutations and DHCP transactions.
    #[must_use]
    pub fn subscribe_device(&self) -> Receiver<TimedEvent> {
        self.device.subscribe()
    }

    /// Subscribes exclusively to DNS resolution, cache, and adblock events.
    #[must_use]
    pub fn subscribe_dns(&self) -> Receiver<TimedEvent> {
        self.dns.subscribe()
    }

    /// Subscribes exclusively to storage and database lifecycle events.
    #[must_use]
    pub fn subscribe_storage(&self) -> Receiver<TimedEvent> {
        self.storage.subscribe()
    }

    /// Subscribes exclusively to `PPPoE` connection and keepalive events.
    #[must_use]
    pub fn subscribe_pppoe(&self) -> Receiver<TimedEvent> {
        self.pppoe.subscribe()
    }

    /// Subscribes exclusively to firewall ruleset and dynamic port events.
    #[must_use]
    pub fn subscribe_firewall(&self) -> Receiver<TimedEvent> {
        self.firewall.subscribe()
    }

    /// Subscribes exclusively to traffic, NIC tuning, and SQM events.
    #[must_use]
    pub fn subscribe_traffic(&self) -> Receiver<TimedEvent> {
        self.traffic.subscribe()
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

    #[must_use]
    pub fn publish_timed(&self, event: TimedEvent) -> usize {
        // Dispatch to domain topic channel
        match &event.event {
            LanforgeEvent::System(SystemEvent::Shutdown) => {
                // Broadcast shutdown to every topic channel to unblock listeners immediately
                let _ = self.system.send(event.clone());
                let _ = self.network.send(event.clone());
                let _ = self.device.send(event.clone());
                let _ = self.dns.send(event.clone());
                let _ = self.storage.send(event.clone());
                let _ = self.pppoe.send(event.clone());
                let _ = self.firewall.send(event.clone());
                let _ = self.traffic.send(event.clone());
            }
            LanforgeEvent::System(SystemEvent::ConfigRaChanged) => {
                let _ = self.system.send(event.clone());
                let _ = self.network.send(event.clone());
            }
            LanforgeEvent::System(
                SystemEvent::ConfigDhcpV4Changed
                | SystemEvent::ConfigDhcpV6Changed
                | SystemEvent::ConfigDhcpOptionsChanged,
            ) => {
                let _ = self.system.send(event.clone());
                let _ = self.device.send(event.clone());
            }
            LanforgeEvent::System(_) => {
                let _ = self.system.send(event.clone());
            }
            LanforgeEvent::Network(_) => {
                let _ = self.network.send(event.clone());
            }
            LanforgeEvent::Device(_) => {
                let _ = self.device.send(event.clone());
            }
            LanforgeEvent::Dns(_) => {
                let _ = self.dns.send(event.clone());
            }
            LanforgeEvent::Storage(_) => {
                let _ = self.storage.send(event.clone());
            }
            LanforgeEvent::Pppoe(_) => {
                let _ = self.pppoe.send(event.clone());
                let _ = self.dns.send(event.clone());
            }
            LanforgeEvent::Firewall(_) => {
                let _ = self.firewall.send(event.clone());
            }
            LanforgeEvent::Traffic(_) => {
                let _ = self.traffic.send(event.clone());
            }
        }

        // Always publish to global bus for full stream receivers (SSE, CLI TUI, log buffers)
        self.global.send(event).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
