//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.
//!
//! ## Event Model
//!
//! The bus follows a **device-centric** model: events primarily describe changes
//! to the identity and state of discovery of network devices rather than low-level
//! protocol actions.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant Worker as Protocol Worker (DHCP/NDP)
//!     participant Table as ManagedTable
//!     participant Bus as EventBus
//!     participant Handler as UI / Control Handler
//!
//!     Worker->>Table: update(DeviceUpdate)
//!     Table->>Bus: publish(LanforgeEvent)
//!     Bus-->>Handler: Event Received
//!     Note right of Handler: UI updates or CLI notification
//! ```

pub mod managed;
#[cfg(test)]
pub mod tests;

pub use managed::ManagedTable;

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::sync::broadcast;

use crate::identifiers::MacAddr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DeviceChange — o que mudou num device
// ---------------------------------------------------------------------------

/// Detailed changes applied to a specific `Device`.
///
/// Published within a [`LanforgeEvent::DeviceUpdated`] event on the bus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceChange {
    /// An IPv4 address was assigned or renewed via DHCPv4.
    V4Assigned { ip: Ipv4Addr },

    /// The IPv4 lease expired and was removed from the device.
    V4Expired,

    /// An IPv6 address was assigned or renewed via DHCPv6.
    V6Assigned { ip: Ipv6Addr, iaid: u32 },

    /// The DHCPv6 lease expired and was removed.
    V6Expired,

    /// An IPv6 prefix was delegated to the device via DHCPv6 Prefix Delegation (IA_PD).
    V6PrefixAssigned {
        /// The base prefix address.
        prefix: Ipv6Addr,
        /// The prefix length (e.g., 60, 64).
        len: u8,
        /// The Identity Association Identifier.
        iaid: u32,
    },

    /// A SLAAC address was observed via Neighbor Discovery (NDP).
    SlaacObserved { addr: Ipv6Addr },

    /// The device's hostname was updated (e.g., via DHCP hint or CLI).
    HostnameChanged { hostname: String },

    /// A static IPv4 reservation was modified or removed via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// A static IPv6 Interface ID (suffix) was modified or removed via CLI.
    V6SuffixChanged {
        suffix: Option<crate::device::Ipv6AddrOrSuffix>,
    },

    /// A DUID was successfully associated with this device's MAC.
    DuidAssociated,
}

// ---------------------------------------------------------------------------
// LanforgeEvent
// ---------------------------------------------------------------------------

/// All events that can be broadcast across the system bus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    // -- Device lifecycle --
    /// A new device was discovered for the first time.
    DeviceDiscovered { mac: MacAddr },
    /// An existing device's state was modified.
    DeviceUpdated { mac: MacAddr, change: DeviceChange },
    /// A device was removed (typically because it was inactive for too long).
    DeviceExpired { mac: MacAddr },

    // -- Infrastructure --
    /// The global IPv6 prefix has changed.
    PrefixChanged {
        /// The new GUA prefix, if any.
        gua: Option<Ipv6Addr>,
        /// Preferred lifetime of the prefix.
        preferred: u32,
        /// Valid lifetime of the prefix.
        valid: u32,
    },
    /// Request an active mDNS network scan.
    ScanRequested,

    // -- System Control --
    /// Notification that the underlying persistent table has changes that need flushing.
    DeviceTableDirty,
    /// Request the daemon to reload its configuration.
    ReloadConfig,
    /// Signal to trigger a SQLite database vacuum.
    DbVacuum,
    /// Request to release a lease for a device.
    LeaseRelease { mac: MacAddr },
    /// Request to force-renew a lease for a device.
    LeaseRenew { mac: MacAddr },
    /// Signal the entire daemon to undergo a graceful shutdown.
    Shutdown,
}

impl LanforgeEvent {
    /// Returns true if this event represents a user-facing system activity
    /// that should be recorded in the persistent log history.
    pub fn is_loggable(&self) -> bool {
        match self {
            LanforgeEvent::DeviceDiscovered { .. }
            | LanforgeEvent::DeviceUpdated { .. }
            | LanforgeEvent::DeviceExpired { .. }
            | LanforgeEvent::PrefixChanged { .. }
            | LanforgeEvent::LeaseRelease { .. }
            | LanforgeEvent::LeaseRenew { .. }
            | LanforgeEvent::DbVacuum
            | LanforgeEvent::ReloadConfig
            | LanforgeEvent::ScanRequested => true,

            // Internal signals or very high-frequency events
            LanforgeEvent::DeviceTableDirty | LanforgeEvent::Shutdown => false,
        }
    }
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/// Internal bus capacity for the broadcast channel.
const BUS_CAPACITY: usize = 256;

/// A thread-safe, shared event bus used for multi-component communication.
///
/// This is typically wrapped in an `Arc` and shared among protocol tasks.
pub struct EventBus {
    tx: broadcast::Sender<LanforgeEvent>,
}

impl EventBus {
    /// Creates a new, initially empty event bus.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Creates a new subscriber to receive events from the bus.
    pub fn subscribe(&self) -> broadcast::Receiver<LanforgeEvent> {
        self.tx.subscribe()
    }

    /// Publishes a new event to the bus.
    ///
    /// Returns the number of active subscribers who received the message.
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
