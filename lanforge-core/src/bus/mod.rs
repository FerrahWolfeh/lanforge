//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.
//!
//! # Event Model
//!
//! The bus follows a **device-centric** model: events primarily describe changes
//! to the identity and state of discovery of network devices rather than low-level
//! protocol actions.
//!
//! # Architecture
//!
//! ```mermaid
//! sequenceDiagram
//!     participant Worker as Protocol Worker (DHCP/NDP)
//!     participant Ctx as LanforgeContext
//!     participant Bus as EventBus
//!     participant Handler as UI / Control Handler
//!
//!     Worker->>Ctx: apply(DeviceUpdate)
//!     Ctx->>Bus: publish(LanforgeEvent)
//!     Bus-->>Handler: Event Received
//!     Note right of Handler: UI updates or CLI notification
//! ```
//!
//! # Key Types
//!
//! - **[`EventBus`]**: The central broadcast channel (capacity: 256 events)
//! - **[`LanforgeEvent`]**: All possible events in the system
//! - **[`DeviceChange`]**: Detailed changes applied to a specific device
//! - **[`TimedEvent`]**: Event wrapper with timestamp and source module metadata
//!
//! # Event Categories
//!
//! | Category              | Events                                           |
//! |-----------------------|--------------------------------------------------|
//! | Device Lifecycle      | `DeviceDiscovered`, `DeviceUpdated`, `DeviceExpired`, `DevicePurged` |
//! | Infrastructure        | `PrefixChanged`, `InterfaceUpdated`, `ScanRequested` |
//! | System Control        | `Shutdown`, `ReloadConfig`, `DbVacuum`, `DbPrune` |
//! | Initialization        | `StateReady`, `DbReady`, `InterfaceReady`, `SystemReady` |
//! | Diagnostic            | `WolTriggered`, `LeaseRelease`, `LeaseRenew`     |

#[cfg(test)]
pub mod tests;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::SystemTime,
};

use tokio::sync::broadcast::{self, Receiver};

use crate::context::state::LeaseTarget;
use crate::identifiers::MacAddr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DeviceChange — o que mudou num device
// ---------------------------------------------------------------------------

/// Detailed changes applied to a specific `Device`.
///
/// Published within a [`LanforgeEvent::DeviceUpdated`] event on the bus.
/// Each variant represents a specific type of state change that UI components
/// or other listeners may care about.
///
/// # Change Types
///
/// | Variant                | Description                                  |
/// |------------------------|----------------------------------------------|
/// | `V4Assigned`           | IPv4 address assigned/renewed via `DHCPv4`     |
/// | `LeaseExpired`         | Dynamic lease expired and removed            |
/// | `V6Assigned`           | IPv6 address assigned/renewed via `DHCPv6`     |
/// | `HostRemoved`          | Device entirely removed from active table    |
/// | `V6PrefixAssigned`     | IPv6 prefix delegated via `DHCPv6-PD`          |
/// | `SlaacObserved`        | SLAAC address observed via `NDP`               |
/// | `SlaacSynced`          | Full SLAAC address synchronization           |
/// | `HostnameChanged`      | Hostname updated (DHCP hint, CLI, mDNS)      |
/// | `V4StaticChanged`      | Static IPv4 reservation modified             |
/// | `V6SuffixChanged`      | Static IPv6 suffix modified                  |
/// | `DuidAssociated`       | DUID linked to device's MAC                  |
/// | `NdpActivity`          | NDP neighbor observed (no SLAAC address)     |
/// | `ArpActivity`          | ARP neighbor observed (IPv4)                 |
/// | `StatusChanged`        | Device online/offline status changed         |
///
/// # Example
///
/// ```rust
/// use lanforge_core::bus::{DeviceChange, LanforgeEvent};
/// use lanforge_core::identifiers::MacAddr;
/// use std::net::Ipv4Addr;
///
/// // Checking for a specific change in an event
/// let change = DeviceChange::V4Assigned { ip: Ipv4Addr::new(192, 168, 1, 10) };
/// assert!(matches!(change, DeviceChange::V4Assigned { .. }));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceChange {
    /// An IPv4 address was assigned or renewed via `DHCPv4`.
    V4Assigned { ip: Ipv4Addr },

    /// A dynamic lease expired and was removed from the device.
    LeaseExpired { target: LeaseTarget },

    /// An IPv6 address was assigned or renewed via `DHCPv6`.
    V6Assigned { ip: Ipv6Addr, iaid: u32 },

    /// The device was entirely removed from the active table due to inactivity.
    HostRemoved,

    /// An IPv6 prefix was delegated to the device via `DHCPv6 Prefix Delegation` (`IA_PD`).
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

    /// A set of SLAAC addresses was synchronized for the device.
    SlaacSynced { addresses: Vec<Ipv6Addr> },

    /// The device's hostname was updated (e.g., via DHCP hint or CLI).
    HostnameChanged { hostname: String },

    /// A static IPv4 reservation was modified or removed via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// A static IPv6 Interface ID (suffix) was modified or removed via CLI.
    V6SuffixChanged {
        suffix: Option<crate::device::Ipv6AddrOrSuffix>,
    },

    /// A DUID was successfully associated with this device's MAC.
    DuidAssociated { duid: crate::identifiers::Duid },

    /// A neighbor was observed via NDP (IPv6) but no SLAAC address was extracted.
    NdpActivity { ip: Ipv6Addr },

    /// An IPv4 neighbor event (ARP) was observed.
    ArpActivity { ip: Ipv4Addr },

    /// The device's reachability status has changed.
    StatusChanged {
        online: bool,
        hostname: Option<String>,
    },
}

/// A wrapper for an event along with its metadata (timestamp, source module).
///
/// All events on the bus are wrapped in `TimedEvent` to enable:
/// - Temporal ordering for event replay and debugging
/// - Source attribution via the `module` field
/// - Loggability determination via [`is_loggable`](TimedEvent::is_loggable)
///
/// # Example
///
/// ```rust
/// use lanforge_core::bus::{TimedEvent, LanforgeEvent};
///
/// let event = TimedEvent::new(
///     LanforgeEvent::Shutdown,
///     Some("cli".to_string()),
/// );
/// assert!(event.module.as_deref() == Some("cli"));
/// assert!(!event.is_loggable()); // Internal signal
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    /// The actual event data.
    pub event: LanforgeEvent,
    /// When the event was created.
    pub timestamp: SystemTime,
    /// Optional identifier for the module that generated the event.
    pub module: Option<String>,
}

impl TimedEvent {
    /// Wraps a raw event with the current system time and an optional module label.
    #[must_use]
    pub fn new(event: LanforgeEvent, module: Option<String>) -> Self {
        Self {
            event,
            timestamp: SystemTime::now(),
            module,
        }
    }
}

// ---------------------------------------------------------------------------
// LanforgeEvent
// ---------------------------------------------------------------------------

/// All events that can be broadcast across the system bus.
///
/// This is the central event type for the entire Lanforge system. Protocol workers,
/// the CLI, and the UI all communicate by publishing and subscribing to these events.
///
/// # Event Categories
///
/// ## Device Lifecycle
/// Events related to network device discovery and state changes.
///
/// ## Infrastructure
/// Events about network interface configuration and scanning.
///
/// ## System Control
/// Administrative commands (shutdown, reload, maintenance).
///
/// ## Initialization
/// Readiness signals for system components (state, DB, interfaces).
///
/// ## Diagnostic
/// Manual triggers for debugging and maintenance operations.
///
/// # Loggability
///
/// Not all events are persisted to the log. Use [`TimedEvent::is_loggable()`]
/// to determine if an event should be written to the database.
/// Generally, internal coordination signals (e.g., `StateReady`, `DbReady`)
/// are not logged, while user-facing changes are.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    // -- Device lifecycle --
    /// A new device was discovered for the first time.
    DeviceDiscovered {
        mac: MacAddr,
        hostname: Option<String>,
    },
    /// An existing device's state was modified.
    DeviceUpdated {
        mac: MacAddr,
        hostname: Option<String>,
        change: DeviceChange,
    },
    /// A device was removed (typically because it was inactive for too long).
    DeviceExpired { mac: MacAddr },
    /// A device was explicitly purged from memory.
    DevicePurged { mac: MacAddr },

    // -- Infrastructure --
    /// The global IPv6 prefix has changed.
    ///
    /// This event is published when a router advertisement updates
    /// the local interface's GUA or ULA prefix.
    PrefixChanged {
        /// The new GUA prefix, if any.
        gua: Option<Ipv6Addr>,
        /// The new ULA prefix, if any.
        ula: Option<Ipv6Addr>,
        /// Preferred lifetime of the prefix (seconds).
        preferred: u32,
        /// Valid lifetime of the prefix (seconds).
        valid: u32,
    },
    /// A local network interface's IP configuration was updated.
    InterfaceUpdated { ifindex: u32 },
    /// Request an active mDNS network scan.
    ScanRequested,
    /// Request an active Neighbor Monitor subnet scan.
    NeighborScanRequested,
    /// A massive ARP subnet scan was started.
    SubnetScanStarted { subnet: String },

    // -- System Control --
    /// Notification that the underlying persistent table has changes that need flushing.
    DeviceTableDirty,
    /// Request the daemon to reload its configuration.
    ReloadConfig,
    /// Signal to trigger a `SQLite` database vacuum.
    DbVacuum,
    /// Request to clear all transient system logs.
    DbLogClean,
    /// Request to remove zombie entries from the database.
    DbPrune,
    /// Request to release a lease for a device.
    LeaseRelease { mac: MacAddr, target: LeaseTarget },
    /// Request to force-renew a lease for a device.
    LeaseRenew { mac: MacAddr, target: LeaseTarget },
    /// Signal the entire daemon to undergo a graceful shutdown.
    Shutdown,

    // -- Initialization & Lifecycle --
    /// Internal device table and static config are loaded.
    StateReady,
    /// Database worker is active and ready for persistence.
    DbReady,
    /// Network interfaces have been discovered and addresses are in the table.
    InterfaceReady,
    /// A specific service has completed its initialization.
    ServiceReady { name: String },
    /// Final signal indicating the entire system is operational.
    SystemReady,

    // -- Diagnostic --
    /// Request to send a Wake-on-LAN packet.
    WolTriggered {
        mac: MacAddr,
        /// Optional IP hint for unicast or directed broadcast.
        ip_hint: Option<Ipv4Addr>,
    },
}

impl TimedEvent {
    /// Returns true if this event represents a user-facing system activity
    /// that should be recorded in the persistent log history.
    #[must_use]
    pub const fn is_loggable(&self) -> bool {
        match &self.event {
            LanforgeEvent::DeviceDiscovered { .. }
            | LanforgeEvent::DeviceUpdated { .. }
            | LanforgeEvent::DeviceExpired { .. }
            | LanforgeEvent::PrefixChanged { .. }
            | LanforgeEvent::InterfaceUpdated { .. }
            | LanforgeEvent::LeaseRelease { .. }
            | LanforgeEvent::LeaseRenew { .. }
            | LanforgeEvent::DbVacuum
            | LanforgeEvent::DbLogClean
            | LanforgeEvent::DbPrune
            | LanforgeEvent::DevicePurged { .. }
            | LanforgeEvent::WolTriggered { .. }
            | LanforgeEvent::ReloadConfig
            | LanforgeEvent::ServiceReady { .. }
            | LanforgeEvent::SystemReady
            | LanforgeEvent::ScanRequested
            | LanforgeEvent::NeighborScanRequested
            | LanforgeEvent::SubnetScanStarted { .. } => true,

            // Internal signals or very high-frequency events
            LanforgeEvent::DeviceTableDirty
            | LanforgeEvent::Shutdown
            | LanforgeEvent::StateReady
            | LanforgeEvent::DbReady
            | LanforgeEvent::InterfaceReady => false,
        }
    }
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/// Internal bus capacity for the broadcast channel.
///
/// This limits the number of events that can be buffered before slow
/// subscribers start lagging. 256 is sufficient for typical Lanforge
/// workloads where events are consumed promptly.
const BUS_CAPACITY: usize = 256;

/// A thread-safe, shared event bus used for multi-component communication.
///
/// This is typically wrapped in an `Arc` and shared among protocol tasks.
/// It uses `tokio::sync::broadcast` under the hood, providing:
///
/// - **Multi-producer**: Any component can publish events
/// - **Multi-consumer**: Multiple subscribers can receive all events
/// - **Lossy**: Slow subscribers may miss events if the buffer fills up
///
/// # Example
///
/// ```rust
/// use lanforge_core::bus::EventBus;
/// use lanforge_core::bus::LanforgeEvent;
/// use std::sync::Arc;
///
/// let bus = Arc::new(EventBus::new());
/// let mut rx = bus.subscribe();
///
/// // Publish an event
/// bus.publish(LanforgeEvent::Shutdown);
///
/// // Receive it
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// if let Ok(timed) = rx.recv().await {
///     assert!(matches!(timed.event, LanforgeEvent::Shutdown));
/// }
/// # });
/// ```
///
/// # Publishing Methods
///
/// | Method                  | Description                              |
/// |-------------------------|------------------------------------------|
/// | `publish(event)`        | Publish with auto-timestamp, no module   |
/// | `publish_timed(event)`  | Publish pre-wrapped `TimedEvent`         |
/// | `publish_with_module()` | Publish with source module attribution   |
pub struct EventBus {
    tx: broadcast::Sender<TimedEvent>,
}

impl EventBus {
    /// Creates a new, initially empty event bus.
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Creates a new subscriber to receive events from the bus.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<TimedEvent> {
        self.tx.subscribe()
    }

    /// Publishes a new event to the bus.
    ///
    /// Returns the number of active subscribers who received the message.
    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.tx.send(TimedEvent::new(event, None)).unwrap_or(0)
    }

    /// Publishes a timed event directly (useful if module info is already known).
    #[must_use]
    pub fn publish_timed(&self, event: TimedEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// Publishes an event with a specific module source.
    #[must_use]
    pub fn publish_with_module(&self, event: LanforgeEvent, module: &str) -> usize {
        self.tx
            .send(TimedEvent::new(event, Some(module.to_string())))
            .unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
