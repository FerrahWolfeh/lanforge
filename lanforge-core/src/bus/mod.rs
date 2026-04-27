//! `EventBus` — The internal event communication system for Lanforge.
//!
//! This module uses `tokio::sync::broadcast` to provide a thread-safe,
//! multi-producer multi-consumer event bus.

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
        prefix: Ipv6Addr,
        len: u8,
        iaid: u32,
    },

    /// A SLAAC address was observed via Neighbor Discovery (NDP).
    SlaacObserved { addr: Ipv6Addr },

    /// The device's reachability status has changed.
    StatusChanged {
        online: bool,
        hostname: Option<String>,
    },

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

    /// The device has been classified into a high-level category (e.g., Printer).
    Classified { class: crate::device::DeviceClass },
    /// The device's physical or logical topology has changed.
    TopologyChanged {
        parent_mac: Option<MacAddr>,
        port: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    pub event: LanforgeEvent,
    pub timestamp: SystemTime,
    pub module: Option<String>,
}

impl TimedEvent {
    #[must_use]
    pub fn new(event: LanforgeEvent, module: Option<String>) -> Self {
        Self {
            event,
            timestamp: SystemTime::now(),
            module,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    DeviceDiscovered {
        mac: MacAddr,
        hostname: Option<String>,
    },
    DeviceUpdated {
        mac: MacAddr,
        hostname: Option<String>,
        change: DeviceChange,
    },
    DeviceExpired {
        mac: MacAddr,
    },
    DevicePurged {
        mac: MacAddr,
    },
    PrefixChanged {
        gua: Option<Ipv6Addr>,
        ula: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    },
    InterfaceUpdated {
        ifindex: u32,
    },
    ScanRequested,
    NeighborScanRequested,
    SubnetScanStarted {
        subnet: String,
    },
    DeviceTableDirty,
    ReloadConfig,
    DbVacuum,
    DbLogClean,
    DbPrune,
    DbReset,
    DbResetCompleted,
    LeaseRelease {
        mac: MacAddr,
        target: LeaseTarget,
    },
    LeaseRenew {
        mac: MacAddr,
        target: LeaseTarget,
    },
    Shutdown,
    StateReady,
    DbReady,
    InterfaceReady,
    ServiceReady {
        name: String,
    },
    SystemReady,
    WolTriggered {
        mac: MacAddr,
        ip_hint: Option<Ipv4Addr>,
    },
    RsReceived {
        mac: MacAddr,
    },
    #[cfg(feature = "adblock")]
    DnsAdblockToggle {
        enabled: bool,
        duration_secs: Option<u64>,
    },
    #[cfg(feature = "adblock")]
    DnsAdblockReload,
    #[cfg(feature = "adblock")]
    DnsQueryBlocked {
        src_addr: std::net::IpAddr,
        domain: String,
    },
}

impl TimedEvent {
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
            | LanforgeEvent::RsReceived { .. }
            | LanforgeEvent::ReloadConfig
            | LanforgeEvent::ServiceReady { .. }
            | LanforgeEvent::SystemReady
            | LanforgeEvent::ScanRequested
            | LanforgeEvent::NeighborScanRequested
            | LanforgeEvent::SubnetScanStarted { .. } => true,
            #[cfg(feature = "adblock")]
            LanforgeEvent::DnsAdblockToggle { .. } | LanforgeEvent::DnsAdblockReload => true,
            _ => false,
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
        self.tx.send(TimedEvent::new(event, None)).unwrap_or(0)
    }

    #[must_use]
    pub fn publish_timed(&self, event: TimedEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

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
