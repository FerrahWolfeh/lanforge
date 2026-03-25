//! `EventBus` — barramento de eventos interno do lanforge.
//!
//! Usa `tokio::sync::broadcast` para comunicação entre tasks.
//!
//! ## Modelo de eventos
//!
//! O barramento é **device-centric**: os eventos descrevem mudanças na
//! identidade e estado dos devices, não ações de protocolo.

pub mod managed;
#[cfg(test)]
pub mod tests;

pub use managed::ManagedTable;

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::sync::broadcast;

use crate::device::MacAddr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DeviceChange — o que mudou num device
// ---------------------------------------------------------------------------

/// Detalha qual aspecto de um `Device` foi alterado.
/// Publicado dentro de `LanforgeEvent::DeviceUpdated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceChange {
    /// Um endereço IPv4 foi atribuído ou renovado.
    V4Assigned { ip: Ipv4Addr },

    /// O lease IPv4 expirou e foi removido.
    V4Expired,

    /// Um endereço IPv6 (`DHCPv6`) foi atribuído ou renovado.
    V6Assigned { ip: Ipv6Addr, iaid: u32 },

    /// O lease IPv6 expirou e foi removido.
    V6Expired,

    /// Um prefixo IPv6 foi delegado via IA_PD.
    V6PrefixAssigned {
        prefix: Ipv6Addr,
        len: u8,
        iaid: u32,
    },

    /// Um endereço SLAAC foi observado via NDP.
    SlaacObserved { addr: Ipv6Addr },

    /// O hostname do device foi atualizado.
    HostnameChanged { hostname: String },

    /// Uma reserva IPv4 estática foi definida ou removida via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// Um sufixo IPv6 estático foi definido ou removido via CLI.
    V6SuffixChanged {
        suffix: Option<crate::device::Ipv6AddrOrSuffix>,
    },

    /// Um DUID foi associado ao device.
    DuidAssociated,
}

// ---------------------------------------------------------------------------
// LanforgeEvent
// ---------------------------------------------------------------------------

/// Eventos que circulam pelo barramento.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    // -- Device lifecycle --
    DeviceDiscovered { mac: MacAddr },
    DeviceUpdated { mac: MacAddr, change: DeviceChange },
    DeviceExpired { mac: MacAddr },

    // -- Infra --
    PrefixChanged {
        gua: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    },

    // -- Control --
    DeviceTableDirty,
    ReloadConfig,
    DbVacuum,
    LeaseRelease { mac: MacAddr },
    LeaseRenew { mac: MacAddr },
    Shutdown,
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

const BUS_CAPACITY: usize = 256;

/// Barramento de eventos compartilhado entre todas as tasks.
pub struct EventBus {
    tx: broadcast::Sender<LanforgeEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Cria um novo receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<LanforgeEvent> {
        self.tx.subscribe()
    }

    /// Publica um evento no barramento.
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }
}
