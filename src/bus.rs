//! EventBus — barramento de eventos interno do lanforge.
//!
//! Usa `tokio::sync::broadcast` para comunicação entre tasks.
//! Cada serviço recebe um Receiver no startup e publica no Sender compartilhado.
//!
//! **Status: STUB** — será implementado na Fase 1.

#![allow(dead_code)]

use tokio::sync::broadcast;

/// Todos os eventos que circulam pelo barramento interno.
#[derive(Clone, Debug)]
pub enum LanforgeEvent {
    // -- Gerados pelo tracker netlink --
    NeighbourUp {
        mac: [u8; 6],
        ip: std::net::IpAddr,
        iface: u32,
    },
    NeighbourDown {
        mac: [u8; 6],
        ip: std::net::IpAddr,
    },
    SlaacSeen {
        mac: [u8; 6],
        ip: std::net::Ipv6Addr,
    },
    PrefixChanged {
        gua: Option<std::net::Ipv6Addr>,
    },

    // -- Gerados pelos servers DHCP --
    LeaseGranted {
        mac: [u8; 6],
        ip: std::net::IpAddr,
        hostname: String,
    },
    LeaseReleased {
        mac: [u8; 6],
        ip: std::net::IpAddr,
    },
    LeaseExpired {
        mac: [u8; 6],
        ip: std::net::IpAddr,
    },
    DuidLearned {
        mac: [u8; 6],
        duid: Vec<u8>,
    },

    // -- Controle interno --
    ReloadConfig,
    DeviceTableDirty,
}

const BUS_CAPACITY: usize = 256;

/// Barramento de eventos compartilhado entre todas as tasks.
pub struct EventBus {
    tx: broadcast::Sender<LanforgeEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        EventBus { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LanforgeEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: LanforgeEvent) {
        // Ignora erro se não há receivers (normal durante startup)
        let _ = self.tx.send(event);
    }
}
