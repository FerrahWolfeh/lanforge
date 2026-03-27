//! `ManagedTable` — wrapper que conecta `DeviceTable` ao `EventBus`.
//!
//! Automatiza a publicação de eventos após cada `apply_update`.

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;

use super::{DeviceChange, EventBus, LanforgeEvent};
use crate::state::DeviceTable;
use crate::state::update::DeviceUpdate;

/// Wrapper em torno do `DeviceTable` que automaticamente publica eventos
/// no `EventBus` após cada `apply_update`.
///
/// É este tipo que deve ser distribuído via `Arc<ManagedTable>` para as tasks
/// de protocolo — não o `DeviceTable` diretamente.
pub struct ManagedTable {
    inner: RwLock<DeviceTable>,
    bus: Arc<EventBus>,
}

impl ManagedTable {
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self {
            inner: RwLock::new(DeviceTable::new()),
            bus,
        }
    }

    /// Aplica um update ao `DeviceTable` e publica os eventos correspondentes.
    pub async fn update(&self, update: DeviceUpdate) {
        let mut table = self.inner.write();

        let opt_mac = mac_of(&update);
        let is_new = if let Some(mac) = opt_mac {
            !table.devices.contains_key(&mac)
        } else {
            false
        };

        let change = device_change_of(&update);
        let changed = table.apply_update(update);

        drop(table);

        if !changed {
            return;
        }

        if let Some(mac) = opt_mac {
            if is_new {
                self.bus.publish(LanforgeEvent::DeviceDiscovered { mac });
            }

            if let Some(change) = change {
                self.bus
                    .publish(LanforgeEvent::DeviceUpdated { mac, change });
            }
        }

        self.bus.publish(LanforgeEvent::DeviceTableDirty);
    }

    /// Leitura do estado interno.
    pub fn read(&self) -> RwLockReadGuard<'_, DeviceTable> {
        self.inner.read()
    }

    /// Acesso de escrita direto — usar apenas para operações de manutenção.
    pub fn write(&self) -> RwLockWriteGuard<'_, DeviceTable> {
        self.inner.write()
    }

    /// Retorna uma referência ao barramento de eventos.
    pub fn bus(&self) -> Arc<EventBus> {
        self.bus.clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

use crate::identifiers::MacAddr;

/// Extrai o MAC de qualquer variante de `DeviceUpdate`, se houver.
const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V4LeaseGranted { mac, .. } => Some(*mac),
        DeviceUpdate::V6LeaseGranted { mac, .. } => *mac,
        DeviceUpdate::V6PrefixAssigned { mac, .. } => *mac,
        DeviceUpdate::SlaacObserved { mac, .. } => Some(*mac),
        DeviceUpdate::NdpSeen { mac, .. } => Some(*mac),
        DeviceUpdate::ArpSeen { mac, .. } => Some(*mac),
        DeviceUpdate::HostnameHint { mac, .. } => Some(*mac),
        DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::CliHostUpdated { mac, .. } => Some(*mac),
        DeviceUpdate::SlaacCleared { mac } => Some(*mac),
        DeviceUpdate::LeaseReleased { mac } => Some(*mac),
        DeviceUpdate::IpDeleted { .. } => None,
        DeviceUpdate::RebuildDnsIndices => None,
    }
}

/// Converte um `DeviceUpdate` no `DeviceChange` correspondente para o bus.
fn device_change_of(update: &DeviceUpdate) -> Option<DeviceChange> {
    match update {
        DeviceUpdate::V4LeaseGranted { ip, .. } => Some(DeviceChange::V4Assigned { ip: *ip }),
        DeviceUpdate::V6LeaseGranted { ip, iaid, .. } => Some(DeviceChange::V6Assigned {
            ip: *ip,
            iaid: *iaid,
        }),
        DeviceUpdate::V6PrefixAssigned {
            prefix, len, iaid, ..
        } => Some(DeviceChange::V6PrefixAssigned {
            prefix: *prefix,
            len: *len,
            iaid: *iaid,
        }),
        DeviceUpdate::SlaacObserved { addr, .. } => {
            Some(DeviceChange::SlaacObserved { addr: *addr })
        }
        DeviceUpdate::HostnameHint { hostname, .. } => Some(DeviceChange::HostnameChanged {
            hostname: hostname.clone(),
        }),
        DeviceUpdate::DuidAssociated { .. } => Some(DeviceChange::DuidAssociated),
        DeviceUpdate::NdpSeen { .. }
        | DeviceUpdate::ArpSeen { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::LeaseReleased { .. } => None,
        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            ..
        } => {
            if let Some(Some(hn)) = hostname {
                return Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                });
            }
            if let Some(v4) = v4_static {
                return Some(DeviceChange::V4StaticChanged { ip: *v4 });
            }
            if let Some(v6) = v6_suffix {
                return Some(DeviceChange::V6SuffixChanged { suffix: v6.clone() });
            }
            None
        }
        DeviceUpdate::IpDeleted { .. } => None,
        DeviceUpdate::RebuildDnsIndices => None,
    }
}
