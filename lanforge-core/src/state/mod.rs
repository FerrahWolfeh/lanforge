//! `DeviceTable` e tipos centrais do lanforge.
//!
//! O modelo central é um Device — um dispositivo físico que pode ter v4, v6
//! e endereços SLAAC ao mesmo tempo. Indexado pelo MAC.
//!
//! ## Fluxo de escrita
//!
//! Nenhum módulo externo deve escrever diretamente nos campos de `Device`.
//! O caminho correto é:
//!
//! ```ignore
//! let update = DeviceUpdate::V4LeaseGranted { mac, ip, expires };
//! let changed = table.apply_update(update);
//! ```
//!
//! `apply_update` é a **única** autoridade para merging e precedência
//! (estático > dinâmico). Se retornar `true`, o caller deve emitir um
//! evento `DeviceTableDirty` no `EventBus`.

pub mod expiry;
pub mod update;

#[cfg(test)]
pub mod tests;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::SystemTime;

use crate::device::{Device, IPv4State, Origin};
use crate::identifiers::{Duid, MacAddr};
use crate::state::update::StaticEntry;

// ---------------------------------------------------------------------------
// DeviceTable
// ---------------------------------------------------------------------------

/// Tabela de dispositivos — compartilhada via Arc<`RwLock`<..>>.
///
/// É a **única autoridade** de estado. Toda escrita passa por `apply_update`.
#[derive(Debug, Clone)]
pub struct DeviceTable {
    devices: HashMap<MacAddr, Device>,
    duid_index: HashMap<Duid, MacAddr>,
    static_entries: HashMap<MacAddr, StaticEntry>,
    ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// Leases IPv6 aprendidos sem MAC ainda (aguardando NDP).
    orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,

    // --- Índices para o Hot Path do DNS ---
    name_index: HashMap<String, MacAddr>,
    ip_index: HashMap<IpAddr, MacAddr>,
}

impl DeviceTable {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            duid_index: HashMap::new(),
            static_entries: HashMap::new(),
            ndp_cache: HashMap::new(),
            orphaned_v6: HashMap::new(),
            name_index: HashMap::new(),
            ip_index: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Leituras públicas
    // -----------------------------------------------------------------------

    /// Busca um dispositivo pelo seu MAC.
    pub fn get_device(&self, mac: &MacAddr) -> Option<&Device> {
        self.devices.get(mac)
    }

    /// Busca um dispositivo pelo seu MAC (mutável).
    pub fn get_device_mut(&mut self, mac: &MacAddr) -> Option<&mut Device> {
        self.devices.get_mut(mac)
    }

    /// Busca um dispositivo pelo hostname.
    pub fn get_by_hostname(&self, hostname: &str) -> Option<&Device> {
        self.name_index
            .get(hostname)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Busca um dispositivo pelo IP.
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<&Device> {
        self.ip_index.get(ip).and_then(|mac| self.devices.get(mac))
    }

    /// Busca um dispositivo pelo DUID.
    pub fn get_by_duid(&self, duid: &Duid) -> Option<&Device> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Recupera o DUID associado a um MAC, se já tiver sido aprendido.
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac)?.duid.as_ref()
    }

    /// Itera sobre todos os devices conhecidos.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// Itera sobre todos os entries estáticos.
    pub fn static_entries(&self) -> impl Iterator<Item = &StaticEntry> {
        self.static_entries.values()
    }

    /// Recupera o MAC associado a um IP via cache NDP.
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|(mac, _)| *mac)
    }

    /// Retorna iterador sobre leases órfãos (V6 sem MAC ainda).
    pub fn iter_orphaned_v6(&self) -> impl Iterator<Item = (&Ipv6Addr, &(Duid, u32, SystemTime))> {
        self.orphaned_v6.iter()
    }

    // -----------------------------------------------------------------------
    // Helpers internos
    // -----------------------------------------------------------------------

    /// Retorna o device mutável, criando-o se não existir.
    /// Prefira `apply_update` para todo o código de protocolo.
    pub fn get_or_insert(&mut self, mac: MacAddr) -> &mut Device {
        self.devices.entry(mac).or_insert_with(|| Device {
            mac,
            hostname: String::new(),
            origin: Origin::Dynamic,
            managed_at: None,
            duid: None,
            v4: IPv4State::None,
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
        })
    }

    /// Adiciona ou atualiza uma entrada estática. Usado principalmente na carga do DB.
    pub fn add_static_entry(&mut self, mac: MacAddr, entry: StaticEntry) {
        self.static_entries.insert(mac, entry);
    }
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}
