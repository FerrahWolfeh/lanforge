//! DeviceTable e tipos centrais do lanforge.
//!
//! O modelo central é um Device — um dispositivo físico que pode ter v4, v6
//! e endereços SLAAC ao mesmo tempo. Indexado pelo MAC.
//!
//! **Status: STUB** — será implementado na Fase 2 (DHCPv4).

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::SystemTime;

/// Endereço MAC de 6 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

/// DUID opaco (DUID-LLT, DUID-LL ou DUID-EN).
/// Aprendido no primeiro contato DHCPv6 e associado ao MAC do dispositivo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duid(pub Vec<u8>);

/// Tudo que se sabe sobre um dispositivo na rede.
#[derive(Debug, Clone)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: String,

    /// true = veio da config estática; false = aprendido dinamicamente
    pub is_static: bool,

    /// DUID aprendido na primeira troca DHCPv6.
    /// None até o dispositivo fazer DHCPv6 pela primeira vez.
    pub duid: Option<Duid>,

    /// Lease IPv4 ativo, se houver.
    pub v4: Option<V4Lease>,

    /// Lease IPv6 stateful ativo, se houver.
    pub v6: Option<V6Lease>,

    /// Endereços SLAAC observados via NDP (pode haver mais de um por dispositivo).
    pub slaac: Vec<Ipv6Addr>,

    /// Última vez que o dispositivo foi visto na rede (qualquer protocolo).
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    pub expires: SystemTime,
}

#[derive(Debug, Clone)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
    pub expires: SystemTime,
}

/// Registro de config estática — lido do config.toml no startup.
/// Define hostname e endereços fixos para um MAC conhecido.
#[derive(Debug, Clone)]
pub struct StaticEntry {
    pub mac: MacAddr,
    pub hostname: String,
    pub v4_ip: Option<Ipv4Addr>,
    /// Sufixo IPv6 fixo (ex: ::1057:cafe).
    pub v6_suffix: Option<Ipv6Addr>,
}

/// Tabela de dispositivos — compartilhada entre todas as tasks via Arc<RwLock<..>>
pub struct DeviceTable {
    /// Dispositivos indexados por MAC.
    devices: HashMap<MacAddr, Device>,

    /// Índice secundário: DUID → MAC.
    duid_index: HashMap<Duid, MacAddr>,

    /// Config estática carregada do config.toml. Imutável em runtime.
    static_entries: HashMap<MacAddr, StaticEntry>,
}

impl DeviceTable {
    pub fn new() -> Self {
        DeviceTable {
            devices: HashMap::new(),
            duid_index: HashMap::new(),
            static_entries: HashMap::new(),
        }
    }

    pub fn get_or_insert(&mut self, mac: MacAddr) -> &mut Device {
        self.devices.entry(mac).or_insert_with(|| Device {
            mac,
            hostname: String::new(),
            is_static: false,
            duid: None,
            v4: None,
            v6: None,
            slaac: Vec::new(),
            last_seen: SystemTime::now(),
        })
    }

    pub fn find_by_duid(&self, duid: &Duid) -> Option<&Device> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac))
    }

    pub fn hostname_for(&self, mac: &MacAddr) -> Option<&str> {
        self.static_entries
            .get(mac)
            .map(|e| e.hostname.as_str())
            .or_else(|| {
                self.devices
                    .get(mac)
                    .filter(|d| !d.hostname.is_empty())
                    .map(|d| d.hostname.as_str())
            })
    }

    pub fn v6_suffix_for(&self, mac: &MacAddr) -> Option<Ipv6Addr> {
        self.static_entries.get(mac).and_then(|e| e.v6_suffix)
    }

    pub fn expire_stale(&mut self) -> bool {
        todo!("Implementar expiração de leases e dispositivos inativos")
    }

    pub fn save(&self, _path: &Path) -> anyhow::Result<()> {
        todo!("Implementar persistência SQLite")
    }

    pub fn load(_path: &Path) -> anyhow::Result<Self> {
        todo!("Implementar carregamento SQLite")
    }
}
