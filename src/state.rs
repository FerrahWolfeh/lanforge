//! DeviceTable e tipos centrais do lanforge.
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

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use crate::config::StaticDeviceCfg;
use crate::dhcp::v6::duid::Duid;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Endereço MAC de 6 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(#[serde(serialize_with = "serialize_mac")] pub [u8; 6]);

fn serialize_mac<S>(mac: &[u8; 6], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

impl MacAddr {
    /// Parse from "aa:bb:cc:dd:ee:ff" (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(MacAddr(bytes))
    }

    /// Constrói a partir de um slice de bytes cru.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(bytes);
            Some(MacAddr(arr))
        } else {
            None
        }
    }
}

/// Zero-cost conversion de array fixo.
impl From<[u8; 6]> for MacAddr {
    fn from(arr: [u8; 6]) -> Self {
        MacAddr(arr)
    }
}

/// Acesso sem cópia ao array interno — útil para FFI / Netlink.
impl AsRef<[u8; 6]> for MacAddr {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

// ---------------------------------------------------------------------------
// Device + Lease types
// ---------------------------------------------------------------------------

/// Tudo que se sabe sobre um dispositivo na rede.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: String,

    /// Indica a origem das configurações do dispositivo.
    pub origin: Origin,

    /// Timestamp Unix de quando foi gerenciado via CLI, se aplicável.
    #[serde(serialize_with = "serialize_time_opt")]
    pub managed_at: Option<SystemTime>,

    /// Configuração estática IPv4 via CLI/TOML (opcional).
    pub v4_static: Option<Ipv4Addr>,

    /// Sufixo estático IPv6 via CLI/TOML (opcional).
    pub v6_suffix: Option<String>,

    /// true = veio da config estática; campos protegidos contra sobrescrita dinâmica.
    pub is_static: bool,
    pub duid: Option<Duid>,
    pub v4: Option<V4Lease>,
    pub v6: Option<V6Lease>,

    /// Endereços SLAAC observados via NDP.
    pub slaac: Vec<Ipv6Addr>,
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Origin {
    Toml,
    Cli,
    #[default]
    Dynamic,
}

impl Origin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Toml => "toml",
            Origin::Cli => "cli",
            Origin::Dynamic => "dynamic",
        }
    }
}

fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match time {
        Some(t) => {
            let elapsed = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
            serializer.serialize_u64(elapsed.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

fn serialize_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    serializer.serialize_u64(elapsed.as_secs())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

/// Registro de config estática para um dispositivo.
#[derive(Debug, Clone)]
pub struct StaticEntry {
    pub mac: MacAddr,
    pub hostname: String,
    pub v4_ip: Option<Ipv4Addr>,
    pub v6_suffix: Option<String>,
}

// ---------------------------------------------------------------------------
// DeviceUpdate — a única forma de mudar estado de um Device
// ---------------------------------------------------------------------------

/// Representa uma mudança atômica de estado proposta por um protocolo
/// (DHCPv4, DHCPv6, SLAAC, Netlink). Não modifica nada sozinho —
/// precisa ser passado para `DeviceTable::apply_update`.
#[derive(Debug, Clone)]
pub enum DeviceUpdate {
    /// DHCPv4 concedeu ou renovou um lease.
    V4LeaseGranted {
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    },

    /// DHCPv6 concedeu ou renovou um lease.
    V6LeaseGranted {
        mac: MacAddr,
        duid: Duid,
        ip: Ipv6Addr,
        expires: SystemTime,
    },

    /// Netlink/NDP observou um endereço SLAAC ativo.
    SlaacObserved { mac: MacAddr, addr: Ipv6Addr },

    /// Netlink viu o par (IPv6, MAC) no cache NDP do kernel.
    /// Não implica lease — apenas "este device está ativo".
    NdpSeen { mac: MacAddr, ip: Ipv6Addr },

    /// Um protocolo aprendeu o hostname do dispositivo (ex: opção DHCP 12).
    /// Ignorado se o device for estático.
    HostnameHint { mac: MacAddr, hostname: String },

    /// Um DUID foi associado ao MAC (geralmente pelo DHCPv6 Solicit).
    DuidAssociated { mac: MacAddr, duid: Duid },

    /// Modificação explícita de campos via CLI (`lanforge host add` / `lanforge host set`).
    CliHostUpdated {
        mac: MacAddr,
        hostname: Option<Option<String>>,
        v4_static: Option<Option<Ipv4Addr>>,
        v6_suffix: Option<Option<String>>,
    },

    /// Limpa todos os endereços SLAAC de um device antes de re-scan.
    SlaacCleared { mac: MacAddr },
}

// ---------------------------------------------------------------------------
// DeviceTable
// ---------------------------------------------------------------------------

/// Tabela de dispositivos — compartilhada via Arc<RwLock<..>>.
///
/// É a **única autoridade** de estado. Toda escrita passa por `apply_update`.
#[derive(Debug, Clone)]
pub struct DeviceTable {
    pub(crate) devices: HashMap<MacAddr, Device>,
    duid_index: HashMap<Duid, MacAddr>,
    pub(crate) static_entries: HashMap<MacAddr, StaticEntry>,
    ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
}

impl DeviceTable {
    pub fn new() -> Self {
        DeviceTable {
            devices: HashMap::new(),
            duid_index: HashMap::new(),
            static_entries: HashMap::new(),
            ndp_cache: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Ponto de entrada principal
    // -----------------------------------------------------------------------

    /// Aplica uma mudança de estado proposta por um protocolo.
    ///
    /// Retorna `true` se o estado efetivamente mudou — o caller deve então
    /// emitir `LanforgeEvent::DeviceTableDirty` no `EventBus`.
    ///
    /// Regras de precedência aplicadas aqui:
    /// - Hostname: config estática nunca é sobrescrita por hints dinâmicos.
    /// - V4 IP: config estática (`StaticEntry.v4_ip`) tem prioridade; o lease
    ///   dinâmico ainda é registrado para controle de expiração, mas o IP
    ///   efetivo deve ser resolvido via `StaticEntry`.
    pub fn apply_update(&mut self, update: DeviceUpdate) -> bool {
        match update {
            DeviceUpdate::V4LeaseGranted { mac, ip, expires } => {
                let dev = self.get_or_insert(mac);
                let new_lease = V4Lease { ip, expires };
                // Só marca dirty se mudou algo relevante
                let changed = dev
                    .v4
                    .as_ref()
                    .is_none_or(|old| old.ip != ip || old.expires != expires);
                dev.v4 = Some(new_lease);
                dev.last_seen = SystemTime::now();
                if changed {
                    debug!("[state] V4 lease {} → {}", mac, ip);
                }
                changed
            }

            DeviceUpdate::V6LeaseGranted {
                mac,
                duid,
                ip,
                expires,
            } => {
                // Garante que o DUID está indexado
                self.duid_index.insert(duid.clone(), mac);
                let dev = self.get_or_insert(mac);
                let changed = dev.duid.as_ref() != Some(&duid)
                    || dev
                        .v6
                        .as_ref()
                        .is_none_or(|old| old.ip != ip || old.expires != expires);
                dev.duid = Some(duid);
                dev.v6 = Some(V6Lease { ip, expires });
                dev.last_seen = SystemTime::now();
                if changed {
                    debug!("[state] V6 lease {} → {}", mac, ip);
                }
                changed
            }

            DeviceUpdate::SlaacObserved { mac, addr } => {
                let dev = self.get_or_insert(mac);
                if dev.slaac.contains(&addr) {
                    dev.last_seen = SystemTime::now();
                    false // sem mudança estrutural
                } else {
                    dev.slaac.push(addr);
                    dev.last_seen = SystemTime::now();
                    debug!("[state] SLAAC {} → {}", mac, addr);
                    true
                }
            }

            DeviceUpdate::NdpSeen { mac, ip } => {
                self.ndp_cache.insert(ip, (mac, SystemTime::now()));
                let dev = self.get_or_insert(mac);
                // last_seen bump não conta como mudança estrutural para o dirty event
                dev.last_seen = SystemTime::now();
                false
            }

            DeviceUpdate::HostnameHint { mac, hostname } => {
                let dev = self.get_or_insert(mac);
                if dev.is_static {
                    // Config estática tem precedência — ignora o hint silenciosamente
                    return false;
                }
                if dev.hostname == hostname {
                    return false;
                }
                debug!("[state] Hostname {} → {:?}", mac, hostname);
                dev.hostname = hostname;
                true
            }

            DeviceUpdate::DuidAssociated { mac, duid } => {
                self.duid_index.insert(duid.clone(), mac);
                let dev = self.get_or_insert(mac);
                if dev.duid.as_ref() == Some(&duid) {
                    return false;
                }
                dev.duid = Some(duid);
                true
            }

            DeviceUpdate::CliHostUpdated {
                mac,
                hostname,
                v4_static,
                v6_suffix,
            } => {
                let dev = self.get_or_insert(mac);

                // Se era gerido pelo TOML, não permitimos modificação via CLI
                if dev.origin == Origin::Toml {
                    warn!(
                        "Tentativa de modificar device estático do TOML via CLI: {}",
                        mac
                    );
                    return false;
                }

                let mut changed = false;

                if let Some(hn_opt) = hostname {
                    if let Some(hn) = hn_opt {
                        if dev.hostname != hn {
                            dev.hostname = hn;
                            changed = true;
                        }
                    } else if !dev.hostname.is_empty() {
                        dev.hostname.clear();
                        changed = true;
                    }
                }

                if let Some(v4_opt) = v4_static
                    && dev.v4_static != v4_opt
                {
                    dev.v4_static = v4_opt;
                    changed = true;
                }

                if let Some(v6_opt) = v6_suffix
                    && dev.v6_suffix != v6_opt
                {
                    dev.v6_suffix = v6_opt;
                    changed = true;
                }

                if changed {
                    dev.origin = Origin::Cli;
                    dev.managed_at = Some(SystemTime::now());
                    dev.is_static = true;
                    dev.last_seen = SystemTime::now();
                    debug!("[state] CLI Host Updated: {}", mac);
                }

                changed
            }

            DeviceUpdate::SlaacCleared { mac } => {
                if let Some(dev) = self.devices.get_mut(&mac) {
                    if dev.slaac.is_empty() {
                        return false;
                    }
                    dev.slaac.clear();
                    return true;
                }
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Inicialização (config estática — não passa por apply_update pois é
    // bootstrap síncrono antes de qualquer serviço estar rodando)
    // -----------------------------------------------------------------------

    /// Carrega entradas estáticas do TOML. Chamado uma vez no startup.
    pub fn load_static_devices(&mut self, entries: &[StaticDeviceCfg]) {
        for e in entries {
            let Some(mac) = MacAddr::parse(&e.mac) else {
                warn!("Invalid MAC in config: '{}', skipping", e.mac);
                continue;
            };

            let v4_ip = e.v4_ip.as_ref().and_then(|s| {
                s.parse::<Ipv4Addr>().ok().or_else(|| {
                    warn!("Invalid v4_ip for {}: '{s}'", e.hostname);
                    None
                })
            });

            let static_entry = StaticEntry {
                mac,
                hostname: e.hostname.clone(),
                v4_ip,
                v6_suffix: e.v6_suffix.clone(),
            };

            info!("  Static device: {} → {} (v4={:?})", mac, e.hostname, v4_ip);
            self.static_entries.insert(mac, static_entry);

            // Pre-popula o device para que hostname resolva imediatamente
            let dev = self.get_or_insert(mac);
            dev.hostname = e.hostname.clone();
            dev.v4_static = v4_ip;
            dev.v6_suffix = e.v6_suffix.clone();
            dev.is_static = true;
            dev.origin = Origin::Toml;
        }
    }

    // -----------------------------------------------------------------------
    // Leituras públicas
    // -----------------------------------------------------------------------

    #[cfg(test)]
    pub fn find_by_duid(&self, duid: &Duid) -> Option<&Device> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Recupera o `Device` pelo MAC, se existir.
    pub fn find_device_by_mac(&self, mac: MacAddr) -> Option<&Device> {
        self.devices.get(&mac)
    }

    /// Recupera o DUID associado a um MAC, se já tiver sido aprendido.
    ///
    /// Útil no DHCPv6 para reutilizar o DUID existente num Renew/Rebind
    /// sem precisar que o cliente o reenvie explicitamente.
    pub fn find_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
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

    // -----------------------------------------------------------------------
    // Manutenção periódica
    // -----------------------------------------------------------------------

    /// Remove leases expirados e devices dinâmicos inativos.
    /// Retorna `true` se houve mudança — dispara `DeviceTableDirty`.
    pub fn expire_stale(&mut self) -> bool {
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(7 * 24 * 3600);
        let ndp_max_age = std::time::Duration::from_secs(24 * 3600);
        let mut changed = false;

        let initial_ndp_len = self.ndp_cache.len();
        self.ndp_cache
            .retain(|_, (_, ts)| ts.elapsed().unwrap_or(std::time::Duration::ZERO) <= ndp_max_age);
        if self.ndp_cache.len() != initial_ndp_len {
            changed = true;
        }

        let macs: Vec<MacAddr> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut remove_device = false;
            if let Some(dev) = self.devices.get_mut(&mac) {
                if let Some(v4) = &dev.v4
                    && v4.expires < now
                {
                    dev.v4 = None;
                    changed = true;
                }
                if let Some(v6) = &dev.v6
                    && v6.expires < now
                {
                    dev.v6 = None;
                    changed = true;
                }
                if !dev.is_static
                    && dev.v4.is_none()
                    && dev.v6.is_none()
                    && dev.slaac.is_empty()
                    && dev.last_seen.elapsed().unwrap_or(std::time::Duration::ZERO) > max_age
                {
                    remove_device = true;
                }
            }

            if remove_device {
                if let Some(dev) = self.devices.remove(&mac)
                    && let Some(duid) = dev.duid
                {
                    self.duid_index.remove(&duid);
                }
                changed = true;
                debug!("[state] Removed stale dynamic device {}", mac);
            }
        }
        changed
    }

    // -----------------------------------------------------------------------
    // Helpers internos (pub(crate) — uso pelos testes e módulos de migração)
    // -----------------------------------------------------------------------

    /// Retorna o device mutável, criando-o se não existir.
    /// Prefira `apply_update` para todo o código de protocolo.
    pub(crate) fn get_or_insert(&mut self, mac: MacAddr) -> &mut Device {
        self.devices.entry(mac).or_insert_with(|| Device {
            mac,
            hostname: String::new(),
            is_static: false,
            origin: Origin::Dynamic,
            managed_at: None,
            v4_static: None,
            v6_suffix: None,
            duid: None,
            v4: None,
            v6: None,
            slaac: Vec::new(),
            last_seen: SystemTime::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- MacAddr ---

    #[test]
    fn mac_parse_display_roundtrip() {
        let input = "e0:d5:5e:e2:d4:89";
        let mac = MacAddr::parse(input).expect("should parse");
        assert_eq!(mac.to_string(), input);
    }

    #[test]
    fn mac_parse_uppercase() {
        let mac = MacAddr::parse("E0:D5:5E:E2:D4:89").unwrap();
        assert_eq!(mac.to_string(), "e0:d5:5e:e2:d4:89");
    }

    #[test]
    fn mac_parse_invalid() {
        assert!(MacAddr::parse("not-a-mac").is_none());
        assert!(MacAddr::parse("e0:d5:5e:e2:d4").is_none());
        assert!(MacAddr::parse("e0:d5:5e:e2:d4:89:ff").is_none());
    }

    #[test]
    fn mac_from_array_and_asref() {
        let arr: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mac = MacAddr::from(arr);
        assert_eq!(mac.as_ref(), &arr);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    // --- apply_update: casos básicos ---

    #[test]
    fn apply_update_v4_lease_granted() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
        assert!(changed);

        let dev = table.devices().next().unwrap();
        assert_eq!(dev.v4.as_ref().unwrap().ip, ip);
    }

    #[test]
    fn apply_update_v4_idempotent() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
        // Mesma info novamente — não deve ser dirty
        let changed = table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
        assert!(!changed, "Lease idêntico não deveria marcar dirty");
    }

    #[test]
    fn apply_update_hostname_hint_respects_static() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        // Simula device estático
        {
            let dev = table.get_or_insert(mac);
            dev.hostname = "static-host".to_string();
            dev.is_static = true;
        }

        let changed = table.apply_update(DeviceUpdate::HostnameHint {
            mac,
            hostname: "dynamic-host".to_string(),
        });

        assert!(!changed, "Hint não deve sobrescrever device estático");
        assert_eq!(table.devices().next().unwrap().hostname, "static-host");
    }

    #[test]
    fn apply_update_hostname_hint_accepted_for_dynamic() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        let changed = table.apply_update(DeviceUpdate::HostnameHint {
            mac,
            hostname: "my-laptop".to_string(),
        });

        assert!(changed);
        assert_eq!(table.devices().next().unwrap().hostname, "my-laptop");
    }

    #[test]
    fn apply_update_slaac_deduplicates() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let addr: Ipv6Addr = "fd97::1234".parse().unwrap();

        assert!(table.apply_update(DeviceUpdate::SlaacObserved { mac, addr }));
        // Duplicata — não deve marcar dirty
        assert!(!table.apply_update(DeviceUpdate::SlaacObserved { mac, addr }));
        assert!(table.apply_update(DeviceUpdate::SlaacObserved {
            mac,
            addr: "fd97::5678".parse().unwrap()
        }));

        assert_eq!(table.devices().next().unwrap().slaac.len(), 2);
    }

    #[test]
    fn apply_update_slaac_cleared() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        table.apply_update(DeviceUpdate::SlaacObserved {
            mac,
            addr: "fd97::1".parse().unwrap(),
        });
        assert!(table.apply_update(DeviceUpdate::SlaacCleared { mac }));
        assert!(table.devices().next().unwrap().slaac.is_empty());
        // Limpar de novo quando já está vazio — não dirty
        assert!(!table.apply_update(DeviceUpdate::SlaacCleared { mac }));
    }

    #[test]
    fn apply_update_duid_associated() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let duid = Duid::new(vec![1, 2, 3, 4]);

        table.get_or_insert(mac).hostname = "DuidHost".to_string();
        assert!(table.apply_update(DeviceUpdate::DuidAssociated {
            mac,
            duid: duid.clone()
        }));

        let found = table.find_by_duid(&duid).expect("deve encontrar via DUID");
        assert_eq!(found.hostname, "DuidHost");

        // Mesmo DUID novamente — não dirty
        assert!(!table.apply_update(DeviceUpdate::DuidAssociated { mac, duid }));
    }

    #[test]
    fn apply_update_ndp_seen_not_dirty() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        // NdpSeen nunca marca dirty (só bump de last_seen e cache)
        assert!(!table.apply_update(DeviceUpdate::NdpSeen { mac, ip }));
        assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));
    }

    // --- expire_stale ---

    #[test]
    fn expire_stale_removes_old_v4_keeps_fresh_v6() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        let past = SystemTime::now() - std::time::Duration::from_secs(100);
        let future = SystemTime::now() + std::time::Duration::from_secs(100);

        let dev = table.get_or_insert(mac);
        dev.v4 = Some(V4Lease {
            ip: "192.168.0.2".parse().unwrap(),
            expires: past,
        });
        dev.v6 = Some(V6Lease {
            ip: "fd00::1".parse().unwrap(),
            expires: future,
        });

        assert!(table.expire_stale());

        let dev_after = table.devices().next().unwrap();
        assert!(dev_after.v4.is_none(), "V4 expirado deve ser removido");
        assert!(dev_after.v6.is_some(), "V6 no futuro deve ser mantido");
    }

    #[test]
    fn ndp_cache_stores_and_retrieves_mac() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        assert!(table.get_mac_from_ndp_cache(&ip).is_none());
        table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
        assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));
    }
}
