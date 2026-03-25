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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use crate::config::StaticDeviceCfg;
use crate::device::{
    Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, MacAddr, Origin, V4Lease, V6Lease,
    V6PrefixLease,
};
use crate::dhcp::v6::duid::Duid;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Device + Lease types
// ---------------------------------------------------------------------------

/// Registro de config estática para um dispositivo.
#[derive(Debug, Clone)]
pub struct StaticEntry {
    pub mac: MacAddr,
    pub hostname: String,
    pub v4_ip: Option<Ipv4Addr>,
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
}

// ---------------------------------------------------------------------------
// DeviceUpdate — a única forma de mudar estado de um Device
// ---------------------------------------------------------------------------

/// Representa uma mudança atômica de estado proposta por um protocolo
/// (`DHCPv4`, `DHCPv6`, SLAAC, Netlink). Não modifica nada sozinho —
/// precisa ser passado para `DeviceTable::apply_update`.
#[derive(Debug, Clone)]
pub enum DeviceUpdate {
    /// `DHCPv4` concedeu ou renovou um lease.
    V4LeaseGranted {
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    },

    /// `DHCPv6` concedeu ou renovou um lease.
    V6LeaseGranted {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    },

    /// `DHCPv6` concedeu ou renovou uma delegação de prefixo (IA_PD).
    V6PrefixAssigned {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    },

    /// Netlink/NDP observou um endereço SLAAC ativo.
    SlaacObserved { mac: MacAddr, addr: Ipv6Addr },

    /// Netlink/NDP observou um endereço IPv6 ativo.
    NdpSeen { mac: MacAddr, ip: Ipv6Addr },

    /// Netlink/ARP observou um endereço IPv4 ativo.
    ArpSeen { mac: MacAddr, ip: Ipv4Addr },

    /// Um protocolo aprendeu o hostname do dispositivo (ex: opção DHCP 12).
    /// Ignorado se o device for estático.
    HostnameHint { mac: MacAddr, hostname: String },

    /// Um DUID foi associado ao MAC (geralmente pelo `DHCPv6` Solicit).
    DuidAssociated {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
    },

    /// Modificação explícita de campos via CLI (`lanforge host add` / `lanforge host set`).
    CliHostUpdated {
        mac: MacAddr,
        hostname: Option<Option<String>>,
        v4_static: Option<Option<Ipv4Addr>>,
        v6_suffix: Option<Option<Ipv6AddrOrSuffix>>,
    },

    /// Limpa todos os endereços SLAAC de um device antes de re-scan.
    SlaacCleared { mac: MacAddr },

    /// Libera formalmente os leases (v4 e v6) de um device via CLI.
    LeaseReleased { mac: MacAddr },

    /// Netlink detectou que um IP (v4 ou v6) foi removido do cache de vizinhos.
    IpDeleted { ip: std::net::IpAddr },
}

// ---------------------------------------------------------------------------
// DeviceTable
// ---------------------------------------------------------------------------

/// Tabela de dispositivos — compartilhada via Arc<`RwLock`<..>>.
///
/// É a **única autoridade** de estado. Toda escrita passa por `apply_update`.
#[derive(Debug, Clone)]
pub struct DeviceTable {
    pub(crate) devices: HashMap<MacAddr, Device>,
    duid_index: HashMap<Duid, MacAddr>,
    pub(crate) static_entries: HashMap<MacAddr, StaticEntry>,
    ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// Leases IPv6 aprendidos sem MAC ainda (aguardando NDP).
    orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,

    // --- Novos Índices para o Hot Path do DNS ---
    pub(crate) name_index: HashMap<String, MacAddr>,
    pub(crate) ip_index: HashMap<IpAddr, MacAddr>,
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
        let changed = match update {
            DeviceUpdate::V4LeaseGranted { mac, ip, expires } => {
                let dev = self.get_or_insert(mac);
                let new_lease = V4Lease { ip, expires };

                match &dev.v4 {
                    IPv4State::Static(s_ip) if *s_ip == ip => false,
                    IPv4State::Dynamic(old) if old.ip == ip && old.expires == expires => false,
                    _ => {
                        debug!("[state] V4 lease {} → {}", mac, ip);
                        dev.v4 = IPv4State::Dynamic(new_lease);
                        dev.last_seen = SystemTime::now();
                        true
                    }
                }
            }

            DeviceUpdate::V6LeaseGranted {
                mac,
                duid,
                iaid,
                ip,
                expires,
            } => {
                if let Some(m) = mac {
                    self.duid_index.insert(duid.clone(), m);
                    let dev = self.get_or_insert(m);
                    let new_lease = V6Lease { ip, iaid, expires };

                    let mut found = false;
                    for state in &mut dev.v6 {
                        if let IPv6State::Dynamic(old) = state
                            && old.iaid == iaid
                        {
                            if old.ip == ip && old.expires == expires {
                                return false;
                            }
                            *old = new_lease.clone();
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        dev.v6.push(IPv6State::Dynamic(new_lease));
                    }
                    dev.duid = Some(duid);
                    dev.last_seen = SystemTime::now();
                    true
                } else {
                    debug!("[state] V6 lease órfão → {}", ip);
                    self.orphaned_v6.insert(ip, (duid, iaid, expires));
                    false
                }
            }

            DeviceUpdate::V6PrefixAssigned {
                mac,
                duid,
                iaid,
                prefix,
                len,
                expires,
            } => {
                if let Some(m) = mac {
                    self.duid_index.insert(duid.clone(), m);
                    let dev = self.get_or_insert(m);
                    let new_lease = V6PrefixLease {
                        prefix,
                        len,
                        iaid,
                        expires,
                    };

                    let mut found = false;
                    for old in &mut dev.v6_prefixes {
                        if old.iaid == iaid {
                            if old.prefix == prefix && old.len == len && old.expires == expires {
                                return false;
                            }
                            *old = new_lease.clone();
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        dev.v6_prefixes.push(new_lease);
                    }
                    dev.duid = Some(duid);
                    dev.last_seen = SystemTime::now();
                    true
                } else {
                    false
                }
            }

            DeviceUpdate::SlaacObserved { mac, addr } => {
                let dev = self.get_or_insert(mac);
                if dev
                    .v6
                    .iter()
                    .any(|s| matches!(s, IPv6State::Slaac(a) if *a == addr))
                {
                    dev.last_seen = SystemTime::now();
                    false
                } else {
                    dev.v6.push(IPv6State::Slaac(addr));
                    dev.last_seen = SystemTime::now();
                    debug!("[state] SLAAC {} → {}", mac, addr);
                    true
                }
            }

            DeviceUpdate::NdpSeen { mac, ip } => {
                self.ndp_cache.insert(ip, (mac, SystemTime::now()));
                if let Some((duid, iaid, expires)) = self.orphaned_v6.remove(&ip) {
                    self.apply_update(DeviceUpdate::V6LeaseGranted {
                        mac: Some(mac),
                        duid,
                        iaid,
                        ip,
                        expires,
                    });
                    return true;
                }
                let dev = self.get_or_insert(mac);
                dev.last_seen = SystemTime::now();
                false
            }

            DeviceUpdate::ArpSeen { mac, ip } => {
                let dev = self.get_or_insert(mac);
                dev.last_seen = SystemTime::now();
                if dev.seen_v4.contains(&ip) {
                    false
                } else {
                    dev.seen_v4.push(ip);
                    true
                }
            }

            DeviceUpdate::HostnameHint { mac, hostname } => {
                let dev = self.get_or_insert(mac);
                if dev.is_static() {
                    return false;
                }
                if dev.hostname == hostname {
                    return false;
                }
                dev.hostname = hostname;
                true
            }

            DeviceUpdate::DuidAssociated { mac, duid, iaid } => {
                let mut changed = false;
                if let Some(m) = mac {
                    self.duid_index.insert(duid.clone(), m);
                    let dev = self.get_or_insert(m);
                    if dev.duid.as_ref() != Some(&duid) {
                        dev.duid = Some(duid.clone());
                        changed = true;
                    }

                    // Resolve órfãos que estavam esperando por este DUID+IAID
                    let mut resolved = Vec::new();
                    for (&ip, (o_duid, o_iaid, _)) in &self.orphaned_v6 {
                        if *o_duid == duid && *o_iaid == iaid {
                            resolved.push(ip);
                        }
                    }

                    for ip in resolved {
                        if let Some((duid, iaid, expires)) = self.orphaned_v6.remove(&ip) {
                            debug!(
                                "[state] Resolvendo órfão via DuidAssociated: {} -> {}",
                                ip, m
                            );
                            self.apply_update(DeviceUpdate::V6LeaseGranted {
                                mac: Some(m),
                                duid,
                                iaid,
                                ip,
                                expires,
                            });
                            changed = true;
                        }
                    }
                }
                changed
            }

            DeviceUpdate::CliHostUpdated {
                mac,
                hostname,
                v4_static,
                v6_suffix,
            } => {
                let dev = self.get_or_insert(mac);
                if dev.origin == Origin::Toml {
                    warn!("Tentativa de modificar device estático do TOML: {}", mac);
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

                if let Some(v4_opt) = v4_static {
                    let new_state = match v4_opt {
                        Some(ip) => IPv4State::Static(ip),
                        None => IPv4State::None,
                    };
                    if dev.v4 != new_state {
                        dev.v4 = new_state;
                        changed = true;
                    }
                }

                if let Some(v6_opt) = v6_suffix {
                    // Suffix update from CLI. If we have multiple V6 states, we should probably
                    // replace the static one or add it.
                    let new_state = v6_opt.map(IPv6State::Static);

                    let mut found = false;
                    if let Some(ns) = &new_state {
                        for state in &mut dev.v6 {
                            if matches!(state, IPv6State::Static(_)) {
                                if state != ns {
                                    *state = ns.clone();
                                    changed = true;
                                }
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            dev.v6.push(ns.clone());
                            changed = true;
                        }
                    } else {
                        // Remove static v6
                        let initial_len = dev.v6.len();
                        dev.v6.retain(|s| !matches!(s, IPv6State::Static(_)));
                        if dev.v6.len() != initial_len {
                            changed = true;
                        }
                    }
                }

                if changed {
                    dev.origin = Origin::Cli;
                    dev.managed_at = Some(SystemTime::now());
                    dev.last_seen = SystemTime::now();

                    // Sync static_entries for legacy components
                    let hostname = dev.hostname.clone();
                    let v4_ip = match dev.v4 {
                        IPv4State::Static(ip) => Some(ip),
                        _ => None,
                    };
                    let v6_suffix = dev.v6.iter().find_map(|s| {
                        if let IPv6State::Static(suffix) = s {
                            Some(suffix.clone())
                        } else {
                            None
                        }
                    });

                    self.static_entries.insert(
                        mac,
                        StaticEntry {
                            mac,
                            hostname,
                            v4_ip,
                            v6_suffix,
                        },
                    );
                }
                changed
            }

            DeviceUpdate::SlaacCleared { mac } => {
                if let Some(dev) = self.devices.get_mut(&mac) {
                    let initial_len = dev.v6.len();
                    dev.v6.retain(|s| !matches!(s, IPv6State::Slaac(_)));
                    return dev.v6.len() != initial_len;
                }
                false
            }

            DeviceUpdate::LeaseReleased { mac } => {
                if let Some(dev) = self.devices.get_mut(&mac) {
                    let mut changed = false;
                    if !matches!(dev.v4, IPv4State::None) {
                        dev.v4 = IPv4State::None;
                        changed = true;
                    }
                    let initial_v6_len = dev.v6.len();
                    dev.v6.retain(|s| !matches!(s, IPv6State::Dynamic(_)));
                    if dev.v6.len() != initial_v6_len {
                        changed = true;
                    }
                    return changed;
                }
                false
            }

            DeviceUpdate::IpDeleted { ip } => {
                let mut changed = false;
                if let std::net::IpAddr::V6(ip6) = ip
                    && self.ndp_cache.remove(&ip6).is_some()
                {
                    changed = true;
                }

                for dev in self.devices.values_mut() {
                    match ip {
                        std::net::IpAddr::V6(ip6) => {
                            let initial_len = dev.v6.len();
                            dev.v6
                                .retain(|s| !matches!(s, IPv6State::Slaac(a) if *a == ip6));
                            if dev.v6.len() != initial_len {
                                changed = true;
                            }
                        }
                        std::net::IpAddr::V4(ip4) => {
                            if let Some(pos) = dev.seen_v4.iter().position(|&x| x == ip4) {
                                dev.seen_v4.remove(pos);
                                changed = true;
                            }
                        }
                    }
                }
                changed
            }
        };

        // -------------------------------------------------------------------
        // ⚡ RECONSTRUÇÃO AUTOMÁTICA DOS ÍNDICES (Otimização do DNS)
        // -------------------------------------------------------------------
        // Se o estado mudou (novo device, lease expirado, SLAAC rotacionado),
        // atualizamos os índices O(1) para garantir que o DNS acerte de primeira.
        if changed {
            self.rebuild_dns_indices();
        }

        changed
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

            let v6_suffix = e.v6_suffix.as_ref().and_then(|s| {
                Ipv6AddrOrSuffix::parse(s).or_else(|| {
                    warn!("Invalid v6_suffix for {}: '{s}'", e.hostname);
                    None
                })
            });

            let static_entry = StaticEntry {
                mac,
                hostname: e.hostname.clone(),
                v4_ip,
                v6_suffix: v6_suffix.clone(),
            };

            info!("  Static device: {} → {} (v4={:?})", mac, e.hostname, v4_ip);
            self.static_entries.insert(mac, static_entry);

            // Pre-popula o device para que hostname resolva imediatamente
            let dev = self.get_or_insert(mac);
            dev.hostname.clone_from(&e.hostname);
            if let Some(ip) = v4_ip {
                dev.v4 = IPv4State::Static(ip);
            }
            if let Some(suf) = v6_suffix {
                dev.v6.push(IPv6State::Static(suf));
            }
            dev.origin = Origin::Toml;
        }

        // Após carregar todos os dispositivos estáticos, construa o índice inicial
        self.rebuild_dns_indices();
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

    /// Recupera o DUID associado a um MAC, se já tiver sido aprendido.
    ///
    /// Útil no `DHCPv6` para reutilizar o DUID existente num Renew/Rebind
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

        // Limpa leases órfãos expirados
        let initial_orphaned_len = self.orphaned_v6.len();
        self.orphaned_v6.retain(|_, (_, _, expires)| *expires > now);
        if self.orphaned_v6.len() != initial_orphaned_len {
            changed = true;
        }

        let macs: Vec<MacAddr> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut remove_device = false;
            if let Some(dev) = self.devices.get_mut(&mac) {
                // V4 expiration
                if let IPv4State::Dynamic(lease) = &dev.v4
                    && lease.expires < now
                {
                    dev.v4 = IPv4State::None;
                    changed = true;
                }
                // V6 expiration
                let initial_v6_len = dev.v6.len();
                dev.v6.retain(|state| match state {
                    IPv6State::Dynamic(lease) => lease.expires > now,
                    _ => true,
                });
                if dev.v6.len() != initial_v6_len {
                    changed = true;
                }

                let initial_prefixes_len = dev.v6_prefixes.len();
                dev.v6_prefixes.retain(|p| p.expires > now);
                if dev.v6_prefixes.len() != initial_prefixes_len {
                    changed = true;
                }

                if !dev.is_static()
                    && matches!(dev.v4, IPv4State::None)
                    && dev.v6.is_empty()
                    && dev.v6_prefixes.is_empty()
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

        if changed {
            self.rebuild_dns_indices();
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

    // -----------------------------------------------------------------------
    // Índices de Alta Performance para o DNS (Hot Path)
    // -----------------------------------------------------------------------

    /// Reconstrói os índices O(1) do DNS do zero.
    /// Isso garante que não teremos IPs ou Hostnames fantasmas presos no cache
    /// após expirações de lease ou rotações de SLAAC.
    pub(crate) fn rebuild_dns_indices(&mut self) {
        self.name_index.clear();
        self.ip_index.clear();

        for (&mac, device) in &self.devices {
            let _static_entry = self.static_entries.get(&mac);

            // 1. Indexa o hostname explícito (sempre em minúsculas)
            if !device.hostname.is_empty() {
                self.name_index
                    .insert(device.hostname.to_ascii_lowercase(), mac);
            }

            // 2. Indexa o fallback obrigatório (host-<mac>)
            let fallback =
                format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase();
            self.name_index.insert(fallback, mac);

            // 3. Indexa IPv4 (Dinâmico e Estático)
            if let Some(ip) = device.v4.ip() {
                self.ip_index.insert(IpAddr::V4(ip), mac);
            }

            // 4. Indexa IPv6 (Dinâmico DHCPv6, SLAAC e Estático Full)
            for state in &device.v6 {
                if let Some(ip) = state.ip() {
                    self.ip_index.insert(IpAddr::V6(ip), mac);
                }
            }

            // Nota: IPs com sufixos estáticos (ex: ::10) compostos com ULA/GUA
            // não estão sendo indexados aqui porque dependem da `DnsConfig` (o prefixo real da rede).
        }

        self.name_index.shrink_to_fit();
        self.ip_index.shrink_to_fit();

        debug!(
            "[state] Índices DNS reconstruídos: {} nomes, {} IPs",
            self.name_index.len(),
            self.ip_index.len()
        );
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
        assert_eq!(dev.v4.ip().unwrap(), ip);
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
            dev.origin = Origin::Toml;
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

        assert_eq!(table.devices().next().unwrap().v6.len(), 2);
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
        assert!(table.devices().next().unwrap().v6.is_empty());
        // Limpar de novo quando já está vazio — não dirty
        assert!(!table.apply_update(DeviceUpdate::SlaacCleared { mac }));
    }

    #[test]
    fn apply_update_lease_released() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let now = SystemTime::now();

        table.apply_update(DeviceUpdate::V4LeaseGranted {
            mac,
            ip: "192.168.1.10".parse().unwrap(),
            expires: now,
        });
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: Some(mac),
            duid: Duid::new(vec![1]),
            iaid: 1,
            ip: "fd97::1".parse().unwrap(),
            expires: now,
        });

        let dev = table.devices.get(&mac).unwrap();
        assert!(matches!(dev.v4, IPv4State::Dynamic(_)));
        assert_eq!(dev.v6.len(), 1);

        assert!(table.apply_update(DeviceUpdate::LeaseReleased { mac }));
        let dev = table.devices.get(&mac).unwrap();
        assert!(matches!(dev.v4, IPv4State::None));
        assert!(dev.v6.is_empty());

        // Repeated release should not be dirty
        assert!(!table.apply_update(DeviceUpdate::LeaseReleased { mac }));
    }

    #[test]
    fn apply_update_duid_associated() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let duid = Duid::new(vec![1, 2, 3, 4]);

        table.get_or_insert(mac).hostname = "DuidHost".to_string();
        assert!(table.apply_update(DeviceUpdate::DuidAssociated {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 1,
        }));

        let found = table.find_by_duid(&duid).expect("deve encontrar via DUID");
        assert_eq!(found.hostname, "DuidHost");

        // Mesmo DUID novamente — não dirty
        assert!(!table.apply_update(DeviceUpdate::DuidAssociated {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 1,
        }));
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
        dev.v4 = IPv4State::Dynamic(V4Lease {
            ip: "192.168.0.2".parse().unwrap(),
            expires: past,
        });
        dev.v6.push(IPv6State::Dynamic(V6Lease {
            ip: "fd00::1".parse().unwrap(),
            expires: future,
            iaid: 1,
        }));

        assert!(table.expire_stale());

        let dev_after = table.devices().next().unwrap();
        assert!(
            matches!(dev_after.v4, IPv4State::None),
            "V4 expirado deve ser removido"
        );
        assert_eq!(dev_after.v6.len(), 1, "V6 no futuro deve ser mantido");
    }

    #[test]
    fn test_orphaned_v6_promotion() {
        let mut table = DeviceTable::new();
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        let ip = "fd97::dead:beef".parse().unwrap();
        let duid = Duid::new(vec![0xaa, 0xbb]);
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        // 1. Lease concedido sem MAC (órfão)
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: None,
            duid: duid.clone(),
            iaid: 100,
            ip,
            expires,
        });

        // Não deve existir device ainda
        assert!(!table.devices.contains_key(&mac));
        assert!(!table.orphaned_v6.is_empty());

        // 2. NDP visto para o mesmo IP -> Promove
        let changed = table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
        assert!(changed);

        // Agora deve existir o device com o DUID e IP corretos
        let dev = table.devices.get(&mac).expect("Device deve existir");
        assert_eq!(dev.duid.as_ref(), Some(&duid));
        assert_eq!(dev.v6[0].ip().unwrap(), ip);
        assert!(table.orphaned_v6.is_empty());
    }

    #[test]
    fn test_cli_host_updated_sync() {
        let mut table = DeviceTable::new();
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);

        // 1. Initial discovery (Empty hostname)
        table.apply_update(DeviceUpdate::NdpSeen {
            mac,
            ip: "fe80::1".parse().unwrap(),
        });

        // 2. Update via CLI (Hostname + Static V4)
        let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
            mac,
            hostname: Some(Some("cli-host".to_string())),
            v4_static: Some(Some("192.168.1.10".parse().unwrap())),
            v6_suffix: Some(Some(Ipv6AddrOrSuffix::parse("::10").unwrap())),
        });

        assert!(changed);
        let dev = table.devices.get(&mac).unwrap();
        assert_eq!(dev.hostname, "cli-host");
        assert!(
            matches!(dev.v4, IPv4State::Static(ip) if ip == "192.168.1.10".parse::<Ipv4Addr>().unwrap())
        );
        assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Static(Ipv6AddrOrSuffix::Suffix(b)) if *b == [0,0,0,0,0,0,0,0x10])));
        assert!(dev.is_static());

        // 3. Verify static_entries sync
        let entry = table
            .static_entries
            .get(&mac)
            .expect("Should have static entry");
        assert_eq!(entry.hostname, "cli-host");
        assert_eq!(entry.v4_ip, Some("192.168.1.10".parse().unwrap()));
        assert!(
            matches!(entry.v6_suffix, Some(Ipv6AddrOrSuffix::Suffix(b)) if b == [0,0,0,0,0,0,0,0x10])
        );

        // 4. Partial update (Only hostname)
        let changed = table.apply_update(DeviceUpdate::CliHostUpdated {
            mac,
            hostname: Some(Some("new-name".to_string())),
            v4_static: None, // No change
            v6_suffix: None, // No change
        });

        assert!(changed);
        let entry = table.static_entries.get(&mac).unwrap();
        assert_eq!(entry.hostname, "new-name");
        assert_eq!(entry.v4_ip, Some("192.168.1.10".parse().unwrap())); // Preserved
    }

    #[test]
    fn test_ip_deleted_cleanup() {
        let mut table = DeviceTable::new();
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let ip: Ipv6Addr = "fd00::1".parse().unwrap();

        // 1. Setup: Add IP to NDP cache and SLAAC list
        table.apply_update(DeviceUpdate::NdpSeen { mac, ip });
        table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });

        let dev = table.devices.get(&mac).unwrap();
        assert!(
            dev.v6
                .iter()
                .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip))
        );
        assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));

        // 2. Delete IP
        let changed = table.apply_update(DeviceUpdate::IpDeleted { ip: ip.into() });
        assert!(changed);

        // 3. Verify cleanup
        assert!(table.get_mac_from_ndp_cache(&ip).is_none());
        let dev = table.devices.get(&mac).unwrap();
        assert!(
            !dev.v6
                .iter()
                .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip))
        );
    }

    #[test]
    fn test_multiple_iaids_and_prefixes() {
        let mut table = DeviceTable::new();
        let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let duid = Duid::new(vec![1, 2, 3]);
        let now = SystemTime::now();
        let future = now + std::time::Duration::from_secs(3600);

        // 1. Atribui primeiro IP (IAID 10)
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 10,
            ip: "fd00::10".parse().unwrap(),
            expires: future,
        });

        // 2. Atribui segundo IP (IAID 20)
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 20,
            ip: "fd00::20".parse().unwrap(),
            expires: future,
        });

        // 3. Atribui primeiro prefixo (IAID 100)
        table.apply_update(DeviceUpdate::V6PrefixAssigned {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 100,
            prefix: "2001:db8:1::".parse().unwrap(),
            len: 64,
            expires: future,
        });

        // 4. Atribui segundo prefixo (IAID 200)
        table.apply_update(DeviceUpdate::V6PrefixAssigned {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 200,
            prefix: "2001:db8:2::".parse().unwrap(),
            len: 64,
            expires: future,
        });

        let dev = table.devices.get(&mac).unwrap();
        assert_eq!(dev.v6.len(), 2, "Deve ter 2 endereços dinâmicos");
        assert_eq!(dev.v6_prefixes.len(), 2, "Deve ter 2 prefixos");

        // 5. Atualiza um deles (mesmo IAID, novo IP) -> Deve substituir
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 10,
            ip: "fd00::11".parse().unwrap(),
            expires: future,
        });

        let dev = table.devices.get(&mac).unwrap();
        assert_eq!(
            dev.v6.len(),
            2,
            "Ainda deve ter 2 endereços (um foi substituído)"
        );
        assert!(dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == "fd00::11".parse::<Ipv6Addr>().unwrap())));
        assert!(!dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == "fd00::10".parse::<Ipv6Addr>().unwrap())));

        // 6. Expiração parcial
        let past = now - std::time::Duration::from_secs(10);
        table.apply_update(DeviceUpdate::V6PrefixAssigned {
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 100,
            prefix: "2001:db8:1::".parse().unwrap(),
            len: 64,
            expires: past,
        });

        assert!(table.expire_stale());
        let dev = table.devices.get(&mac).unwrap();
        assert_eq!(
            dev.v6_prefixes.len(),
            1,
            "Somente o prefixo IAID 200 deve restar"
        );
        assert_eq!(dev.v6_prefixes[0].iaid, 200);
    }

    #[test]
    fn apply_update_duid_associated_resolves_orphan() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let duid = Duid::generate_ll_from_mac([1, 2, 3, 4, 5, 6]);
        let iaid = 42;
        let ip: Ipv6Addr = "fd00::dead:beef".parse().unwrap();
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        // 1. Recebe um lease sem MAC (órfão)
        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac: None,
            duid: duid.clone(),
            iaid,
            ip,
            expires,
        });

        assert!(table.orphaned_v6.contains_key(&ip));
        assert!(!table.devices.contains_key(&mac));

        // 2. Recebe associação DUID+IAID+MAC (ex: via Solicit que precedeu o Request, ou via DB)
        let changed = table.apply_update(DeviceUpdate::DuidAssociated {
            mac: Some(mac),
            duid: duid.clone(),
            iaid,
        });

        assert!(changed);
        assert!(
            !table.orphaned_v6.contains_key(&ip),
            "Órfão deveria ter sido resolvido"
        );

        let dev = table
            .devices
            .get(&mac)
            .expect("Device deve ter sido criado");
        assert_eq!(dev.duid.as_ref(), Some(&duid));
        assert!(
            dev.v6
                .iter()
                .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
        );
    }
}
