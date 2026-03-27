//! `DeviceUpdate` — a única forma de mudar estado de um Device.
//!
//! Contém o enum `DeviceUpdate` e a implementação de `apply_update` no
//! `DeviceTable`, que é a autoridade única para merging e precedência.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use tracing::{debug, warn};

use crate::device::{
    IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V4Lease, V6Lease, V6PrefixLease,
};
use crate::identifiers::{Duid, MacAddr};
use crate::state::DeviceTable;

// ---------------------------------------------------------------------------
// StaticEntry
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
// DeviceUpdate
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

    /// Remove um host completamente (usado para hosts estáticos/CLI).
    HostRemoved { mac: MacAddr },

    /// Libera formalmente os leases (v4 e v6) de um device via CLI.
    LeaseReleased { mac: MacAddr },

    /// Netlink detectou que um IP (v4 ou v6) foi removido do cache de vizinhos.
    IpDeleted { ip: std::net::IpAddr },

    /// Rebuild DNS indices
    RebuildDnsIndices,
}

// ---------------------------------------------------------------------------
// apply_update — autoridade única de merging
// ---------------------------------------------------------------------------

impl DeviceTable {
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
            DeviceUpdate::HostRemoved { mac } => {
                let mut changed = false;
                if let Some(dev) = self.devices.remove(&mac) {
                    if let Some(duid) = dev.duid {
                        self.duid_index.remove(&duid);
                    }
                    changed = true;
                }
                if self.static_entries.remove(&mac).is_some() {
                    changed = true;
                }
                changed
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
            DeviceUpdate::RebuildDnsIndices => {
                self.rebuild_dns_indices();
                false
            }
        };

        // ⚡ RECONSTRUÇÃO AUTOMÁTICA DOS ÍNDICES (Otimização do DNS)
        if changed {
            self.rebuild_dns_indices();
        }

        changed
    }

    // -----------------------------------------------------------------------
    // Inicialização (config estática)
    // -----------------------------------------------------------------------

    /// Insere um dispositivo estático já validado.
    /// Chamado pela orquestração durante o startup.
    pub fn add_static_device(
        &mut self,
        mac: MacAddr,
        hostname: String,
        v4_ip: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
    ) {
        let static_entry = StaticEntry {
            mac,
            hostname: hostname.clone(),
            v4_ip,
            v6_suffix: v6_suffix.clone(),
        };

        self.static_entries.insert(mac, static_entry);

        let dev = self.get_or_insert(mac);
        dev.hostname = hostname;

        if let Some(ip) = v4_ip {
            dev.v4 = IPv4State::Static(ip);
        }
        if let Some(suf) = v6_suffix {
            dev.v6.push(IPv6State::Static(suf));
        }
        dev.origin = Origin::Toml;
    }
}
