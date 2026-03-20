//! DeviceTable e tipos centrais do lanforge.
//!
//! O modelo central é um Device — um dispositivo físico que pode ter v4, v6
//! e endereços SLAAC ao mesmo tempo. Indexado pelo MAC.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use crate::config::StaticDeviceCfg;
use crate::dhcp::v6::duid::Duid;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Endereço MAC de 6 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

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

    /// Construct from a raw 6-byte slice
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
#[derive(Debug, Clone)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: String,

    /// true = veio da config estática
    pub is_static: bool,
    pub duid: Option<Duid>,
    pub v4: Option<V4Lease>,
    pub v6: Option<V6Lease>,

    /// Endereços SLAAC observados via NDP.
    pub slaac: Vec<Ipv6Addr>,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    pub expires: SystemTime,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
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
// DeviceTable
// ---------------------------------------------------------------------------

/// Tabela de dispositivos — compartilhada via Arc<RwLock<..>>
#[derive(Debug, Clone)]
pub struct DeviceTable {
    pub(crate) devices: HashMap<MacAddr, Device>,
    duid_index: HashMap<Duid, MacAddr>,
    static_entries: HashMap<MacAddr, StaticEntry>,
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

    /// Load static device entries from the parsed TOML config.
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

            // Pre-populate device in the table so hostname resolves immediately
            let dev = self.get_or_insert(mac);
            dev.hostname = e.hostname.clone();
            dev.is_static = true;
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

    pub fn set_duid(&mut self, mac: MacAddr, duid: Duid) {
        if let Some(dev) = self.devices.get_mut(&mac) {
            dev.duid = Some(duid.clone());
        }
        self.duid_index.insert(duid, mac);
    }

    #[allow(dead_code)]
    pub fn find_by_duid(&self, duid: &Duid) -> Option<&Device> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Hostname efetivo: config estática > hostname dinâmico > None
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

    pub fn v6_suffix_for(&self, mac: &MacAddr) -> Option<&str> {
        self.static_entries
            .get(mac)
            .and_then(|e| e.v6_suffix.as_deref())
    }

    /// Record a SLAAC address for a device (avoids duplicates).
    pub fn record_slaac(&mut self, mac: MacAddr, addr: Ipv6Addr) {
        let dev = self.get_or_insert(mac);
        if !dev.slaac.contains(&addr) {
            dev.slaac.push(addr);
        }
        dev.last_seen = SystemTime::now();
    }

    /// Clear all SLAAC addresses for a device (called before re-scanning).
    pub fn clear_slaac(&mut self, mac: MacAddr) {
        if let Some(dev) = self.devices.get_mut(&mac) {
            dev.slaac.clear();
        }
    }

    /// Iterate over all known devices.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// Iterate over all static entries.
    pub fn static_entries(&self) -> impl Iterator<Item = &StaticEntry> {
        self.static_entries.values()
    }

    /// Atualiza o cache NDP com informações em tempo real do Netlink.
    pub fn update_ndp_cache(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        self.ndp_cache.insert(ip, (mac, SystemTime::now()));

        // Aproveitamos o evento do kernel para dar um "bump" no last_seen do dispositivo físico
        let dev = self.get_or_insert(mac);
        dev.last_seen = SystemTime::now();
    }

    /// Recupera o MAC associado a um IP via cache NDP.
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|(mac, _)| *mac)
    }

    /// Remove expired dynamic leases and inactive dynamic devices.
    pub fn expire_stale(&mut self) -> bool {
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(7 * 24 * 3600); // 7 days
        let ndp_max_age = std::time::Duration::from_secs(24 * 3600); // 1 dia para IP link-local
        let mut changed = false;

        // Limpa o cache NDP velho
        let initial_ndp_len = self.ndp_cache.len();
        self.ndp_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed().unwrap_or(std::time::Duration::ZERO) <= ndp_max_age
        });
        if self.ndp_cache.len() != initial_ndp_len {
            changed = true;
        }

        let macs: Vec<MacAddr> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut remove_device = false;
            if let Some(dev) = self.devices.get_mut(&mac) {
                // Expire v4
                if let Some(v4) = &dev.v4
                    && v4.expires < now
                {
                    dev.v4 = None;
                    changed = true;
                }
                // Expire v6
                if let Some(v6) = &dev.v6
                    && v6.expires < now
                {
                    dev.v6 = None;
                    changed = true;
                }
                // Check if device is entirely stale (dynamic and unseen for 7 days)
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
                tracing::debug!("[state] Removed stale dynamic device {}", mac);
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(MacAddr::parse("e0:d5:5e:e2:d4").is_none()); // 5 octetos
        assert!(MacAddr::parse("e0:d5:5e:e2:d4:89:ff").is_none()); // 7 octetos
    }

    #[test]
    fn hostname_static_overrides_dynamic() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        table.get_or_insert(mac).hostname = "dynamic".into();

        table.load_static_devices(&[StaticDeviceCfg {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "StaticName".into(),
            v4_ip: None,
            v6_suffix: None,
        }]);

        // O nome da config estática sempre tem precedência
        assert_eq!(table.hostname_for(&mac), Some("StaticName"));
    }

    #[test]
    fn record_slaac_deduplicates() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let addr: Ipv6Addr = "fd97::1234".parse().unwrap();

        table.record_slaac(mac, addr);
        table.record_slaac(mac, addr); // Tentativa de duplicar
        table.record_slaac(mac, "fd97::5678".parse().unwrap());

        let dev = table.devices().next().unwrap();
        assert_eq!(dev.slaac.len(), 2, "Não deveria duplicar IPs SLAAC iguais");
    }

    #[test]
    fn ndp_cache_stores_and_retrieves_mac() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        assert!(table.get_mac_from_ndp_cache(&ip).is_none());

        table.update_ndp_cache(ip, mac);
        assert_eq!(table.get_mac_from_ndp_cache(&ip), Some(mac));
    }

    #[test]
    fn duid_indexing_resolves_devices() {
        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let duid = Duid::new(vec![1, 2, 3, 4]);

        table.get_or_insert(mac).hostname = "DuidHost".to_string();
        table.set_duid(mac, duid.clone());

        let found = table
            .find_by_duid(&duid)
            .expect("Device deveria ser encontrado via DUID");
        assert_eq!(found.hostname, "DuidHost");
    }

    #[test]
    fn expire_stale_removes_old_leases_but_keeps_fresh_ones() {
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

        let changed = table.expire_stale();

        assert!(changed, "Deveria acusar mudança na tabela");

        let dev_after = table.devices().next().unwrap();
        assert!(
            dev_after.v4.is_none(),
            "O Lease V4 expirado deveria ter sido limpo"
        );
        assert!(
            dev_after.v6.is_some(),
            "O Lease V6 no futuro deve ser mantido"
        );
    }
}
