use super::ConfigFile;
use super::section::Section;
use serde::Serialize;
use std::collections::BTreeMap;

fn hash_section<T: Serialize>(value: &T) -> u64 {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    lanforge_crypto::content_hash64(&bytes)
}

/// Computes per-section 64-bit deterministic hashes for change detection.
#[must_use]
pub fn section_hashes(cfg: &ConfigFile) -> BTreeMap<Section, u64> {
    let mut map = BTreeMap::new();
    map.insert(Section::System, hash_section(&cfg.system));
    map.insert(Section::Database, hash_section(&cfg.database));
    map.insert(Section::Api, hash_section(&cfg.api));
    map.insert(Section::Http, hash_section(&cfg.http));
    map.insert(Section::Monitor, hash_section(&cfg.monitor));
    map.insert(Section::Mdns, hash_section(&cfg.mdns));
    map.insert(Section::Tftp, hash_section(&cfg.tftp));
    map.insert(Section::Dhcp, hash_section(&cfg.dhcp));
    map.insert(Section::Ra, hash_section(&cfg.ra));
    map.insert(Section::Dns, hash_section(&cfg.dns));
    map.insert(Section::Adblock, hash_section(&cfg.adblock));
    map.insert(Section::Firewall, hash_section(&cfg.firewall));
    map.insert(Section::Pppoe, hash_section(&cfg.pppoe));
    map.insert(Section::Traffic, hash_section(&cfg.traffic));
    map.insert(Section::Hosts, hash_section(&cfg.hosts));
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_hashes_stability() {
        let mut cfg1 = ConfigFile::default();
        cfg1.system.iface = "eth0".to_string();

        let mut cfg2 = ConfigFile::default();
        cfg2.system.iface = "eth0".to_string();

        let h1 = section_hashes(&cfg1);
        let h2 = section_hashes(&cfg2);
        assert_eq!(h1, h2);

        // Mutate one section
        cfg2.system.iface = "eth1".to_string();
        let h3 = section_hashes(&cfg2);
        assert_ne!(h1[&Section::System], h3[&Section::System]);
        // Untouched sections retain the exact same hash
        assert_eq!(h1[&Section::Database], h3[&Section::Database]);
        assert_eq!(h1[&Section::Dhcp], h3[&Section::Dhcp]);
        assert_eq!(h1[&Section::Firewall], h3[&Section::Firewall]);
    }
}
