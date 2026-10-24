use super::ConfigFile;
use super::section::{Section, SectionSet};
use toml_edit::{DocumentMut, Item};

fn reindex_table_positions(table: &mut toml_edit::Table, next_pos: &mut isize) {
    table.set_position(Some(*next_pos));
    *next_pos += 1;
    for (_, item) in table.iter_mut() {
        match item {
            toml_edit::Item::Table(sub) => reindex_table_positions(sub, next_pos),
            toml_edit::Item::ArrayOfTables(arr) => {
                for sub in arr.iter_mut() {
                    reindex_table_positions(sub, next_pos);
                }
            }
            _ => {}
        }
    }
}

/// Patches only dirty sections into the `DocumentMut`, preserving comments, ordering, and
/// formatting of all untouched sections.
pub fn patch_sections(
    doc: &mut DocumentMut,
    cfg: &ConfigFile,
    dirty: SectionSet,
) -> Result<(), String> {
    for sec in Section::ALL {
        if !dirty.contains(sec.as_bitflag()) {
            continue;
        }

        let key = sec.name();
        let section_toml = match sec {
            Section::System => toml::to_string(&cfg.system),
            Section::Database => toml::to_string(&cfg.database),
            Section::Api => toml::to_string(&cfg.api),
            Section::Http => toml::to_string(&cfg.http),
            Section::Monitor => toml::to_string(&cfg.monitor),
            Section::Mdns => toml::to_string(&cfg.mdns),
            Section::Tftp => toml::to_string(&cfg.tftp),
            Section::Dhcp => toml::to_string(&cfg.dhcp),
            Section::Ra => toml::to_string(&cfg.ra),
            Section::Dns => toml::to_string(&cfg.dns),
            Section::Adblock => toml::to_string(&cfg.adblock),
            Section::Firewall => toml::to_string(&cfg.firewall),
            Section::Pppoe => toml::to_string(&cfg.pppoe),
            Section::Traffic => toml::to_string(&cfg.traffic),
            Section::Hosts => {
                #[derive(serde::Serialize)]
                struct HostsWrapper<'a> {
                    hosts: &'a std::collections::BTreeMap<String, super::sections::HostFileEntry>,
                }
                let wrapper = HostsWrapper { hosts: &cfg.hosts };
                toml::to_string(&wrapper)
            }
        }
        .map_err(|e| format!("Failed to serialize section '{key}': {e}"))?;

        let parsed: DocumentMut = section_toml
            .parse()
            .map_err(|e| format!("Failed to parse serialized section '{key}': {e}"))?;

        if sec == Section::Hosts {
            if let Some(item) = parsed.get("hosts") {
                doc.insert("hosts", item.clone());
            } else {
                doc.remove("hosts");
            }
        } else {
            let mut table = parsed.into_table();
            // If the section table contains only subtables without root scalar values
            // (e.g. [dhcp] containing only [dhcp.v4] and [dhcp.v6]), mark it implicit
            // so toml_edit does not emit an empty, dead `[dhcp]` header.
            if sec == Section::Dhcp {
                table.set_implicit(true);
            }
            doc.insert(key, Item::Table(table));
        }
    }

    // Sort top-level sections in canonical Section::ALL order so that updates from
    // the API/worker don't scatter newly updated sections across the file.
    let mut reordered = DocumentMut::new();
    for sec in Section::ALL {
        let name = sec.name();
        if let Some((k, item)) = doc.remove_entry(name) {
            reordered.insert(&k, item);
        }
    }
    // Any remaining custom or unknown top-level keys
    let remaining_keys: Vec<String> = doc.iter().map(|(k, _)| k.to_string()).collect();
    for k in remaining_keys {
        if let Some((key, item)) = doc.remove_entry(&k) {
            reordered.insert(&key, item);
        }
    }

    // Re-index all table positions in strict document traversal order.
    // toml_edit uses `table.position()` internally to sort table headers on serialization.
    // Without reindexing, tables parsed from different fragments retain conflicting positions,
    // leading to subtables being interleaved across unrelated sections (e.g. hosts inside ra).
    let mut next_pos = 0;
    reindex_table_positions(reordered.as_table_mut(), &mut next_pos);

    // Ensure clean empty line separation between top-level sections
    for (idx, (_, item)) in reordered.iter_mut().enumerate() {
        if idx == 0 {
            continue;
        }
        if let Item::Table(t) = item {
            if t.is_implicit() {
                if let Some((_, first_child)) = t.iter_mut().next() {
                    match first_child {
                        Item::Table(ct) => ensure_leading_newline(ct.decor_mut()),
                        Item::ArrayOfTables(arr) => {
                            if let Some(ct) = arr.iter_mut().next() {
                                ensure_leading_newline(ct.decor_mut());
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                ensure_leading_newline(t.decor_mut());
            }
        }
    }

    *doc = reordered;

    Ok(())
}

fn ensure_leading_newline(decor: &mut toml_edit::Decor) {
    let p = decor.prefix().and_then(|s| s.as_str()).unwrap_or("");
    if !p.starts_with('\n') {
        decor.set_prefix(format!("\n{p}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_sections_preserves_comments() {
        let initial_toml = r#"# Main Lanforge configuration file
# Managed by admin

[system]
# LAN interface comment
iface = "end0"
search_domains = ["lan"]

# Database comment
[database]
config_path = "/var/lib/lanforge/config.redb"

[firewall.zones.lan]
interfaces = ["br0"]
input = "accept"
"#;

        let mut doc: DocumentMut = initial_toml.parse().unwrap();
        let mut cfg = ConfigFile::default();
        cfg.system.iface = "end0".to_string();
        cfg.system.search_domains = vec!["lan".to_string()];
        cfg.firewall.zones.insert(
            "lan".to_string(),
            super::super::sections::FirewallZoneFile {
                interfaces: vec!["br0".to_string(), "lan0".to_string()],
                input: "accept".to_string(),
                forward: "accept".to_string(),
                masquerade: false,
                mtu_fix: false,
                open_ports: vec!["22/tcp".to_string()],
                allowed_subnets: Vec::new(),
            },
        );

        // Patch ONLY firewall
        patch_sections(&mut doc, &cfg, SectionSet::FIREWALL).unwrap();

        let output = doc.to_string();
        assert!(output.contains("# Main Lanforge configuration file"));
        assert!(output.contains("# Managed by admin"));
        assert!(output.contains("# LAN interface comment"));
        assert!(output.contains("# Database comment"));
        assert!(output.contains("lan0"));
        assert!(output.contains("22/tcp"));
    }

    #[test]
    fn test_patch_sections_dhcp_no_empty_header_and_order() {
        let initial_toml = r#"[system]
iface = "lan0"

[firewall]
enabled = true
"#;

        let mut doc: DocumentMut = initial_toml.parse().unwrap();
        let mut cfg = ConfigFile::default();
        cfg.system.iface = "lan0".to_string();
        cfg.dhcp.v4.enabled = true;
        cfg.dhcp.v4.pools.insert(
            "lan".to_string(),
            super::super::sections::Dhcpv4PoolFile {
                range: "192.168.1.10-192.168.1.50".to_string(),
                lease: None,
                router: None,
                subnet_mask: None,
                dns: Vec::new(),
            },
        );

        patch_sections(&mut doc, &cfg, SectionSet::DHCP).unwrap();

        let output = doc.to_string();
        // [dhcp] empty table header should NOT appear
        assert!(!output.contains("\n[dhcp]\n"));
        assert!(output.contains("[dhcp.v4]"));
        // DHCP section should be ordered between system and firewall
        let sys_pos = output.find("[system]").unwrap();
        let dhcp_pos = output.find("[dhcp.v4]").unwrap();
        let fw_pos = output.find("[firewall]").unwrap();
        assert!(sys_pos < dhcp_pos);
        assert!(dhcp_pos < fw_pos);
    }

    #[test]
    fn test_patch_subtables_not_interleaved() {
        let initial_toml = r#"[system]
iface = "lan0"

[database]
config_path = "/var/lib/lanforge/config.redb"

[ra.prefixes.auto_gua]
source = "auto_gua"

[ra.prefixes.auto_ula]
source = "auto_ula"

[ra.dnssl.lan]
domains = ["lan"]
"#;

        let mut doc: DocumentMut = initial_toml.parse().unwrap();
        let mut cfg = ConfigFile::default();
        cfg.system.iface = "lan0".to_string();
        cfg.hosts.insert(
            "TL-SG105E".to_string(),
            super::super::sections::HostFileEntry {
                mac: Some("68:ff:7b:45:49:a2".to_string()),
                v4: Some("192.168.3.4".parse().unwrap()),
                v6_suffix: None,
                v6: None,
                dns: Some(true),
            },
        );
        cfg.hosts.insert(
            "archie".to_string(),
            super::super::sections::HostFileEntry {
                mac: Some("bc:fc:e7:8a:a9:73".to_string()),
                v4: Some("192.168.0.2".parse().unwrap()),
                v6_suffix: None,
                v6: None,
                dns: Some(true),
            },
        );

        // Patch ONLY hosts into an existing document that has RA and database
        patch_sections(&mut doc, &cfg, SectionSet::HOSTS).unwrap();

        let output = doc.to_string();

        let db_pos = output.find("[database]").unwrap();
        let ra_gua_pos = output.find("[ra.prefixes.auto_gua]").unwrap();
        let ra_ula_pos = output.find("[ra.prefixes.auto_ula]").unwrap();
        let ra_dnssl_pos = output.find("[ra.dnssl.lan]").unwrap();
        let host1_pos = output.find("[hosts.TL-SG105E]").unwrap();
        let host2_pos = output.find("[hosts.archie]").unwrap();

        // 1. Database is before RA
        assert!(db_pos < ra_gua_pos);
        // 2. All RA subtables stay contiguous before any hosts table
        assert!(ra_gua_pos < ra_ula_pos);
        assert!(ra_ula_pos < ra_dnssl_pos);
        assert!(ra_dnssl_pos < host1_pos);
        assert!(host1_pos < host2_pos);
    }
}
