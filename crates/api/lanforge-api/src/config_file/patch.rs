use super::ConfigFile;
use super::section::{Section, SectionSet};
use toml_edit::{DocumentMut, Item};

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
            let table = parsed.into_table();
            doc.insert(key, Item::Table(table));
        }
    }

    Ok(())
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
}
