use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod convert;
pub mod duration;
pub mod hash;
pub mod patch;
pub mod section;
pub mod sections;

pub use duration::HumanDuration;
pub use hash::section_hashes;
pub use patch::patch_sections;
pub use section::{Section, SectionSet};
pub use sections::*;
pub use toml_edit;

/// Root configuration file representation for `lanforge.toml`.
///
/// Combines static system settings with dynamic subsystem configurations
/// using compact, human-named section maps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub system: SystemFile,
    #[serde(default)]
    pub database: DatabaseFile,
    #[serde(default)]
    pub api: ApiFile,
    #[serde(default)]
    pub http: HttpFile,
    #[serde(default)]
    pub monitor: MonitorFile,
    #[serde(default)]
    pub mdns: MdnsFile,
    #[serde(default)]
    pub tftp: TftpFile,
    #[serde(default)]
    pub dhcp: DhcpFile,
    #[serde(default)]
    pub ra: RaFile,
    #[serde(default)]
    pub dns: DnsFile,
    #[serde(default)]
    pub adblock: AdblockFile,
    #[serde(default)]
    pub firewall: FirewallFile,
    #[serde(default)]
    pub pppoe: PppoeFile,
    #[serde(default)]
    pub traffic: TrafficFile,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<String, HostFileEntry>,
}

impl ConfigFile {
    /// Parses a TOML configuration string into a strongly-typed `ConfigFile`.
    pub fn parse(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Renders the complete configuration as a well-formatted TOML string.
    pub fn render_full(&self) -> Result<String, toml::ser::Error> {
        let mut out = String::from(
            "# Lanforge Configuration File\n# Automatically synchronized by Lanforge\n\n",
        );
        let content = toml::to_string(self)?;
        out.push_str(&content);
        Ok(out)
    }
}

/// Atomically writes content to a file using a temporary file in the same directory.
pub fn write_toml_atomically(path: &std::path::Path, content: &str) -> Result<(), std::io::Error> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("lanforge.toml"),
        std::process::id()
    ));

    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_lossless() {
        let mut cfg = ConfigFile::default();
        cfg.system.iface = "end0".to_string();
        cfg.system.search_domains = vec!["lan".to_string(), "home.arpa".to_string()];

        cfg.dhcp.v4.pools.insert(
            "lan".to_string(),
            Dhcpv4PoolFile {
                range: "192.168.1.100-192.168.1.200".to_string(),
                lease: Some(HumanDuration(43200)),
                router: Some("192.168.1.1".parse().unwrap()),
                subnet_mask: Some("255.255.255.0".parse().unwrap()),
                dns: vec!["192.168.1.1".parse().unwrap()],
            },
        );

        cfg.dns.rewrites.insert(
            "nas.lan".to_string(),
            DnsRewriteFile {
                target: "192.168.1.10".to_string(),
                rtype: Some("A".to_string()),
            },
        );

        cfg.hosts.insert(
            "nas".to_string(),
            HostFileEntry {
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                v4: Some("192.168.1.10".parse().unwrap()),
                v6_suffix: Some("::10".to_string()),
                v6: None,
                dns: Some(true),
            },
        );

        let rendered = cfg.render_full().unwrap();
        let parsed = ConfigFile::parse(&rendered).unwrap();
        assert_eq!(cfg, parsed);
    }
}
