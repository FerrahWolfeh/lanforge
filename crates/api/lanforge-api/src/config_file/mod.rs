use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::traffic::TrafficConfig;
use serde::{Deserialize, Serialize};

pub mod convert;
pub mod dns;
pub mod duration;
pub mod effective;
pub mod hash;
pub mod hosts;
pub mod patch;
pub mod section;
pub mod sections;

pub use convert::DhcpSettings;
pub use dns::{
    DnsFile, DnsRewriteItem, DnsRewriteTable, DnsRewriteValue, DnsSettings, DnsUpstreamFile,
    NamedUpstream,
};
pub use duration::HumanDuration;
pub use effective::{
    RaInputs, add_default_ra_prefixes, effective_firewall, effective_ra, log_issues,
    set_aside_issues,
};
pub use hash::section_hashes;
pub use hosts::StaticHost;
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
    /// The PPPoE client's own type: this file is its only source (config-storage step 2).
    pub pppoe: PppoeConfig,
    #[serde(default)]
    /// NIC tuning and SQM: the traffic service's own type, file-owned like `pppoe`.
    pub traffic: TrafficConfig,
    /// Static hosts, in file order (see `HostFileEntry`).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "sections::named_tables"
    )]
    pub hosts: Vec<(String, HostFileEntry)>,
}

impl ConfigFile {
    /// Parses a TOML configuration string into a strongly-typed `ConfigFile`.
    pub fn parse(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Parses like [`Self::parse`], but a file-owned section (`SectionSet::FILE_OWNED`) that does
    /// not fit its type is set aside instead of failing the whole file: it takes its default and
    /// is returned with the error. One wrong value in `[firewall]` must not take DHCP and DNS down
    /// with it. A file that is not TOML at all, or a wrong value elsewhere, is still an error.
    pub fn parse_lenient(content: &str) -> Result<(Self, Vec<(Section, String)>), toml::de::Error> {
        let first_error = match Self::parse(content) {
            Ok(cfg) => return Ok((cfg, Vec::new())),
            Err(e) => e,
        };
        let Ok(mut doc) = content.parse::<toml_edit::DocumentMut>() else {
            return Err(first_error);
        };
        let mut set_aside = Vec::new();
        for sec in Section::ALL {
            if !SectionSet::FILE_OWNED.contains(sec.as_bitflag()) {
                continue;
            }
            let Some(item) = doc.get(sec.name()) else {
                continue;
            };
            let mut alone = toml_edit::DocumentMut::new();
            alone.insert(sec.name(), item.clone());
            if let Err(e) = Self::parse(&alone.to_string()) {
                doc.remove(sec.name());
                set_aside.push((sec, e.message().trim().to_string()));
            }
        }
        if set_aside.is_empty() {
            return Err(first_error);
        }
        Self::parse(&doc.to_string()).map(|cfg| (cfg, set_aside))
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

/// Writes `sections` of `cfg` into the config file at `path`, keeping everything else in the
/// file (other sections, comments, formatting). A file that cannot be read or parsed is an
/// error, never replaced: the caller must not apply a change it could not persist.
pub fn persist_sections(
    path: &std::path::Path,
    cfg: &ConfigFile,
    sections: SectionSet,
) -> Result<(), std::io::Error> {
    use std::io::{Error, ErrorKind};
    let text = std::fs::read_to_string(path)?;
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("invalid TOML: {e}")))?;
    patch_sections(&mut doc, cfg, sections).map_err(|e| Error::other(e.to_string()))?;
    write_toml_atomically(path, &doc.to_string())
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
mod roundtrip_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_file_owned_section_is_set_aside_not_the_whole_file() {
        let text = "[system]\niface = \"lan0\"\n\n[pppoe]\nmru = \"big\"\n\n[traffic.sqm]\nenabled = true\n";
        assert!(ConfigFile::parse(text).is_err());

        let (cfg, set_aside) = ConfigFile::parse_lenient(text).unwrap();
        assert_eq!(cfg.system.iface, "lan0", "the rest of the file is read");
        assert!(cfg.traffic.sqm.enabled);
        assert_eq!(cfg.pppoe, PppoeConfig::default());
        assert_eq!(set_aside.len(), 1);
        assert_eq!(set_aside[0].0, Section::Pppoe);
        assert!(
            set_aside[0].1.contains("mru") || set_aside[0].1.contains("invalid"),
            "{:?}",
            set_aside[0].1
        );
    }

    #[test]
    fn errors_outside_file_owned_sections_still_fail() {
        assert!(ConfigFile::parse_lenient("[system]\niface = 3\n").is_err());
        assert!(ConfigFile::parse_lenient("[pppoe\n").is_err());
    }

    #[test]
    fn test_roundtrip_lossless() {
        let mut cfg = ConfigFile::default();
        cfg.system.iface = "end0".to_string();
        cfg.system.search_domains = vec!["lan".to_string(), "home.arpa".to_string()];

        cfg.dhcp.v4.pools.push((
            "lan".to_string(),
            Dhcpv4PoolFile {
                range: "192.168.1.100-192.168.1.200".to_string(),
                lease: Some(HumanDuration(43200)),
                router: Some("192.168.1.1".parse().unwrap()),
                subnet_mask: Some("255.255.255.0".parse().unwrap()),
                dns: vec!["192.168.1.1".parse().unwrap()],
                ..Default::default()
            },
        ));

        cfg.dns.rewrites.push((
            "nas.lan".to_string(),
            DnsRewriteValue(vec![DnsRewriteItem::Answer("192.168.1.10".to_string())]),
        ));

        cfg.hosts.push((
            "nas".to_string(),
            HostFileEntry {
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                v4: Some("192.168.1.10".parse().unwrap()),
                v6_suffix: Some("::10".to_string()),
                v6: None,
                dns: None,
                ..Default::default()
            },
        ));

        let rendered = cfg.render_full().unwrap();
        let parsed = ConfigFile::parse(&rendered).unwrap();
        assert_eq!(cfg, parsed);
    }
}
