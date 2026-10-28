use std::path::{Path, PathBuf};

use crate::ClientContext;
use lanforge_api::api::SystemConfigExport;
use lanforge_api::config_file::{
    ConfigFile, SectionSet, patch_sections, persist_sections, toml_edit::DocumentMut,
    write_toml_atomically as api_write_toml_atomically,
};

/// Atomically writes content to a file using a temporary file in the same directory.
pub fn write_toml_atomically(path: &Path, content: &str) -> Result<(), std::io::Error> {
    api_write_toml_atomically(path, content)
}

/// Generates a well-formatted TOML configuration string from a `SystemConfigExport`.
/// If `existing_content` is provided, patches dirty sections while preserving user comments.
pub fn generate_toml_from_export(
    export: &SystemConfigExport,
    db_url: &str,
    existing_content: Option<&str>,
) -> String {
    let mut cfg = ConfigFile::from(export);
    if !db_url.is_empty() && db_url != "memory" {
        cfg.database.config_path = db_url.to_string();
    }

    if let Some(existing) = existing_content
        && let Ok(mut doc) = existing.parse::<DocumentMut>()
        && patch_sections(&mut doc, &cfg, SectionSet::DYNAMIC).is_ok()
    {
        return doc.to_string();
    }

    cfg.render_full().unwrap_or_default()
}

/// Whether a config change reached the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persisted {
    /// Written to the config file.
    File,
    /// The config file is read-only (or unknown): the change lives in memory only.
    MemoryOnly,
}

impl Persisted {
    /// The success message for a change of `what`.
    #[must_use]
    pub fn message(self, what: &str) -> String {
        match self {
            Self::File => format!("{what} updated successfully"),
            Self::MemoryOnly => format!(
                "{what} updated in memory only, not saved: the configuration file is read-only or not set"
            ),
        }
    }
}

impl ClientContext {
    /// Writes the `sections` set by `fill` into the config file (file-owned sections, see
    /// `phase-7-config-storage`). Call it **before** applying the change in memory: an error
    /// means nothing was written and the change must be rejected.
    pub fn persist_config_sections(
        &self,
        sections: SectionSet,
        fill: impl FnOnce(&mut ConfigFile),
    ) -> Result<Persisted, String> {
        if !self.ctx.is_config_writable() {
            return Ok(Persisted::MemoryOnly);
        }
        let Some(path) = self.ctx.config_path() else {
            return Ok(Persisted::MemoryOnly);
        };
        let mut cfg = ConfigFile::default();
        fill(&mut cfg);
        let _file_guard = self.ctx.config_file_lock();
        persist_sections(&path, &cfg, sections)
            .map(|()| Persisted::File)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Writes `fw` to `[firewall]` (see [`Self::persist_config_sections`]). Zones are keyed by
    /// name in the file, so a zone defined twice cannot be written and is refused.
    pub fn persist_firewall(
        &self,
        fw: &lanforge_types::network::firewall::FirewallConfig,
    ) -> Result<Persisted, String> {
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = fw.zones.iter().find(|z| !seen.insert(z.name.as_str())) {
            return Err(format!("zone '{}' is defined twice", dup.name));
        }
        self.persist_config_sections(SectionSet::FIREWALL, |file| {
            file.firewall = lanforge_api::config_file::FirewallFile::from_config(fw);
        })
    }

    /// Changes the DHCP options and/or pools: `change` edits the live settings, the result is
    /// written to `[dhcp]` and `[tftp]` (see [`Self::persist_config_sections`]) and then
    /// applied as the file now holds it (unnamed pools are named, repeated names made unique).
    /// A value the file form cannot hold (a pool whose first address is past its last, ...) is
    /// refused: nothing written, nothing applied.
    pub fn change_dhcp(
        &self,
        change: impl FnOnce(&mut lanforge_api::config_file::DhcpSettings),
    ) -> Result<Persisted, String> {
        let _serial = self.ctx.config_change_lock();
        let live = lanforge_api::config_file::DhcpSettings {
            options: self.ctx.get_dhcp_options(),
            v4_pools: self.ctx.get_dhcp_v4_pools(),
            v6_pools: self.ctx.get_dhcp_v6_pools(),
        };
        let mut wanted = live.clone();
        change(&mut wanted);
        let mut file = ConfigFile::default();
        file.set_dhcp_settings(&wanted);
        let (dhcp, issues) = file.dhcp_settings();
        if !issues.is_empty() {
            return Err(issues.join("; "));
        }
        let persisted = self.persist_config_sections(SectionSet::DHCP | SectionSet::TFTP, |f| {
            f.dhcp = file.dhcp;
            f.tftp = file.tftp;
        })?;
        let mut patch = lanforge_core::context::ConfigPatch::new();
        if dhcp.options != live.options {
            patch = patch.with_dhcp_options(dhcp.options);
        }
        if dhcp.v4_pools != live.v4_pools {
            patch = patch.with_dhcp_v4_pools(dhcp.v4_pools);
        }
        if dhcp.v6_pools != live.v6_pools {
            patch = patch.with_dhcp_v6_pools(dhcp.v6_pools);
        }
        let _ = self.ctx.apply_config(patch);
        Ok(persisted)
    }

    /// Changes the RA configuration: `change` edits the live one, the result is written to
    /// `[ra]` (see [`Self::persist_config_sections`]) and then applied as the file now holds it.
    /// The LAN interface the daemon fills in is not written (the file follows `[system] iface`).
    /// A value the file form cannot hold (a prefix address that is not IPv6, ...) is refused:
    /// nothing written, nothing applied.
    pub fn change_ra(
        &self,
        change: impl FnOnce(&mut lanforge_types::network::ra::RaServerConfig),
    ) -> Result<Persisted, String> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.ctx.get_ra_server_config();
        change(&mut wanted);
        let lan_iface = self.ctx.target_interface_name();
        if wanted.iface.is_some() && wanted.iface == lan_iface {
            wanted.iface = None;
        }
        let file = lanforge_api::config_file::RaFile::from_config(&wanted);
        let (mut ra, issues) = file.to_config();
        if !issues.is_empty() {
            return Err(issues.join("; "));
        }
        let persisted = self.persist_config_sections(SectionSet::RA, |f| f.ra = file)?;
        if ra.iface.is_none() {
            ra.iface = lan_iface;
        }
        self.ctx.update_ra_server_config(ra);
        Ok(persisted)
    }

    /// Changes the static hosts: `change` edits the live ones (`ctx.static_hosts`), the result is
    /// written to `[hosts]` (see [`Self::persist_config_sections`]) and the device table is made
    /// to follow it (`apply_static_hosts`: a host left out becomes a discovered device again).
    /// A host the file form cannot hold, or the router itself, is refused: nothing written,
    /// nothing applied.
    pub fn change_hosts(
        &self,
        change: impl FnOnce(&mut Vec<lanforge_types::device::StaticHost>),
    ) -> Result<Persisted, String> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.ctx.static_hosts();
        change(&mut wanted);
        if let Some(router) = wanted.iter().find(|h| {
            self.ctx
                .get_device(&h.mac)
                .is_some_and(|d| d.origin == lanforge_types::device::Origin::System)
        }) {
            return Err(format!("{} is this router; not a static host", router.mac));
        }
        let mut file = ConfigFile::default();
        file.set_static_hosts(&wanted);
        let (hosts, issues) = file.static_hosts();
        if !issues.is_empty() {
            return Err(issues.join("; "));
        }
        let persisted =
            self.persist_config_sections(SectionSet::HOSTS, |f| f.hosts = file.hosts)?;
        let _ = self.ctx.apply_static_hosts(&hosts);
        Ok(persisted)
    }

    /// The DNS settings running now, as `[dns]` holds them: upstreams, mode, rewrites and
    /// reverse resolvers are the live ones; the listener and the upstream group names are not
    /// kept in memory and come from the file (an upstream it does not name is named after the
    /// domain it forwards, else `default`).
    pub(crate) fn live_dns_settings(&self) -> lanforge_api::config_file::DnsSettings {
        use lanforge_api::config_file::{DnsSettings, NamedUpstream};

        let file = self
            .ctx
            .config_path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| ConfigFile::parse_lenient(&text).ok())
            .map(|(cfg, _)| cfg.dns.to_config().0)
            .unwrap_or_default();
        let upstreams = self
            .ctx
            .get_dns_upstreams()
            .into_iter()
            .map(|target| NamedUpstream {
                name: file
                    .upstreams
                    .iter()
                    .find(|u| u.target == target)
                    .map(|u| u.name.clone())
                    .or_else(|| target.domain.clone())
                    .unwrap_or_else(|| "default".to_string()),
                target,
            })
            .collect();
        DnsSettings {
            enabled: file.enabled,
            listen: file.listen,
            upstream_mode: self.ctx.get_dns_upstream_mode(),
            upstreams,
            reverse: self.ctx.all_reverse_resolvers(),
            rewrites: self.ctx.get_dns_rewrites(),
        }
    }

    /// Changes the DNS settings: `change` edits the live ones, the result is written to `[dns]`
    /// (see [`Self::persist_config_sections`]) and then applied as the file now holds it. A value
    /// the file form cannot hold (a rewrite whose type does not fit its answer, ...) is refused:
    /// nothing written, nothing applied.
    pub fn change_dns(
        &self,
        change: impl FnOnce(&mut lanforge_api::config_file::DnsSettings),
    ) -> Result<Persisted, String> {
        let _serial = self.ctx.config_change_lock();
        let mut wanted = self.live_dns_settings();
        change(&mut wanted);
        let file = lanforge_api::config_file::DnsFile::from_config(&wanted);
        let (dns, issues) = file.to_config();
        if !issues.is_empty() {
            return Err(issues.join("; "));
        }
        let persisted = self.persist_config_sections(SectionSet::DNS, |f| f.dns = file)?;
        self.apply_dns_settings(dns);
        Ok(persisted)
    }

    /// Applies the parts of `dns` that differ from the live settings. The listener is bound at
    /// start-up and is not changed here.
    pub fn apply_dns_settings(&self, dns: lanforge_api::config_file::DnsSettings) {
        let upstreams: Vec<_> = dns.upstreams.into_iter().map(|u| u.target).collect();
        let mut patch = lanforge_core::context::ConfigPatch::new();
        if self.ctx.get_dns_upstreams() != upstreams {
            patch = patch.with_dns_upstreams(upstreams);
        }
        if self.ctx.get_dns_upstream_mode() != dns.upstream_mode {
            patch = patch.with_dns_upstream_mode(dns.upstream_mode);
        }
        if self.ctx.get_dns_rewrites() != dns.rewrites {
            patch = patch.with_dns_rewrites(dns.rewrites);
        }
        let _ = self.ctx.apply_config(patch);
        if self.ctx.all_reverse_resolvers() != dns.reverse {
            self.ctx.set_reverse_resolvers(dns.reverse);
        }
    }

    /// Extracts the consolidated static configuration snapshot of the system.
    pub async fn export_system_config_data(&self) -> SystemConfigExport {
        if let lanforge_api::api::Response::SystemConfig(export) =
            self.handle_system_config_export().await
        {
            *export
        } else {
            SystemConfigExport::default()
        }
    }

    /// Exports the consolidated configuration as a formatted TOML string.
    pub async fn export_system_config_toml(&self) -> String {
        let export = self.export_system_config_data().await;
        let db_url = if self.ctx.is_recovery_mode() {
            "memory".to_string()
        } else {
            std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "/var/lib/lanforge/config.redb".to_string())
        };
        let target_path = self.resolve_config_path();
        let existing_content = target_path.and_then(|p| std::fs::read_to_string(p).ok());
        generate_toml_from_export(&export, &db_url, existing_content.as_deref())
    }

    /// Resolves the candidate configuration file path for writes.
    pub fn resolve_config_path(&self) -> Option<PathBuf> {
        if let Some(p) = self.ctx.config_path() {
            if let Some(parent) = p.parent() {
                if parent.as_os_str().is_empty() || parent.exists() {
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }

        let candidates = ["/etc/lanforge/lanforge.toml", "lanforge.toml"];
        for c in candidates {
            let p = Path::new(c);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
        None
    }

    /// Writes the exported system configuration to disk atomically, preserving comments if an existing
    /// file exists.
    pub async fn flush_static_config_to_toml(&self) -> Result<PathBuf, String> {
        let target_path = self
            .resolve_config_path()
            .unwrap_or_else(|| PathBuf::from("/etc/lanforge/lanforge.toml"));

        let content = self.export_system_config_toml().await;
        write_toml_atomically(&target_path, &content).map_err(|e| e.to_string())?;
        Ok(target_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_api::api::SystemConfigExport;

    #[test]
    fn test_generate_toml_from_export_basic() {
        let export = SystemConfigExport::default();
        let toml_str = generate_toml_from_export(&export, "memory", None);

        assert!(toml_str.contains("[database]"));
        assert!(toml_str.contains("[system]"));
        assert!(toml_str.contains("[dns]"));
        assert!(toml_str.contains("[adblock]"));

        // Ensure it parses back as a valid ConfigFile
        let cfg = ConfigFile::parse(&toml_str).expect("Generated TOML must parse into ConfigFile");
        assert!(!cfg.adblock.enabled);
    }

    #[test]
    fn test_generate_toml_from_export_adblock_roundtrip() {
        use lanforge_types::network::dns::{
            AdblockUrlEntry,
            adblock::{
                AdblockDbConfig, AdblockRuleAction, AdblockRuleEntry, AdblockSourceFormat,
                AdblockUrlKind, BlockingMode,
            },
            upstream::UpstreamProtocol,
        };

        let export = SystemConfigExport {
            dns_adblock_config: AdblockDbConfig {
                enabled: true,
                blocking_mode: BlockingMode::NxDomain,
                blocking_ip_v4: None,
                blocking_ip_v6: None,
                refresh_time: lanforge_types::network::dns::adblock::TimeOfDay {
                    hour: 4,
                    minute: 30,
                },
            },
            dns_adblock_urls: vec![
                AdblockUrlEntry {
                    id: Some(1),
                    name: Some("stevenblack".to_string()),
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                        .to_string(),
                    kind: AdblockUrlKind::Blocklist,
                    format: AdblockSourceFormat::Auto,
                },
                AdblockUrlEntry {
                    id: Some(2),
                    name: Some("example-allow".to_string()),
                    url: "https://example.com/allowlist.txt".to_string(),
                    kind: AdblockUrlKind::Allowlist,
                    format: AdblockSourceFormat::Auto,
                },
            ],
            dns_allowlist: vec![lanforge_api::api::AllowlistEntry {
                id: 1,
                domain: "safe-subdomain.example.com".to_string(),
            }],
            dns_adblock_rules: Some(vec![
                AdblockRuleEntry {
                    id: Some(1),
                    name: Some("tracking-bad".to_string()),
                    domain: "tracking.bad.com".to_string(),
                    action: AdblockRuleAction::Block,
                    enabled: true,
                },
                AdblockRuleEntry {
                    id: Some(2),
                    name: Some("goodsite".to_string()),
                    domain: "goodsite.org".to_string(),
                    action: AdblockRuleAction::Allow,
                    enabled: false,
                },
            ]),
            dns_upstreams: vec![lanforge_api::api::DnsUpstreamConfig {
                name: Some("cloudflare".to_string()),
                addr: "1.1.1.1:53".parse().unwrap(),
                protocol: UpstreamProtocol::Udp,
                domain: Some("cloudflare".to_string()),
            }],
            ..Default::default()
        };

        let toml_str = generate_toml_from_export(&export, "memory", None);

        assert!(toml_str.contains("enabled = true"));
        assert!(toml_str.contains("blocking_mode = \"nxdomain\""));
        assert!(toml_str.contains("refresh_time = \"04:30\""));
        assert!(
            toml_str.contains("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
        );
        assert!(toml_str.contains("https://example.com/allowlist.txt"));
        assert!(toml_str.contains("safe-subdomain.example.com"));
        assert!(toml_str.contains("tracking.bad.com"));
        assert!(toml_str.contains("action = \"block\""));
        assert!(toml_str.contains("goodsite.org"));
        assert!(toml_str.contains("action = \"allow\""));
        assert!(toml_str.contains("udp://1.1.1.1:53"));

        // Ensure it parses back into ConfigFile
        let parsed = ConfigFile::parse(&toml_str).expect("Generated TOML must be valid ConfigFile");
        assert!(parsed.adblock.enabled);
        assert_eq!(parsed.adblock.blocking_mode, "nxdomain");
        assert_eq!(parsed.adblock.sources.len(), 2);
        assert_eq!(parsed.adblock.rules.len(), 2);
    }
}
