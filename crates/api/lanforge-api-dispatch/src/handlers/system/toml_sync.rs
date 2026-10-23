use std::path::{Path, PathBuf};

use crate::ClientContext;
use lanforge_api::api::SystemConfigExport;
use lanforge_api::config_file::{
    ConfigFile, SectionSet, patch_sections, toml_edit::DocumentMut,
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

impl ClientContext {
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
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                        .to_string(),
                    kind: AdblockUrlKind::Blocklist,
                    format: AdblockSourceFormat::Auto,
                },
                AdblockUrlEntry {
                    id: Some(2),
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
                    domain: "tracking.bad.com".to_string(),
                    action: AdblockRuleAction::Block,
                    enabled: true,
                },
                AdblockRuleEntry {
                    id: Some(2),
                    domain: "goodsite.org".to_string(),
                    action: AdblockRuleAction::Allow,
                    enabled: false,
                },
            ]),
            dns_upstreams: vec![lanforge_api::api::DnsUpstreamConfig {
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
