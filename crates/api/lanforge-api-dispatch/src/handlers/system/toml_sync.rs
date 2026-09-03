use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use crate::ClientContext;
use lanforge_api::api::SystemConfigExport;

/// Atomically writes content to a file using a temporary file in the same directory.
pub fn write_toml_atomically(path: &Path, content: &str) -> Result<(), std::io::Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("lanforge.toml"),
        std::process::id()
    ));

    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Generates a well-formatted TOML configuration string from a `SystemConfigExport`.
/// Preserves extra sections (e.g. `[http]`, `[api]`, `[monitor]`, `[mdns]`) from `existing_content` if available.
pub fn generate_toml_from_export(
    export: &SystemConfigExport,
    db_url: &str,
    existing_content: Option<&str>,
) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("# Lanforge Configuration File\n# Automatically synchronized by Lanforge\n\n");

    // 1. [system]
    out.push_str("[system]\n");
    let mut iface_written = false;
    let mut search_domains_written = false;

    if let Some(existing) = existing_content
        && let Ok(val) = toml::from_str::<toml::Value>(existing)
        && let Some(sys) = val.get("system").and_then(|s| s.as_table())
    {
        if let Some(iface) = sys.get("iface").and_then(|i| i.as_str()) {
            out.push_str(&format!("iface = \"{iface}\"\n"));
            iface_written = true;
        }
        if let Some(domains) = sys.get("search_domains").and_then(|d| d.as_array()) {
            let d_strs: Vec<String> = domains
                .iter()
                .filter_map(|d| d.as_str().map(|s| format!("\"{s}\"")))
                .collect();
            out.push_str(&format!("search_domains = [{}]\n", d_strs.join(", ")));
            search_domains_written = true;
        }
        if let Some(prefix) = sys.get("target_prefix").and_then(|p| p.as_str()) {
            out.push_str(&format!("target_prefix = \"{prefix}\"\n"));
        }
        if let Some(debounce) = sys.get("debounce_secs").and_then(|d| d.as_integer()) {
            out.push_str(&format!("debounce_secs = {debounce}\n"));
        }
    }

    if !iface_written {
        out.push_str("iface = \"\"\n");
    }
    if !search_domains_written {
        out.push_str("search_domains = [\"lan\"]\n");
    }
    out.push('\n');

    // 2. [database]
    out.push_str("[database]\n");
    out.push_str(&format!("url = \"{db_url}\"\n"));
    out.push_str("log_url = \"/tmp/lanforge-logs.jsonl\"\n");
    out.push_str("flush_interval = 60\n\n");

    // 3. [dhcp.v4]
    out.push_str("[dhcp.v4]\n");
    if let Some(ref opts) = export.dhcp_options {
        out.push_str(&format!("enabled = {}\n", opts.v4.enabled));
        out.push_str(&format!("lease_time = {}\n", opts.v4.lease_time));
        if let Some(router) = opts.v4.router {
            out.push_str(&format!("router = \"{router}\"\n"));
        }
        if let Some(mask) = opts.v4.subnet_mask {
            out.push_str(&format!("subnet_mask = \"{mask}\"\n"));
        }
        if !opts.v4.dns_servers.is_empty() {
            let dns_strs: Vec<String> = opts
                .v4
                .dns_servers
                .iter()
                .map(|ip| format!("\"{ip}\""))
                .collect();
            out.push_str(&format!("dns = [{}]\n", dns_strs.join(", ")));
        }
        if let Some(ref domain) = opts.v4.domain_name {
            out.push_str(&format!("domain_name = \"{domain}\"\n"));
        }
        if !opts.v4.search_domains.is_empty() {
            let s_strs: Vec<String> = opts
                .v4
                .search_domains
                .iter()
                .map(|d| format!("\"{d}\""))
                .collect();
            out.push_str(&format!("search_domains = [{}]\n", s_strs.join(", ")));
        }
        if let Some(ref boot) = opts.v4.boot_file {
            out.push_str(&format!("boot_file = \"{boot}\"\n"));
        }
    } else {
        out.push_str("enabled = true\n");
    }
    out.push('\n');

    // 3b. [[dhcp.v4.pools]]
    if let Some(ref pools) = export.dhcp_v4_pools {
        for pool in pools {
            out.push_str("[[dhcp.v4.pools]]\n");
            if let Some(ref name) = pool.name {
                out.push_str(&format!("name = \"{name}\"\n"));
            }
            out.push_str(&format!("range_start = \"{}\"\n", pool.range_start));
            out.push_str(&format!("range_end = \"{}\"\n", pool.range_end));
            if let Some(router) = pool.router {
                out.push_str(&format!("router = \"{router}\"\n"));
            }
            if let Some(mask) = pool.subnet_mask {
                out.push_str(&format!("subnet_mask = \"{mask}\"\n"));
            }
            if let Some(lease) = pool.lease_time {
                out.push_str(&format!("lease_time = {lease}\n"));
            }
            if !pool.dns_servers.is_empty() {
                let d_strs: Vec<String> = pool
                    .dns_servers
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect();
                out.push_str(&format!("dns_servers = [{}]\n", d_strs.join(", ")));
            }
            out.push('\n');
        }
    }

    // 4. [dhcp.v6]
    if let Some(ref opts) = export.dhcp_options {
        out.push_str("[dhcp.v6]\n");
        out.push_str(&format!("enabled = {}\n", opts.v6.enabled));
        out.push_str(&format!("lease_time = {}\n", opts.v6.lease_time));
        if !opts.v6.dns_servers.is_empty() {
            let d_strs: Vec<String> = opts
                .v6
                .dns_servers
                .iter()
                .map(|ip| format!("\"{ip}\""))
                .collect();
            out.push_str(&format!("dns_servers = [{}]\n", d_strs.join(", ")));
        }
        out.push('\n');
    }

    // 5. [dns]
    out.push_str("[dns]\n");
    out.push_str("enabled = true\n");
    out.push_str(&format!(
        "adblock_enabled = {}\n\n",
        export.dns_adblock_config.enabled
    ));

    // 5b. [[dns.rewrites]]
    for rw in &export.dns_rewrites {
        out.push_str("[[dns.rewrites]]\n");
        out.push_str(&format!("domain = \"{}\"\n", rw.domain));
        out.push_str(&format!("rtype = \"{}\"\n", rw.rtype));
        out.push_str(&format!("answer = \"{}\"\n\n", rw.answer));
    }

    // 5c. [[dns.upstreams]]
    for up in &export.dns_upstreams {
        out.push_str("[[dns.upstreams]]\n");
        out.push_str(&format!("addr = \"{}\"\n", up.addr));
        out.push_str(&format!("protocol = \"{}\"\n", up.protocol));
        if let Some(ref dom) = up.domain {
            out.push_str(&format!("domain = \"{dom}\"\n"));
        }
        out.push('\n');
    }

    // 6. [ra]
    out.push_str("[ra]\n");
    out.push_str("enabled = true\n\n");

    if let Some(ref prefixes) = export.ra_prefixes {
        for prefix in prefixes {
            out.push_str("[[ra.prefix]]\n");
            let src_str = match prefix.source {
                lanforge_types::network::ra::PrefixSource::Ula => "ula",
                lanforge_types::network::ra::PrefixSource::AutoGua => "auto_gua",
                lanforge_types::network::ra::PrefixSource::Static => "static",
            };
            out.push_str(&format!("source = \"{src_str}\"\n"));
            if let Some(ref addr) = prefix.address {
                out.push_str(&format!("address = \"{addr}\"\n"));
            }
            out.push_str(&format!("prefix_len = {}\n", prefix.prefix_len));
            out.push_str(&format!("on_link = {}\n", prefix.on_link));
            out.push_str(&format!("autonomous = {}\n\n", prefix.autonomous));
        }
    }

    if let Some(ref rdnss) = export.ra_rdnss {
        for r in rdnss {
            out.push_str("[[ra.rdnss]]\n");
            let s_strs: Vec<String> = r.servers.iter().map(|s| format!("\"{s}\"")).collect();
            out.push_str(&format!("servers = [{}]\n", s_strs.join(", ")));
            if let Some(lifetime) = r.lifetime {
                out.push_str(&format!("lifetime = {lifetime}\n"));
            }
            out.push('\n');
        }
    }

    if let Some(ref dnssl) = export.ra_dnssl {
        for d in dnssl {
            out.push_str("[[ra.dnssl]]\n");
            let d_strs: Vec<String> = d.domains.iter().map(|s| format!("\"{s}\"")).collect();
            out.push_str(&format!("domains = [{}]\n", d_strs.join(", ")));
            if let Some(lifetime) = d.lifetime {
                out.push_str(&format!("lifetime = {lifetime}\n"));
            }
            out.push('\n');
        }
    }

    // 7. [pppoe]
    if let Some(ref pppoe) = export.pppoe_config {
        out.push_str("[pppoe]\n");
        out.push_str(&format!("enabled = {}\n", pppoe.enabled));
        out.push_str(&format!("wan_iface = \"{}\"\n", pppoe.wan_iface));
        out.push_str(&format!("username = \"{}\"\n", pppoe.username));
        out.push_str(&format!("password = \"{}\"\n", pppoe.password));
        out.push_str(&format!("mru = {}\n\n", pppoe.mru));
    }

    // 8. Static Devices [[devices]]
    for host in &export.hosts {
        out.push_str("[[devices]]\n");
        out.push_str(&format!("mac = \"{}\"\n", host.mac));
        out.push_str(&format!("hostname = \"{}\"\n", host.hostname));
        if let Some(ip) = host.v4_fixed {
            out.push_str(&format!("v4_ip = \"{ip}\"\n"));
        }
        if let Some(suf) = host.v6_suffix {
            out.push_str(&format!("v6_suffix = \"{suf}\"\n"));
        }
        out.push('\n');
    }

    // 9. Preserve auxiliary sections from existing file
    if let Some(existing) = existing_content
        && let Ok(val) = toml::from_str::<toml::Value>(existing)
    {
        let preserve_keys = ["http", "api", "monitor", "mdns", "tftp"];
        for key in preserve_keys {
            if let Some(sec) = val.get(key)
                && let Ok(sec_str) = toml::to_string(sec)
            {
                out.push_str(&format!("[{key}]\n{sec_str}\n"));
            }
        }
    }

    out
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
            if let Some(parent) = p.parent()
                && (parent.as_os_str().is_empty() || parent.exists())
            {
                return Some(p.to_path_buf());
            }
        }
        None
    }

    /// In memory mode, flushes only static and configurable data to the active `lanforge.toml`.
    /// Volatile runtime state (dynamic devices, DHCP leases, DNS cache) is intentionally omitted.
    pub async fn flush_static_config_to_toml(&self) -> Result<PathBuf, String> {
        if !self.db.is_in_memory() {
            return Err("System is not running in in-memory mode".to_string());
        }

        let target_path = match self.resolve_config_path() {
            Some(p) => p,
            None => {
                let err = "No writable configuration path found for lanforge.toml".to_string();
                warn!("{err}");
                return Err(err);
            }
        };

        let existing_content = fs::read_to_string(&target_path).ok();
        let export = self.export_system_config_data().await;
        let toml_str = generate_toml_from_export(&export, "memory", existing_content.as_deref());

        if let Err(e) = write_toml_atomically(&target_path, &toml_str) {
            let err = format!(
                "Failed to write configuration to {}: {e}",
                target_path.display()
            );
            error!("{err}");
            return Err(err);
        }

        info!(
            "Ephemeral persistence: successfully flushed static configurations to {}",
            target_path.display()
        );
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
        assert!(toml_str.contains("url = \"memory\""));
        assert!(toml_str.contains("[system]"));
        assert!(toml_str.contains("[dns]"));
        assert!(toml_str.contains("adblock_enabled = false"));

        // Ensure it parses back as valid TOML
        let val: toml::Value = toml::from_str(&toml_str).expect("Generated TOML must be valid");
        assert_eq!(
            val.get("database")
                .and_then(|d| d.get("url"))
                .and_then(|u| u.as_str()),
            Some("memory")
        );
    }

    #[test]
    fn test_write_toml_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("sub").join("lanforge.toml");

        let content = "[database]\nurl = \"memory\"\n";
        write_toml_atomically(&target, content).expect("atomic write must succeed");

        let read_back = fs::read_to_string(&target).expect("read back");
        assert_eq!(read_back, content);
    }
}
