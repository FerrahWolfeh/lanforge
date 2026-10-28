//! `lanforge reload`: re-reads the config file and applies what changed, in place (no event,
//! no service restart; `phase-1-config-patch` F3).
//!
//! File-owned sections (`SectionSet::FILE_OWNED`) have no other source: they are applied as the
//! boot applies them — entries the file gets wrong left out, adjustments other settings force
//! derived in memory — and the file is not rewritten. The other sections still go through the
//! import. An unreadable or invalid file applies nothing.

use lanforge_api::api::{Response, SimpleSuccess, SystemConfigExport};
use lanforge_api::config_file::{
    ConfigFile, RaInputs, Section, effective_firewall, effective_ra, log_issues, set_aside_issues,
};
use tracing::info;

use crate::ClientContext;

impl ClientContext {
    pub async fn handle_reload(&self) -> Response {
        let Some(path) = self.resolve_config_path() else {
            return Response::Error {
                error: "Configuration file path could not be resolved".to_string(),
            };
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                return Response::Error {
                    error: format!("Failed to read configuration from {}: {e}", path.display()),
                };
            }
        };
        let (file, set_aside) = match ConfigFile::parse_lenient(&content) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Response::Error {
                    error: format!("Failed to parse configuration from {}: {e}", path.display()),
                };
            }
        };

        let mut issues = set_aside_issues(&set_aside);
        self.reload_file_owned(&file, &set_aside, &mut issues);
        self.ctx.set_config_issues(issues);

        let mut export = SystemConfigExport::from(&file);
        export.pppoe_config = None;
        export.traffic_config = None;
        export.firewall_config = None;
        export.dhcp_options = None;
        export.dhcp_v4_pools = None;
        export.dhcp_v6_pools = None;
        export.ra_prefixes = None;
        export.ra_rdnss = None;
        export.ra_dnssl = None;
        export.dns_rewrites = Vec::new();
        export.dns_upstreams = Vec::new();
        export.dns_reverse_resolvers = None;
        export.hosts = Vec::new();
        match self.handle_system_config_import(export).await {
            Response::SystemConfigImport(import_res) => {
                if import_res.total_success {
                    Response::Success(SimpleSuccess {
                        message: format!("Configuration reloaded from {}", path.display()),
                    })
                } else {
                    Response::Error {
                        error: format!(
                            "Configuration reload completed with errors: {:?}",
                            import_res.results
                        ),
                    }
                }
            }
            other => other,
        }
    }

    /// Applies the file-owned sections of `file` that differ from the live ones. A set-aside
    /// section keeps running as it is: its defaults are for a boot with no other source, not
    /// for replacing a working configuration.
    fn reload_file_owned(
        &self,
        file: &ConfigFile,
        set_aside: &[(Section, String)],
        issues: &mut Vec<String>,
    ) {
        let ctx = &self.ctx;
        let applies = |sec: Section| !set_aside.iter().any(|(s, _)| *s == sec);

        if applies(Section::Pppoe) && ctx.get_pppoe_config().as_ref() != Some(&file.pppoe) {
            info!("Reload: [pppoe] changed; applying");
            ctx.update_pppoe_config(file.pppoe.clone());
        }
        if applies(Section::Traffic) && ctx.get_traffic_config().as_ref() != Some(&file.traffic) {
            info!("Reload: [traffic] changed; applying");
            ctx.update_traffic_config(file.traffic.clone());
        }
        if applies(Section::Firewall) {
            let (configured, fw_issues) = file.firewall.to_config();
            issues.extend(log_issues(fw_issues));
            let effective = effective_firewall(
                configured,
                ctx.get_pppoe_config().as_ref(),
                ctx.get_traffic_config().is_some_and(|t| t.sqm.enabled),
                &ctx.target_interface_name().unwrap_or_default(),
            );
            if ctx.get_firewall_config().as_ref() != Some(&effective) {
                info!("Reload: [firewall] changed; applying");
                ctx.update_firewall_config(effective);
            }
        }
        if applies(Section::Ra) {
            let (configured, ra_issues) = file.ra.to_config();
            issues.extend(log_issues(ra_issues));
            let inputs = RaInputs {
                lan_iface: ctx.target_interface_name().unwrap_or_default(),
                // The ULA the boot resolved: it may have been generated, not read from the file.
                ula: ctx.get_status().and_then(|s| s.ula_prefix),
                search_domains: file.search_domains(),
                dhcpv6_dns: file.dhcp.v6.dns.clone(),
            };
            let effective = effective_ra(configured, &inputs);
            if ctx.get_ra_server_config() != effective {
                info!("Reload: [ra] changed; applying");
                ctx.update_ra_server_config(effective);
            }
        }
        if applies(Section::Hosts) {
            let _serial = ctx.config_change_lock();
            let (hosts, host_issues) = file.static_hosts();
            issues.extend(log_issues(host_issues));
            if ctx.static_hosts() != hosts {
                info!("Reload: [hosts] changed; applying");
            }
            issues.extend(log_issues(ctx.apply_static_hosts(&hosts)));
        }
        if applies(Section::Dns) {
            let _serial = ctx.config_change_lock();
            let (dns, dns_issues) = file.dns.to_config();
            issues.extend(log_issues(dns_issues));
            let live = (
                ctx.get_dns_upstreams(),
                ctx.get_dns_upstream_mode(),
                ctx.get_dns_rewrites(),
                ctx.all_reverse_resolvers(),
            );
            let wanted = (
                dns.upstreams
                    .iter()
                    .map(|u| u.target.clone())
                    .collect::<Vec<_>>(),
                dns.upstream_mode,
                dns.rewrites.clone(),
                dns.reverse.clone(),
            );
            if live != wanted {
                info!("Reload: [dns] changed; applying (listen takes effect on restart)");
                self.apply_dns_settings(dns);
            }
        }
        if applies(Section::Dhcp) {
            let _serial = ctx.config_change_lock();
            let (dhcp, dhcp_issues) = file.dhcp_settings();
            issues.extend(log_issues(dhcp_issues));
            let options_changed = ctx.get_dhcp_options() != dhcp.options;
            let v4_changed = ctx.get_dhcp_v4_pools() != dhcp.v4_pools;
            let v6_changed = ctx.get_dhcp_v6_pools() != dhcp.v6_pools;
            if options_changed || v4_changed || v6_changed {
                info!("Reload: [dhcp]/[tftp] changed; applying");
                let mut update = lanforge_core::context::ConfigPatch::new();
                if options_changed {
                    update = update.with_dhcp_options(dhcp.options);
                }
                if v4_changed {
                    update = update.with_dhcp_v4_pools(dhcp.v4_pools);
                }
                if v6_changed {
                    update = update.with_dhcp_v6_pools(dhcp.v6_pools);
                }
                let _ = ctx.apply_config(update);
            }
        }
    }
}
