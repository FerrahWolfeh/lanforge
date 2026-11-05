//! `lanforge reload`: re-reads the config file and applies what changed, in place (no event,
//! no service restart; `phase-1-config-patch` F3).
//!
//! File-owned sections (`SectionSet::FILE_OWNED`) have no other source: they are applied as the
//! boot applies them — entries the file gets wrong left out, adjustments other settings force
//! derived in memory — and the file is not rewritten. Of the other sections only the LAN
//! interface name applies live; the rest take effect on the next start. An unreadable or
//! invalid file applies nothing.

use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_api::config_file::{
    ConfigFile, RaInputs, Section, effective_ra, log_issues, set_aside_issues,
};
use lanforge_core::context::ConfigPatch;
use lanforge_types::config::SiteDomains;
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
        self.reload_file_owned(&path, &file, &set_aside, &mut issues);
        self.ctx.set_config_issues(issues);

        if !file.system.iface.is_empty() {
            self.ctx
                .set_target_interface_name(file.system.iface.clone());
        }
        Response::Success(SimpleSuccess {
            message: format!("Configuration reloaded from {}", path.display()),
        })
    }

    /// Applies the file-owned sections of `file` that differ from the live ones, as one config
    /// patch (one `ConfigChanged`, every subscriber woken once). A set-aside section keeps
    /// running as it is: its defaults are for a boot with no other source, not for replacing a
    /// working configuration.
    fn reload_file_owned(
        &self,
        path: &std::path::Path,
        file: &ConfigFile,
        set_aside: &[(Section, String)],
        issues: &mut Vec<String>,
    ) {
        let ctx = &self.ctx;
        let applies = |sec: Section| !set_aside.iter().any(|(s, _)| *s == sec);
        let _serial = ctx.config_change_lock();
        let mut patch = ConfigPatch::new();
        let mut reverse = None;

        if applies(Section::System) {
            let domains = SiteDomains(file.search_domains());
            if ctx.get_site_domains() != domains {
                info!(domains = ?domains.0, "Reload: [system] search_domains changed; applying");
                patch = patch.with_site_domains(domains);
            }
        }

        if applies(Section::Pppoe) && ctx.get_pppoe_config().as_ref() != Some(&file.pppoe) {
            info!("Reload: [pppoe] changed; applying");
            patch = patch.with_pppoe(file.pppoe.clone());
        }
        if applies(Section::Traffic) && ctx.get_traffic_config().as_ref() != Some(&file.traffic) {
            info!("Reload: [traffic] changed; applying");
            patch = patch.with_traffic(file.traffic.clone());
        }
        if applies(Section::Firewall) {
            let (configured, fw_issues) = file.firewall.to_config();
            issues.extend(log_issues(fw_issues));
            // The firewall service derives what it runs (PPPoE/SQM/LAN) from this itself.
            if ctx.get_firewall_config().as_ref() != Some(&configured) {
                info!("Reload: [firewall] changed; applying");
                patch = patch.with_firewall(configured);
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
                patch = patch.with_ra(effective);
            }
        }
        if applies(Section::Hosts) {
            // State, not config: the device table follows `[hosts]` directly.
            let (hosts, host_issues) = file.static_hosts();
            issues.extend(log_issues(host_issues));
            if ctx.static_hosts() != hosts {
                info!("Reload: [hosts] changed; applying");
            }
            issues.extend(log_issues(ctx.apply_static_hosts(&hosts)));
        }
        if applies(Section::Dns) {
            let (dns, dns_issues) = file.dns.to_config();
            issues.extend(log_issues(dns_issues));
            // The listener and `enabled` only when they changed: the DNS service alone restarts
            // (or goes dormant), nothing else is touched.
            let listener = dns.listener(&ctx.get_dns_listen());
            if listener != ctx.get_dns_listen() {
                info!("Reload: [dns] listener or enabled changed; restarting the DNS service");
                patch = patch.with_dns_listen(listener);
            }
            reverse = Some(dns.reverse.clone());
            patch = self.dns_settings_patch(patch, dns);
            if patch.dns_upstreams.is_some()
                || patch.dns_upstream_mode.is_some()
                || patch.dns_rewrites.is_some()
            {
                info!("Reload: [dns] changed; applying");
            }
        }
        if applies(Section::Adblock) {
            let (adblock, adblock_issues) = file.adblock.to_config();
            issues.extend(log_issues(adblock_issues));
            patch = self.adblock_settings_patch(patch, &adblock);
            if patch.dns_adblock.is_some() || patch.dns_adblock_urls.is_some() {
                info!("Reload: [adblock] changed; applying");
            }
            // A rules file that cannot be read keeps the rules that run.
            let (rules, rules_issues) = adblock.load_rules(path);
            issues.extend(log_issues(rules_issues));
            if let Some(rules) = rules
                && ctx.get_dns_adblock_rules() != rules
            {
                info!("Reload: adblock rules file changed; applying");
                patch = patch.with_dns_adblock_rules(rules);
            }
        }
        if applies(Section::Dhcp) {
            let (dhcp, dhcp_issues) = file.dhcp_settings();
            issues.extend(log_issues(dhcp_issues));
            let options_changed = ctx.get_dhcp_options() != dhcp.options;
            let v4_changed = ctx.get_dhcp_v4_pools() != dhcp.v4_pools;
            let v6_changed = ctx.get_dhcp_v6_pools() != dhcp.v6_pools;
            if options_changed || v4_changed || v6_changed {
                info!("Reload: [dhcp]/[tftp] changed; applying");
            }
            if options_changed {
                patch = patch.with_dhcp_options(dhcp.options);
            }
            if v4_changed {
                patch = patch.with_dhcp_v4_pools(dhcp.v4_pools);
            }
            if v6_changed {
                patch = patch.with_dhcp_v6_pools(dhcp.v6_pools);
            }
        }

        let _ = ctx.apply_config(patch);
        if let Some(reverse) = reverse {
            self.sync_reverse_resolvers(reverse);
        }
    }
}
