//! What the daemon runs for a file-owned section when other settings change it, and how
//! config file problems are reported. Derived in memory at boot and on reload, never written
//! back: the file keeps what the admin wrote.

use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;

/// Logs config values that were not applied as written (left out or closed).
#[must_use]
pub fn log_issues(issues: Vec<String>) -> Vec<String> {
    for issue in &issues {
        tracing::error!("Config: {issue}");
    }
    issues
}

/// Logs each set-aside section and words it for the admin.
#[must_use]
pub fn set_aside_issues(set_aside: &[(super::Section, String)]) -> Vec<String> {
    set_aside
        .iter()
        .map(|(sec, err)| {
            let issue = format!("[{sec}] is invalid and was not applied (defaults in use): {err}");
            tracing::error!("Config: {issue}");
            issue
        })
        .collect()
}

/// What other sections force on the configured firewall:
/// - flowtable offload and the DNS/`VoWiFi` bypasses off when the `PPPoE` dataplane turns them
///   off, and offload off under SQM (CAKE must see every packet);
/// - the LAN interface in the internal zone when no zone has it, `podman*` in `trusted`.
///
/// The same rules the boot used to apply and save into the database.
#[must_use]
pub fn effective_firewall(
    mut fw: FirewallConfig,
    pppoe: Option<&PppoeConfig>,
    sqm_enabled: bool,
    lan_iface: &str,
) -> FirewallConfig {
    if let Some(nft) = pppoe.map(|p| &p.nftables) {
        fw.flow_offload &= nft.flow_offload;
        fw.bypass_dns &= nft.bypass_dns;
        fw.bypass_vowifi &= nft.bypass_vowifi;
    }
    if sqm_enabled {
        fw.flow_offload = false;
    }
    if !lan_iface.is_empty()
        && !fw
            .zones
            .iter()
            .any(|z| z.interfaces.iter().any(|i| i == lan_iface))
        && let Some(internal) = fw
            .zones
            .iter_mut()
            .find(|z| z.name == "internal" || z.name == "lan")
    {
        internal.interfaces.push(lan_iface.to_string());
    }
    if let Some(trusted) = fw.zones.iter_mut().find(|z| z.name == "trusted")
        && !trusted.interfaces.iter().any(|i| i == "podman*")
    {
        trusted.interfaces.push("podman*".into());
    }
    fw
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(fw: FirewallConfig, sqm: bool, lan: &str) -> FirewallConfig {
        effective_firewall(fw, None, sqm, lan)
    }

    #[test]
    fn sqm_turns_offload_off_and_lan_joins_internal() {
        let fw = FirewallConfig {
            flow_offload: true,
            ..FirewallConfig::default()
        };
        let out = run(fw, true, "lan0");
        assert!(!out.flow_offload);
        let internal = out.zones.iter().find(|z| z.name == "internal").unwrap();
        assert_eq!(internal.interfaces, vec!["lan0".to_string()]);
    }

    #[test]
    fn an_already_adjusted_firewall_is_unchanged() {
        let mut fw = FirewallConfig {
            flow_offload: false,
            ..FirewallConfig::default()
        };
        fw.zones[0].interfaces = vec!["lan0".into()];
        assert_eq!(run(fw.clone(), true, "lan0"), fw);
    }
}
