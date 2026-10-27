//! `lanforge reload`: re-reads the config file and applies the file-owned sections that changed.
//!
//! Sections migrated to "files are config" (`phase-7-config-storage`) have no other source, so
//! an offline edit takes effect here without a daemon restart. An unreadable or invalid file
//! applies nothing: the running configuration stays as it is.

use lanforge_api::config_file::{ConfigFile, Section};
use lanforge_core::context::LanforgeContext;
use tracing::{info, warn};

/// Re-reads the config file and applies the file-owned sections that differ from the live ones.
pub fn reload_file_sections(ctx: &LanforgeContext) {
    let Some(path) = ctx.config_path() else {
        return;
    };
    let (file, set_aside) = match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|text| ConfigFile::parse_lenient(&text).map_err(|e| e.to_string()))
    {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!(
                "Reload: '{}' cannot be read or parsed ({e}); nothing applied",
                path.display()
            );
            return;
        }
    };
    let mut issues = crate::config::toml::set_aside_issues(&set_aside);
    // A set-aside section keeps running as it is: its defaults are for a boot with no
    // other source, not for replacing a working configuration.
    let applies = |sec: Section| !set_aside.iter().any(|(s, _)| *s == sec);

    #[cfg(feature = "pppoe")]
    if applies(Section::Pppoe) && ctx.get_pppoe_config().as_ref() != Some(&file.pppoe) {
        info!("Reload: [pppoe] changed in '{}'; applying", path.display());
        ctx.update_pppoe_config(file.pppoe);
    }
    #[cfg(feature = "traffic")]
    if applies(Section::Traffic) && ctx.get_traffic_config().as_ref() != Some(&file.traffic) {
        info!(
            "Reload: [traffic] changed in '{}'; applying",
            path.display()
        );
        ctx.update_traffic_config(file.traffic);
    }
    #[cfg(feature = "nft")]
    if applies(Section::Firewall) {
        let (configured, fw_issues) = file.firewall.to_config();
        issues.extend(crate::config::toml::log_issues(fw_issues));
        let effective = crate::config::firewall::effective_firewall(
            configured,
            #[cfg(feature = "pppoe")]
            ctx.get_pppoe_config().as_ref(),
            ctx.get_traffic_config().is_some_and(|t| t.sqm.enabled),
            &ctx.target_interface_name().unwrap_or_default(),
        );
        if ctx.get_firewall_config().as_ref() != Some(&effective) {
            info!(
                "Reload: [firewall] changed in '{}'; applying",
                path.display()
            );
            ctx.update_firewall_config(effective);
        }
    }
    #[cfg(not(any(feature = "pppoe", feature = "traffic", feature = "nft")))]
    let _ = (file, applies);
    ctx.set_config_issues(issues);
}

#[cfg(all(test, feature = "pppoe"))]
mod tests {
    use std::sync::Arc;

    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;

    use super::*;

    #[test]
    fn reload_applies_an_offline_pppoe_edit() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[pppoe]\nenabled = true\nusername = \"new-user\"\n\n[pppoe.nftables]\nbypass_dns = false\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        let live = ctx.get_pppoe_config().expect("applied");
        assert_eq!(live.username, "new-user");
        assert!(!live.nftables.bypass_dns, "nested fields are applied too");
    }

    #[cfg(feature = "traffic")]
    #[test]
    fn reload_applies_an_offline_traffic_edit() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[traffic.sqm]\nenabled = true\ndownload_mbps = 700\nrtt_ms = 30\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        let live = ctx.get_traffic_config().expect("applied");
        assert!(live.sqm.enabled);
        assert_eq!(live.sqm.download_mbps, 700);
        assert_eq!(live.sqm.rtt_ms, Some(30));
    }

    /// A broken `[pppoe]` on reload leaves the running `PPPoE` alone (its default would disable
    /// it) and reports the problem; the valid sections still apply.
    #[cfg(all(feature = "pppoe", feature = "traffic"))]
    #[test]
    fn broken_section_on_reload_keeps_running_config_and_is_reported() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let running = lanforge_types::network::pppoe::PppoeConfig {
            enabled: true,
            username: "working".into(),
            ..Default::default()
        };
        ctx.update_pppoe_config(running.clone());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[pppoe]\nmru = \"big\"\n\n[traffic.sqm]\nenabled = true\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        assert_eq!(ctx.get_pppoe_config(), Some(running));
        assert!(ctx.get_traffic_config().is_some_and(|t| t.sqm.enabled));
        let issues = ctx.config_issues();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(issues[0].starts_with("[pppoe]"), "{issues:?}");
    }

    /// An offline `[firewall]` edit applies on reload; a wrong entry in it is left out (nothing
    /// opened for it) and reported, the rest applies.
    #[cfg(feature = "nft")]
    #[test]
    fn reload_applies_a_firewall_edit_and_leaves_out_a_wrong_entry() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        ctx.update_firewall_config(lanforge_nft::FirewallConfig::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(
            &path,
            "[firewall.port_forwards.game]\nproto = \"udp\"\nport = 7777\nto = \"192.0.2.7\"\n\n\
             [firewall.port_forwards.typo]\nport = 445\nto = \"192.0.2.300\"\n",
        )
        .unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        let fw = ctx.get_firewall_config().unwrap();
        assert_eq!(fw.port_forwards.len(), 1);
        assert_eq!(fw.port_forwards[0].external_port, 7777);
        let issues = ctx.config_issues();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(issues[0].contains("typo"), "{issues:?}");
    }

    /// A `[firewall]` that does not parse keeps the running firewall (its default would drop
    /// every port forward) and is reported.
    #[cfg(feature = "nft")]
    #[test]
    fn unreadable_firewall_section_keeps_the_running_firewall() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let mut running = lanforge_nft::FirewallConfig::default();
        running.port_forwards.push(lanforge_nft::PortForwardRule {
            comment: Some("kept".into()),
            src_zone: "external".into(),
            internal_ip: "192.0.2.9".parse().unwrap(),
            external_port: 9999,
            internal_port: 9999,
            protocol: lanforge_nft::L4Protocol::Tcp,
            enable_hairpin: true,
        });
        ctx.update_firewall_config(running.clone());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, "[firewall]\nenabled = \"yes\"\n").unwrap();
        ctx.set_config_path(&path);

        reload_file_sections(&ctx);

        assert_eq!(ctx.get_firewall_config(), Some(running));
        assert!(ctx.config_issues()[0].starts_with("[firewall]"));
    }

    #[test]
    fn invalid_file_applies_nothing() {
        let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        std::fs::write(&path, "[pppoe\nusername = \"x\"\n").unwrap();
        ctx.set_config_path(&path);
        let before = ctx.get_pppoe_config();

        reload_file_sections(&ctx);

        assert_eq!(ctx.get_pppoe_config(), before);
    }
}
