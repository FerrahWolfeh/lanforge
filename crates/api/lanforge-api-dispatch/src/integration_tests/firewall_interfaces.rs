//! A zone interface that takes the WAN (or matches every interface) must not reach the
//! ruleset through the API: both write routes refuse it.

use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::snapshot::WanSnapshot;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// A router with its `PPPoE` WAN up on `ppp0` and its LAN on `lan0`.
fn client_with_wan() -> ClientContext {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    ctx.set_target_interface_name("lan0".to_string());
    ctx.set_wan_snapshot(WanSnapshot {
        ifname: Some("ppp0".to_string()),
        ..WanSnapshot::default()
    });
    ClientContext {
        current_gua: None,
        uptime_secs: 10,
        ctx,
        active_clients: Arc::new(AtomicUsize::new(0)),
    }
}

/// The default config with `ifaces` added to zone `zone`.
fn with_interfaces(zone: &str, ifaces: &[&str]) -> FirewallConfig {
    let mut cfg = FirewallConfig::default();
    let z = cfg
        .zones
        .iter_mut()
        .find(|z| z.name == zone)
        .expect("default zone");
    z.interfaces.extend(ifaces.iter().map(ToString::to_string));
    cfg
}

async fn propose_errors(client: &ClientContext, cfg: FirewallConfig) -> Vec<String> {
    match client.handle_firewall_propose(cfg).await {
        Response::FirewallValidation(report) => {
            assert_eq!(report.valid, report.errors.is_empty());
            assert_eq!(report.valid, report.tx_id.is_some());
            report.errors
        }
        other => panic!("expected a validation report, got {other:?}"),
    }
}

#[tokio::test]
async fn default_config_passes_with_wan_and_lan_known() {
    let client = client_with_wan();
    let errors = propose_errors(&client, FirewallConfig::default()).await;
    assert!(errors.is_empty(), "{errors:?}");
}

#[tokio::test]
async fn propose_refuses_internal_wildcard_taking_the_wan() {
    let client = client_with_wan();
    // `ppp*` is a prefix match in nftables: it takes `ppp0`, which the ruleset binds to
    // `external` by itself (not written in the zone, so no plain overlap).
    let errors = propose_errors(&client, with_interfaces("internal", &["ppp*"])).await;
    assert!(
        errors.iter().any(|e| e.contains("WAN interface 'ppp0'")),
        "{errors:?}"
    );
}

#[tokio::test]
async fn propose_refuses_trusted_zone_naming_the_wan() {
    let client = client_with_wan();
    let mut cfg = with_interfaces("trusted", &["ppp0"]);
    // The WAN not written in `external` either: only the active WAN shows the conflict.
    cfg.zones
        .iter_mut()
        .find(|z| z.name == "external")
        .unwrap()
        .interfaces
        .clear();
    let errors = propose_errors(&client, cfg).await;
    assert!(
        errors.iter().any(|e| e.contains("WAN interface 'ppp0'")),
        "{errors:?}"
    );
}

#[tokio::test]
async fn propose_refuses_external_zone_holding_the_lan() {
    let client = client_with_wan();
    let errors = propose_errors(&client, with_interfaces("external", &["lan*"])).await;
    assert!(
        errors.iter().any(|e| e.contains("LAN interface 'lan0'")),
        "{errors:?}"
    );
}

#[tokio::test]
async fn propose_refuses_wildcard_overlapping_another_zone() {
    let client = client_with_wan();
    let mut cfg = with_interfaces("internal", &["en*"]);
    cfg.zones
        .iter_mut()
        .find(|z| z.name == "trusted")
        .unwrap()
        .interfaces
        .push("enp3s0".to_string());
    let errors = propose_errors(&client, cfg).await;
    assert!(
        errors.iter().any(|e| e.contains("Interface overlap")),
        "{errors:?}"
    );
}

#[tokio::test]
async fn propose_refuses_bare_star_and_empty_names() {
    let client = client_with_wan();
    for bad in ["*", "", "eth 0", "a-name-longer-than-15"] {
        let errors = propose_errors(&client, with_interfaces("internal", &[bad])).await;
        assert!(
            errors
                .iter()
                .any(|e| e.contains(&format!("interface '{bad}'"))),
            "{bad:?}: {errors:?}"
        );
    }
}

#[tokio::test]
async fn update_route_refuses_what_propose_refuses() {
    let client = client_with_wan();
    let resp = client
        .handle_update_firewall_config(with_interfaces("internal", &["ppp*"]))
        .await;
    assert!(
        matches!(&resp, Response::Rejected { error } if error.contains("WAN interface 'ppp0'")),
        "expected Response::Rejected, got {resp:?}"
    );
    assert!(
        client.ctx.get_firewall_config().is_none_or(|fw| fw
            .zones
            .iter()
            .all(|z| !z.interfaces.iter().any(|i| i == "ppp*"))),
        "a refused config must not be applied"
    );
}

#[tokio::test]
async fn update_route_still_applies_a_valid_config() {
    let client = client_with_wan();
    let resp = client
        .handle_update_firewall_config(with_interfaces("internal", &["br0"]))
        .await;
    assert!(matches!(resp, Response::Success(_)), "{resp:?}");
    assert!(client.ctx.get_firewall_config().is_some_and(|fw| {
        fw.zones
            .iter()
            .any(|z| z.interfaces.iter().any(|i| i == "br0"))
    }));
}

/// An uplink zone not called `external` (masquerading) may hold the WAN: the guard refused it,
/// so such a file could not be changed from the `WebUI` anymore.
#[tokio::test]
async fn propose_accepts_an_uplink_zone_with_another_name() {
    let client = client_with_wan();
    let mut cfg = FirewallConfig::default();
    for zone in &mut cfg.zones {
        if zone.name == "external" {
            zone.name = "isp".into();
            zone.interfaces = vec!["ppp0".into()];
        }
    }
    for fwd in &mut cfg.forwardings {
        for end in [&mut fwd.from, &mut fwd.to] {
            if end == "external" {
                *end = "isp".into();
            }
        }
    }
    let errors = propose_errors(&client, cfg).await;
    assert!(errors.is_empty(), "{errors:?}");
}
