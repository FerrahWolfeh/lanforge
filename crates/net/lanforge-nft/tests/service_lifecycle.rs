use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_nft::NftService;
use lanforge_types::events::TimedEvent;
use lanforge_types::events::firewall::{FirewallAppliedSummary, FirewallEvent};
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallMode, FirewallPolicy, FirewallStopAction,
    FirewallZone, HostPortRule, L4Protocol, PortForwardRule,
};
use lanforge_types::network::snapshot::{WanSnapshot, WanState};
use lanforge_types::system::{ServiceId, ServiceState};
use std::net::IpAddr;
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    // Seed default enabled firewall config
    ctx.update_firewall_config(FirewallConfig {
        enabled: true,
        mode: FirewallMode::Full,
        ..Default::default()
    });
    ctx.set_target_interface_name("lan0".to_string());

    (ctx, bus)
}

async fn wait_for_ruleset_applied(
    sub: &mut broadcast::Receiver<TimedEvent>,
) -> FirewallAppliedSummary {
    loop {
        let evt = timeout(Duration::from_millis(500), sub.recv())
            .await
            .expect("Timeout waiting for RulesetApplied")
            .expect("Recv error");
        if let LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(summary)) = evt.event {
            return *summary;
        }
    }
}

#[tokio::test]
async fn test_nft_service_inert_full_lifecycle() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    // 1. Instantiate in inert mode (rootless dry-run)
    let mut service = NftService::inert();
    assert!(service.is_inert(), "Service must report inert mode");

    // 2. Initialize service
    service
        .init(&ctx)
        .await
        .expect("Init must succeed in inert mode");

    // Expect initial RulesetApplied event
    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.table, "lanforge");

    let baseline_payload = service
        .last_applied_payload()
        .expect("Payload must be captured");
    assert!(baseline_payload.contains("\"lanforge\""));
    assert!(baseline_payload.contains("lan0"));

    // 3. Spawn background event loop
    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });

    // Yield to let the spawned task initialize its subscriptions
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Test Dynamic Port Open Request (via context helper)
    let port_req = DynamicPortRequest {
        service: "webui".into(),
        zone: "internal".into(),
        port: 3000,
        protocol: L4Protocol::Tcp,
        comment: Some("WebUI Dynamic Port".into()),
    };
    ctx.register_service_port(port_req);

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert!(summary.rules_count >= 1);

    let updated_payload = service
        .last_applied_payload()
        .expect("Payload must be present");
    assert!(
        updated_payload.contains("3000"),
        "Dynamic port 3000 must be present in ruleset"
    );

    // 5. Test PPPoE WAN Session Up (WAN becomes ppp0)
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        PppoeSessionUp {
            interface: "ppp0".into(),
            ac_mac: None,
            ac_name: None,
            session_id: 1,
            mru: 1492,
            ipv4: Some("10.0.0.2".parse().unwrap()),
            ipv4_peer: Some("10.0.0.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
            ipv6_link_local: true,
        },
    ))));

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface, Some("ppp0".to_string()));

    let wan_payload = service
        .last_applied_payload()
        .expect("Payload must be present");
    assert!(
        wan_payload.contains("ppp0"),
        "External WAN interface ppp0 must be present in ruleset"
    );

    // 6. Test Dynamic Port Release Request (via context helper)
    ctx.release_service_port("webui", 3000, L4Protocol::Tcp);

    let _summary = wait_for_ruleset_applied(&mut fw_sub).await;

    let released_payload = service
        .last_applied_payload()
        .expect("Payload must be present");
    assert!(
        !released_payload.contains("3000"),
        "Released port 3000 must NOT be present in ruleset"
    );

    // 7. Clean Shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let serve_res = timeout(Duration::from_millis(500), serve_handle)
        .await
        .expect("Timeout awaiting serve exit")
        .expect("Join error");
    assert!(serve_res.is_ok());

    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_firewall_reacts_to_ruleset_changed_in_place() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Update config: change to Minimal mode and add dmz zone
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.mode = FirewallMode::Minimal;
    cfg.zones.push(FirewallZone {
        name: "dmz".into(),
        interfaces: vec!["eth2".into()],
        open_ports: Vec::new(),
        allowed_subnets: Vec::new(),
        input_policy: FirewallPolicy::Drop,
        forward_policy: FirewallPolicy::Drop,
        masquerade: false,
        mtu_fix: false,
    });
    ctx.update_firewall_config(cfg);

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.table, "lanforge");

    let minimal_payload = service.last_applied_payload().expect("Payload must exist");
    assert!(
        !minimal_payload.contains("\"input\""),
        "Minimal mode must not create an input chain"
    );

    // 2. Update config: switch back to Full mode and add a port forward rule
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.mode = FirewallMode::Full;
    cfg.port_forwards.push(PortForwardRule {
        comment: Some("Plex Media Server".into()),
        src_zone: "external".into(),
        internal_ip: "192.168.1.55".parse::<IpAddr>().unwrap(),
        external_port: 32400,
        internal_port: 32400,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });
    ctx.update_firewall_config(cfg);

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert!(summary.rules_count >= 1);

    let full_payload = service.last_applied_payload().expect("Payload must exist");
    assert!(full_payload.contains("\"input\""));
    assert!(full_payload.contains("32400"));
    assert!(full_payload.contains("192.168.1.55"));
    assert!(full_payload.contains("\"prerouting\""));

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_firewall_disabled_state_lifecycle_transitions() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(ctx.get_service_state(ServiceId::Nft), ServiceState::Online);

    // 1. Disable firewall in context and notify
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.enabled = false;
    ctx.update_firewall_config(cfg);

    // Allow event to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Service state must transition to Inactive
    assert_eq!(
        ctx.get_service_state(ServiceId::Nft),
        ServiceState::Inactive
    );

    // 2. Re-enable firewall in context and notify
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.enabled = true;
    ctx.update_firewall_config(cfg);

    let _summary = wait_for_ruleset_applied(&mut fw_sub).await;

    // Service state must transition back to Online
    assert_eq!(ctx.get_service_state(ServiceId::Nft), ServiceState::Online);

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
    assert_eq!(
        ctx.get_service_state(ServiceId::Nft),
        ServiceState::Inactive
    );
}

#[tokio::test]
async fn test_firewall_reacts_to_pppoe_wan_reconnect_and_interface_swap() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Session Up on ppp0
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        PppoeSessionUp {
            interface: "ppp0".into(),
            ac_mac: None,
            ac_name: None,
            session_id: 1,
            mru: 1492,
            ipv4: Some("100.64.0.10".parse().unwrap()),
            ipv4_peer: Some("100.64.0.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
            ipv6_link_local: true,
        },
    ))));

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface, Some("ppp0".to_string()));
    let payload = service.last_applied_payload().unwrap();
    assert!(payload.contains("ppp0"));

    // 2. Session Down
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
        reason: "Peer disconnected".into(),
    }));

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface, None);
    let payload = service.last_applied_payload().unwrap();
    assert!(!payload.contains("ppp0"));

    // 3. New Session Up on ppp1 (e.g. secondary interface)
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        PppoeSessionUp {
            interface: "ppp1".into(),
            ac_mac: None,
            ac_name: None,
            session_id: 2,
            mru: 1492,
            ipv4: Some("100.64.0.20".parse().unwrap()),
            ipv4_peer: Some("100.64.0.1".parse().unwrap()),
            dns: vec!["8.8.8.8".parse().unwrap()],
            ipv6_link_local: true,
        },
    ))));

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface, Some("ppp1".to_string()));
    let payload = service.last_applied_payload().unwrap();
    assert!(payload.contains("ppp1"));
    assert!(!payload.contains("ppp0"));

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_firewall_reacts_to_system_reload_config() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send SystemEvent::ReloadConfig
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));

    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.table, "lanforge");

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_firewall_concurrent_dynamic_port_burst() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        s.serve(&ctx_clone, &h).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn 8 concurrent tasks registering dynamic ports
    let mut handles = Vec::new();
    for i in 0..8 {
        let ctx_c = ctx.clone();
        handles.push(tokio::spawn(async move {
            let port = 9000 + i;
            let req = DynamicPortRequest {
                service: format!("worker-{i}"),
                zone: "internal".into(),
                port,
                protocol: L4Protocol::Tcp,
                comment: Some(format!("Worker port {port}")),
            };
            ctx_c.register_service_port(req);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Wait for the final burst to settle
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain firewall events until we get the latest
    let mut last_summary = None;
    while let Ok(evt) = fw_sub.try_recv() {
        if let LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(summary)) = evt.event {
            last_summary = Some(*summary);
        }
    }

    if let Some(summary) = last_summary {
        assert!(summary.rules_count >= 8);
    }
    let payload = service.last_applied_payload().unwrap();
    for i in 0..8 {
        let port = 9000 + i;
        assert!(
            payload.contains(&port.to_string()),
            "Payload must contain port {port}"
        );
    }

    // Now release all worker ports concurrently
    let mut release_handles = Vec::new();
    for i in 0..8 {
        let ctx_c = ctx.clone();
        release_handles.push(tokio::spawn(async move {
            let port = 9000 + i;
            ctx_c.release_service_port(&format!("worker-{i}"), port, L4Protocol::Tcp);
        }));
    }

    for h in release_handles {
        h.await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let released_payload = service.last_applied_payload().unwrap();
    for i in 0..8 {
        let port = 9000 + i;
        assert!(
            !released_payload.contains(&format!("\"dport\": {port}")),
            "Port {port} should be released"
        );
    }

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_firewall_service_control_stop_and_restart() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(ctx.get_service_state(ServiceId::Nft), ServiceState::Online);

    // Commands arrive from the supervisor, as they do for an admin `lanforge service ...`.
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let mut s = service_clone;
        let h = ServiceHandle::with_command_channel(ServiceId::Nft, ctx_clone.clone(), cmd_rx);
        s.serve(&ctx_clone, &h).await
    });

    // Restart reapplies the ruleset in place: the service keeps running, no unprotected window.
    cmd_tx
        .send(ServiceCommand::Restart)
        .await
        .expect("service alive");
    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.table, "lanforge");
    assert_eq!(ctx.get_service_state(ServiceId::Nft), ServiceState::Online);
    assert!(
        !serve_handle.is_finished(),
        "restart must not end the serve loop"
    );

    // Stop ends serve; cleanup locks the WAN down and marks the service Inactive.
    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let res = tokio::time::timeout(Duration::from_secs(1), serve_handle)
        .await
        .expect("serve must return on Stop")
        .expect("join error");
    assert!(res.is_ok());
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
    assert_eq!(
        ctx.get_service_state(ServiceId::Nft),
        ServiceState::Inactive
    );
}

/// Compact JSON of every rule in a captured payload, plus each chain's `(name, policy)`.
fn rules_and_chains(payload: &str) -> (Vec<String>, Vec<(String, String)>) {
    let v: serde_json::Value = serde_json::from_str(payload).expect("payload is JSON");
    let mut rules = Vec::new();
    let mut chains = Vec::new();
    for cmd in v["nftables"].as_array().expect("nftables array") {
        let Some(obj) = cmd.get("add") else { continue };
        if let Some(rule) = obj.get("rule") {
            rules.push(rule["expr"].to_string());
        }
        if let Some(chain) = obj.get("chain") {
            chains.push((
                chain["name"].as_str().unwrap_or_default().to_string(),
                chain["policy"].as_str().unwrap_or_default().to_string(),
            ));
        }
    }
    (rules, chains)
}

const IIF_PPP0: &str = r#""key":"iifname"}},"op":"==","right":"ppp0""#;

/// An admin `stop` (or daemon shutdown) must leave the WAN closed: forwarding stays enabled in the
/// kernel, so removing the table would expose every LAN GUA and every host service on `ppp0`.
#[tokio::test]
async fn test_firewall_stop_locks_down_wan_instead_of_removing_table() {
    let (ctx, bus) = create_test_context();
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.port_forwards = vec![
        PortForwardRule {
            comment: Some("v4 dnat".into()),
            src_zone: "external".into(),
            internal_ip: "192.168.1.10".parse().unwrap(),
            external_port: 8443,
            internal_port: 443,
            protocol: L4Protocol::Tcp,
            enable_hairpin: true,
        },
        PortForwardRule {
            comment: Some("v6 pinhole".into()),
            src_zone: "external".into(),
            internal_ip: "2001:db8::cafe".parse().unwrap(),
            external_port: 2200,
            internal_port: 2200,
            protocol: L4Protocol::Tcp,
            enable_hairpin: false,
        },
    ];
    let ext = cfg.zones.iter_mut().find(|z| z.name == "external").unwrap();
    ext.open_ports.push(HostPortRule {
        comment: Some("host ssh on wan".into()),
        port: 2222,
        protocol: L4Protocol::Tcp,
    });
    ctx.update_firewall_config(cfg);

    let mut fw_sub = bus.subscribe_firewall();
    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let probe = service.clone();
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    // Like the supervisor runner, `cleanup` runs on the instance that served.
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::with_command_channel(ServiceId::Nft, ctx_clone.clone(), cmd_rx);
        let res = service.serve(&ctx_clone, &h).await;
        (service, res)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        PppoeSessionUp {
            interface: "ppp0".into(),
            ac_mac: None,
            ac_name: None,
            session_id: 1,
            mru: 1492,
            ipv4: Some("100.64.0.10".parse().unwrap()),
            ipv4_peer: Some("100.64.0.1".parse().unwrap()),
            dns: vec!["1.1.1.1".parse().unwrap()],
            ipv6_link_local: true,
        },
    ))));
    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface.as_deref(), Some("ppp0"));
    let full = probe.last_applied_payload().unwrap();
    assert!(
        full.contains("2001:db8::cafe") && full.contains("2222"),
        "fixture sanity"
    );

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let (mut service, res) = timeout(Duration::from_secs(1), serve_handle)
        .await
        .expect("serve must return on Stop")
        .expect("join error");
    res.expect("serve ok");
    service.cleanup(&ctx).await.expect("Cleanup must succeed");

    let lockdown = probe
        .last_applied_payload()
        .expect("stop must leave a ruleset in the kernel, not delete the table");
    assert!(
        lockdown != full,
        "stop must replace the live ruleset with the lockdown one"
    );
    let (rules, chains) = rules_and_chains(&lockdown);

    for hook in ["input", "forward"] {
        assert!(
            chains.iter().any(|(n, p)| n == hook && p == "drop"),
            "{hook} chain must exist with policy drop: {chains:?}"
        );
    }
    for rule in &rules {
        for leaked in [
            "192.168.1.10",
            "2001:db8::cafe",
            "2222",
            "8443",
            "\"dnat\":{",
        ] {
            assert!(
                !rule.contains(leaked),
                "lockdown keeps a WAN opening ({leaked}): {rule}"
            );
        }
        if rule.contains(IIF_PPP0) {
            assert!(
                !rule.contains("accept"),
                "lockdown accepts WAN ingress: {rule}"
            );
        }
        // DNS / VoWiFi bypasses match every interface, WAN included.
        if !rule.contains("iifname") {
            for port in ["\"right\":53}", "\"right\":500}", "\"right\":4500}"] {
                assert!(
                    !rule.contains(port),
                    "interface-less bypass survives lockdown: {rule}"
                );
            }
        }
    }
    assert!(
        rules
            .iter()
            .any(|r| r.contains(IIF_PPP0) && r.contains("drop")),
        "the WAN zone must be dropped explicitly, not only by chain policy"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.contains("\"ppp0\"") && r.contains("masquerade")),
        "LAN must keep reaching the internet through the WAN"
    );
    assert!(
        rules.iter().any(|r| r.contains("\"right\":546}")),
        "DHCPv6 client replies must still reach the router (PD renewal)"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.contains("\"lan0\"") && r.contains("accept")),
        "LAN must keep reaching the router (recovery path)"
    );
}

/// `on_stop = "remove"` is the explicit opt-out: the table is deleted and nothing of ours remains.
#[tokio::test]
async fn test_firewall_stop_removes_table_when_configured() {
    let (ctx, bus) = create_test_context();
    let mut cfg = ctx.get_firewall_config().unwrap();
    cfg.on_stop = FirewallStopAction::Remove;
    ctx.update_firewall_config(cfg);

    let mut fw_sub = bus.subscribe_firewall();
    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let _ = wait_for_ruleset_applied(&mut fw_sub).await;
    assert!(service.last_applied_payload().is_some());

    service.cleanup(&ctx).await.expect("Cleanup must succeed");
    assert!(
        service.last_applied_payload().is_none(),
        "remove must leave no ruleset behind"
    );
    assert_eq!(
        ctx.get_service_state(ServiceId::Nft),
        ServiceState::Inactive
    );
}

/// A firewall started while the WAN is already up (admin `service stop/start firewall`, or a
/// supervisor restart) gets no `SessionUp` and no WAN watch change: it must read the current WAN
/// instead of compiling a ruleset without it.
#[tokio::test]
async fn test_firewall_start_with_wan_already_up_binds_wan() {
    let (ctx, bus) = create_test_context();
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifname: Some("ppp0".into()),
        generation: 1,
        ..Default::default()
    });

    let mut fw_sub = bus.subscribe_firewall();
    let mut service = NftService::inert();
    service.init(&ctx).await.expect("Init must succeed");
    let summary = wait_for_ruleset_applied(&mut fw_sub).await;
    assert_eq!(summary.wan_iface.as_deref(), Some("ppp0"));
    let payload = service.last_applied_payload().unwrap();
    assert!(payload.contains("\"ppp0\""), "startup ruleset must bind the live WAN");
}
