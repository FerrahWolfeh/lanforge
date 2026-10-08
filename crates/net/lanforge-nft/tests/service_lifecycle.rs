use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_nft::NftService;
use lanforge_types::events::firewall::{FirewallAppliedSummary, FirewallEvent};
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::events::TimedEvent;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallMode, L4Protocol,
};
use tokio::sync::broadcast;
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
    service.init(&ctx).await.expect("Init must succeed in inert mode");

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
        s.serve(&ctx_clone).await
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
