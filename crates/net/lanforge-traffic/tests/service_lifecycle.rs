use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_traffic::TrafficService;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, SqmDiffserv, TrafficConfig};
use lanforge_types::system::ServiceState;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.set_target_interface_name("lan0".to_string());
    (ctx, bus)
}

#[tokio::test]
async fn test_traffic_service_inert_full_lifecycle() {
    let (ctx, bus) = create_test_context();
    let mut traffic_sub = bus.subscribe_traffic();

    let cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-3".into(),
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: true,
            interface: "auto".into(),
            download_mbps: 300,
            upload_mbps: 150,
            diffserv: SqmDiffserv::Diffserv4,
            ingress_device: "ifb4lanforge".into(),
            ..Default::default()
        },
    };

    // 1. Initialize inert service
    let mut service = TrafficService::inert(cfg);
    assert!(service.is_inert());

    // 2. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone).await });

    // Allow task to initialize and subscribe
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify initial startup events (TuningApplied + initial fallback SqmApplied on lan0)
    let tuning_evt = timeout(Duration::from_millis(500), traffic_sub.recv())
        .await
        .expect("Timeout waiting for TuningApplied")
        .expect("Recv error");
    assert!(matches!(
        tuning_evt.event,
        LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::TuningApplied { .. })
    ));

    let initial_sqm_evt = timeout(Duration::from_millis(500), traffic_sub.recv())
        .await
        .expect("Timeout waiting for initial SqmApplied")
        .expect("Recv error");
    assert!(matches!(
        initial_sqm_evt.event,
        LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::SqmApplied { ref interface, .. } if interface == "lan0")
    ));

    // Verify status updated in context
    let status = ctx.with_state(|s| s.interfaces.traffic_status.clone());
    assert!(status.is_some());
    let status = status.unwrap();
    assert!(status.tuning_applied);
    assert_eq!(status.download_mbps, 300);
    assert_eq!(status.upload_mbps, 150);

    // 3. Simulate PPPoE WAN Session Up
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

    // Wait for SqmApplied event rebound on ppp0
    let sqm_applied_evt = timeout(Duration::from_millis(500), traffic_sub.recv())
        .await
        .expect("Timeout waiting for SqmApplied on ppp0")
        .expect("Recv error");

    assert!(matches!(
        sqm_applied_evt.event,
        LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::SqmApplied { ref interface, .. } if interface == "ppp0")
    ));

    let status_after_pppoe = ctx.with_state(|s| s.interfaces.traffic_status.clone()).unwrap();
    assert!(status_after_pppoe.sqm_active);
    assert_eq!(status_after_pppoe.wan_interface, Some("ppp0".to_string()));
    assert_eq!(status_after_pppoe.service_state, ServiceState::Online);

    // 4. Simulate PPPoE Session Down
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
        reason: "User requested disconnect".into(),
    }));

    let sqm_cleared_evt = timeout(Duration::from_millis(500), traffic_sub.recv())
        .await
        .expect("Timeout waiting for SqmCleared")
        .expect("Recv error");

    assert!(matches!(
        sqm_cleared_evt.event,
        LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::SqmCleared { .. })
    ));

    // 5. Clean Shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let serve_res = timeout(Duration::from_millis(500), serve_handle)
        .await
        .expect("Timeout waiting for serve to exit")
        .expect("Join error");
    assert!(serve_res.is_ok());

    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}
