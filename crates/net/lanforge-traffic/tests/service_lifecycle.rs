use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_traffic::TrafficService;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::events::TimedEvent;
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, SqmDiffserv, TrafficConfig};
use lanforge_types::system::{ServiceId, ServiceState};
use tokio::sync::broadcast;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.set_target_interface_name("lan0".to_string());
    (ctx, bus)
}

async fn wait_for_sqm_applied(sub: &mut broadcast::Receiver<TimedEvent>) -> (u32, u32) {
    loop {
        let evt = timeout(Duration::from_millis(500), sub.recv())
            .await
            .expect("Timeout waiting for SqmApplied")
            .expect("Recv error");
        if let LanforgeEvent::Traffic(ref e) = evt.event
            && let TrafficEvent::SqmApplied { download_mbps, upload_mbps, .. } = **e
        {
            return (download_mbps, upload_mbps);
        }
    }
}

async fn wait_for_sqm_cleared(sub: &mut broadcast::Receiver<TimedEvent>) {
    loop {
        let evt = timeout(Duration::from_millis(500), sub.recv())
            .await
            .expect("Timeout waiting for SqmCleared")
            .expect("Recv error");
        if let LanforgeEvent::Traffic(ref e) = evt.event
            && let TrafficEvent::SqmCleared { .. } = **e
        {
            return;
        }
    }
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
    let h = ServiceHandle::new(ServiceId::Traffic, ctx_clone.clone());
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone, &h).await });

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
    let status = ctx.traffic_status();
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

    let status_after_pppoe = ctx.traffic_status().unwrap();
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

#[tokio::test]
async fn test_traffic_reacts_to_config_change_in_place() {
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

    ctx.update_traffic_config(cfg.clone());
    let mut service = TrafficService::inert(cfg);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Traffic, ctx_clone.clone());
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone, &h).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain initial startup events
    while traffic_sub.try_recv().is_ok() {}

    // 1. Update bandwidth limits in-place (300/150 -> 800/400)
    let mut new_cfg = ctx.get_traffic_config().unwrap_or_default();
    new_cfg.sqm.download_mbps = 800;
    new_cfg.sqm.upload_mbps = 400;
    ctx.update_traffic_config(new_cfg);

    let (down, up) = wait_for_sqm_applied(&mut traffic_sub).await;
    assert_eq!(down, 800);
    assert_eq!(up, 400);

    let status = ctx.traffic_status().unwrap();
    assert_eq!(status.download_mbps, 800);
    assert_eq!(status.upload_mbps, 400);

    // 2. Disable SQM in-place
    let mut disabled_cfg = ctx.get_traffic_config().unwrap_or_default();
    disabled_cfg.sqm.enabled = false;
    ctx.update_traffic_config(disabled_cfg);

    wait_for_sqm_cleared(&mut traffic_sub).await;

    let status_disabled = ctx.traffic_status().unwrap();
    assert!(!status_disabled.sqm_active);

    // 3. Re-enable SQM in-place
    let mut reenabled_cfg = ctx.get_traffic_config().unwrap_or_default();
    reenabled_cfg.sqm.enabled = true;
    ctx.update_traffic_config(reenabled_cfg);

    let (down_re, up_re) = wait_for_sqm_applied(&mut traffic_sub).await;
    assert_eq!(down_re, 800);
    assert_eq!(up_re, 400);

    let status_reenabled = ctx.traffic_status().unwrap();
    assert!(status_reenabled.sqm_active);

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}

#[tokio::test]
async fn test_traffic_inactive_when_all_disabled() {
    let (ctx, _bus) = create_test_context();

    let cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: false,
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: false,
            ..Default::default()
        },
    };

    let mut service = TrafficService::inert(cfg);
    // When both are disabled, serve() must complete immediately with Ok(())
    let h = ServiceHandle::new(ServiceId::Traffic, ctx.clone());
    timeout(Duration::from_millis(500), service.serve(&ctx, &h)).await
        .expect("serve() must not hang when features are disabled")
        .expect("serve() must return Ok(())");

    assert_eq!(ctx.get_service_state(ServiceId::Traffic), ServiceState::Inactive);
}

#[tokio::test]
async fn test_traffic_reacts_to_interface_ready() {
    let (ctx, bus) = create_test_context();
    let mut traffic_sub = bus.subscribe_traffic();

    let cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-3".into(),
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: false,
            ..Default::default()
        },
    };

    let mut service = TrafficService::inert(cfg);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Traffic, ctx_clone.clone());
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone, &h).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain initial startup event
    let _ = timeout(Duration::from_millis(500), traffic_sub.recv()).await.unwrap().unwrap();

    // Change target interface to lan1 and notify
    ctx.set_target_interface_name("lan1".to_string());
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::InterfaceReady));

    // Allow event to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = ctx.traffic_status().unwrap();
    assert!(status.tuned_interfaces.contains(&"lan1".to_string()));

    // Cleanup
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = serve_handle.await;
    service.cleanup(&ctx).await.expect("Cleanup must succeed");
}
