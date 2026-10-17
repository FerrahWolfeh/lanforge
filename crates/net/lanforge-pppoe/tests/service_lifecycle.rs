use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_pppoe::{PppoeConfig, PppoeService};
use lanforge_types::events::TimedEvent;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::system::{PppoeSessionState, ServiceAction, ServiceState};
use tokio::sync::broadcast;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

async fn wait_for_pppoe_event<F, T>(
    sub: &mut broadcast::Receiver<TimedEvent>,
    filter: F,
) -> T
where
    F: Fn(&PppoeEvent) -> Option<T>,
{
    loop {
        let evt = timeout(Duration::from_secs(2), sub.recv())
            .await
            .expect("Timeout waiting for PPPoE event")
            .expect("Recv error");
        if let LanforgeEvent::Pppoe(ref pe) = evt.event
            && let Some(res) = filter(pe)
        {
            return res;
        }
    }
}

async fn wait_for_session_up(sub: &mut broadcast::Receiver<TimedEvent>) -> PppoeSessionUp {
    wait_for_pppoe_event(sub, |evt| match evt {
        PppoeEvent::SessionUp(session) => Some(*session.clone()),
        _ => None,
    })
    .await
}

async fn wait_for_session_down(sub: &mut broadcast::Receiver<TimedEvent>) -> String {
    wait_for_pppoe_event(sub, |evt| match evt {
        PppoeEvent::SessionDown { reason } => Some(reason.clone()),
        _ => None,
    })
    .await
}

#[tokio::test]
async fn test_pppoe_inert_session_up_and_shutdown() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    assert!(service.is_inert());

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Verify SessionUp is emitted with complete parameters
    let session = wait_for_session_up(&mut pppoe_sub).await;
    assert_eq!(session.interface, "ppp0");
    assert_eq!(session.ipv4, Some(Ipv4Addr::new(100, 64, 0, 2)));
    assert_eq!(session.ipv4_peer, Some(Ipv4Addr::new(100, 64, 0, 1)));
    assert_eq!(session.dns.len(), 2);
    assert_eq!(session.mru, 1492);

    // 2. Verify state and readiness
    assert!(ctx.is_pppoe_ready());
    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Online);
    ctx.with_state(|s| {
        let status = s.interfaces.pppoe_status.as_ref().expect("status set");
        assert_eq!(status.state, PppoeSessionState::Connected);
        assert_eq!(status.local_ip, Some(Ipv4Addr::new(100, 64, 0, 2)));
    });

    // 3. Graceful shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let reason = wait_for_session_down(&mut pppoe_sub).await;
    assert_eq!(reason, "Graceful shutdown");

    // 4. Verify post-shutdown state
    assert!(!ctx.is_pppoe_ready());
    ctx.with_state(|s| {
        assert!(s.interfaces.pppoe_status.is_none());
    });

    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_pppoe_reacts_to_config_change_in_place() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "initial_user".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;
    assert!(ctx.is_pppoe_ready());

    // 2. Change credentials in-place (Golden Rule of Isolation)
    let updated_cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "updated_user".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(updated_cfg);

    // 3. Old session is torn down, then new session is established in-place
    let down_reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(down_reason.contains("Configuration updated"));

    let new_session = wait_for_session_up(&mut pppoe_sub).await;
    assert_eq!(new_session.interface, "ppp0");
    assert!(ctx.is_pppoe_ready());

    // 4. Disable PPPoE in-place
    let disabled_cfg = PppoeConfig {
        enabled: false,
        wan_iface: "eth1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(disabled_cfg);

    let down_reason2 = wait_for_session_down(&mut pppoe_sub).await;
    assert!(down_reason2.contains("Configuration updated"));

    // 5. Service terminates cleanly with Inactive state
    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Inactive);
    assert!(!ctx.is_pppoe_ready());
}

#[tokio::test]
async fn test_pppoe_reacts_to_service_control_restart() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "user_restart".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Issue Restart service control
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
        id: "pppoe".into(),
        action: ServiceAction::Restart,
    }));

    // 3. Verify session bounce: SessionDown followed by SessionUp
    let down_reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(down_reason.contains("Service control") || down_reason.contains("restarted"));

    let _ = wait_for_session_up(&mut pppoe_sub).await;
    assert!(ctx.is_pppoe_ready());

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = wait_for_session_down(&mut pppoe_sub).await;
    let _ = handle.await;
}

#[tokio::test]
async fn test_pppoe_reacts_to_service_control_stop() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "user_stop".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Issue Stop service control
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
        id: "pppoe".into(),
        action: ServiceAction::Stop,
    }));

    // 3. Expect SessionDown and transition to Inactive
    let down_reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(down_reason.contains("Service control") || down_reason.contains("stopped"));

    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Inactive);
}

#[tokio::test]
async fn test_pppoe_emits_auth_failed_and_reconnecting() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "fail_auth".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Expect AuthFailed event
    let reason = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::AuthFailed { reason } => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(reason.contains("authentication failed"));

    // 2. Expect Reconnecting event
    let (attempt, delay) = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        } => Some((*attempt, *next_retry_secs)),
        _ => None,
    })
    .await;
    assert_eq!(attempt, 1);
    assert_eq!(delay, 1);

    // 3. Graceful shutdown during reconnect delay
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(1), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_pppoe_carrier_drop_and_recovery() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "carrier_drop".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Carrier drop triggers SessionDown
    let reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(reason.contains("carrier loss") || reason.contains("timeout"));

    // 3. Expect Reconnecting event
    let attempt = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::Reconnecting { attempt, .. } => Some(*attempt),
        _ => None,
    })
    .await;
    assert_eq!(attempt, 1);

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}

#[tokio::test]
async fn test_pppoe_disabled_at_startup_transitions_to_inactive() {
    let (ctx, _bus) = create_test_context();

    let cfg = PppoeConfig {
        enabled: false,
        ..Default::default()
    };

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let res = service.serve(&ctx).await;
    assert!(res.is_ok());

    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Inactive);
    assert!(ctx.is_pppoe_ready(), "Disabled service must not block readiness");
}

#[tokio::test]
async fn test_pppoe_cleanup_guarantees_session_down_on_abort() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "abort_test".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let mut service = PppoeService::inert(cfg, ctx.clone());
    let ctx_clone = ctx.clone();

    // 1. Manually establish session status in context to simulate an active session
    let disc_res = lanforge_pppoe::discovery::DiscoveryResult {
        ac_mac: lanforge_types::identifiers::MacAddr([0x02, 0, 0, 0xac, 0, 1]),
        ac_name: Some("bras".into()),
        session_id: 10,
    };
    let lcp_res = lanforge_pppoe::lcp::LcpNegotiated {
        mru: 1492,
        local_magic: 1,
        peer_magic: 2,
        auth_method: lanforge_types::network::pppoe::AuthMethod::ChapMd5,
    };
    let ipcp_res = lanforge_pppoe::ipcp::IpcpNegotiated {
        local_ip: Some(Ipv4Addr::new(100, 64, 0, 2)),
        peer_ip: Some(Ipv4Addr::new(100, 64, 0, 1)),
        dns: vec![],
        local_v6_ll: None,
        peer_v6_ll: None,
    };

    service.publish_connected_status("ppp0", &disc_res, &lcp_res, &ipcp_res);
    assert!(ctx.is_pppoe_ready());

    // 2. Call cleanup directly (as the supervisor would on unexpected task abort)
    let res = service.cleanup(&ctx_clone).await;
    assert!(res.is_ok());

    // 3. Verify SessionDown was published and state cleaned
    let reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(reason.contains("Service stopped or shut down"));
    assert!(!ctx.is_pppoe_ready());
    ctx.with_state(|s| {
        assert!(s.interfaces.pppoe_status.is_none());
    });
}
