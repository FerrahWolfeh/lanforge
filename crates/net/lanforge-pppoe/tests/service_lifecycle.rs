mod mock_bras;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, LossPolicy, ServiceCommand, ServiceHandle, StatusReport,
};
use lanforge_pppoe::{PppoeConfig, PppoeService};
use lanforge_transport::PppoeTransport;
use lanforge_types::events::TimedEvent;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::network::snapshot::{WanSnapshot, WanState};
use lanforge_types::system::{PppoeSessionState, ServiceId, ServiceState};
use mock_bras::{MockBrasConfig, spawn_mock_bras};
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

/// Handle wired to a command channel, as the supervisor provides (admin stop/restart).
fn controlled_handle(ctx: &LanforgeContext) -> (ServiceHandle, mpsc::Sender<ServiceCommand>) {
    let (tx, rx) = mpsc::channel(8);
    (
        ServiceHandle::with_command_channel(ServiceId::Pppoe, ctx.clone(), rx),
        tx,
    )
}

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

async fn wait_for_pppoe_event<F, T>(sub: &mut broadcast::Receiver<TimedEvent>, filter: F) -> T
where
    F: Fn(&PppoeEvent) -> Option<T>,
{
    loop {
        let evt = timeout(Duration::from_secs(3), sub.recv())
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

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    assert!(service.is_inert());

    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Verify SessionUp is emitted with complete parameters
    let session = wait_for_session_up(&mut pppoe_sub).await;
    assert_eq!(session.interface, "ppp0");
    assert_eq!(session.ipv4, Some(Ipv4Addr::new(100, 64, 0, 2)));
    assert_eq!(session.ipv4_peer, Some(Ipv4Addr::new(100, 64, 0, 1)));
    assert_eq!(session.dns.len(), 2);
    assert_eq!(session.mru, 1492);

    // 2. Verify state and readiness
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Online
    );
    {
        let status = ctx.pppoe_status().expect("status set");
        assert_eq!(status.state, PppoeSessionState::Connected);
        assert_eq!(status.local_ip, Some(Ipv4Addr::new(100, 64, 0, 2)));
    }

    // 3. Graceful shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let reason = wait_for_session_down(&mut pppoe_sub).await;
    assert_eq!(reason, "Graceful shutdown");

    // 4. Verify post-shutdown state
    assert!(ctx.pppoe_status().is_none());

    let res = timeout(Duration::from_secs(2), handle)
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

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Online
    );

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
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Online
    );

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
    let res = timeout(Duration::from_secs(2), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Inactive
    );
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

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(&ctx_clone);
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Issue Restart service control
    cmd_tx
        .send(ServiceCommand::Restart)
        .await
        .expect("service alive");

    // 3. Verify session bounce: SessionDown followed by SessionUp
    let down_reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(
        down_reason.contains("restarted"),
        "unexpected reason: {down_reason}"
    );

    let _ = wait_for_session_up(&mut pppoe_sub).await;
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Online
    );

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

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(&ctx_clone);
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Issue Stop service control
    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");

    // 3. Expect SessionDown and transition to Inactive
    let down_reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(
        down_reason.contains("stopped"),
        "unexpected reason: {down_reason}"
    );

    let res = timeout(Duration::from_secs(2), handle)
        .await
        .expect("join timeout")
        .expect("join handle error");
    assert!(res.is_ok());
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Inactive
    );
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

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(
        handle_inert,
        MockBrasConfig {
            auth_ok: false,
            ..Default::default()
        },
    );

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Expect AuthFailed event
    let reason = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::AuthFailed { reason } => Some(reason.clone()),
        _ => None,
    })
    .await;
    assert!(reason.to_lowercase().contains("authentication failed"));

    // 2. Expect Reconnecting event, and no SessionDown: the session never came up.
    let (attempt, delay) = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::SessionDown { reason } => panic!("SessionDown without SessionUp: {reason}"),
        PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        } => Some((*attempt, *next_retry_secs)),
        _ => None,
    })
    .await;
    // An explicit reject cannot be fixed by retrying fast: at least the reject floor, even with
    // `reconnect_delay_secs = 1`.
    assert_eq!(attempt, 1);
    assert!(
        delay >= lanforge_pppoe::backoff::REJECT_FLOOR.as_secs(),
        "rejected credentials retried after {delay}s"
    );

    // 3. Graceful shutdown during reconnect delay
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let res = timeout(Duration::from_secs(2), handle)
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
        lcp_echo_interval_secs: 1,
        lcp_echo_max_failures: 1,
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(
        handle_inert,
        MockBrasConfig {
            send_echo_replies: false,
            ..Default::default()
        },
    );

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // 1. Initial connect
    let _ = wait_for_session_up(&mut pppoe_sub).await;

    // 2. Missing echo replies trigger keepalive timeout -> SessionDown
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

    let (_handle_inert, transport) = PppoeTransport::inert();
    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx.clone());
    let res = service.serve(&ctx, &h).await;
    assert!(res.is_ok());

    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Inactive
    );
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

    let (_handle_inert, transport) = PppoeTransport::inert();
    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
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
        early_frames: Vec::new(),
    };
    let ipcp_res = lanforge_pppoe::ipcp::IpcpNegotiated {
        local_ip: Some(Ipv4Addr::new(100, 64, 0, 2)),
        peer_ip: Some(Ipv4Addr::new(100, 64, 0, 1)),
        dns: smallvec::smallvec![],
        local_v6_ll: None,
        peer_v6_ll: None,
    };

    service.publish_connected_status("ppp0", &disc_res, &lcp_res, &ipcp_res);
    assert!(ctx.pppoe_status().is_some());

    // 2. Call cleanup directly (as the supervisor would on unexpected task abort)
    let res = service.cleanup(&ctx_clone).await;
    assert!(res.is_ok());

    // 3. Verify SessionDown was published and state cleaned
    let reason = wait_for_session_down(&mut pppoe_sub).await;
    assert!(reason.contains("Service stopped or shut down"));
    assert!(ctx.pppoe_status().is_none());
}

#[tokio::test]
async fn test_pppoe_with_terminal_probe_enabled_reports_terminal_status() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let (handle_prober, prober) =
        lanforge_transport::ArpProber::inert([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let responder = tokio::spawn(async move {
        if let Some(_req) = handle_prober.recv_payload().await {
            let target_mac = [0x3c, 0x84, 0x6a, 0xbc, 0x8c, 0xe5];
            let mut reply = Vec::with_capacity(42);
            reply.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
            reply.extend_from_slice(&target_mac);
            reply.extend_from_slice(&[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
            reply.extend_from_slice(&target_mac);
            reply.extend_from_slice(&[192, 168, 1, 1]);
            reply.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
            reply.extend_from_slice(&[0, 0, 0, 0]);
            handle_prober.inject(reply, ()).await;
        }
    });

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "wan0".into(),
        username: "client1".into(),
        terminal_probe: lanforge_types::network::pppoe::TerminalProbeConfig {
            enabled: true,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            ..Default::default()
        },
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport).with_prober(prober);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    let _ = wait_for_session_up(&mut pppoe_sub).await;
    let _ = responder.await;

    // Verify terminal status is reflected in global state
    {
        let status = ctx.pppoe_status().expect("status set");
        assert_eq!(status.terminal_reachable, Some(true));
        assert_eq!(
            status.terminal_mac,
            Some(lanforge_types::identifiers::MacAddr([
                0x3c, 0x84, 0x6a, 0xbc, 0x8c, 0xe5
            ]))
        );
        assert!(status.terminal_rtt_us.is_some());
    }

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}

#[tokio::test]
async fn test_pppoe_with_injected_prober_reports_probe_response() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let (handle_prober, prober) =
        lanforge_transport::ArpProber::inert([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "wan0".into(),
        username: "client1".into(),
        terminal_probe: lanforge_types::network::pppoe::TerminalProbeConfig {
            enabled: true,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            ..Default::default()
        },
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport).with_prober(prober);
    let ctx_clone = ctx.clone();

    // Spawn inert prober mock responder in background
    let responder = tokio::spawn(async move {
        // Wait for ARP request from prober
        if let Some(_req) = handle_prober.recv_payload().await {
            let target_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
            // Format an ARP reply
            let mut reply_frame = Vec::with_capacity(42);
            reply_frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Dst MAC
            reply_frame.extend_from_slice(&target_mac); // Src MAC
            reply_frame.extend_from_slice(&[0x08, 0x06]); // Eth type: ARP
            reply_frame.extend_from_slice(&[0x00, 0x01]); // HTYPE
            reply_frame.extend_from_slice(&[0x08, 0x00]); // PTYPE
            reply_frame.push(6); // HLEN
            reply_frame.push(4); // PLEN
            reply_frame.extend_from_slice(&[0x00, 0x02]); // Opcode: reply
            reply_frame.extend_from_slice(&target_mac); // Sender MAC
            reply_frame.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
            reply_frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Target MAC
            reply_frame.extend_from_slice(&[0, 0, 0, 0]); // Target IP
            handle_prober.inject(reply_frame, ()).await;
        }
    });

    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let service_handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    let _ = wait_for_session_up(&mut pppoe_sub).await;
    let _ = responder.await;

    // Verify injected prober results in global state
    {
        let status = ctx.pppoe_status().expect("status set");
        assert_eq!(status.terminal_reachable, Some(true));
        assert_eq!(
            status.terminal_mac,
            Some(lanforge_types::identifiers::MacAddr([
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x01
            ]))
        );
        assert!(status.terminal_rtt_us.is_some());
    }

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = service_handle.await;
}

/// A concentrator that drops the session seconds after it comes up must not be hammered: the
/// failure count survives a short-lived session and the retry delay grows (ISPs flag accounts that
/// reconnect in tight loops).
#[tokio::test(start_paused = true)]
async fn test_pppoe_flapping_session_backs_off() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "flap".into(),
        reconnect_delay_secs: 10,
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(
        handle_inert,
        MockBrasConfig {
            terminate_after: Some(Duration::from_secs(3)),
            ..Default::default()
        },
    );

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    // Virtual clock: minutes of backoff pass instantly.
    let mut seen = Vec::new();
    while seen.len() < 4 {
        let evt = timeout(Duration::from_secs(3600), pppoe_sub.recv())
            .await
            .expect("no Reconnecting within an hour")
            .expect("bus open");
        if let LanforgeEvent::Pppoe(PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        }) = evt.event
        {
            seen.push((attempt, next_retry_secs));
        }
    }

    let attempts: Vec<u32> = seen.iter().map(|(a, _)| *a).collect();
    assert_eq!(attempts, [1, 2, 3, 4], "flaps must accumulate: {seen:?}");
    for pair in seen.windows(2) {
        assert!(pair[1].1 > pair[0].1, "delay must grow: {seen:?}");
    }

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// AGENTS.md async hygiene: a lagged broadcast receiver skips, only a closed one ends the loop.
/// The keepalive treated any system-bus `recv` error as the end of the session, so a burst of
/// system events (boot, many services reporting) tore down a healthy PPPoE session and the
/// household got a reconnect and a new delegated prefix for nothing.
#[tokio::test]
async fn test_pppoe_session_survives_a_lagged_system_bus() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });
    wait_for_session_up(&mut pppoe_sub).await;

    // Far beyond the system topic capacity, without yielding: the keepalive receiver lags.
    for _ in 0..1000 {
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceReady {
            id: ServiceId::Dns,
        }));
    }

    let down = timeout(
        Duration::from_millis(500),
        wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
            PppoeEvent::SessionDown { reason } => Some(reason.clone()),
            _ => None,
        }),
    )
    .await;
    assert!(down.is_err(), "session torn down by a lagged bus: {down:?}");
    assert_eq!(
        ctx.get_service_state(ServiceId::Pppoe),
        ServiceState::Online
    );

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// D-1: losing a `Requires` dependency with `LossPolicy::Continue` must not touch the service. The
/// serve loop raced commands against the session future, so *any* command — including the
/// `DependencyLost` the supervisor sends when `interfaces` flaps — dropped the live session
/// (no PADT, no SessionDown) and started a new discovery while the concentrator still held the old
/// session.
#[tokio::test]
async fn test_pppoe_session_survives_dependency_notifications() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(&ctx);
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });
    wait_for_session_up(&mut pppoe_sub).await;

    for cmd in [
        ServiceCommand::DependencyLost {
            id: ServiceId::Interfaces,
            policy: LossPolicy::Continue,
        },
        ServiceCommand::DependencyRestored {
            id: ServiceId::Interfaces,
        },
        ServiceCommand::Start,
    ] {
        cmd_tx.send(cmd).await.expect("service alive");
    }

    let churn = timeout(
        Duration::from_millis(500),
        wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
            PppoeEvent::SessionDown { reason } => Some(format!("down: {reason}")),
            PppoeEvent::SessionUp(_) => Some("renegotiated".into()),
            _ => None,
        }),
    )
    .await;
    assert!(
        churn.is_err(),
        "session disturbed by a notification: {churn:?}"
    );

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// One SessionDown per SessionUp. An admin stop tears the session down in the serve loop and the
/// supervisor then calls `cleanup()`; the old heuristic also looked at the WAN snapshot, which the
/// `wan` service updates asynchronously, so the second teardown published a second SessionDown and
/// every consumer (firewall, traffic, DNS) reacted twice.
#[tokio::test]
async fn test_pppoe_stop_then_cleanup_publishes_one_session_down() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(&ctx);
    let handle = tokio::spawn(async move {
        let res = service.serve(&ctx_clone, &h).await;
        (service, res)
    });
    let up = wait_for_session_up(&mut pppoe_sub).await;
    // What the `wan` service publishes on SessionUp; it has not processed SessionDown yet.
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifname: Some(up.interface),
        generation: 1,
        ..Default::default()
    });

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let (mut service, res) = timeout(Duration::from_secs(2), handle)
        .await
        .expect("serve returns on Stop")
        .expect("join");
    assert!(res.is_ok());
    service.cleanup(&ctx).await.expect("cleanup");

    let mut downs = Vec::new();
    while let Ok(Ok(evt)) = timeout(Duration::from_millis(200), pppoe_sub.recv()).await {
        if let LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) = evt.event {
            downs.push(reason);
        }
    }
    assert_eq!(
        downs,
        ["Service stopped"],
        "exactly one SessionDown per session"
    );
}

/// RFC 2516 §5.5: either side may end the session with a PADT. Ignoring the concentrator's PADT
/// left the WAN dead until the LCP echo gave up (5 × 20 s by default) before reconnecting.
#[tokio::test(start_paused = true)]
async fn test_pppoe_reacts_to_padt_from_the_concentrator() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(
        handle_inert,
        MockBrasConfig {
            padt_after: Some(Duration::from_secs(1)),
            ..Default::default()
        },
    );

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_clone.clone());
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });
    wait_for_session_up(&mut pppoe_sub).await;
    let up_at = tokio::time::Instant::now();

    let reason = timeout(Duration::from_secs(600), async {
        loop {
            if let Ok(evt) = pppoe_sub.recv().await
                && let LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) = evt.event
            {
                return reason;
            }
        }
    })
    .await
    .expect("session must go down");
    let after = up_at.elapsed();
    assert!(
        after < Duration::from_secs(5),
        "PADT noticed after {after:?} ({reason})"
    );

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Daemon readiness (`READY=1` to systemd) waits for every service to settle. WAN readiness is the
/// physical path to the modem/terminal, not the ISP session: a concentrator that does not answer
/// must not keep PPPoE unsettled, or `TimeoutStartSec` kills the daemon and the LAN (DHCP, DNS,
/// firewall) restart-loops with it.
#[tokio::test]
async fn test_pppoe_settles_before_the_session_is_up() {
    let (ctx, _bus) = create_test_context();

    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(
        handle_inert,
        MockBrasConfig {
            fail_discovery: true,
            ..Default::default()
        },
    );

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(&ctx);
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });

    let settled = timeout(Duration::from_secs(2), async {
        loop {
            let st = ctx.get_service_state(ServiceId::Pppoe);
            if matches!(st, ServiceState::Degraded | ServiceState::Online) {
                return st;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(
        settled,
        Ok(ServiceState::Degraded),
        "PPPoE must settle (Degraded) while the ISP does not answer"
    );

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// The supervisor node (what dependents such as `wan` follow) only learns states reported through
/// the handle. PPPoE wrote Online/Degraded straight into the context and relied on the
/// once-per-start ServiceReady bridge, so its node could disagree with its real state.
#[tokio::test]
async fn test_pppoe_reports_its_state_through_the_handle() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();
    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    ctx.update_pppoe_config(cfg.clone());

    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());

    let (status_tx, mut status_rx) = tokio::sync::watch::channel::<StatusReport>(None);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let h = ServiceHandle::with_command_channel(ServiceId::Pppoe, ctx.clone(), cmd_rx)
        .with_status_reporter(status_tx);

    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move { service.serve(&ctx_clone, &h).await });
    wait_for_session_up(&mut pppoe_sub).await;

    let mut seen = Vec::new();
    timeout(Duration::from_secs(1), async {
        loop {
            if let Some((state, _)) = status_rx.borrow_and_update().clone() {
                if seen.last() != Some(&state) {
                    seen.push(state);
                }
                if state == ServiceState::Online {
                    return;
                }
            }
            if status_rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("handle never reported Online: {seen:?}"));
    assert_eq!(seen.last(), Some(&ServiceState::Online));

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// The ISP's IPv6 resolvers come in RAs on the session link (RDNSS) after the session is up:
/// they join IPCP's IPv4 ones in the status and `DnsServersChanged` tells DNS; a zero lifetime
/// withdraws them.
#[tokio::test]
async fn test_pppoe_follows_the_isp_ipv6_resolvers_from_ra() {
    use lanforge_transport::Icmp6Transport;
    use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};

    /// An RA from the ISP router with one RDNSS option.
    fn ra(lifetime: u32, dns: Ipv6Addr) -> Vec<u8> {
        let mut m = vec![134, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[25, 3, 0, 0]);
        m.extend_from_slice(&lifetime.to_be_bytes());
        m.extend_from_slice(&dns.octets());
        m
    }

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
    let (handle_inert, transport) = PppoeTransport::inert();
    let _bras = spawn_mock_bras(handle_inert, MockBrasConfig::default());
    let (ra_handle, ra_transport) = Icmp6Transport::inert();
    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport)
        .with_wan_ra_transport(ra_transport);
    let ctx_serve = ctx.clone();
    let h = ServiceHandle::new(ServiceId::Pppoe, ctx_serve.clone());
    let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });

    let session = wait_for_session_up(&mut pppoe_sub).await;
    let ipcp_dns = session.dns.clone();
    assert_eq!(ipcp_dns.len(), 2);

    let router: SocketAddrV6 = "[fe80::1]:0".parse().unwrap();
    let isp_v6: Ipv6Addr = "2001:db8::53".parse().unwrap();
    ra_handle.inject(ra(600, isp_v6), router).await;
    let servers = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::DnsServersChanged { servers } => Some(servers.clone()),
        _ => None,
    })
    .await;
    let mut want = ipcp_dns.clone();
    want.push(IpAddr::V6(isp_v6));
    assert_eq!(servers, want, "IPCP IPv4 first, then the RA's IPv6");
    assert_eq!(ctx.pppoe_status().expect("status").dns_servers, want);

    ra_handle.inject(ra(0, isp_v6), router).await;
    let servers = wait_for_pppoe_event(&mut pppoe_sub, |evt| match evt {
        PppoeEvent::DnsServersChanged { servers } => Some(servers.clone()),
        _ => None,
    })
    .await;
    assert_eq!(servers, ipcp_dns, "lifetime 0 withdraws it");
    assert_eq!(ctx.pppoe_status().expect("status").dns_servers, ipcp_dns);

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    wait_for_session_down(&mut pppoe_sub).await;
    let _ = timeout(Duration::from_secs(2), serve).await;
}

/// What the concentrator saw, plus the serve task as the supervisor's runner holds it.
type Served = tokio::task::JoinHandle<(PppoeService, Result<(), CoreError>)>;

/// Starts the service against a mock concentrator.
fn start_with_bras(
    ctx: &LanforgeContext,
    cfg: PppoeConfig,
    bras: MockBrasConfig,
) -> (
    Arc<std::sync::Mutex<mock_bras::Seen>>,
    mpsc::Sender<ServiceCommand>,
    Served,
) {
    ctx.update_pppoe_config(cfg.clone());
    let (handle_inert, transport) = PppoeTransport::inert();
    let seen = bras.seen.clone();
    let _bras = spawn_mock_bras(handle_inert, bras);
    let mut service = PppoeService::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let (h, cmd_tx) = controlled_handle(ctx);
    let handle = tokio::spawn(async move {
        let res = service.serve(&ctx_clone, &h).await;
        (service, res)
    });
    (seen, cmd_tx, handle)
}

/// New credentials end the session and the next one must log in with them. The service went
/// back to discovery with the configuration it held before the change (the keepalive saw the
/// change, the service never did): the ISP got the old username again.
#[tokio::test]
async fn test_pppoe_reconnects_with_the_new_credentials() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();
    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "old_user".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    let (seen, _cmd_tx, handle) = start_with_bras(&ctx, cfg.clone(), MockBrasConfig::default());
    wait_for_session_up(&mut pppoe_sub).await;

    ctx.update_pppoe_config(PppoeConfig {
        username: "new_user".into(),
        ..cfg
    });
    wait_for_session_down(&mut pppoe_sub).await;
    wait_for_session_up(&mut pppoe_sub).await;

    assert_eq!(seen.lock().unwrap().chap_names, ["old_user", "new_user"]);
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}

/// Runtime-only settings (LCP echo, reconnect pacing, PADT on stop) apply to the live session:
/// no reconnect, and the session ends by the new rules.
#[tokio::test]
async fn test_pppoe_runtime_settings_apply_without_reconnect() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();
    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "client1".into(),
        ..Default::default()
    };
    let (seen, cmd_tx, handle) = start_with_bras(&ctx, cfg.clone(), MockBrasConfig::default());
    wait_for_session_up(&mut pppoe_sub).await;

    ctx.update_pppoe_config(PppoeConfig {
        lcp_echo_interval_secs: 7,
        lcp_echo_max_failures: 9,
        reconnect_delay_secs: 30,
        discovery_padi_retries: 2,
        send_padt_on_shutdown: false,
        ..cfg
    });
    // Nothing may happen to the session: no SessionDown, no new login.
    let quiet = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = pppoe_sub.recv().await
                && let LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) = evt.event
            {
                return reason;
            }
        }
    })
    .await;
    assert!(quiet.is_err(), "session dropped: {quiet:?}");
    assert_eq!(seen.lock().unwrap().chap_names, ["client1"]);

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let (_, res) = timeout(Duration::from_secs(2), handle)
        .await
        .expect("serve returns on Stop")
        .expect("join");
    assert!(res.is_ok());
    assert_eq!(
        seen.lock().unwrap().padts,
        0,
        "PADT sent although switched off"
    );
}

/// A change that lands while the session is still being negotiated (discovery, LCP, auth) is not
/// lost: the keepalive used to open a fresh subscription, already "up to date", and the session
/// stayed on the old credentials until the next drop.
#[tokio::test]
async fn test_pppoe_change_during_negotiation_is_not_lost() {
    let (ctx, bus) = create_test_context();
    let mut pppoe_sub = bus.subscribe_pppoe();
    let cfg = PppoeConfig {
        enabled: true,
        wan_iface: "eth1".into(),
        username: "old_user".into(),
        reconnect_delay_secs: 1,
        ..Default::default()
    };
    let bras = MockBrasConfig {
        pado_delay: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let (seen, _cmd_tx, handle) = start_with_bras(&ctx, cfg.clone(), bras);
    timeout(Duration::from_secs(2), async {
        while ctx
            .pppoe_status()
            .is_none_or(|s| s.state != PppoeSessionState::Discovering)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("discovery starts");
    ctx.update_pppoe_config(PppoeConfig {
        username: "new_user".into(),
        ..cfg
    });

    let names = timeout(Duration::from_secs(5), async {
        loop {
            wait_for_session_up(&mut pppoe_sub).await;
            let names = seen.lock().unwrap().chap_names.clone();
            if names.last().is_some_and(|n| n == "new_user") {
                return names;
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "never logged in with the new user: {:?}",
            seen.lock().unwrap().chap_names
        )
    });
    assert!(names.len() <= 2, "{names:?}");
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_secs(2), handle).await;
}
