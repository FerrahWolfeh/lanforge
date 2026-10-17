use crate::bus::{EventBus, FirewallEvent, LanforgeEvent, SystemEvent};
use crate::context::LanforgeContext;
use crate::context::state::State;
use crate::error::CoreError;
use crate::service::{ServiceControl, ServiceDependency};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, L4Protocol,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::system::{Cap, ServiceState, SystemStatus};
use lanforge_types::update::DeviceUpdate;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_core_state_concurrency_stress() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let mut write_tasks = Vec::new();
    for t_idx in 0u8..10 {
        let ctx = ctx.clone();
        write_tasks.push(tokio::spawn(async move {
            for i in 0u8..20 {
                let mac_bytes = [0x00, 0x11, 0x22, 0x33, t_idx, i];
                let mac = MacAddr(mac_bytes);
                let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
                    mac,
                    hostname: format!("host-{t_idx}-{i}"),
                });
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut read_tasks = Vec::new();
    for _ in 0..10 {
        let ctx = ctx.clone();
        read_tasks.push(tokio::spawn(async move {
            for _ in 0..20 {
                ctx.with_state(|s| {
                    let _ = s.devices.len();
                });
                let _ = ctx.get_device(&MacAddr([0x00, 0x11, 0x22, 0x33, 0, 0]));
                tokio::task::yield_now().await;
            }
        }));
    }

    for t in write_tasks {
        t.await.unwrap();
    }
    for t in read_tasks {
        t.await.unwrap();
    }

    // Verify all 200 devices were added
    let count = ctx.with_state(|s| s.devices.len());
    assert_eq!(count, 200);
}

#[tokio::test]
async fn test_wait_for_service_dependency() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    // 1. When already online, wait_for_dependency returns Ok(()) immediately
    ctx.set_service_state("dns", ServiceState::Online);
    let res = ctx
        .wait_for_dependency(ServiceDependency::Service("dns"))
        .await;
    assert!(res.is_ok());

    // 2. When not online, it waits for ServiceReady event
    let ctx_clone = ctx.clone();
    let wait_handle = tokio::spawn(async move {
        ctx_clone
            .wait_for_dependency(ServiceDependency::Service("db"))
            .await
    });

    // Cooperative yield to let wait_handle spawn and register its listener
    tokio::task::yield_now().await;
    ctx.set_service_state("db", ServiceState::Online);
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceReady {
        name: "db".to_string(),
    }));

    let res = wait_handle.await.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_wait_for_condition_shutdown_aborts() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    // 1. If context is already terminated, wait_for_db immediately fails with Shutdown
    ctx.terminate();
    let res = ctx.wait_for_db().await;
    assert!(matches!(res, Err(CoreError::Shutdown)));

    // 2. If waiting and shutdown is signaled on the bus, wait terminates with Shutdown
    ctx.reset_lifecycle();
    let ctx_clone = ctx.clone();
    let wait_handle = tokio::spawn(async move {
        ctx_clone.wait_for_db().await
    });

    tokio::task::yield_now().await;
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let res = wait_handle.await.unwrap();
    assert!(matches!(res, Err(CoreError::Shutdown)));
}

#[tokio::test]
async fn test_service_handle_stream() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    let mut handle = ctx.service_handle();

    // 1. Publish regular event
    let _ = handle.publish(LanforgeEvent::System(SystemEvent::DbReady));
    let next = handle.next_event().await;
    assert!(matches!(next.unwrap().event, LanforgeEvent::System(SystemEvent::DbReady)));

    // 2. Shutdown terminates the stream
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let next = handle.next_event().await;
    assert!(next.is_none());
}

#[tokio::test]
async fn test_service_control_idempotency() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    let mut rx = bus.subscribe_system();

    let ctrl = ServiceControl::new("test-svc", ctx.clone());
    assert_eq!(ctrl.id(), "test-svc");

    // Signal ready first time
    ctrl.signal_ready();
    assert_eq!(ctx.get_service_state("test-svc"), ServiceState::Online);

    let mut ready_count = 0;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::System(SystemEvent::ServiceReady { ref name }) if name == "test-svc") {
            ready_count += 1;
        }
    }
    assert_eq!(ready_count, 1);

    // Signal ready a second time (should be a no-op due to atomic swap)
    ctrl.signal_ready();
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.event, LanforgeEvent::System(SystemEvent::ServiceReady { ref name }) if name == "test-svc") {
            ready_count += 1;
        }
    }
    assert_eq!(ready_count, 1, "ServiceControl::signal_ready must be idempotent");
}

#[tokio::test]
async fn test_dynamic_pppoe_config() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    assert!(ctx.get_pppoe_config().is_none());

    let cfg = PppoeConfig {
        username: "test_user".to_string(),
        wan_iface: "eth42".to_string(),
        ..Default::default()
    };

    ctx.update_pppoe_config(cfg);

    let retrieved = ctx.get_pppoe_config();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.username, "test_user");
    assert_eq!(retrieved.wan_iface, "eth42");
}

#[tokio::test]
async fn test_server_capabilities_matrix() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    // Set custom compiled capabilities
    ctx.set_compiled_caps(smallvec::smallvec![
        Cap::Dns,
        Cap::DhcpV4,
        Cap::DhcpV6,
        Cap::Http,
    ]);

    // Status with DNS enabled, but DHCP disabled
    ctx.set_status(SystemStatus {
        dns_enabled: true,
        dhcp_v4_enabled: false,
        dhcp_v6_enabled: false,
        http_enabled: true,
        ..Default::default()
    });

    let caps = ctx.server_capabilities();
    assert!(caps.enabled.contains(&Cap::Dns));
    assert!(caps.enabled.contains(&Cap::Http));
    assert!(!caps.enabled.contains(&Cap::DhcpV4));
    assert!(!caps.enabled.contains(&Cap::DhcpV6));
}

#[tokio::test]
async fn test_dynamic_port_registration() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    let mut rx = bus.subscribe_firewall();

    // Register HTTP port 80
    ctx.register_service_port(DynamicPortRequest {
        service: "webui".to_string(),
        zone: "internal".to_string(),
        comment: Some("WebUI port".to_string()),
        port: 80,
        protocol: L4Protocol::Tcp,
    });

    let ev = rx.try_recv().unwrap();
    assert!(matches!(
        ev.event,
        LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(ref req)) if req.port == 80 && req.service == "webui"
    ));

    // Register same port again: must not duplicate
    ctx.register_service_port(DynamicPortRequest {
        service: "webui".to_string(),
        zone: "internal".to_string(),
        comment: Some("WebUI port".to_string()),
        port: 80,
        protocol: L4Protocol::Tcp,
    });
    assert_eq!(ctx.registered_service_ports().len(), 1);

    // Release port
    ctx.release_service_port("webui", 80, L4Protocol::Tcp);
    assert_eq!(ctx.registered_service_ports().len(), 0);

    let ev = rx.try_recv().unwrap();
    assert!(matches!(
        ev.event,
        LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { port, .. }) if port == 80
    ));
}

#[tokio::test]
async fn test_firewall_transaction_lifecycle() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let candidate = FirewallConfig::default();

    // Stage transaction
    let report = ctx.stage_firewall_transaction(candidate);
    assert!(report.valid);
    let tx_id = report.tx_id.expect("Expected transaction ID for valid candidate");

    // Retrieve staged transaction
    let staged = ctx.get_staged_firewall_transaction();
    assert!(staged.is_some());
    let staged = staged.unwrap();
    assert_eq!(staged.tx_id, tx_id);

    // Set rollback deadline
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    assert!(ctx.set_firewall_transaction_rollback(&tx_id, deadline));

    // Clear transaction
    let cleared = ctx.clear_staged_firewall_transaction(Some(&tx_id));
    assert!(cleared.is_some());
    assert!(ctx.get_staged_firewall_transaction().is_none());
}
