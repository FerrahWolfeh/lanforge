use lanforge::event_loop::ReadinessTracker;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::system::{ServiceId, ServiceState};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn test_event_loop_pre_seeded_readiness_reconciliation() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    // Simulate 5 services that have already transitioned to Online in Context
    // BEFORE the event loop even starts.
    let mut expected_services = HashSet::new();
    for id in [
        ServiceId::Db,
        ServiceId::Dns,
        ServiceId::Dhcp4,
        ServiceId::Dhcp6,
        ServiceId::Ra,
    ] {
        expected_services.insert(id);
        ctx.set_service_state(id, ServiceState::Online);
    }

    let mut sys_listener = bus.subscribe_system();

    // 1. Initialize tracker: pre-seeded services reconcile immediately
    let mut tracker = ReadinessTracker::new(&ctx, expected_services);

    // Verify that SystemReady is immediately published
    let event = timeout(Duration::from_millis(500), sys_listener.recv())
        .await
        .expect("Timeout waiting for SystemReady")
        .expect("Recv error");

    assert!(
        matches!(event.event, LanforgeEvent::System(SystemEvent::SystemReady)),
        "Expected SystemReady event, got: {:?}",
        event.event
    );

    // 2. Further calls are idempotent
    tracker.try_emit_system_ready();
    assert!(sys_listener.try_recv().is_err());
}

#[tokio::test]
async fn test_event_loop_concurrent_broadcast_readiness() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    let services = [
        ServiceId::Uds,
        ServiceId::Http,
        ServiceId::Tftp,
        ServiceId::Discovery,
        ServiceId::Pppoe,
    ];
    let mut expected_services = HashSet::new();
    for id in services {
        expected_services.insert(id);
    }

    let mut sys_listener = bus.subscribe_system();
    let mut tracker = ReadinessTracker::new(&ctx, expected_services);

    // Progressively report services ready
    for id in &services[..services.len() - 1] {
        tracker.on_service_ready(*id);
        // Not ready yet
        assert!(sys_listener.try_recv().is_err());
    }

    // Report final service
    let last = services[services.len() - 1];
    tracker.on_service_ready(last);

    // Verify SystemReady arrives promptly
    let event = timeout(Duration::from_millis(500), sys_listener.recv())
        .await
        .expect("Timeout waiting for SystemReady")
        .expect("Recv error");

    assert!(
        matches!(event.event, LanforgeEvent::System(SystemEvent::SystemReady)),
        "Expected SystemReady event, got: {:?}",
        event.event
    );
}

/// A ServiceReady lost to a lagged bus (15 services starting at once) was never recovered: the
/// periodic check only re-logged "still waiting", READY=1 never reached systemd and its start
/// timeout killed the whole daemon. The periodic check must re-read the services' real state.
#[tokio::test]
async fn test_periodic_check_recovers_a_lost_service_ready() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    ctx.set_service_state(ServiceId::Dns, ServiceState::Starting);
    let mut sys_listener = bus.subscribe_system();

    let mut tracker = ReadinessTracker::new(&ctx, HashSet::from([ServiceId::Dns]));
    assert!(sys_listener.try_recv().is_err(), "not ready yet");

    // The service settles, but its ServiceReady never reaches the tracker.
    ctx.set_service_state(ServiceId::Dns, ServiceState::Online);
    tracker.check_pending();

    let event = timeout(Duration::from_millis(200), sys_listener.recv())
        .await
        .expect("SystemReady after the periodic check")
        .expect("bus open");
    assert!(matches!(
        event.event,
        LanforgeEvent::System(SystemEvent::SystemReady)
    ));
}

/// One service stuck starting must not get the daemon killed by systemd's start timeout: past the
/// deadline READY=1 goes out, while SystemReady still waits for every service.
#[tokio::test]
async fn test_systemd_ready_is_not_held_hostage_by_one_service() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    ctx.set_service_state(ServiceId::Dns, ServiceState::Online);
    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Starting);
    let mut sys_listener = bus.subscribe_system();

    let mut tracker =
        ReadinessTracker::new(&ctx, HashSet::from([ServiceId::Dns, ServiceId::Pppoe]));
    let start = tokio::time::Instant::now();

    tracker.check_pending_at(start + Duration::from_secs(5));
    assert!(!tracker.systemd_ready_sent(), "too early");

    tracker.check_pending_at(start + lanforge::event_loop::SYSTEMD_READY_DEADLINE);
    assert!(
        tracker.systemd_ready_sent(),
        "deadline passed: READY=1 must go out"
    );
    assert!(
        sys_listener.try_recv().is_err(),
        "SystemReady still waits for the stuck service"
    );

    ctx.set_service_state(ServiceId::Pppoe, ServiceState::Degraded);
    tracker.check_pending_at(start + Duration::from_secs(20));
    let event = sys_listener
        .try_recv()
        .expect("SystemReady once all settled");
    assert!(matches!(
        event.event,
        LanforgeEvent::System(SystemEvent::SystemReady)
    ));
}
