use lanforge::event_loop::ReadinessTracker;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::state::State;
use lanforge_core::context::LanforgeContext;
use lanforge_types::system::ServiceState;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_event_loop_pre_seeded_readiness_reconciliation() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    // Simulate 5 services that have already transitioned to Online in Context
    // BEFORE the event loop even starts.
    let mut expected_services = HashSet::new();
    for name in ["db", "dns", "dhcpv4", "dhcpv6", "ra"] {
        expected_services.insert(name.to_string());
        ctx.set_service_state(name, ServiceState::Online);
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

    let services = ["control", "http", "tftp", "monitor", "pppoe"];
    let mut expected_services = HashSet::new();
    for name in services {
        expected_services.insert(name.to_string());
    }

    let mut sys_listener = bus.subscribe_system();
    let mut tracker = ReadinessTracker::new(&ctx, expected_services);

    // Progressively report services ready
    for name in &services[..services.len() - 1] {
        tracker.on_service_ready(name);
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
