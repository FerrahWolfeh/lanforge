use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use lanforge::event_loop::ReadinessTracker;
use lanforge::registry::ServiceRegistry;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::state::State;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, LanforgeService, RestartPolicy, RuntimeClass, ServiceHandle,
    ServiceSpec,
};
use lanforge_types::system::{DegradedReason, ServiceState, StateDetail};
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// 1. Acceptance Test: ready_is_truthful
// PPPoE is not Online before session; SystemReady still emitted when Degraded.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_ready_is_truthful() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    let services = ["dns", "dhcpv4", "pppoe"];
    let mut expected_services = HashSet::new();
    for s in services {
        expected_services.insert(s.to_string());
    }

    let mut sys_listener = bus.subscribe_system();
    let mut tracker = ReadinessTracker::new(&ctx, expected_services);

    // Simulate DNS & DHCP becoming Online
    let h_dns = ServiceHandle::new("dns", ctx.clone());
    h_dns.ready();
    tracker.on_service_ready("dns");

    let h_dhcp = ServiceHandle::new("dhcpv4", ctx.clone());
    h_dhcp.ready();
    tracker.on_service_ready("dhcpv4");

    // Simulate PPPoE failing connection attempts and marking itself Degraded (truthful)
    let h_pppoe = ServiceHandle::new("pppoe", ctx.clone());
    assert_ne!(ctx.get_service_state("pppoe"), ServiceState::Online);
    h_pppoe.degraded(DegradedReason::custom("no pppoe session"));
    tracker.on_service_ready("pppoe");

    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Degraded);

    // Verify SystemReady is emitted because all services settled (Online + Degraded)
    let ready_event = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = sys_listener.recv().await
                && matches!(evt.event, LanforgeEvent::System(SystemEvent::SystemReady))
            {
                return true;
            }
        }
    })
    .await
    .expect("SystemReady should be emitted even with PPPoE Degraded");

    assert!(ready_event);
}

// ---------------------------------------------------------------------------
// 2. Acceptance Test: ready_idempotent_and_reset
// Calling ready() multiple times in the same generation emits exactly 1 event.
// On restart, exactly 1 new ServiceReady event is emitted per start generation.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_ready_idempotent_and_reset() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let mut sub = bus.subscribe_system();

    // First generation
    let h = ServiceHandle::new("test-svc", ctx.clone());
    assert!(!h.is_ready());

    // Call ready multiple times in the same generation
    h.ready();
    h.ready();
    h.ready();
    assert!(h.is_ready());

    // Expect exactly ONE ServiceReady event
    let event1 = sub.recv().await.unwrap();
    assert!(matches!(
        event1.event,
        LanforgeEvent::System(SystemEvent::ServiceReady { ref name }) if name == "test-svc"
    ));

    // Ensure no spurious duplicate events were queued
    assert!(sub.try_recv().is_err());

    // Second generation (simulating restart via a new handle)
    let h2 = ServiceHandle::new("test-svc", ctx.clone());
    assert!(!h2.is_ready());

    h2.ready();
    h2.ready();

    let event2 = sub.recv().await.unwrap();
    assert!(matches!(
        event2.event,
        LanforgeEvent::System(SystemEvent::ServiceReady { ref name }) if name == "test-svc"
    ));
    assert!(sub.try_recv().is_err());
}

// ---------------------------------------------------------------------------
// 3. Acceptance Test: clean_exit_resettable
// Clean exit (Ok(())) settles service to Inactive, does not enter backoff loop.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_clean_exit_resettable() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, move || {
        let a = attempts_clone.clone();
        CleanExitService { attempts: a }
    });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // Give time for clean exit
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Must execute once and settle in Inactive
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert_eq!(ctx.get_service_state("clean-exit"), ServiceState::Inactive);

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

struct CleanExitService {
    attempts: Arc<AtomicU32>,
}
impl LanforgeService for CleanExitService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: "clean-exit",
            display_name: "Clean Exit Service",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                max_retries: 3,
                healthy_uptime: Duration::from_millis(100),
            },
            shutdown_timeout: Duration::from_millis(100),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}
impl AsyncService for CleanExitService {
    async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 4. Acceptance Test: retry_exhausted_keeps_daemon
// Non-recovering service => Error, daemon alive, other services unaffected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_retry_exhausted_keeps_daemon() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, move || {
        let a = attempts_clone.clone();
        FailingService { attempts: a }
    });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // Wait until retries are exhausted
    timeout(Duration::from_secs(2), async {
        loop {
            if ctx.get_service_state("failing-svc") == ServiceState::Error {
                let detail = ctx.get_service_detail("failing-svc");
                if matches!(detail, Some(StateDetail::Failed { attempts: 3, .. })) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Service must exhaust retries and settle in Error");

    assert_eq!(ctx.get_service_state("failing-svc"), ServiceState::Error);
    assert!(ctx.is_running(), "Daemon must NOT be terminated on retry exhaustion!");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

struct FailingService {
    attempts: Arc<AtomicU32>,
}
impl LanforgeService for FailingService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: "failing-svc",
            display_name: "Failing Service",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(5),
                max_retries: 3,
                healthy_uptime: Duration::from_millis(50),
            },
            shutdown_timeout: Duration::from_millis(50),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}
impl AsyncService for FailingService {
    async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(CoreError::Generic("persistent hardware failure".into()))
    }
}
