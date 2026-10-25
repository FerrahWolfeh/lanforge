use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use lanforge::bootstrap::BootstrapResult;
use lanforge::config::Config;
use lanforge::event_loop::{LoopResult, run_event_loop};
use lanforge::supervisor::supervise_async;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceHandle, ServiceMeta};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::system::{DegradedReason, ServiceState, StateDetail};
use tempfile::tempdir;
use tokio::sync::broadcast;
use tokio::time::timeout;

async fn setup_test_bootstrap() -> BootstrapResult {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("test.redb");
    let log_db_path = dir.path().join("test_log.jsonl");

    let cfg = Arc::new(Config {
        database: DatabaseConfig {
            config_path: db_path.display().to_string(),
            runtime_path: log_db_path.display().to_string(),
            ..Default::default()
        },
        ..Config::default()
    });

    let db = Arc::new(LanforgeDb::open(&cfg.database).expect("open db"));
    let log_db = Arc::new(LogDb::open(&cfg.database.runtime_path).expect("open log_db"));

    let (conn, rt_handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(conn);

    let (messages, _) = broadcast::channel(16);

    BootstrapResult {
        cfg,
        rt_handle,
        messages,
        target_ifindex: 1,
        db,
        log_db,
    }
}

// ---------------------------------------------------------------------------
// 1. Acceptance Test: ready_is_truthful
// PPPoE is not Online before session; SystemReady still emitted when Degraded.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_ready_is_truthful() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let bootstrap = setup_test_bootstrap().await;

    let services = ["dns", "dhcpv4", "pppoe"];
    let mut expected_services = HashSet::new();
    for s in services {
        expected_services.insert(s.to_string());
    }

    let sys_rx = bus.subscribe_system();
    let net_rx = bus.subscribe_network();
    let mut sys_listener = bus.subscribe_system();

    let ctx_loop = ctx.clone();
    let bootstrap_loop = bootstrap.clone();
    let expected_clone = expected_services.clone();

    let loop_handle = tokio::spawn(async move {
        run_event_loop(
            bootstrap_loop,
            ctx_loop,
            sys_rx,
            net_rx,
            expected_clone,
        )
        .await
    });

    // Simulate DNS & DHCP becoming Online
    let h_dns = ServiceHandle::new("dns", ctx.clone());
    h_dns.ready();

    let h_dhcp = ServiceHandle::new("dhcpv4", ctx.clone());
    h_dhcp.ready();

    // Simulate PPPoE failing connection attempts and marking itself Degraded (truthful)
    let h_pppoe = ServiceHandle::new("pppoe", ctx.clone());
    assert_ne!(ctx.get_service_state("pppoe"), ServiceState::Online);
    h_pppoe.degraded(DegradedReason::custom("no pppoe session"));

    assert_eq!(ctx.get_service_state("pppoe"), ServiceState::Degraded);

    // Verify SystemReady is STILL emitted because all services settled (Online + Degraded)
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

    // Clean shutdown of event loop
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
    let res = timeout(Duration::from_millis(500), loop_handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(res, LoopResult::Reload);
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
    let mut ready_count = 0;
    while let Ok(evt) = timeout(Duration::from_millis(50), sub.recv()).await {
        if let Ok(timed) = evt
            && let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = timed.event
            && name == "test-svc"
        {
            ready_count += 1;
        }
    }
    assert_eq!(ready_count, 1, "ready() must be idempotent per start generation");

    // New generation (simulating supervisor restarting service)
    let h2 = ServiceHandle::new("test-svc", ctx.clone());
    assert!(!h2.is_ready(), "New handle generation must reset signaled state");
    h2.ready();

    // Expect exactly ONE new ServiceReady event
    let mut ready_count_2 = 0;
    while let Ok(evt) = timeout(Duration::from_millis(50), sub.recv()).await {
        if let Ok(timed) = evt
            && let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = timed.event
            && name == "test-svc"
        {
            ready_count_2 += 1;
        }
    }
    assert_eq!(ready_count_2, 1, "New generation emits exactly 1 event on ready");
}

// ---------------------------------------------------------------------------
// 3. Acceptance Test: exit_ok_is_inactive
// serve returns Ok => Inactive(Exited), no restart loop.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acceptance_exit_ok_is_inactive() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        supervise_async(&ctx_clone, move || {
            let a = attempts_clone.clone();
            CleanExitService { attempts: a }
        })
        .await;
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "Clean Ok(()) exit must NOT trigger a restart loop"
    );
    assert_eq!(ctx.get_service_state("clean-exit"), ServiceState::Inactive);
    let detail = ctx.get_service_detail("clean-exit");
    assert_eq!(detail, Some(StateDetail::Exited));

    ctx.terminate();
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = handle.await;
}

struct CleanExitService {
    attempts: Arc<AtomicU32>,
}
impl LanforgeService for CleanExitService {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "clean-exit",
            display_name: "Clean Exit Service",
            critical: false,
            max_retries: 3,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            shutdown_timeout: Duration::from_millis(100),
            multi_threaded: false,
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

    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        supervise_async(&ctx_clone, move || {
            let a = attempts_clone.clone();
            FailingService { attempts: a }
        })
        .await;
    });

    timeout(Duration::from_secs(2), handle)
        .await
        .expect("Supervisor must finish on retry exhaustion")
        .expect("Task join error");

    assert_eq!(ctx.get_service_state("failing-svc"), ServiceState::Error);
    assert!(ctx.is_running(), "Daemon must NOT be terminated on retry exhaustion!");

    let detail = ctx.get_service_detail("failing-svc");
    assert!(matches!(detail, Some(StateDetail::Failed { attempts: 3, .. })));
}

struct FailingService {
    attempts: Arc<AtomicU32>,
}
impl LanforgeService for FailingService {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "failing-svc",
            display_name: "Failing Service",
            critical: true, // Legacy flag, must be a no-op now
            max_retries: 3,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            shutdown_timeout: Duration::from_millis(50),
            multi_threaded: false,
        }
    }
}
impl AsyncService for FailingService {
    async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(CoreError::Generic("persistent hardware failure".into()))
    }
}
