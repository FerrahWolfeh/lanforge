//! Phase 3 Acceptance Tests — Graph Supervisor, DAG Validation, and Lifecycle Policies.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lanforge::registry::ServiceRegistry;
use lanforge::supervisor::graph::{DependencyGraph, GraphError};
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, DormantReason, Edge, LanforgeService, LossPolicy,
    RestartPolicy, RuntimeClass, ServiceHandle, ServiceSpec,
};
use lanforge_types::system::{ServiceId, ServiceState, StateDetail};
use tokio::sync::Notify;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_test_ctx() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    LanforgeContext::new(bus, State::new(), None)
}

fn dummy_spec(
    id: ServiceId,
    deps: &'static [Edge],
    condition: Condition,
) -> ServiceSpec {
    ServiceSpec {
        id,
        display_name: id.as_str(),
        runtime: RuntimeClass::Shared,
        restart: RestartPolicy {
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_retries: 3,
            healthy_uptime: Duration::from_millis(50),
        },
        shutdown_timeout: Duration::from_millis(50),
        deps,
        condition,
    }
}

// ---------------------------------------------------------------------------
// 1. DAG Validation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_graph_is_acyclic_real_catalog() {
    static DB_DEPS: &[Edge] = &[];
    static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];
    static DHCP4_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static DHCP6_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static RA_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static DNS_DEPS: &[Edge] = &[
        Edge::after(ServiceId::Db),
        Edge::wants(ServiceId::Dhcp4),
        Edge::wants(ServiceId::Dhcp6),
    ];
    static MONITOR_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static TRAFFIC_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static TFTP_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];
    static PPPOE_DEPS: &[Edge] = &[];
    static NFT_DEPS: &[Edge] = &[Edge::after(ServiceId::Db), Edge::wants(ServiceId::Pppoe)];
    static UDS_DEPS: &[Edge] = &[];

    let catalog = vec![
        dummy_spec(ServiceId::Db, DB_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Http, HTTP_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Dhcp4, DHCP4_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Dhcp6, DHCP6_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Ra, RA_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Dns, DNS_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Discovery, MONITOR_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Traffic, TRAFFIC_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Tftp, TFTP_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Pppoe, PPPOE_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Nft, NFT_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Uds, UDS_DEPS, Condition::ALWAYS),
    ];

    let graph = DependencyGraph::build(catalog).expect("Real catalog must be acyclic");
    let order = graph.topological_order();

    let db_idx = order.iter().position(|&s| s == ServiceId::Db).unwrap();
    let http_idx = order.iter().position(|&s| s == ServiceId::Http).unwrap();
    let dns_idx = order.iter().position(|&s| s == ServiceId::Dns).unwrap();
    let nft_idx = order.iter().position(|&s| s == ServiceId::Nft).unwrap();

    assert!(db_idx < http_idx, "db must precede http");
    assert!(db_idx < dns_idx, "db must precede dns");
    assert!(db_idx < nft_idx, "db must precede nft");
}

#[test]
fn test_graph_rejects_cycle() {
    static A_DEPS: &[Edge] = &[Edge::after(ServiceId::Dhcp4)];
    static B_DEPS: &[Edge] = &[Edge::after(ServiceId::Dhcp6)];
    static C_DEPS: &[Edge] = &[Edge::after(ServiceId::Dns)];

    let specs = vec![
        dummy_spec(ServiceId::Dns, A_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Dhcp4, B_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Dhcp6, C_DEPS, Condition::ALWAYS),
    ];

    let err = DependencyGraph::build(specs).unwrap_err();
    match err {
        GraphError::CycleDetected(cycle) => {
            assert!(cycle.contains(&ServiceId::Dns));
            assert!(cycle.contains(&ServiceId::Dhcp4));
            assert!(cycle.contains(&ServiceId::Dhcp6));
        }
        other => panic!("Expected CycleDetected, got {other:?}"),
    }
}

#[test]
fn test_graph_rejects_unknown_dep() {
    static A_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];

    let specs = vec![dummy_spec(ServiceId::Http, A_DEPS, Condition::ALWAYS)];
    let err = DependencyGraph::build(specs).unwrap_err();

    assert_eq!(
        err,
        GraphError::UnknownDependency {
            from: ServiceId::Http,
            to: ServiceId::Db,
        }
    );
}

// ---------------------------------------------------------------------------
// 2. Ordering & Dependency Blocking Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_requires_blocks_until_online() {
    let ctx = init_test_ctx();
    let gate = Arc::new(Notify::new());
    let b_started = Arc::new(AtomicBool::new(false));

    static A_DEPS: &[Edge] = &[];
    static B_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];

    struct SvcA {
        gate: Arc<Notify>,
    }
    impl LanforgeService for SvcA {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, A_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcA {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            self.gate.notified().await;
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    struct SvcB {
        started: Arc<AtomicBool>,
    }
    impl LanforgeService for SvcB {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, B_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcB {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let gate_clone = Arc::clone(&gate);
    registry.register(&ctx, move || SvcA { gate: Arc::clone(&gate_clone) });
    let started_clone = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB { started: Arc::clone(&started_clone) });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // SvcB must NOT have started because SvcA has not signaled ready yet
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!b_started.load(Ordering::SeqCst), "SvcB must be blocked waiting for SvcA to be Online");

    // Unblock SvcA
    gate.notify_one();

    // Now SvcB starts and runs
    timeout(Duration::from_millis(500), async {
        while !b_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SvcB must start after SvcA is Online");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_wants_does_not_block() {
    let ctx = init_test_ctx();
    let b_started = Arc::new(AtomicBool::new(false));

    static A_DEPS: &[Edge] = &[];
    static B_DEPS: &[Edge] = &[Edge::wants(ServiceId::Db)];

    struct SvcA;
    impl LanforgeService for SvcA {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, A_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcA {
        async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
            // SvcA stays starting / never calls ready()
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(())
        }
    }

    struct SvcB {
        started: Arc<AtomicBool>,
    }
    impl LanforgeService for SvcB {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, B_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcB {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || SvcA);
    let started_clone = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB { started: Arc::clone(&started_clone) });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // SvcB starts immediately regardless of SvcA
    timeout(Duration::from_millis(200), async {
        while !b_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SvcB must start without blocking on wanted SvcA");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

// ---------------------------------------------------------------------------
// 3. Loss Policy Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_loss_policy_restart_bounces_service() {
    let ctx = init_test_ctx();
    let b_runs = Arc::new(AtomicU32::new(0));

    static A_DEPS: &[Edge] = &[];
    static B_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];

    struct SvcA {
        dropped: bool,
    }
    impl LanforgeService for SvcA {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, A_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcA {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            if !self.dropped {
                h.ready();
                tokio::time::sleep(Duration::from_millis(30)).await;
                self.dropped = true;
                // Leave Online by exiting with error
                return Err(CoreError::Generic("flapped".into()));
            }
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    struct SvcB {
        runs: Arc<AtomicU32>,
    }
    impl LanforgeService for SvcB {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, B_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcB {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || SvcA { dropped: false });
    let runs_clone = Arc::clone(&b_runs);
    registry.register(&ctx, move || SvcB { runs: Arc::clone(&runs_clone) });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // Wait for SvcB to restart due to SvcA failure
    timeout(Duration::from_secs(1), async {
        while b_runs.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SvcB must restart when required SvcA is lost with LossPolicy::Restart");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

// ---------------------------------------------------------------------------
// 4. Condition Toggle & Dormancy Propagation Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dormant_requires_propagates() {
    let ctx = init_test_ctx();

    static A_DEPS: &[Edge] = &[];
    static B_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];

    struct SvcA;
    impl LanforgeService for SvcA {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(
                ServiceId::Db,
                A_DEPS,
                Condition {
                    sections: &[],
                    eval: |_| Activation::Dormant(DormantReason::disabled("db")),
                },
            )
        }
    }
    impl AsyncService for SvcA {
        async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
            Ok(())
        }
    }

    struct SvcB;
    impl LanforgeService for SvcB {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, B_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcB {
        async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
            panic!("SvcB should never serve because required SvcA is dormant!");
        }
    }

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || SvcA);
    registry.register(&ctx, || SvcB);

    let supervisor = registry.start(&ctx).expect("start supervisor");

    timeout(Duration::from_millis(200), async {
        loop {
            if ctx.get_service_state(ServiceId::Http) == ServiceState::Inactive {
                let detail = ctx.get_service_detail(ServiceId::Http);
                if matches!(detail, Some(StateDetail::DependencyDormant(_))) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SvcB must become Inactive(DependencyDormant) when SvcA is dormant");

    supervisor.shutdown(&ctx, Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------------------
// 5. Shutdown Reverse Order Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_shutdown_reverse_order() {
    let ctx = init_test_ctx();
    let stop_log = Arc::new(Mutex::new(Vec::new()));

    static DB_DEPS: &[Edge] = &[];
    static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];

    struct SvcDb {
        log: Arc<Mutex<Vec<ServiceId>>>,
    }
    impl LanforgeService for SvcDb {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, DB_DEPS, Condition::ALWAYS)
        }
        fn on_shutdown(&mut self) -> Result<(), CoreError> {
            self.log.lock().unwrap().push(ServiceId::Db);
            Ok(())
        }
    }
    impl AsyncService for SvcDb {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    struct SvcHttp {
        log: Arc<Mutex<Vec<ServiceId>>>,
    }
    impl LanforgeService for SvcHttp {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, HTTP_DEPS, Condition::ALWAYS)
        }
        fn on_shutdown(&mut self) -> Result<(), CoreError> {
            self.log.lock().unwrap().push(ServiceId::Http);
            Ok(())
        }
    }
    impl AsyncService for SvcHttp {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let log1 = Arc::clone(&stop_log);
    registry.register(&ctx, move || SvcDb { log: Arc::clone(&log1) });
    let log2 = Arc::clone(&stop_log);
    registry.register(&ctx, move || SvcHttp { log: Arc::clone(&log2) });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // Wait until both are Online
    timeout(Duration::from_millis(500), async {
        while ctx.get_service_state(ServiceId::Db) != ServiceState::Online
            || ctx.get_service_state(ServiceId::Http) != ServiceState::Online
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Both services must be Online");

    supervisor.shutdown(&ctx, Duration::from_millis(500)).await;

    let order = stop_log.lock().unwrap().clone();
    assert_eq!(order, vec![ServiceId::Http, ServiceId::Db], "Reverse-topological shutdown must stop http before db");
}

#[tokio::test]
async fn test_after_waits_for_settled() {
    let ctx = init_test_ctx();
    let gate = Arc::new(Notify::new());
    let b_started = Arc::new(AtomicBool::new(false));

    static A_DEPS: &[Edge] = &[];
    static B_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];

    struct SvcA {
        gate: Arc<Notify>,
    }
    impl LanforgeService for SvcA {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Db, A_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcA {
        async fn serve(&mut self, _ctx: &LanforgeContext, _h: &ServiceHandle) -> Result<(), CoreError> {
            self.gate.notified().await;
            // Exit with error to settle in Error state
            Err(CoreError::Generic("settled as error".into()))
        }
    }

    struct SvcB {
        started: Arc<AtomicBool>,
    }
    impl LanforgeService for SvcB {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(ServiceId::Http, B_DEPS, Condition::ALWAYS)
        }
    }
    impl AsyncService for SvcB {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let g = Arc::clone(&gate);
    registry.register(&ctx, move || SvcA { gate: Arc::clone(&g) });
    let b = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB { started: Arc::clone(&b) });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // SvcB does not start while SvcA is in Starting
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!b_started.load(Ordering::SeqCst), "SvcB must wait until SvcA settles");

    // Unblock SvcA to let it settle in Error
    gate.notify_one();

    // SvcB proceeds once SvcA settles
    timeout(Duration::from_millis(500), async {
        while !b_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SvcB must start after SvcA has settled");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_condition_toggle_isolated() {
    let ctx = init_test_ctx();
    static TOGGLE: AtomicBool = AtomicBool::new(true);

    static SVC_DEPS: &[Edge] = &[];

    struct ToggleSvc;
    impl LanforgeService for ToggleSvc {
        fn spec(&self) -> ServiceSpec {
            dummy_spec(
                ServiceId::Tftp,
                SVC_DEPS,
                Condition {
                    sections: &[],
                    eval: |_| {
                        if TOGGLE.load(Ordering::SeqCst) {
                            Activation::Active
                        } else {
                            Activation::Dormant(DormantReason::disabled("toggle"))
                        }
                    },
                },
            )
        }
    }
    impl AsyncService for ToggleSvc {
        async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || ToggleSvc);

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // Wait until Online
    timeout(Duration::from_millis(300), async {
        while ctx.get_service_state(ServiceId::Tftp) != ServiceState::Online {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Service must be Online initially");

    // Toggle off
    TOGGLE.store(false, Ordering::SeqCst);
    supervisor.reevaluate_conditions();

    // Context is still running
    assert!(ctx.is_running(), "Daemon must not restart or crash when toggling condition");

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}
