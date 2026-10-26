//! Phase 3 Acceptance Tests — Graph Supervisor, DAG Validation, and Lifecycle Policies.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lanforge::registry::ServiceRegistry;
use lanforge::supervisor::graph::{DependencyGraph, GraphError};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, DegradedReason, DormantReason, Edge, LanforgeService,
    LossPolicy, RestartPolicy, RuntimeClass, ServiceCommand, ServiceHandle, ServiceSpec,
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

fn dummy_spec(id: ServiceId, deps: &'static [Edge], condition: Condition) -> ServiceSpec {
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
    static INTERFACES_DEPS: &[Edge] = &[];
    static DB_DEPS: &[Edge] = &[];
    static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];
    static PPPOE_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Continue)];
    static WAN_DEPS: &[Edge] = &[
        Edge::wants(ServiceId::Pppoe),
        Edge::wants(ServiceId::Interfaces),
    ];
    static DHCP4_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Degrade)];
    static DHCP6_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static RA_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static DNS_DEPS: &[Edge] = &[
        Edge::after(ServiceId::Db),
        Edge::wants(ServiceId::Wan),
        Edge::wants(ServiceId::Interfaces),
        Edge::wants(ServiceId::Dhcp4),
        Edge::wants(ServiceId::Dhcp6),
    ];
    static MONITOR_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Degrade),
        Edge::after(ServiceId::Db),
    ];
    static TRAFFIC_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static TFTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Degrade)];
    static NFT_DEPS: &[Edge] = &[
        Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
        Edge::wants(ServiceId::Wan),
    ];
    static UDS_DEPS: &[Edge] = &[];

    let catalog = vec![
        dummy_spec(ServiceId::Interfaces, INTERFACES_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Db, DB_DEPS, Condition::ALWAYS),
        dummy_spec(ServiceId::Wan, WAN_DEPS, Condition::ALWAYS),
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

    let if_idx = order
        .iter()
        .position(|&s| s == ServiceId::Interfaces)
        .unwrap();
    let pppoe_idx = order.iter().position(|&s| s == ServiceId::Pppoe).unwrap();
    let wan_idx = order.iter().position(|&s| s == ServiceId::Wan).unwrap();
    let nft_idx = order.iter().position(|&s| s == ServiceId::Nft).unwrap();

    assert!(if_idx < pppoe_idx, "interfaces must precede pppoe");
    assert!(pppoe_idx < wan_idx, "pppoe must precede wan");
    assert!(wan_idx < nft_idx, "wan must precede nft");
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
    static A_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];

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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let gate_clone = Arc::clone(&gate);
    registry.register(&ctx, move || SvcA {
        gate: Arc::clone(&gate_clone),
    });
    let started_clone = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB {
        started: Arc::clone(&started_clone),
    });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // SvcB must NOT have started because SvcA has not signaled ready yet
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !b_started.load(Ordering::SeqCst),
        "SvcB must be blocked waiting for SvcA to be Online"
    );

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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            _h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || SvcA);
    let started_clone = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB {
        started: Arc::clone(&started_clone),
    });

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

/// Required dependency that is ready, flaps (exits with an error), then comes back after a delay
/// long enough for dependents to observe the loss window.
struct FlappingDb {
    runs: Arc<AtomicU32>,
}
impl LanforgeService for FlappingDb {
    fn spec(&self) -> ServiceSpec {
        dummy_spec(ServiceId::Db, &[], Condition::ALWAYS)
    }
}
impl AsyncService for FlappingDb {
    async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if self.runs.fetch_add(1, Ordering::SeqCst) == 0 {
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Err(CoreError::Generic("flapped".into()));
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        h.ready();
        h.run_until_stopped(std::future::pending::<Result<(), CoreError>>())
            .await
            .map(|_| ())
    }
}

/// Dependent that counts its starts and records the lifecycle commands it receives.
struct Dependent {
    deps: &'static [Edge],
    runs: Arc<AtomicU32>,
    commands: Arc<Mutex<Vec<ServiceCommand>>>,
}
impl LanforgeService for Dependent {
    fn spec(&self) -> ServiceSpec {
        dummy_spec(ServiceId::Http, self.deps, Condition::ALWAYS)
    }
}
impl AsyncService for Dependent {
    async fn serve(&mut self, _ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        h.ready();
        loop {
            match h.next_command().await {
                ServiceCommand::Stop | ServiceCommand::Shutdown => return Ok(()),
                cmd => self.commands.lock().unwrap().push(cmd),
            }
        }
    }
}

/// D-1: losing a required dependency never stops or restarts the dependent, whatever its
/// `LossPolicy`; the dependent is notified, its status reflects the policy while the dependency
/// is gone, it returns to `Online` on recovery, and shutdown still completes during the loss.
async fn assert_loss_policy_never_restarts(
    deps: &'static [Edge],
    expected_detail: Option<StateDetail>,
) {
    let ctx = init_test_ctx();
    let db_runs = Arc::new(AtomicU32::new(0));
    let dep_runs = Arc::new(AtomicU32::new(0));
    let commands = Arc::new(Mutex::new(Vec::new()));

    let mut registry = ServiceRegistry::new();
    let db_runs_c = Arc::clone(&db_runs);
    registry.register(&ctx, move || FlappingDb {
        runs: Arc::clone(&db_runs_c),
    });
    let (dep_runs_c, commands_c) = (Arc::clone(&dep_runs), Arc::clone(&commands));
    registry.register(&ctx, move || Dependent {
        deps,
        runs: Arc::clone(&dep_runs_c),
        commands: Arc::clone(&commands_c),
    });
    let supervisor = registry.start(&ctx).expect("start supervisor");

    let has = |pred: fn(&ServiceCommand) -> bool| commands.lock().unwrap().iter().any(pred);
    timeout(Duration::from_secs(1), async {
        while !has(|c| {
            matches!(
                c,
                ServiceCommand::DependencyLost {
                    id: ServiceId::Db,
                    ..
                }
            )
        }) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dependent must be notified of the loss");

    // Inside the loss window (the dependency takes 150 ms to come back).
    let (state, detail) = (
        ctx.get_service_state(ServiceId::Http),
        ctx.get_service_detail(ServiceId::Http),
    );
    match &expected_detail {
        Some(expected) => {
            assert_eq!(state, ServiceState::Degraded);
            assert_eq!(detail.as_ref(), Some(expected));
        }
        None => assert_eq!(
            state,
            ServiceState::Online,
            "Continue must not change the status"
        ),
    }

    timeout(Duration::from_secs(1), async {
        while !has(|c| matches!(c, ServiceCommand::DependencyRestored { id: ServiceId::Db })) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dependent must be notified of the recovery");

    assert_eq!(ctx.get_service_state(ServiceId::Http), ServiceState::Online);
    assert_eq!(ctx.get_service_detail(ServiceId::Http), None);
    assert_eq!(
        dep_runs.load(Ordering::SeqCst),
        1,
        "dependency loss must never restart the dependent"
    );
    assert!(
        db_runs.load(Ordering::SeqCst) >= 2,
        "the dependency itself must have flapped"
    );

    timeout(
        Duration::from_secs(1),
        supervisor.shutdown(&ctx, Duration::from_millis(200)),
    )
    .await
    .expect("shutdown must complete");
}

#[tokio::test]
async fn no_loss_policy_restarts_service_continue() {
    static DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];
    assert_loss_policy_never_restarts(DEPS, None).await;
}

#[tokio::test]
async fn no_loss_policy_restarts_service_degrade() {
    static DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Degrade)];
    assert_loss_policy_never_restarts(
        DEPS,
        Some(StateDetail::Degraded(DegradedReason::Custom("db".into()))),
    )
    .await;
}

#[tokio::test]
async fn no_loss_policy_restarts_service_pause() {
    static DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Pause)];
    assert_loss_policy_never_restarts(DEPS, Some(StateDetail::Paused(ServiceId::Db))).await;
}

/// Shutdown must not hang while a dependent is paused on a dependency that never returns.
#[tokio::test]
async fn shutdown_completes_while_paused() {
    struct DeadDb;
    impl LanforgeService for DeadDb {
        fn spec(&self) -> ServiceSpec {
            let mut spec = dummy_spec(ServiceId::Db, &[], Condition::ALWAYS);
            spec.restart.max_retries = 1;
            spec
        }
    }
    impl AsyncService for DeadDb {
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_millis(30)).await;
            Err(CoreError::Generic("gone".into()))
        }
    }
    static DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Pause)];

    let ctx = init_test_ctx();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut registry = ServiceRegistry::new();
    registry.register(&ctx, || DeadDb);
    let commands_c = Arc::clone(&commands);
    registry.register(&ctx, move || Dependent {
        deps: DEPS,
        runs: Arc::new(AtomicU32::new(0)),
        commands: Arc::clone(&commands_c),
    });
    let supervisor = registry.start(&ctx).expect("start supervisor");

    timeout(Duration::from_secs(1), async {
        while ctx.get_service_detail(ServiceId::Http) != Some(StateDetail::Paused(ServiceId::Db)) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dependent must be paused");

    timeout(
        Duration::from_secs(1),
        supervisor.shutdown(&ctx, Duration::from_millis(200)),
    )
    .await
    .expect("shutdown must complete while a dependent is paused");
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            _h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            _h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
    static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Continue)];

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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            h.ready();
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let log1 = Arc::clone(&stop_log);
    registry.register(&ctx, move || SvcDb {
        log: Arc::clone(&log1),
    });
    let log2 = Arc::clone(&stop_log);
    registry.register(&ctx, move || SvcHttp {
        log: Arc::clone(&log2),
    });

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
    assert_eq!(
        order,
        vec![ServiceId::Http, ServiceId::Db],
        "Reverse-topological shutdown must stop http before db"
    );
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            _h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
            self.started.store(true, Ordering::SeqCst);
            h.ready();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }
    }

    let mut registry = ServiceRegistry::new();
    let g = Arc::clone(&gate);
    registry.register(&ctx, move || SvcA {
        gate: Arc::clone(&g),
    });
    let b = Arc::clone(&b_started);
    registry.register(&ctx, move || SvcB {
        started: Arc::clone(&b),
    });

    let supervisor = registry.start(&ctx).expect("start supervisor");

    // SvcB does not start while SvcA is in Starting
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !b_started.load(Ordering::SeqCst),
        "SvcB must wait until SvcA settles"
    );

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
        async fn serve(
            &mut self,
            _ctx: &LanforgeContext,
            h: &ServiceHandle,
        ) -> Result<(), CoreError> {
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
    assert!(
        ctx.is_running(),
        "Daemon must not restart or crash when toggling condition"
    );

    supervisor.shutdown(&ctx, Duration::from_millis(200)).await;
}
