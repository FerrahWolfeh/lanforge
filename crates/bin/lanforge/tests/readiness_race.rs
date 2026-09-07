use lanforge::bootstrap::BootstrapResult;
use lanforge::config::Config;
use lanforge::event_loop::{LoopResult, run_event_loop};
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::system::ServiceState;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};

async fn setup_test_bootstrap() -> BootstrapResult {
    let dir = tempdir().expect("Failed to create temp dir");
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

    let db = Arc::new(LanforgeDb::open(&cfg.database).await.expect("open db"));
    let log_db = Arc::new(
        LogDb::open(&cfg.database.runtime_path)
            .await
            .expect("open log_db"),
    );

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

#[tokio::test]
async fn test_event_loop_pre_seeded_readiness_reconciliation() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let bootstrap = setup_test_bootstrap().await;

    // Simulate 5 services that have already transitioned to Online in Context
    // BEFORE the event loop even starts.
    let mut expected_services = HashSet::new();
    for name in ["db", "dns", "dhcpv4", "dhcpv6", "ra"] {
        expected_services.insert(name.to_string());
        ctx.set_service_state(name, ServiceState::Online);
    }

    let mut sys_listener = bus.subscribe_system();

    let sys_rx = bus.subscribe_system();
    let net_rx = bus.subscribe_network();
    let sto_rx = bus.subscribe_storage();

    let ctx_loop = ctx.clone();
    let bootstrap_loop = bootstrap.clone();
    let expected_clone = expected_services.clone();

    let loop_handle = tokio::spawn(async move {
        run_event_loop(
            bootstrap_loop,
            ctx_loop,
            sys_rx,
            net_rx,
            sto_rx,
            expected_clone,
        )
        .await
    });

    // 1. Verify that SystemReady is immediately published on startup
    let event = timeout(Duration::from_millis(500), sys_listener.recv())
        .await
        .expect("Timeout waiting for SystemReady")
        .expect("Recv error");

    assert!(
        matches!(event.event, LanforgeEvent::System(SystemEvent::SystemReady)),
        "Expected SystemReady event, got: {:?}",
        event.event
    );

    // 2. Trigger clean loop exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));

    let res = timeout(Duration::from_millis(500), loop_handle)
        .await
        .expect("Timeout awaiting event loop exit")
        .expect("Join error")
        .expect("Event loop error");

    assert_eq!(res, LoopResult::Reload);
}

#[tokio::test]
async fn test_event_loop_concurrent_broadcast_readiness() {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);
    let bootstrap = setup_test_bootstrap().await;

    let services = ["control", "http", "tftp", "monitor", "pppoe"];
    let mut expected_services = HashSet::new();
    for name in services {
        expected_services.insert(name.to_string());
    }

    // Subscribe BEFORE spawning/publishing (pattern used in app.rs)
    let sys_rx = bus.subscribe_system();
    let net_rx = bus.subscribe_network();
    let sto_rx = bus.subscribe_storage();

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
            sto_rx,
            expected_clone,
        )
        .await
    });

    // Concurrently publish ServiceReady for all expected services
    for name in services {
        let bus_c = bus.clone();
        let name_s = name.to_string();
        tokio::spawn(async move {
            let _ = bus_c.publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                name: name_s,
            }));
        });
    }

    // Verify SystemReady arrives promptly
    loop {
        let event = timeout(Duration::from_millis(500), sys_listener.recv())
            .await
            .expect("Timeout waiting for SystemReady")
            .expect("Recv error");

        if matches!(event.event, LanforgeEvent::System(SystemEvent::SystemReady)) {
            break;
        }
    }

    // Clean exit
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));

    let res = timeout(Duration::from_millis(500), loop_handle)
        .await
        .expect("Timeout awaiting event loop exit")
        .expect("Join error")
        .expect("Event loop error");

    assert_eq!(res, LoopResult::Reload);
}
