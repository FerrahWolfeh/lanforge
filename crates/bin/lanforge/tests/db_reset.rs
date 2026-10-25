use lanforge::config::Config;
use lanforge_api::rpc::LanforgeRpcClient;
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::{EventBus, LanforgeEvent, StorageEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::ServiceControl;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::worker::DbWorker;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;

use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use lanforge_uds::server::handle_client;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::tempdir;
use tokio::io::duplex;
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_full_db_reset_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup temporary environment
    let dir = tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("test.redb");
    let log_db_path = dir.path().join("test_log.jsonl");

    let mac_dyn = MacAddr::parse("00:00:00:00:00:01").unwrap();
    let mac_static = MacAddr::parse("00:00:00:00:00:02").unwrap();

    let cfg = Arc::new(Config {
        database: DatabaseConfig {
            config_path: db_path.display().to_string(),
            runtime_path: log_db_path.display().to_string(),
            ..Default::default()
        },
        ..Config::default()
    });

    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    // 2. Add some initial state (dynamic and static)
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac: mac_dyn,
        ip: "192.168.1.10".parse::<Ipv4Addr>().unwrap(),
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_static,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::Set("static-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set("192.168.1.20".parse::<Ipv4Addr>().unwrap()),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Static,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
        }),
    });

    // 3. Spawn DbWorker
    let ctx_db = ctx.clone();
    let db = Arc::new(
        LanforgeDb::open(&cfg.database)
            .expect("Failed to open DB"),
    );
    let log_db = Arc::new(
        LogDb::open(&cfg.database.runtime_path)
            .expect("Failed to open LogDB"),
    );

    let mut db_worker = DbWorker::new(cfg.database.clone(), ctx_db.clone(), db.clone(), log_db.clone());
    let ctrl = ServiceControl::new("db", ctx.clone());
    tokio::spawn(async move {
        use lanforge_core::service::AsyncService;
        let _ = db_worker.init(&ctx_db).await;
        ctrl.signal_ready();
        let _ = db_worker.serve(&ctx_db, &ctrl).await;
    });

    // Wait for DB ready
    ctx.wait_for_db().await.expect("DB failed to become ready");

    // Force a flush to disk so we have something to reset
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Storage(StorageEvent::TableDirty));
    sleep(Duration::from_millis(500)).await;

    // 4. Setup Mock Client and API handler
    let (client, server) = duplex(1024);
    let ctx_api = ctx.clone();

    // We need a dummy ClientContext
    let client_ctx = ClientContext {
        ctx: ctx_api,
        uptime_secs: 0,
        current_gua: None,
        active_clients: Arc::new(AtomicUsize::new(0)),
    };

    tokio::spawn(async move {
        let _ = handle_client(server, client_ctx).await;
    });

    // 5. Mock Event Loop for DbResetCompleted
    let ctx_loop = ctx.clone();
    let mut bus_rx = bus.subscribe();
    tokio::spawn(async move {
        while let Ok(te) = bus_rx.recv().await {
            if matches!(
                te.event,
                LanforgeEvent::Storage(StorageEvent::DbResetCompleted)
            ) {
                ctx_loop.reset();
                let _ = ctx_loop.apply(DeviceUpdate::CliHostUpdated {
                    mac: mac_static,
                    update: Box::new(CliHostUpdate {
                        hostname: FieldUpdate::from(Some("static-host".to_string())),
                        duid: FieldUpdate::NoChange,
                        v4_static: FieldUpdate::from(Some(Ipv4Addr::new(192, 168, 1, 20))),
                        v6_suffix: FieldUpdate::NoChange,
                        origin: Origin::Static,
                        boot_file: FieldUpdate::NoChange,
                        dns_fallback: FieldUpdate::NoChange,
                        class: FieldUpdate::NoChange,
                    }),
                });
                break;
            }
        }
    });

    // 6. Send DB Reset Command via RPC Client
    let mut rpc_client = LanforgeRpcClient::new(client);
    let resp = rpc_client.db_reset().await.expect("RPC db_reset failed");
    assert!(
        resp.message.contains("Factory reset completed"),
        "Expected reset message, got: {}",
        resp.message
    );

    // 7. Verify result
    // Wait for the chain to complete
    sleep(Duration::from_millis(1000)).await;

    ctx.with_state(|state| {
        assert!(
            !state.devices.contains_key(&mac_dyn),
            "Dynamic device should be gone after reset"
        );
        assert!(
            state.devices.contains_key(&mac_static),
            "Static device should be re-seeded after reset"
        );
        assert_eq!(
            state.devices.get(&mac_static).unwrap().hostname.name,
            "static-host"
        );
    });

    println!("✅ Reset chain verified!");
}
