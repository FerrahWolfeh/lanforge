use lanforge::bootstrap::Bootstrapper;
use lanforge::config::Config;
use lanforge::config::toml::StaticDeviceCfg;
use lanforge_api::server::{ClientContext, handle_client};
use lanforge_core::bus::{EventBus, LanforgeEvent, StorageEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::device::Origin;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::service::ServiceControl;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::worker::DbWorker;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_full_db_reset_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup temporary environment
    let dir = tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("test.db");
    let log_db_path = dir.path().join("test_log.db");
    let db_url = format!("sqlite:{}", db_path.display());
    let log_db_url = format!("sqlite:{}", log_db_path.display());

    let mac_dyn = MacAddr::parse("00:00:00:00:00:01").unwrap();
    let mac_static = MacAddr::parse("00:00:00:00:00:02").unwrap();

    let mut cfg = Config {
        database: DatabaseConfig {
            url: db_url.clone(),
            log_url: log_db_url.clone(),
            ..Default::default()
        },
        ..Config::default()
    };
    cfg.devices.push(StaticDeviceCfg {
        mac: mac_static.to_string(),
        hostname: "static-host".to_string(),
        duid: None,
        v4_ip: Some("192.168.1.20".to_string()),
        v6_suffix: None,
        boot_file: None,
    });
    let cfg = Arc::new(cfg);

    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus.clone(), State::new(), None);

    // 2. Add some initial state (dynamic and static)
    use lanforge_core::context::state::{CliHostUpdate, DeviceUpdate, FieldUpdate};
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac: mac_dyn,
        ip: "192.168.1.10".parse::<Ipv4Addr>().unwrap(),
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_static,
        update: CliHostUpdate {
            hostname: FieldUpdate::Set("static-host".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::Set("192.168.1.20".parse::<Ipv4Addr>().unwrap()),
            v6_suffix: FieldUpdate::NoChange,
            origin: Origin::Cli,
            boot_file: FieldUpdate::NoChange,
        },
    });

    // 3. Spawn DbWorker
    let ctx_db = ctx.clone();
    let mut db_worker = DbWorker::new(
        DatabaseConfig {
            url: db_url,
            log_url: log_db_url,
            ..Default::default()
        },
        ctx_db,
    );
    let ctrl = ServiceControl::new("db", ctx.clone());
    tokio::spawn(async move {
        use lanforge_core::service::AsyncService;
        let _ = db_worker.run(ctrl).await;
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
    let api_cfg = Arc::new(cfg.to_api_config());

    // We need a dummy ClientContext
    let client_ctx = ClientContext {
        ctx: ctx_api,
        cfg: api_cfg,
        uptime_secs: 0,
        current_gua: None,
        last_scan_secs_ago: 0,
    };

    tokio::spawn(async move {
        let _ = handle_client(server, client_ctx).await;
    });

    let (reader, mut writer) = tokio::io::split(client);
    let mut reader = BufReader::new(reader);

    // 5. Mock Event Loop for DbResetCompleted
    let ctx_loop = ctx.clone();
    let cfg_loop = cfg.clone();
    let mut bus_rx = bus.subscribe();
    tokio::spawn(async move {
        while let Ok(te) = bus_rx.recv().await {
            if matches!(
                te.event,
                LanforgeEvent::Storage(StorageEvent::DbResetCompleted)
            ) {
                ctx_loop.reset();
                let mut state = ctx_loop.write();
                Bootstrapper::reload_static_devices_into_state(&mut state, &cfg_loop);
                break;
            }
        }
    });

    // 6. Send DB Reset Command
    writer
        .write_all(b"{\"command\":\"db_reset\"}\n")
        .await
        .unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.contains("Simulating cold start"),
        "Expected reset message, got: {}",
        line
    );

    // 7. Verify result
    // Wait for the chain to complete
    sleep(Duration::from_millis(1000)).await;

    let state = ctx.read();
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

    println!("✅ Reset chain verified!");
}
