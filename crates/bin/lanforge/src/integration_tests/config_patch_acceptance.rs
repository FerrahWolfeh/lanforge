//! A reload of an unchanged file goes through the real API handler and must change nothing.
//! (The `ConfigPatch` semantics themselves are tested in `lanforge-core`.)

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use lanforge_api::api::{Response, SystemConfigExport};
use lanforge_api::config_file::{ConfigFile, RaInputs, effective_ra};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::state::State;
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_core::service::ServiceHandle;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_db::worker::DbWorker;
use lanforge_types::system::ServiceId;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);
    (ctx, bus)
}

#[tokio::test]
async fn test_acceptance_reload_noop() {
    let (ctx, _bus) = create_test_context();

    // Setup DB worker so storage handle is available
    let db_dir = tempfile::tempdir().unwrap();
    let db_cfg = DatabaseConfig {
        config_path: db_dir.path().join("test.redb").display().to_string(),
        runtime_path: db_dir.path().join("test_log.jsonl").display().to_string(),
        ..Default::default()
    };
    let db = Arc::new(LanforgeDb::open(&db_cfg).unwrap());
    let log_db = Arc::new(LogDb::open(&db_cfg.runtime_path).unwrap());
    let mut db_worker = DbWorker::new(db_cfg, ctx.clone(), db, log_db);
    let ctx_db = ctx.clone();
    let ctrl = ServiceHandle::new(ServiceId::Db, ctx.clone());
    tokio::spawn(async move {
        use lanforge_core::service::AsyncService;
        let _ = db_worker.init(&ctx_db).await;
        ctrl.ready();
        let _ = db_worker.serve(&ctx_db, &ctrl).await;
    });
    ctx.wait_for_service(ServiceId::Db)
        .await
        .expect("DB failed to become ready");

    // Create a temporary configuration file matching context
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("lanforge.toml");

    let initial_toml = r#"
[system]
iface = "lan0"

[pppoe]
enabled = false
wan_iface = "eth1"
username = ""
"#;
    fs::write(&config_path, initial_toml).unwrap();

    ctx.set_config_path(&config_path);

    // Hydrate context to match the on-disk initial state
    let cfg_file = ConfigFile::parse(initial_toml).unwrap();
    // The RA the boot runs: `[ra]` plus what the daemon derives (no LAN interface set here).
    let ra = effective_ra(
        cfg_file.ra.to_config().0,
        &RaInputs {
            search_domains: cfg_file.search_domains(),
            ..Default::default()
        },
    );
    let export = SystemConfigExport::from(cfg_file);
    let mut initial_patch = ConfigPatch::new().with_ra_server(ra);
    if let Some(pppoe) = export.pppoe_config {
        initial_patch = initial_patch.with_pppoe(*pppoe);
    }
    if let Some(dhcp_opts) = export.dhcp_options {
        initial_patch = initial_patch.with_dhcp_options(*dhcp_opts);
    }
    if let Some(fw) = export.firewall_config {
        initial_patch = initial_patch.with_firewall(*fw);
    }
    if let Some(tr) = export.traffic_config {
        initial_patch = initial_patch.with_traffic(*tr);
    }
    initial_patch = initial_patch.with_dns_adblock(export.dns_adblock_config);
    ctx.hydrate_config(initial_patch);

    // Client context for RPC operations
    let client = ClientContext::new(ctx.clone());
    let mut sys_rx = ctx.bus().subscribe_system();

    // Trigger reload
    let res = client.handle_reload().await;
    match res {
        Response::Success(s) => {
            assert!(
                s.message.contains("reloaded"),
                "Reload must succeed: {}",
                s.message
            );
        }
        other => panic!("Unexpected reload response: {other:?}"),
    }

    // Unchanged config must emit ZERO ConfigChanged events
    while let Ok(Ok(timed)) = timeout(Duration::from_millis(50), sys_rx.recv()).await {
        if let LanforgeEvent::System(SystemEvent::ConfigChanged { sections }) = timed.event {
            panic!("No ConfigChanged event expected on no-op reload, got: {sections:?}");
        }
    }
}
