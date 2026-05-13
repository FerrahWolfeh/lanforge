use lanforge_api::config::ApiConfig;
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_core::types::device::Hostname;
use lanforge_core::types::identifiers::MacAddr;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LeaseDb;
use lanforge_db::log_engine::LogDb;
use lanforge_http::server::HttpService;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

async fn init_test_context() -> (LanforgeContext, Arc<LeaseDb>, Arc<LogDb>) {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        LeaseDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());
    (LanforgeContext::new(bus, table, None), db, log_db)
}

#[tokio::test]
async fn test_http_simulation_basic() {
    let (ctx, db, log_db) = init_test_context().await;

    // 1. Setup Config
    let api_cfg = ApiConfig {
        http_listen: Some("127.0.0.1:1080".parse().unwrap()),
        lan_iface: "lo".to_string(),
        ..Default::default()
    };
    let cfg = Arc::new(api_cfg);

    // 2. Start HTTP Service
    let mut service = HttpService::new(cfg, ctx.clone(), db, log_db);
    let ctrl = ServiceControl::new("http", ctx.clone());

    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        service.run(ctrl).await.expect("Service failed");
    });

    // Wait for ServiceReady event
    loop {
        let event = rx.recv().await.expect("Bus closed");
        if let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
            && name == "http"
        {
            break;
        }
    }

    // 3. Query using reqwest
    let client = reqwest::Client::new();

    // Test /status
    let resp = client
        .get("http://127.0.0.1:1080/status")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("Invalid JSON");
    assert_eq!(json["service"], "lanforge");
    assert_eq!(json["status"], "running");

    // Test /register
    let register_payload = serde_json::json!({
        "mac": "00:11:22:33:44:66",
        "hostname": "http-device"
    });
    let resp = client
        .post("http://127.0.0.1:1080/register")
        .json(&register_payload)
        .send()
        .await
        .expect("Register request failed");

    assert_eq!(resp.status(), 200);

    // Verify that device is in context
    sleep(Duration::from_millis(100)).await; // Wait for apply
    let mac = MacAddr::parse("00:11:22:33:44:66").unwrap();
    let device = ctx.get_device(&mac).expect("Device not registered");
    assert_eq!(device.hostname, Hostname::from("http-device"));

    // Cleanup: Shutdown context
    ctx.terminate();
}
