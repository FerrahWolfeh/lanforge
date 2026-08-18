use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::log_engine::LogDb;
use lanforge_http::config::HttpConfig;
use lanforge_http::server::HttpService;
use std::sync::Arc;

async fn init_test_context() -> (LanforgeContext, Arc<LanforgeDb>, Arc<LogDb>) {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
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

    // Bind on :0 so the OS assigns a free port, avoiding conflicts when
    // tests run in parallel or multiple `cargo test` processes run concurrently.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // HttpService will re-bind; window is negligibly small in CI

    let http_cfg = HttpConfig {
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        enabled: true,
        allow_plaintext_http: true,
        ..Default::default()
    };
    let cfg = Arc::new(http_cfg);

    let mut service = HttpService::new(cfg, ctx.clone(), db, log_db);
    let ctrl = ServiceControl::new("http", ctx.clone());
    let ctx_service = ctx.clone();

    let mut rx = ctx.bus().subscribe();

    tokio::spawn(async move {
        ctrl.signal_ready();
        service.serve(&ctx_service).await.expect("Service failed");
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

    let client = lanforge_http::remote::default_http_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/api/v1/status").parse().unwrap();
    let req = hyper::Request::builder()
        .uri(uri)
        .body(http_body_util::Full::default())
        .unwrap();
    let res = client.request(req).await.expect("Failed to send request");

    assert_eq!(res.status(), 200);
}
