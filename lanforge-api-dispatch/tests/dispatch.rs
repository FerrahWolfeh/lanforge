use lanforge_api::api::{HostConfigEntry, Response};
use lanforge_api_dispatch::ClientContext;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LeaseDb;
use lanforge_db::log_engine::LogDb;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

async fn init_test_context() -> ClientContext {
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
    let ctx = LanforgeContext::new(bus, table, None);

    ClientContext {
        current_gua: None,
        uptime_secs: 100,
        last_scan_secs_ago: 5,
        ctx,
        db,
        log_db,
        active_clients: Arc::new(AtomicUsize::new(1)),
    }
}

#[tokio::test]
async fn test_dispatch_status() {
    let client_ctx = init_test_context().await;
    let res = client_ctx.handle_status().await;
    assert!(matches!(res, Response::Status(_)));
}

#[tokio::test]
async fn test_dispatch_topology() {
    let client_ctx = init_test_context().await;
    let res = client_ctx.handle_topology().await;
    assert!(matches!(res, Response::Topology(_)));
}

#[tokio::test]
async fn test_dispatch_devices() {
    let client_ctx = init_test_context().await;
    let res = client_ctx
        .handle_devices(None, None, None, None, None, None)
        .await;
    if let Response::Devices(d) = res {
        assert_eq!(d.devices.len(), 0);
        assert_eq!(d.meta.total, 0);
    } else {
        panic!("Expected Response::Devices");
    }
}

#[tokio::test]
async fn test_dispatch_hosts_crud() {
    let client_ctx = init_test_context().await;

    // 1. Initial hosts should be empty
    let res = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res {
        assert_eq!(h.hosts.len(), 0);
    } else {
        panic!("Expected Response::Hosts");
    }

    // 2. Add a host
    let entry = HostConfigEntry {
        mac: "00:11:22:33:44:55".to_string(),
        hostname: "test-host".to_string(),
        v4_fixed: Some("192.168.1.100".to_string()),
        v6_suffix: None,
        origin: "static".to_string(),
    };
    let add_res = client_ctx.handle_host_add(entry).await;
    assert!(matches!(add_res, Response::Success(_)));

    // 3. Verify host is listed
    let res2 = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res2 {
        assert_eq!(h.hosts.len(), 1);
        assert_eq!(h.hosts[0].mac, "00:11:22:33:44:55");
        assert_eq!(h.hosts[0].hostname, "test-host");
    } else {
        panic!("Expected Response::Hosts");
    }

    // 4. Remove host
    let remove_res = client_ctx
        .handle_host_remove("00:11:22:33:44:55".to_string())
        .await;
    assert!(matches!(remove_res, Response::Success(_)));

    // 5. Verify hosts empty again
    let res3 = client_ctx.handle_hosts().await;
    if let Response::Hosts(h) = res3 {
        assert_eq!(h.hosts.len(), 0);
    } else {
        panic!("Expected Response::Hosts");
    }
}
