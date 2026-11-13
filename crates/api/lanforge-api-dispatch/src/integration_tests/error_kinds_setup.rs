use crate::ClientContext;
use lanforge_api::api::{Response, SetupPayload};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::worker::DbWorker;
use lanforge_db::{LanforgeDb, LogDb};
use lanforge_types::system::ServiceId;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::task::yield_now;

async fn test_client_with_storage() -> ClientContext {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open_in_memory());
    let mut worker = DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Db, ctx_worker.clone());
        let _ = worker.serve(&ctx_worker, &h).await;
    });
    while ctx.storage_handle().is_none() {
        yield_now().await;
    }
    ClientContext {
        current_gua: None,
        uptime_secs: 10,
        ctx,
        active_clients: Arc::new(AtomicUsize::new(0)),
    }
}

fn valid_setup_payload() -> SetupPayload {
    SetupPayload {
        admin_username: "admin".to_string(),
        admin_password: "correct-horse-battery".to_string(),
        lan_iface: "lan0".to_string(),
        lan_ip: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        domain_name: "lan".to_string(),
        dhcp_enabled: true,
        dhcp_pool_start: Ipv4Addr::new(192, 168, 1, 100),
        dhcp_pool_end: Ipv4Addr::new(192, 168, 1, 200),
        dhcp_router: None,
        dhcp_v6_enabled: false,
        dhcp_v6_pool_range: None,
        ra: None,
        upstream_dns: vec![],
        adblock_enabled: false,
        adblock_sources: vec![],
        wan: None,
        firewall_mode: None,
    }
}

#[tokio::test]
async fn setup_when_already_locked_returns_rejected() {
    let client = test_client_with_storage().await;
    client.ctx.set_recovery_mode(true);
    let resp = client.handle_setup(valid_setup_payload()).await;
    assert!(
        matches!(resp, Response::Rejected { .. }),
        "expected Response::Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn setup_with_empty_username_returns_rejected() {
    let client = test_client_with_storage().await;
    let mut payload = valid_setup_payload();
    payload.admin_username = "   ".to_string();
    let resp = client.handle_setup(payload).await;
    assert!(
        matches!(resp, Response::Rejected { .. }),
        "expected Response::Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn setup_with_short_password_returns_rejected() {
    let client = test_client_with_storage().await;
    let mut payload = valid_setup_payload();
    payload.admin_password = "short".to_string();
    let resp = client.handle_setup(payload).await;
    assert!(
        matches!(resp, Response::Rejected { .. }),
        "expected Response::Rejected, got {resp:?}"
    );
}
