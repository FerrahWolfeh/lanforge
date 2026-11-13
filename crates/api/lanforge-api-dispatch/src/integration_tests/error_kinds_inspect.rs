use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::MacAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

fn test_client() -> ClientContext {
    let bus = Arc::new(EventBus::new());
    let ctx = LanforgeContext::new(bus, State::new(), None);
    ClientContext {
        current_gua: None,
        uptime_secs: 10,
        ctx,
        active_clients: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn whois_missing_device_returns_not_found() {
    let client = test_client();
    let resp = client.handle_whois("unknown-host".to_string()).await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn wol_missing_target_returns_not_found() {
    let client = test_client();
    let resp = client.handle_wol("unknown-host".to_string()).await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn purge_missing_device_returns_not_found() {
    let client = test_client();
    let mac = MacAddr::parse("02:00:00:00:00:99").unwrap();
    let resp = client.handle_purge(mac).await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}
