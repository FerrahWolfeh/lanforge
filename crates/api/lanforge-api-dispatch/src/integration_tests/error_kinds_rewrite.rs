use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
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
async fn dns_rewrite_remove_missing_returns_not_found() {
    let client = test_client();
    let resp = client.handle_dns_rewrite_remove(999_999).await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}
