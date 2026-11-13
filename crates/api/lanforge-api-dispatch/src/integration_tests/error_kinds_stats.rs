use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use std::net::SocketAddr;
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
async fn dns_upstream_remove_missing_returns_not_found() {
    let client = test_client();
    let addr: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let resp = client
        .handle_dns_upstream_remove(addr, UpstreamProtocol::Udp, None)
        .await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}
