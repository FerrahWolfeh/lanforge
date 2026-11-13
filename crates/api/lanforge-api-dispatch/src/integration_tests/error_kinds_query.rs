use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::dns_handle::DnsHandle;
use lanforge_core::context::state::State;
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{mpsc, oneshot};

#[tokio::test]
async fn dns_query_parse_error_returns_rejected_while_missing_handle_stays_error() {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None);
    let client = ClientContext {
        current_gua: None,
        uptime_secs: 10,
        ctx: ctx.clone(),
        active_clients: Arc::new(AtomicUsize::new(0)),
    };

    // Without a DNS handle, it is a server-side failure (Error).
    let missing_resp = client
        .handle_dns_query("example.com".to_string(), None)
        .await;
    assert!(
        matches!(missing_resp, Response::Error { .. }),
        "expected Error when DNS handle is missing, got {missing_resp:?}"
    );

    // With a DNS handle returning a query-question parse failure, it is Rejected.
    let (tx, mut rx) = mpsc::channel::<(DnsRequest, oneshot::Sender<DnsResponse>)>(4);
    tokio::spawn(async move {
        if let Some((DnsRequest::Query { .. }, reply)) = rx.recv().await {
            let _ = reply.send(DnsResponse::Query(Err(
                "Failed to parse query question".to_string()
            )));
        }
    });
    ctx.set_dns_handle(DnsHandle::new(tx));

    let bad_resp = client
        .handle_dns_query("bad..query".to_string(), None)
        .await;
    assert!(
        matches!(bad_resp, Response::Rejected { ref error } if error.contains("Failed to parse query question")),
        "expected Rejected, got {bad_resp:?}"
    );
}
