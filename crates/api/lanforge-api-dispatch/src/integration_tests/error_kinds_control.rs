use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::network::firewall::{FirewallCommitRequest, FirewallConfig};
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
async fn pppoe_config_missing_returns_not_found() {
    let client = test_client();
    let resp = client.handle_pppoe_config().await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn firewall_commit_without_staged_tx_returns_not_found() {
    let client = test_client();
    let resp = client
        .handle_firewall_commit(FirewallCommitRequest {
            tx_id: "missing-tx".to_string(),
            auto_rollback_secs: None,
        })
        .await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn firewall_commit_tx_mismatch_returns_rejected() {
    let client = test_client();
    let report = match client
        .handle_firewall_propose(FirewallConfig::default())
        .await
    {
        Response::FirewallValidation(r) => r,
        other => panic!("expected FirewallValidation, got {other:?}"),
    };
    assert_ne!(report.tx_id.as_deref(), Some("wrong-tx"));

    let resp = client
        .handle_firewall_commit(FirewallCommitRequest {
            tx_id: "wrong-tx".to_string(),
            auto_rollback_secs: None,
        })
        .await;
    assert!(
        matches!(resp, Response::Rejected { .. }),
        "expected Response::Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn firewall_confirm_missing_tx_returns_not_found() {
    let client = test_client();
    let resp = client
        .handle_firewall_confirm("missing-tx".to_string())
        .await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn firewall_abort_missing_tx_returns_not_found() {
    let client = test_client();
    let resp = client.handle_firewall_abort("missing-tx".to_string()).await;
    assert!(
        matches!(resp, Response::NotFound { .. }),
        "expected Response::NotFound, got {resp:?}"
    );
}
