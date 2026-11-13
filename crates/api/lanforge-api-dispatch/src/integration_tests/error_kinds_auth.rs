use crate::ClientContext;
use lanforge_api::api::Response;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::worker::DbWorker;
use lanforge_db::{LanforgeDb, LogDb};
use lanforge_types::system::ServiceId;
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

#[tokio::test]
async fn ak_renew_missing_token_returns_not_found() {
    let client = test_client_with_storage().await;
    let resp = client.handle_ak_renew("no-such-token".to_string()).await;
    assert!(
        matches!(resp, Response::NotFound { ref error } if error.contains("not found")),
        "expected NotFound, got {resp:?}"
    );
}

#[tokio::test]
async fn user_create_empty_username_returns_rejected() {
    let client = test_client_with_storage().await;
    let resp = client
        .handle_user_create("   ".to_string(), "longenough".to_string(), None)
        .await;
    assert!(
        matches!(resp, Response::Rejected { ref error } if error.contains("empty")),
        "expected Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn user_create_short_password_returns_rejected() {
    let client = test_client_with_storage().await;
    let resp = client
        .handle_user_create("alice".to_string(), "short".to_string(), None)
        .await;
    assert!(
        matches!(resp, Response::Rejected { ref error } if error.contains("8 characters")),
        "expected Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn user_create_invalid_role_returns_rejected() {
    let client = test_client_with_storage().await;
    let resp = client
        .handle_user_create(
            "alice".to_string(),
            "longenough".to_string(),
            Some("superuser".to_string()),
        )
        .await;
    assert!(
        matches!(resp, Response::Rejected { .. }),
        "expected Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn user_delete_last_user_returns_rejected() {
    let client = test_client_with_storage().await;
    let create_resp = client
        .handle_user_create("alice".to_string(), "longenough".to_string(), None)
        .await;
    assert!(
        matches!(create_resp, Response::User(_)),
        "got {create_resp:?}"
    );

    let resp = client.handle_user_delete("alice".to_string()).await;
    assert!(
        matches!(resp, Response::Rejected { ref error } if error.contains("last remaining")),
        "expected Rejected, got {resp:?}"
    );
}

#[tokio::test]
async fn user_passwd_short_password_returns_rejected() {
    let client = test_client_with_storage().await;
    let resp = client
        .handle_user_passwd("alice".to_string(), "short".to_string())
        .await;
    assert!(
        matches!(resp, Response::Rejected { ref error } if error.contains("8 characters")),
        "expected Rejected, got {resp:?}"
    );
}
