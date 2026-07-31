use crate::auth::AuthManager;
use std::time::SystemTime;

#[tokio::test]
async fn test_auth_manager_token_lifecycle() {
    let auth = AuthManager::new();

    // Generate
    let token = auth
        .generate_token("admin", "admin")
        .expect("Token generation failed");
    assert!(!token.is_empty());

    // Validate
    let claims = auth
        .validate_token(&token)
        .expect("Token validation failed");
    assert_eq!(claims.sub, "admin");

    // Invalid token
    let result = auth.validate_token("invalid.token.here");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_auth_token_expiration() {
    let auth = AuthManager::new();
    // Since we can't easily mock time in jsonwebtoken without more effort,
    // we just verify that exp is set in the future.
    let token = auth.generate_token("admin", "admin").unwrap();

    let claims = auth.validate_token(&token).unwrap();

    let now = usize::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    assert!(claims.exp > now);
    assert!(claims.exp <= now + 86400);
}

#[cfg(feature = "client")]
#[tokio::test]
async fn test_remote_client_init() {
    use crate::remote::RemoteClient;
    let _client = RemoteClient::new(
        "http://127.0.0.1:8080".to_string(),
        Some("test-token".into()),
    );
    // Just verify basic state for now as full integration requires a server
}

#[cfg(feature = "server")]
#[tokio::test]
async fn test_http_error_into_response() {
    use crate::error::HttpError;
    use axum::http::StatusCode;
    use axum::response::IntoResponse as ax_response;

    let err = HttpError::Auth("Access denied".to_string());
    let response = ax_response::into_response(err);
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "server")]
#[tokio::test]
async fn test_handle_login() {
    use crate::config::HttpConfig;
    use crate::routes::auth::{LoginRequest, handle_login};
    use crate::server::AppState;
    use axum::Json;
    use axum::extract::State;
    use lanforge_core::bus::EventBus;
    use lanforge_core::context::LanforgeContext;
    use lanforge_core::context::state::State as CoreState;
    use lanforge_db::config::DatabaseConfig;
    use lanforge_db::engine::LanforgeDb;
    use lanforge_db::log_engine::LogDb;
    use std::sync::Arc;
    use std::time::Instant;

    let bus = Arc::new(EventBus::new());
    let core_state = CoreState::new();
    let ctx = LanforgeContext::new(bus, core_state, None);
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());

    // 1. Test when auth is disabled (auth_password_hash = None)
    let state_no_auth = AppState {
        cfg: Arc::new(HttpConfig {
            auth_password_hash: None,
            ..Default::default()
        }),
        ctx: ctx.clone(),
        db: db.clone(),
        log_db: log_db.clone(),
        auth: Arc::new(AuthManager::new()),
        start_time: Instant::now(),
    };

    let res = handle_login(
        State(state_no_auth),
        Json(LoginRequest {
            username: None,
            password: Some("any_password".to_string()),
            token: None,
            remember_me: None,
        }),
    )
    .await;
    assert!(res.is_err());

    // 2. Test when auth is enabled
    let password = "my_secure_password";
    let hash = lanforge_core::utils::auth::hash_password(password);
    let state_with_auth = AppState {
        cfg: Arc::new(HttpConfig {
            auth_password_hash: Some(hash),
            ..Default::default()
        }),
        ctx,
        db,
        log_db,
        auth: Arc::new(AuthManager::new()),
        start_time: Instant::now(),
    };

    // Correct password
    let res_correct = handle_login(
        State(state_with_auth.clone()),
        Json(LoginRequest {
            username: Some("admin".to_string()),
            password: Some(password.to_string()),
            token: None,
            remember_me: None,
        }),
    )
    .await;
    assert!(res_correct.is_ok());

    // Incorrect password
    let res_incorrect = handle_login(
        State(state_with_auth),
        Json(LoginRequest {
            username: Some("admin".to_string()),
            password: Some("wrong_password".to_string()),
            token: None,
            remember_me: None,
        }),
    )
    .await;
    assert!(res_incorrect.is_err());
}
