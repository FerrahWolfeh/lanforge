use crate::auth::AuthManager;
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LeaseDb;
use lanforge_db::log_engine::LogDb;
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(feature = "server")]
async fn create_test_context() -> (LanforgeContext, Arc<LeaseDb>, Arc<LogDb>) {
    let bus = Arc::new(EventBus::new());
    let db = Arc::new(
        LeaseDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let log_db = Arc::new(LogDb::open("sqlite::memory:").await.unwrap());
    (LanforgeContext::new(bus, State::new(), None), db, log_db)
}

#[tokio::test]
async fn test_auth_manager_token_lifecycle() {
    let auth = AuthManager::new();

    // Generate
    let token = auth
        .generate_token("admin")
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
    let token = auth.generate_token("admin").unwrap();
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

#[cfg(feature = "remote")]
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
async fn test_app_state_creation() {
    use crate::server::AppState;
    use lanforge_api::config::ApiConfig;

    let (ctx, db, log_db) = create_test_context().await;
    let cfg = Arc::new(ApiConfig {
        socket_path: "/tmp/lanforge.sock".to_string(),
        lan_iface: "eth0".to_string(),
        ra_enabled: true,
        ula_prefix: None,
        dhcp_v4_enabled: true,
        dhcp_v6_enabled: true,
        dns_enabled: true,
        dns_upstream: None,
        db_path: "/tmp/leases.db".to_string(),
        db_url: "sqlite:///tmp/leases.db".to_string(),
        log_db_path: "/tmp/lanforge_logs.db".to_string(),
        log_db_url: "sqlite:///tmp/lanforge_logs.db".to_string(),
        tcp_port: None,
        http_listen: None,
        dot_listen: None,
        dhcp_v4_range_size: 100,
        dhcp_v6_pool_size: Some(100),
        auth_password_hash: None,
        tls_cert: None,
        tls_key: None,
        boot_dir: None,
        ..ApiConfig::default()
    });
    let state = AppState {
        cfg,
        ctx,
        db,
        log_db,
        auth: Arc::new(AuthManager::new()),
        start_time: std::time::Instant::now(),
    };

    assert!(state.auth.generate_token("test").is_ok());
}
