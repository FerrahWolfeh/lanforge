use crate::auth::AuthManager;
use std::time::SystemTime;

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
