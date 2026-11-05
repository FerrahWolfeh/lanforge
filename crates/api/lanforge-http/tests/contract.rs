#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
// Entry-point contract tests for `lanforge-http`.
//
// Uses `tower::ServiceExt::oneshot` to drive the Axum router directly —
// no TCP port is bound, so tests are hermetic and instantaneous.
// Each test function covers a logical group of scenarios in a grid table,
// reducing boilerplate while maximising coverage of the API contract.
#![cfg(feature = "server")]
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lanforge_core::{
    bus::EventBus,
    context::{LanforgeContext, state::State as CoreState},
    service::AsyncService,
};
use lanforge_db::{UserStore, config::DatabaseConfig, engine::LanforgeDb, log_engine::LogDb, redb};
use lanforge_http::{auth::AuthManager, config::HttpConfig, server::AppState};
use lanforge_types::{
    auth::{ApiScope, ApiScopes, UserRole},
    network::firewall::FirewallConfig,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Instant};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// TestApp harness
// ---------------------------------------------------------------------------

struct TestApp {
    router: Router,
    /// JWT bearer token, stored here once acquired via login.
    token: Option<String>,
    /// Elevation token sent with every request once `elevate` ran.
    elevation: Option<String>,
}

/// Build the same router the real `HttpService` builds, minus
/// `CompressionLayer`/`CorsLayer` (not needed in tests).
fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api", lanforge_http::server::api_router(&state))
        .with_state(state)
}

async fn make_state(with_auth: bool) -> AppState {
    let bus = Arc::new(EventBus::new());
    let table = CoreState::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let api_db = Arc::new(db.redb().clone());
    let log_db = Arc::new(LogDb::open_in_memory());
    let ctx = LanforgeContext::new(bus, table, None);

    let mut worker = lanforge_db::worker::DbWorker::new(
        DatabaseConfig::default(),
        ctx.clone(),
        Arc::clone(&db),
        Arc::clone(&log_db),
    );
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let h_worker = lanforge_core::service::ServiceHandle::new(
            lanforge_types::system::ServiceId::Db,
            ctx_worker.clone(),
        );
        let _ = worker.serve(&ctx_worker, &h_worker).await;
    });

    AppState {
        cfg: Arc::new(HttpConfig {
            auth_password_hash: if with_auth {
                Some(lanforge_crypto::hash_password("testpass"))
            } else {
                None
            },
            allow_plaintext_http: true,
            ..Default::default()
        }),
        ctx,
        db: api_db,
        log_db,
        auth: Arc::new(AuthManager::new()),
        start_time: Instant::now(),
    }
}

impl TestApp {
    /// Build an app with authentication **disabled** (no password hash set).
    /// All requests pass through the middleware unchecked.
    async fn no_auth() -> Self {
        Self {
            router: build_router(make_state(false).await),
            token: None,
            elevation: None,
        }
    }

    /// Build an app with authentication **enabled**, then immediately perform
    /// a login call to acquire a JWT stored for all subsequent helper calls.
    async fn with_auth() -> Self {
        let state = make_state(true).await;
        let router = build_router(state);

        let login_res = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"password": "testpass"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            login_res.status(),
            StatusCode::OK,
            "TestApp login failed during setup"
        );
        let bytes = login_res.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let token = body
            .get("data")
            .and_then(|d| d.get("token"))
            .or_else(|| body.get("token"))
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        Self {
            router,
            token: Some(token),
            elevation: None,
        }
    }

    /// Re-authenticates with the password: sensitive actions (users, token creation) need it.
    async fn elevate(&mut self) {
        let (status, body) = self
            .post("/api/v1/auth/elevate", &json!({"password": "testpass"}))
            .await;
        assert_eq!(status, StatusCode::OK, "elevation failed: {body}");
        self.elevation = Some(
            body["data"]["elevation_token"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }

    /// Core dispatcher: build a request and drive it through the router.
    /// Returns `(status_code, parsed_json_body)`.
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        authed: bool,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");

        if authed && let Some(token) = &self.token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if authed && let Some(elevation) = &self.elevation {
            builder = builder.header("x-lanforge-elevation", elevation);
        }

        let req = builder.body(Body::from(body.unwrap_or_default())).unwrap();

        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.call("GET", path, None, true).await
    }

    async fn get_raw(&self, path: &str) -> (StatusCode, String, axum::http::HeaderMap) {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(token) = &self.token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let req = builder.body(Body::empty()).unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).to_string();
        (status, text, headers)
    }

    async fn post<T: Serialize>(&self, path: &str, body: &T) -> (StatusCode, Value) {
        self.call("POST", path, Some(serde_json::to_vec(body).unwrap()), true)
            .await
    }

    /// POST without an Authorization header — used to probe auth walls.
    async fn post_no_token<T: Serialize>(&self, path: &str, body: &T) -> (StatusCode, Value) {
        self.call("POST", path, Some(serde_json::to_vec(body).unwrap()), false)
            .await
    }

    /// GET without an Authorization header — used to probe auth walls.
    async fn get_no_token(&self, path: &str) -> (StatusCode, Value) {
        self.call("GET", path, None, false).await
    }

    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        self.call("DELETE", path, None, true).await
    }

    async fn put<T: Serialize>(&self, path: &str, body: &T) -> (StatusCode, Value) {
        self.call("PUT", path, Some(serde_json::to_vec(body).unwrap()), true)
            .await
    }

    async fn delete_with<T: Serialize>(&self, path: &str, body: &T) -> (StatusCode, Value) {
        self.call(
            "DELETE",
            path,
            Some(serde_json::to_vec(body).unwrap()),
            true,
        )
        .await
    }

    async fn patch<T: Serialize>(&self, path: &str, body: &T) -> (StatusCode, Value) {
        self.call("PATCH", path, Some(serde_json::to_vec(body).unwrap()), true)
            .await
    }
}

// ---------------------------------------------------------------------------
// Group 0 — Smoke: read-only endpoints return 200 on an empty database
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_smoke_read_endpoints() {
    let app = TestApp::no_auth().await;

    // (description, path)
    let cases = [
        ("status", "/api/v1/status"),
        ("service_banners", "/api/v1/service_banners"),
        ("hosts empty", "/api/v1/hosts"),
        ("dns/rewrites", "/api/v1/dns/rewrites"),
        ("dns/upstreams", "/api/v1/dns/upstreams"),
        ("dns/stats", "/api/v1/dns/stats"),
        ("devices", "/api/v1/devices"),
        ("db/stats", "/api/v1/db/stats"),
        ("traffic/status", "/api/v1/traffic/status"),
        ("traffic/config", "/api/v1/traffic/config"),
        ("traffic/telemetry", "/api/v1/traffic/telemetry"),
    ];

    for (desc, path) in cases {
        let (status, _) = app.get(path).await;
        assert_eq!(status, StatusCode::OK, "Smoke GET failed: {desc} ({path})");
    }
}

// ---------------------------------------------------------------------------
// Group 1 — Authentication middleware contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_middleware_contract() {
    // App with auth enabled but no token acquired yet.
    let state = make_state(true).await;
    let router = build_router(state);
    let unauthed_app = TestApp {
        router,
        token: None,
        elevation: None,
    };

    // Grid: (description, expected_status)
    // These calls all hit `/api/v1/status` without a valid token.
    let wall_cases: &[(&str, &str, StatusCode)] = &[
        (
            "no Authorization header",
            "/api/v1/status",
            StatusCode::UNAUTHORIZED,
        ),
        ("bad token", "/api/v1/status", StatusCode::UNAUTHORIZED),
        (
            "service_banners with no token",
            "/api/v1/service_banners",
            StatusCode::UNAUTHORIZED,
        ),
    ];

    // No-token calls
    for (desc, path, expected) in wall_cases {
        let (status, _) = unauthed_app.get_no_token(path).await;
        assert_eq!(status, *expected, "Auth wall failed: {desc}");
    }

    // Bad token (not a valid JWT)
    let bad_token_req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header(header::AUTHORIZATION, "Bearer this.is.garbage")
        .body(Body::empty())
        .unwrap();
    let res = unauthed_app
        .router
        .clone()
        .oneshot(bad_token_req)
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Bad token should be rejected"
    );

    // Login grid
    let authed_app = TestApp::with_auth().await;

    // Correct login: 200 + body contains "token"
    let (status, body) = authed_app
        .post_no_token("/api/auth/login", &json!({"password": "testpass"}))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Correct password login should succeed"
    );
    assert!(
        body["data"]["token"].is_string() || body["token"].is_string(),
        "Login response should include token field"
    );

    // Wrong password: 401
    let (status, _) = authed_app
        .post_no_token("/api/auth/login", &json!({"password": "wrongpassword"}))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Wrong password should be rejected"
    );

    // /api/v1/auth/validate is always public (excluded by middleware)
    let validate_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/validate")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"token": "any-value"})).unwrap(),
        ))
        .unwrap();
    let res = authed_app
        .router
        .clone()
        .oneshot(validate_req)
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "validate endpoint should be public"
    );

    // Token generation needs re-authentication, then works for the admin
    let (status, _) = authed_app
        .post("/api/v1/auth/tokens", &json!({"name": "test-token"}))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "token creation needs elevation"
    );
    let mut authed_app = authed_app;
    authed_app.elevate().await;
    let (status, body) = authed_app
        .post("/api/v1/auth/tokens", &json!({"name": "test-token"}))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Authenticated admin should be able to generate tokens"
    );
    assert!(
        body["data"]["token"]
            .as_str()
            .unwrap()
            .starts_with("lf_ak_")
    );

    // Unauthenticated token generation must return 401 Unauthorized
    let (status, _) = unauthed_app
        .post("/api/v1/auth/tokens", &json!({"name": "test-token"}))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Unauthenticated token generation must be rejected"
    );

    // With a valid token, protected endpoints should be accessible
    let (status, _) = authed_app.get("/api/v1/status").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Valid JWT token should allow access"
    );
}

#[tokio::test]
async fn test_auth_persistence_unavailable_contract() {
    let bus = Arc::new(EventBus::new());
    let table = CoreState::new();
    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    );
    let api_db = Arc::new(db.redb().clone());
    let log_db = Arc::new(LogDb::open_in_memory());
    let ctx = LanforgeContext::new(bus, table, None);

    let state = AppState {
        cfg: Arc::new(HttpConfig {
            auth_password_hash: Some(lanforge_crypto::hash_password("testpass")),
            allow_plaintext_http: true,
            ..Default::default()
        }),
        ctx,
        db: api_db,
        log_db,
        auth: Arc::new(AuthManager::new()),
        start_time: Instant::now(),
    };

    let router = build_router(state);

    // 1. Initial valid login to obtain a JWT session token
    let login_req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"password": "testpass"})).unwrap(),
        ))
        .unwrap();
    let res = router.clone().oneshot(login_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let valid_jwt = body["data"]["token"].as_str().unwrap().to_string();

    // 2. Corrupt TABLE_USERS with non-postcard garbage bytes
    const TABLE_USERS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("users");
    {
        let write_txn = db.redb().begin_write().unwrap();
        let mut table = write_txn.open_table(TABLE_USERS).unwrap();
        table.insert("corrupt_admin", &[0xff, 0xff][..]).unwrap();
        drop(table);
        write_txn.commit().unwrap();
    }

    // 3. Password login for corrupted user must return 503 Service Unavailable ("persistence unavailable")
    let corrupt_login_req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "username": "corrupt_admin",
                "password": "anypassword"
            }))
            .unwrap(),
        ))
        .unwrap();
    let res = router.clone().oneshot(corrupt_login_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("persistence unavailable"),
        "Expected 'persistence unavailable' error message, got: {body:?}"
    );

    // 4. Corrupt TABLE_API_TOKENS with non-postcard garbage bytes
    const TABLE_API_TOKENS: redb::TableDefinition<&str, &[u8]> =
        redb::TableDefinition::new("api_tokens");
    {
        let write_txn = db.redb().begin_write().unwrap();
        let mut table = write_txn.open_table(TABLE_API_TOKENS).unwrap();
        table
            .insert("corrupt_token_key", &[0xff, 0xff][..])
            .unwrap();
        drop(table);
        write_txn.commit().unwrap();
    }

    // 5. API token login with corrupted token must return 503 Service Unavailable ("persistence unavailable")
    let corrupt_token_login_req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "token": "corrupt_token_key"
            }))
            .unwrap(),
        ))
        .unwrap();
    let res = router
        .clone()
        .oneshot(corrupt_token_login_req)
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("persistence unavailable"),
        "Expected 'persistence unavailable' error message, got: {body:?}"
    );

    // 6. Accessing protected endpoint with corrupted token via Authorization header returns 503
    let middleware_req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header(header::AUTHORIZATION, "Bearer corrupt_token_key")
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(middleware_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("persistence unavailable"),
        "Expected 'persistence unavailable' error message, got: {body:?}"
    );

    // 7. Request with valid pre-existing JWT session token succeeds without querying DB (200 OK)
    let jwt_req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header(header::AUTHORIZATION, format!("Bearer {valid_jwt}"))
        .body(Body::empty())
        .unwrap();
    let res = router.clone().oneshot(jwt_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Group 2 — Hosts CRUD contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hosts_contract() {
    let app = TestApp::no_auth().await;

    // --- Happy path: add → verify → patch → delete → verify gone ---
    let mac = "aa:bb:cc:dd:ee:01";
    let host = json!({
        "mac": mac,
        "hostname": "contract-host",
        "v4_fixed": "192.168.5.50",
        "v6_suffix": null,
        "origin": "Static"
    });

    // Add
    let (status, _) = app.post("/api/v1/hosts", &host).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "host_add happy path");

    // List — should contain exactly our host
    let (status, body) = app.get("/api/v1/hosts").await;
    assert_eq!(status, StatusCode::OK);
    let hosts = &body["data"]["hosts"];
    assert_eq!(
        hosts.as_array().map(|a| a.len()),
        Some(1),
        "should have 1 host after add"
    );
    assert_eq!(hosts[0]["hostname"], "contract-host");

    // Patch hostname (valid field)
    let patch = json!({"field": "hostname", "value": "contract-host-renamed"});
    let (status, _) = app.patch(&format!("/api/v1/hosts/{mac}"), &patch).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "patch hostname happy path");

    // Verify rename
    let (_, body) = app.get("/api/v1/hosts").await;
    assert_eq!(
        body["data"]["hosts"][0]["hostname"],
        "contract-host-renamed"
    );

    // Delete
    let (status, _) = app.delete(&format!("/api/v1/hosts/{mac}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "host_remove happy path");

    // List — should be empty
    let (_, body) = app.get("/api/v1/hosts").await;
    assert_eq!(
        body["data"]["hosts"].as_array().map(|a| a.len()),
        Some(0),
        "host list should be empty after remove"
    );

    // --- Validation guardrails (negative grid) ---
    // (description, body, expected_status)
    let guardrail_cases: &[(&str, Value, StatusCode)] = &[
        (
            "empty body → missing required fields",
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "malformed MAC address",
            json!({
                "mac": "not-a-mac",
                "hostname": "test",
                "origin": "Static"
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "invalid IPv4 syntax",
            json!({
                "mac": "aa:bb:cc:dd:ee:02",
                "hostname": "test",
                "v4_fixed": "999.999.999.999",
                "origin": "Static"
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];

    for (desc, body, expected) in guardrail_cases {
        let (status, _) = app.post("/api/v1/hosts", body).await;
        assert_eq!(status, *expected, "Hosts guardrail: {desc}");
    }

    // Verify optional origin and hostname defaults (e.g. from WebUI)
    let host_minimal = json!({
        "mac": "aa:bb:cc:dd:ee:04"
    });
    let (status, _) = app.post("/api/v1/hosts", &host_minimal).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "host_add with minimal fields (no hostname, no origin) should succeed"
    );

    // --- Edge cases that reach dispatch ---
    // Re-add a host so we can patch it
    let mac2 = "aa:bb:cc:dd:ee:03";
    app.post(
        "/api/v1/hosts",
        &json!({"mac": mac2, "hostname": "edge-host", "origin": "Static"}),
    )
    .await;

    let edge_cases: &[(&str, Value, StatusCode)] = &[
        (
            "patch with invalid IP — refused (it used to be ignored and still pin the host)",
            json!({"field": "v4_static", "value": "not-an-ip"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "patch with unknown field — refused",
            json!({"field": "nonexistent_field", "value": "anything"}),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (desc, body, expected) in edge_cases {
        let (status, _) = app.patch(&format!("/api/v1/hosts/{mac2}"), body).await;
        assert_eq!(status, *expected, "Hosts edge case: {desc}");
    }

    // Remove non-existent MAC — silent 204 (SQLite deletes 0 rows, ctx.apply is no-op)
    let (status, _) = app.delete("/api/v1/hosts/de:ad:be:ef:00:ff").await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "Remove non-existent MAC should silently succeed"
    );
}

// ---------------------------------------------------------------------------
// Group 3 — DNS Rewrites contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_rewrites_contract() {
    let app = TestApp::no_auth().await;

    // --- Happy path: add A record → list → remove by id → list empty ---
    let rewrite = json!({
        "domain": "test.lan",
        "rtype": "A",
        "answer": "10.0.0.1"
    });

    let (status, _) = app.post("/api/v1/dns/rewrites", &rewrite).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "rewrite_add happy path");

    let (status, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(status, StatusCode::OK);
    let rewrites = &body["data"]["rewrites"];
    assert_eq!(rewrites.as_array().map(|a| a.len()), Some(1));
    assert_eq!(rewrites[0]["domain"], "test.lan");
    let rule_id = rewrites[0]["id"]
        .as_i64()
        .expect("rule id must be an integer");

    // Remove by ID
    let (status, _) = app.delete(&format!("/api/v1/dns/rewrites/{rule_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "rewrite_remove happy path");

    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(
        body["data"]["rewrites"].as_array().map(|a| a.len()),
        Some(0),
        "rewrites should be empty after remove"
    );

    // --- Bulk: add two, then clear all ---
    app.post(
        "/api/v1/dns/rewrites",
        &json!({"domain": "one.lan", "rtype": "A", "answer": "1.1.1.1"}),
    )
    .await;
    app.post(
        "/api/v1/dns/rewrites",
        &json!({"domain": "two.lan", "rtype": "A", "answer": "2.2.2.2"}),
    )
    .await;
    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(
        body["data"]["rewrites"].as_array().map(|a| a.len()),
        Some(2)
    );

    let (status, _) = app.delete("/api/v1/dns/rewrites").await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "rewrite_clear should succeed"
    );

    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(
        body["data"]["rewrites"].as_array().map(|a| a.len()),
        Some(0)
    );

    // --- dev: dynamic rewrite (the WebUI sends rtype DEVICE) ---
    let (status, _) = app
        .post(
            "/api/v1/dns/rewrites",
            &json!({"domain": "dynamic.lan", "rtype": "DEVICE", "answer": "dev:testhost"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "dev: rewrite should be accepted"
    );
    app.delete("/api/v1/dns/rewrites").await; // clean up

    // A device answer is not a CNAME: refused (today a 500, like every refused change), not
    // stored.
    let (status, _) = app
        .post(
            "/api/v1/dns/rewrites",
            &json!({"domain": "dynamic.lan", "rtype": "CNAME", "answer": "dev:testhost"}),
        )
        .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "CNAME rtype with a dev: answer must be refused, got {status}"
    );
    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(
        body["data"]["rewrites"].as_array().map(|a| a.len()),
        Some(0)
    );

    // --- Validation guardrails (negative grid) ---
    // (description, body, ideal_expected_status)
    //
    // Note: the ideal contract for invalid input is 400 Bad Request.
    // Currently `handle_rewrite_add` maps answer parse failures to HttpError::Generic → 500.
    // The test asserts the IDEAL expected status (400), serving as a spec for future correction.
    let guardrail_cases: &[(&str, Value, StatusCode)] = &[
        (
            "missing domain field → 422 from Axum JSON rejection",
            json!({"rtype": "A", "answer": "1.2.3.4"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "empty body → 422",
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "invalid answer string (ideal: 400 Bad Request)",
            json!({"domain": "bad.lan", "rtype": "A", "answer": ":::invalid:::"}),
            StatusCode::BAD_REQUEST,
        ),
    ];

    for (desc, body, expected) in guardrail_cases {
        let (status, _) = app.post("/api/v1/dns/rewrites", body).await;
        assert_eq!(status, *expected, "DNS rewrites guardrail: {desc}");
    }

    // Removing an unknown rule is an error, never a success that removed nothing.
    let (status, _) = app.delete("/api/v1/dns/rewrites/99999").await;
    assert!(
        !status.is_success(),
        "removing an unknown rewrite id must fail, got {status}"
    );
}

/// The `WebUI` reads JSON numbers as doubles: a 63-bit content-hash id comes back rounded, so it
/// removes by the rule's content instead.
#[tokio::test]
async fn test_dns_rewrite_remove_works_for_a_javascript_client() {
    let app = TestApp::no_auth().await;
    for rule in [
        json!({"domain": "nas.lan", "rtype": "A", "answer": "192.168.1.10"}),
        json!({"domain": "tv.lan", "rtype": "DEVICE", "answer": "dev:tv|192.168.1.20"}),
    ] {
        let (status, _) = app.post("/api/v1/dns/rewrites", &rule).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    let listed = body["data"]["rewrites"].as_array().unwrap().clone();
    assert_eq!(listed.len(), 2);

    // What a JavaScript client holds after `JSON.parse`.
    let exact = listed[0]["id"].as_i64().unwrap();
    let seen_by_js = listed[0]["id"].as_f64().unwrap();
    assert_ne!(format!("{seen_by_js:.0}"), exact.to_string());
    let (status, _) = app
        .delete(&format!("/api/v1/dns/rewrites/{seen_by_js:.0}"))
        .await;
    assert!(
        !status.is_success(),
        "a rounded id must not report a removal, got {status}"
    );

    // By content, as listed (the `id` sent along is ignored).
    for rule in &listed {
        let (status, body) = app.delete_with("/api/v1/dns/rewrites/rule", rule).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "remove {rule}: {body}");
    }
    let (_, body) = app.get("/api/v1/dns/rewrites").await;
    assert_eq!(body["data"]["rewrites"].as_array().map(Vec::len), Some(0));

    let (status, _) = app
        .delete_with("/api/v1/dns/rewrites/rule", &listed[0])
        .await;
    assert!(
        !status.is_success(),
        "removing it twice must fail, got {status}"
    );
}

/// Manual adblock rules are disabled and removed by their text, as the listing gives it.
#[cfg(feature = "adblock")]
#[tokio::test]
async fn test_adblock_rule_by_text_works_for_a_javascript_client() {
    let app = TestApp::no_auth().await;
    let (status, body) = app
        .post(
            "/api/v1/dns/adblock/rules",
            &json!({"domain": "track.example", "action": "block"}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let listed = |body: &Value| body["data"]["rules"].as_array().unwrap().clone();
    let (_, body) = app.get("/api/v1/dns/adblock/rules").await;
    let rules = listed(&body);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["domain"], "||track.example^");

    let seen_by_js = rules[0]["id"].as_f64().unwrap();
    let (status, _) = app
        .delete(&format!("/api/v1/dns/adblock/rules/{seen_by_js:.0}"))
        .await;
    assert!(
        !status.is_success(),
        "a rounded id matches no rule, got {status}"
    );

    let (status, body) = app
        .put(
            "/api/v1/dns/adblock/rules/status",
            &json!({"rule": "||track.example^", "enabled": false}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, body) = app.get("/api/v1/dns/adblock/rules").await;
    assert_eq!(listed(&body)[0]["enabled"], false);

    let (status, body) = app
        .delete_with(
            "/api/v1/dns/adblock/rules",
            &json!({"rule": "||track.example^"}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, body) = app.get("/api/v1/dns/adblock/rules").await;
    assert!(listed(&body).is_empty());
}

// ---------------------------------------------------------------------------
// Group 4 — DNS Upstreams contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_dns_upstreams_contract() {
    let app = TestApp::no_auth().await;

    // --- Happy path: add → list → remove ---
    // Upstreams are added/removed via query params (not JSON body)
    // The colon in the IP:Port must be URL-encoded as %3A in query params.
    let add_path = "/api/v1/dns/upstreams?addr=9.9.9.9%3A53&protocol=udp";
    let (status, _) = app.post(add_path, &json!({})).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "dns_upstream_add happy path"
    );

    let (status, body) = app.get("/api/v1/dns/upstreams").await;
    assert_eq!(status, StatusCode::OK);
    let upstreams = &body["data"]["upstreams"];
    assert_eq!(
        upstreams.as_array().map(|a| a.len()),
        Some(1),
        "should have 1 upstream after addition"
    );

    let remove_path = "/api/v1/dns/upstreams?addr=9.9.9.9%3A53&protocol=udp";
    let (status, _) = app.delete(remove_path).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "dns_upstream_remove happy path"
    );

    let (_, body) = app.get("/api/v1/dns/upstreams").await;
    assert_eq!(
        body["data"]["upstreams"].as_array().map(|a| a.len()),
        Some(0)
    );

    // --- Guardrails ---
    let guardrail_cases: &[(&str, &str, StatusCode)] = &[
        (
            "missing addr param → 400",
            "/api/v1/dns/upstreams?protocol=udp",
            StatusCode::BAD_REQUEST,
        ),
        (
            "missing protocol param → 400",
            "/api/v1/dns/upstreams?addr=1.1.1.1%3A53",
            StatusCode::BAD_REQUEST,
        ),
        (
            "invalid addr format → 400",
            "/api/v1/dns/upstreams?addr=not-an-addr&protocol=udp",
            StatusCode::BAD_REQUEST,
        ),
    ];

    for (desc, path, expected) in guardrail_cases {
        let (status, _) = app.post(path, &json!({})).await;
        assert_eq!(status, *expected, "DNS upstreams guardrail: {desc}");
    }

    // --- Preset: one PUT replaces the default upstreams ---
    let (status, body) = app
        .put(
            "/api/v1/dns/upstreams",
            &json!({"upstreams": ["9.9.9.9", "[2620:fe::fe]:53"]}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "preset: {body}");
    let (_, body) = app.get("/api/v1/dns/upstreams").await;
    assert_eq!(
        body["data"]["upstreams"].as_array().map(|a| a.len()),
        Some(2),
        "{body}"
    );

    // A refused change is the caller's (400) and says why; nothing changes.
    let (status, body) = app
        .put("/api/v1/dns/upstreams", &json!({"upstreams": []}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("configuration file")),
        "{body}"
    );
    let (_, body) = app.get("/api/v1/dns/upstreams").await;
    assert_eq!(
        body["data"]["upstreams"].as_array().map(|a| a.len()),
        Some(2)
    );

    // Removing an upstream that is not there: 404.
    let (status, _) = app
        .delete("/api/v1/dns/upstreams?addr=8.8.8.8%3A53&protocol=udp")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Group 5 — System Config import/export contract
// ---------------------------------------------------------------------------

/// The TOML export is the daemon's config file as it is on disk (comments included), through
/// both routes; it used to be rendered from the live values, dropping what they do not carry.
#[tokio::test]
async fn toml_export_is_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lanforge.toml");
    let text = "# the admin's note\n[system]\niface = \"lan0\"\n";
    std::fs::write(&path, text).unwrap();
    let state = make_state(false).await;
    state.ctx.set_config_path(&path);
    let app = TestApp {
        router: build_router(state),
        token: None,
        elevation: None,
    };

    for route in ["/api/v1/config?format=toml", "/api/v1/config/toml"] {
        let (status, body, headers) = app.get_raw(route).await;
        assert_eq!(status, StatusCode::OK, "{route}");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(body, text, "{route}");
    }
}

#[tokio::test]
async fn test_system_config_contract() {
    let app = TestApp::no_auth().await;

    // --- Export empty state ---
    let (status, body) = app.get("/api/v1/config").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "config export on empty DB should succeed"
    );
    assert_eq!(body["data"]["hosts"].as_array().map(|a| a.len()), Some(0));
    assert_eq!(
        body["data"]["dns_rewrites"].as_array().map(|a| a.len()),
        Some(0)
    );

    // --- Import with overwrite=true ---
    let config = json!({
        "hosts": [{
            "mac": "cc:dd:ee:ff:00:01",
            "hostname": "config-host",
            "v4_fixed": "10.0.1.1",
            "v6_suffix": null,
            "origin": "Static"
        }],
        "dns_rewrites": [{
            "domain": "config.lan",
            "rtype": "A",
            "answer": { "a": "10.0.1.1" }
        }],
        "dns_upstreams": [],
        "dns_adblock_config": {
            "enabled": false,
            "blocking_mode": "null_ip",
            "blocking_ip_v4": null,
            "blocking_ip_v6": null,
            "refresh_time": { "hour": 3, "minute": 0 }
        },
        "dns_adblock_urls": [],
        "dns_allowlist": [],
        "overwrite": true
    });

    let (status, _) = app.post("/api/v1/config", &config).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "config import overwrite=true should succeed"
    );

    // Export again and verify imported data is present
    let (status, body) = app.get("/api/v1/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["hosts"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(body["data"]["hosts"][0]["hostname"], "config-host");
    assert_eq!(
        body["data"]["dns_rewrites"].as_array().map(|a| a.len()),
        Some(1)
    );
    assert_eq!(body["data"]["dns_rewrites"][0]["domain"], "config.lan");

    // --- Merge semantics (overwrite=false) ---
    // Add a second host via import without overwriting
    let merge_config = json!({
        "hosts": [{
            "mac": "cc:dd:ee:ff:00:02",
            "hostname": "merged-host",
            "v4_fixed": null,
            "v6_suffix": null,
            "origin": "Static"
        }],
        "dns_rewrites": [],
        "dns_upstreams": [],
        "dns_adblock_config": {
            "enabled": false,
            "blocking_mode": "null_ip",
            "blocking_ip_v4": null,
            "blocking_ip_v6": null,
            "refresh_time": { "hour": 3, "minute": 0 }
        },
        "dns_adblock_urls": [],
        "dns_allowlist": [],
        "overwrite": false
    });
    let (status, _) = app.post("/api/v1/config", &merge_config).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "config import overwrite=false should succeed"
    );

    let (_, body) = app.get("/api/v1/config").await;
    assert_eq!(
        body["data"]["hosts"].as_array().map(|a| a.len()),
        Some(2),
        "merge import should add to existing hosts, not replace"
    );

    // Overwrite=true clears back to 1
    let overwrite_one = json!({
        "hosts": [{
            "mac": "cc:dd:ee:ff:00:03",
            "hostname": "only-host",
            "v4_fixed": null,
            "v6_suffix": null,
            "origin": "Static"
        }],
        "dns_rewrites": [],
        "dns_upstreams": [],
        "dns_adblock_config": {
            "enabled": false,
            "blocking_mode": "null_ip",
            "blocking_ip_v4": null,
            "blocking_ip_v6": null,
            "refresh_time": { "hour": 3, "minute": 0 }
        },
        "dns_adblock_urls": [],
        "dns_allowlist": [],
        "overwrite": true
    });
    app.post("/api/v1/config", &overwrite_one).await;

    let (_, body) = app.get("/api/v1/config").await;
    assert_eq!(
        body["data"]["hosts"].as_array().map(|a| a.len()),
        Some(1),
        "overwrite=true should wipe previous hosts"
    );
    assert_eq!(body["data"]["hosts"][0]["hostname"], "only-host");

    // No config file (memory only): the TOML export has nothing to hand out.
    let (toml_status, _, _) = app.get_raw("/api/v1/config?format=toml").await;
    assert_eq!(toml_status, StatusCode::NOT_FOUND);

    // --- Malformed import bodies (guardrails) ---
    let guardrail_cases: &[(&str, Value, StatusCode)] = &[
        (
            "non-object body → 422",
            json!("not-an-object"),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "empty body → 422",
            json!({}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "array instead of object → 422",
            json!([{"mac": "aa:bb:cc:dd:ee:ff"}]),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];

    for (desc, body, expected) in guardrail_cases {
        let (status, _) = app.post("/api/v1/config", body).await;
        assert_eq!(status, *expected, "System config guardrail: {desc}");
    }
}

// ---------------------------------------------------------------------------
// Group 6 — DB maintenance & DNS cache operations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_db_and_cache_operations() {
    let app = TestApp::no_auth().await;

    // (description, method, path, expected_status)
    let cases: &[(&str, &str, &str, StatusCode)] = &[
        (
            "db/prune",
            "POST",
            "/api/v1/db/prune",
            StatusCode::NO_CONTENT,
        ),
        (
            "db/log-clean",
            "POST",
            "/api/v1/db/log-clean",
            StatusCode::NO_CONTENT,
        ),
        ("db/stats", "GET", "/api/v1/db/stats", StatusCode::OK),
        (
            "dns/cache dump",
            "GET",
            "/api/v1/dns/cache",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "dns/cache flush",
            "DELETE",
            "/api/v1/dns/cache",
            StatusCode::NO_CONTENT,
        ),
        (
            "dns/cache stats",
            "GET",
            "/api/v1/dns/cache/stats",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];

    for (desc, method, path, expected) in cases {
        let (status, _) = app.call(method, path, None, true).await;
        assert_eq!(status, *expected, "DB/cache op: {desc}");
    }

    // db/reset without X-Confirm header → 400 (server-side guard)
    let (status, body) = app.delete("/api/v1/db").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "db/reset without X-Confirm should return 400"
    );
    assert!(body["error"].is_string(), "error field should be present");
}

#[tokio::test]
async fn test_firewall_contract() {
    let app = TestApp::with_auth().await;

    // 1. GET /api/v1/firewall/status
    let (status, body) = app.get("/api/v1/firewall/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["table"], "lanforge");
    assert_eq!(body["data"]["enabled"], true);

    // 2. GET /api/v1/firewall/config
    let (status, body) = app.get("/api/v1/firewall/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["table_name"], "lanforge");
    assert!(body["data"]["zones"].is_array());

    // 3. POST /api/v1/firewall/config
    let mut config: FirewallConfig = serde_json::from_value(body["data"].clone()).unwrap();
    config.flow_offload = false;
    let (status, body) = app.post("/api/v1/firewall/config", &config).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["message"]
            .as_str()
            .unwrap()
            .contains("updated")
    );

    // Verify config was updated
    let (status, body) = app.get("/api/v1/firewall/config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["flow_offload"], false);

    // 4. POST /api/v1/firewall/reload
    let (status, body) = app.post("/api/v1/firewall/reload", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["message"].as_str().unwrap().contains("reload"));
}

#[tokio::test]
async fn test_firewall_transactional_handshake_contract() {
    use lanforge_types::network::firewall::{L4Protocol, PortForwardRule};
    use std::net::Ipv4Addr;

    let app = TestApp::with_auth().await;

    // Fetch baseline config
    let (status, body) = app.get("/api/v1/firewall/config").await;
    assert_eq!(status, StatusCode::OK);
    let mut candidate: FirewallConfig = serde_json::from_value(body["data"].clone()).unwrap();

    // 1. Propose invalid candidate (collision on port 8443)
    let mut invalid_candidate = candidate.clone();
    invalid_candidate.port_forwards.push(PortForwardRule {
        comment: Some("Rule 1".into()),
        src_zone: "external".into(),
        internal_ip: Ipv4Addr::new(192, 168, 1, 50).into(),
        external_port: 8443,
        internal_port: 8443,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
        family: None,
    });
    invalid_candidate.port_forwards.push(PortForwardRule {
        comment: Some("Rule 2 colliding".into()),
        src_zone: "external".into(),
        internal_ip: Ipv4Addr::new(192, 168, 1, 60).into(),
        external_port: 8443,
        internal_port: 8443,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
        family: None,
    });

    let (status, body) = app
        .post("/api/v1/firewall/propose", &invalid_candidate)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["valid"], false);
    assert!(body["data"]["tx_id"].is_null());
    assert!(!body["data"]["errors"].as_array().unwrap().is_empty());

    // 2. Propose valid candidate
    candidate.flow_offload = true;
    candidate.port_forwards.push(PortForwardRule {
        comment: Some("Plex Server".into()),
        src_zone: "external".into(),
        internal_ip: Ipv4Addr::new(192, 168, 1, 100).into(),
        external_port: 32400,
        internal_port: 32400,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
        family: None,
    });

    let (status, body) = app.post("/api/v1/firewall/propose", &candidate).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["valid"], true);
    let tx_id = body["data"]["tx_id"]
        .as_str()
        .expect("tx_id must be present")
        .to_string();
    assert!(!body["data"]["diff_summary"].as_array().unwrap().is_empty());

    // 3. Commit with auto-rollback window
    let commit_req = json!({
        "tx_id": tx_id,
        "auto_rollback_secs": 30
    });
    let (status, body) = app.post("/api/v1/firewall/commit", &commit_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["success"], true);
    assert_eq!(body["data"]["auto_rollback_active"], true);

    // 4. Confirm transaction
    let confirm_req = json!({ "tx_id": tx_id });
    let (status, body) = app.post("/api/v1/firewall/confirm", &confirm_req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["message"]
            .as_str()
            .unwrap()
            .contains("confirmed")
    );

    // 5. Verify config has the new port forward
    let (status, body) = app.get("/api/v1/firewall/config").await;
    assert_eq!(status, StatusCode::OK);
    let updated_config: FirewallConfig = serde_json::from_value(body["data"].clone()).unwrap();
    assert!(
        updated_config
            .port_forwards
            .iter()
            .any(|pf| pf.external_port == 32400)
    );
}

#[tokio::test]
async fn test_users_contract() {
    let mut app = TestApp::with_auth().await;
    app.elevate().await;

    // 1. List users
    let (status, body) = app.get("/api/v1/users").await;
    assert_eq!(status, StatusCode::OK);
    // body is {"data": {"users": [...]}}
    let users = body["data"]["users"]
        .as_array()
        .expect("users array in data");
    assert!(!users.is_empty(), "default admin user should exist");
    assert_eq!(users[0]["username"], "admin");

    // 2. Create user
    let new_user = json!({
        "username": "operator1",
        "password": "secretpassword",
        "role": "operator"
    });
    let (status, body) = app.post("/api/v1/users", &new_user).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["user"]["username"], "operator1");

    // 3. List users again
    let (status, body) = app.get("/api/v1/users").await;
    assert_eq!(status, StatusCode::OK);
    let users = body["data"]["users"].as_array().unwrap();
    assert_eq!(users.len(), 2);

    // 4. Delete user
    let (status, _) = app.delete("/api/v1/users/operator1").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_traffic_telemetry_contract() {
    let app = TestApp::no_auth().await;

    let (status, body) = app.get("/api/v1/traffic/telemetry").await;
    assert_eq!(status, StatusCode::OK);

    let data = &body["data"];
    assert!(
        data["timestamp"].as_u64().is_some(),
        "timestamp must be present"
    );
    assert!(
        data["interfaces"].as_array().is_some(),
        "interfaces must be a list"
    );
}

#[tokio::test]
async fn test_events_contract() {
    let state = make_state(false).await;
    let ev1 = lanforge_types::events::TimedEvent::new(lanforge_core::bus::LanforgeEvent::System(
        lanforge_types::events::SystemEvent::SystemReady,
    ));
    let ev2 = lanforge_types::events::TimedEvent::new(lanforge_core::bus::LanforgeEvent::Firewall(
        lanforge_types::events::FirewallEvent::RulesetFlushed,
    ));
    let mut buf = Vec::new();
    state
        .log_db
        .record_logs_batch(&[ev1, ev2], &mut buf)
        .unwrap();

    let router = build_router(state);
    let app = TestApp {
        router,
        token: None,
        elevation: None,
    };

    // 1. GET /api/v1/events (REST fallback)
    let (status, body) = app.get("/api/v1/events").await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 2);
    assert_eq!(body["meta"]["total"], 2);

    // Verify fields
    assert!(data[0]["timestamp_ms"].as_u64().is_some());
    assert!(data[0]["topic"].as_str().is_some());
    assert!(data[0]["kind"].as_str().is_some());

    // 2. GET /api/v1/events/history with filter
    let (status, body) = app.get("/api/v1/events/history?filter=system").await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["topic"], "system");

    // 3. GET /api/v1/events/history with limit
    let (status, body) = app.get("/api/v1/events/history?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
}

// ---------------------------------------------------------------------------
// D-11 — authentication fails closed when the user table cannot be read
// ---------------------------------------------------------------------------

/// State with no password hash and **no storage worker**: a setup request that slips past
/// the HTTP gate reaches the dispatcher and fails there with 400, never touching files.
fn bare_state(db: &Arc<LanforgeDb>) -> AppState {
    AppState {
        cfg: Arc::new(HttpConfig {
            auth_password_hash: None,
            allow_plaintext_http: true,
            ..Default::default()
        }),
        ctx: LanforgeContext::new(Arc::new(EventBus::new()), CoreState::new(), None),
        db: Arc::new(db.redb().clone()),
        log_db: Arc::new(LogDb::open_in_memory()),
        auth: Arc::new(AuthManager::new()),
        start_time: Instant::now(),
    }
}

fn in_memory_db() -> Arc<LanforgeDb> {
    Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            config_path: "memory".to_string(),
            ..Default::default()
        })
        .unwrap(),
    )
}

/// Replaces a table with one of the wrong key/value types: every open of it then errors.
fn break_table(db: &LanforgeDb, name: &str) {
    let txn = db.redb().begin_write().unwrap();
    txn.delete_table(redb::TableDefinition::<&str, &[u8]>::new(name))
        .unwrap();
    txn.open_table(redb::TableDefinition::<u64, u64>::new(name))
        .unwrap();
    txn.commit().unwrap();
}

fn setup_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/system/setup")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "admin_username": "intruder",
                "admin_password": "intruder-password",
                "lan_iface": "lan0",
                "lan_ip": "192.168.1.1",
                "domain_name": "lan",
                "dhcp_enabled": true,
                "dhcp_pool_start": "192.168.1.100",
                "dhcp_pool_end": "192.168.1.200",
                "adblock_enabled": false,
                "wan": null
            }))
            .unwrap(),
        ))
        .unwrap()
}

async fn auth_status_required(router: &Router) -> bool {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    body["data"]["auth_required"].as_bool().unwrap()
}

#[tokio::test]
async fn test_auth_fails_closed_when_user_table_unreadable() {
    let db = in_memory_db();
    break_table(&db, "users");
    break_table(&db, "meta");
    let router = build_router(bare_state(&db));

    // A protected endpoint without any token: 503, never served unauthenticated.
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    assert!(auth_status_required(&router).await);

    // First-run setup must not reopen because the user table cannot be read.
    let res = router.clone().oneshot(setup_request()).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_recovery_mode_requires_auth_and_locks_setup() {
    // Recovery mode: the persistent DB did not open, an empty in-memory one stands in.
    let db = in_memory_db();
    let state = bare_state(&db);
    state.ctx.set_recovery_mode(true);
    let router = build_router(state);

    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    assert!(auth_status_required(&router).await);

    // No hash file and the real users unreachable: login says why instead of "invalid".
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"password": "anything"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    let res = router.clone().oneshot(setup_request()).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// change-password — only the session's own user, only with the current password
// ---------------------------------------------------------------------------

const ADMIN_PASSWORD: &str = "correct-horse";

/// Auth-enabled state with an `admin` user and a valid session token for it.
fn state_with_admin(db: &Arc<LanforgeDb>) -> (AppState, String) {
    let state = bare_state(db);
    state
        .db
        .create_user(
            "admin",
            &lanforge_crypto::hash_password(ADMIN_PASSWORD),
            UserRole::Admin,
            0,
        )
        .unwrap();
    let session = state.auth.generate_token("admin", "admin", 0).unwrap();
    (state, session)
}

async fn change_password(router: &Router, token: &str, body: Value) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/change-password")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn admin_password_is(db: &LanforgeDb, password: &str) -> bool {
    let user = db.redb().get_user_by_username("admin").unwrap().unwrap();
    lanforge_crypto::verify_password(&user.password_hash, password)
}

#[tokio::test]
async fn test_change_password_requires_the_current_password() {
    let db = in_memory_db();
    let (state, session) = state_with_admin(&db);
    let router = build_router(state);

    // A stolen session alone must not be enough to take the account over.
    let status = change_password(&router, &session, json!({"new_password": "attacker-pw"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(admin_password_is(&db, ADMIN_PASSWORD));

    // A wrong current password is refused with 403, not 401: a 401 logs the WebUI out.
    let status = change_password(
        &router,
        &session,
        json!({"current_password": "wrong", "new_password": "attacker-pw"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(admin_password_is(&db, ADMIN_PASSWORD));

    // The field name the WebUI sends.
    let status = change_password(
        &router,
        &session,
        json!({"current_password": ADMIN_PASSWORD, "new_password": "new-secret-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(admin_password_is(&db, "new-secret-1"));
}

#[tokio::test]
async fn test_api_token_cannot_change_a_user_password() {
    let db = in_memory_db();
    let (state, _session) = state_with_admin(&db);
    // A token's name is not a username: one named "admin" must not act as the admin user.
    state
        .db
        .store_api_token(
            "monitoring-token",
            "admin",
            &ApiScopes::from_slice(&[ApiScope::Monitoring]),
            None,
            0,
        )
        .unwrap();
    let router = build_router(state);

    let status = change_password(
        &router,
        "monitoring-token",
        json!({"current_password": ADMIN_PASSWORD, "new_password": "attacker-pw"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(admin_password_is(&db, ADMIN_PASSWORD));
}

#[tokio::test]
async fn test_change_password_db_error_is_unavailable() {
    let db = in_memory_db();
    let (state, session) = state_with_admin(&db);
    state.auth.set_has_users(true);
    break_table(&db, "users");
    let router = build_router(state);

    let status = change_password(
        &router,
        &session,
        json!({"current_password": ADMIN_PASSWORD, "new_password": "new-secret-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Authorization — roles, token scopes and re-authentication are enforced
// ---------------------------------------------------------------------------

/// Full state (with storage worker) holding an admin and a viewer, plus a monitoring token
/// named "admin" (a token name is not a user).
async fn authz_app() -> Router {
    let state = make_state(false).await;
    for (name, role) in [("admin", UserRole::Admin), ("viewer", UserRole::Viewer)] {
        state
            .db
            .create_user(
                name,
                &lanforge_crypto::hash_password(ADMIN_PASSWORD),
                role,
                0,
            )
            .unwrap();
    }
    state
        .db
        .store_api_token(
            "lf_ak_monitoring",
            "admin",
            &ApiScopes::from_slice(&[ApiScope::Monitoring]),
            None,
            0,
        )
        .unwrap();
    build_router(state)
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    token: &str,
    elevation: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(e) = elevation {
        builder = builder.header("x-lanforge-elevation", e);
    }
    let res = router
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn login(router: &Router, body: Value) -> (StatusCode, String) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let token = body["data"]["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (status, token)
}

async fn elevate(router: &Router, session: &str, password: &str) -> (StatusCode, String) {
    let (status, body) = send(
        router,
        "POST",
        "/api/v1/auth/elevate",
        session,
        None,
        json!({ "password": password }),
    )
    .await;
    let token = body["data"]["elevation_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (status, token)
}

#[tokio::test]
async fn test_viewer_cannot_write_or_read_secrets() {
    let router = authz_app().await;
    let (_, viewer) = login(
        &router,
        json!({"username": "viewer", "password": ADMIN_PASSWORD}),
    )
    .await;
    assert!(!viewer.is_empty());

    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/devices",
        &viewer,
        None,
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Elevation proves who you are, it does not add permissions.
    let (status, elevation) = elevate(&router, &viewer, ADMIN_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    for (method, uri, body) in [
        (
            "PUT",
            "/api/v1/users/admin/password",
            json!({"password": "taken-over"}),
        ),
        (
            "POST",
            "/api/v1/users",
            json!({"username": "x", "password": "xxxxxxxx", "role": "admin"}),
        ),
        (
            "POST",
            "/api/v1/auth/tokens",
            json!({"name": "mine", "scopes": ["admin"]}),
        ),
        ("POST", "/api/v1/system/shutdown", json!(null)),
        ("GET", "/api/v1/pppoe/config", json!(null)),
        ("GET", "/api/v1/system/config/toml", json!(null)),
    ] {
        let (status, _) = send(&router, method, uri, &viewer, Some(&elevation), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "viewer {method} {uri}");
    }
}

#[tokio::test]
async fn test_monitoring_token_is_read_only_even_after_login() {
    let router = authz_app().await;

    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/status",
        "lf_ak_monitoring",
        None,
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (method, uri) in [
        ("POST", "/api/v1/auth/tokens"),
        ("PUT", "/api/v1/users/admin/password"),
        ("POST", "/api/v1/firewall/config"),
        ("GET", "/api/v1/pppoe/config"),
    ] {
        let (status, _) = send(
            &router,
            method,
            uri,
            "lf_ak_monitoring",
            None,
            json!({"name": "x", "password": "taken-over"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "token {method} {uri}");
    }

    // Logging in with the token must not mint an admin session.
    let (status, session) = login(&router, json!({"token": "lf_ak_monitoring"})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        "POST",
        "/api/v1/auth/tokens",
        &session,
        None,
        json!({"name": "escalated", "scopes": ["admin"]}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/pppoe/config",
        &session,
        None,
        json!(null),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "token login must keep the token's scopes"
    );
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/auth/me",
        &session,
        None,
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_admin_needs_reauthentication_for_account_changes() {
    let router = authz_app().await;
    let (_, admin) = login(
        &router,
        json!({"username": "admin", "password": ADMIN_PASSWORD}),
    )
    .await;
    let reset = json!({"password": "new-viewer-pw"});

    // A session alone (e.g. stolen) cannot reset a password.
    let (status, _) = send(
        &router,
        "PUT",
        "/api/v1/users/viewer/password",
        &admin,
        None,
        reset.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = elevate(&router, &admin, "wrong-password").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Another user's elevation token does not count.
    let (_, viewer) = login(
        &router,
        json!({"username": "viewer", "password": ADMIN_PASSWORD}),
    )
    .await;
    let (_, viewer_elevation) = elevate(&router, &viewer, ADMIN_PASSWORD).await;
    let (status, _) = send(
        &router,
        "PUT",
        "/api/v1/users/viewer/password",
        &admin,
        Some(&viewer_elevation),
        reset.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An elevation token is not a session.
    let (status, elevation) = elevate(&router, &admin, ADMIN_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/status",
        &elevation,
        None,
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        &router,
        "PUT",
        "/api/v1/users/viewer/password",
        &admin,
        Some(&elevation),
        reset,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Session revocation — a password change, reset or user deletion ends sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_change_ends_other_sessions() {
    let router = authz_app().await;
    let creds = json!({"username": "admin", "password": ADMIN_PASSWORD});
    let (_, stolen) = login(&router, creds.clone()).await;
    let (_, mine) = login(&router, creds).await;

    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/auth/change-password",
        &mine,
        None,
        json!({"current_password": ADMIN_PASSWORD, "new_password": "brand-new-pw"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let renewed = body["data"]["token"].as_str().unwrap().to_string();

    let (status, _) = send(&router, "GET", "/api/v1/status", &stolen, None, json!(null)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old sessions must end");
    let (status, _) = send(
        &router,
        "GET",
        "/api/v1/status",
        &renewed,
        None,
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the changer keeps a session");
}

#[tokio::test]
async fn test_admin_reset_and_delete_end_the_users_sessions() {
    let router = authz_app().await;
    let (_, admin) = login(
        &router,
        json!({"username": "admin", "password": ADMIN_PASSWORD}),
    )
    .await;
    let (_, elevation) = elevate(&router, &admin, ADMIN_PASSWORD).await;
    let (_, viewer) = login(
        &router,
        json!({"username": "viewer", "password": ADMIN_PASSWORD}),
    )
    .await;

    let (status, _) = send(
        &router,
        "PUT",
        "/api/v1/users/viewer/password",
        &admin,
        Some(&elevation),
        json!({"password": "reset-by-admin"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, "GET", "/api/v1/status", &viewer, None, json!(null)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reset must end the session"
    );

    let (_, viewer) = login(
        &router,
        json!({"username": "viewer", "password": "reset-by-admin"}),
    )
    .await;
    let (status, _) = send(
        &router,
        "DELETE",
        "/api/v1/users/viewer",
        &admin,
        Some(&elevation),
        json!(null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, "GET", "/api/v1/status", &viewer, None, json!(null)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a deleted user is signed out"
    );
}

/// Password guessing is throttled per client: after its free failures a client gets 429 with
/// `Retry-After` even for the right password, while another client still logs in.
#[tokio::test]
async fn test_login_guessing_is_throttled_per_client() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let router = build_router(make_state(true).await);
    let login = |from: &str, password: &str| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"password": password})).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(from.parse::<SocketAddr>().unwrap()));
        router.clone().oneshot(req)
    };

    for _ in 0..6 {
        let res = login("192.0.2.66:40000", "guess").await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = login("192.0.2.66:40001", "testpass").await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(header::RETRY_AFTER));

    let res = login("192.0.2.10:40000", "testpass").await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// Every API answer names the daemon's build, a refused one too: the CLI compares it with its
/// own before it reads anything else.
#[tokio::test]
async fn every_answer_names_the_daemon_build() {
    let open = TestApp::no_auth().await;
    let (status, _, headers) = open.get_raw("/api/v1/status").await;
    assert_eq!(status, StatusCode::OK);
    let token = headers[lanforge_api::BUILD_HEADER].to_str().unwrap();
    assert_eq!(
        lanforge_types::build::BuildInfo::parse(token).map(|b| b.version),
        Some(env!("CARGO_PKG_VERSION").to_string())
    );

    let locked = TestApp {
        router: build_router(make_state(true).await),
        token: None,
        elevation: None,
    };
    let (status, _, headers) = locked.get_raw("/api/v1/status").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key(lanforge_api::BUILD_HEADER));
}
