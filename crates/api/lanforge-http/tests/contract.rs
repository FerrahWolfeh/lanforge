// Entry-point contract tests for `lanforge-http`.
//
// Uses `tower::ServiceExt::oneshot` to drive the Axum router directly —
// no TCP port is bound, so tests are hermetic and instantaneous.
// Each test function covers a logical group of scenarios in a grid table,
// reducing boilerplate while maximising coverage of the API contract.

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
use lanforge_db::{config::DatabaseConfig, engine::LanforgeDb, log_engine::LogDb};
use lanforge_http::{auth::AuthManager, config::HttpConfig, routes, server::AppState};
use lanforge_types::network::firewall::FirewallConfig;
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
}

/// Build the same router the real `HttpService` builds, minus
/// `CompressionLayer`/`CorsLayer` (not needed in tests).
fn build_router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/api",
            routes::router().layer(axum::middleware::from_fn_with_state(
                state.clone(),
                lanforge_http::auth::middleware,
            )),
        )
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
    let log_db = Arc::new(LogDb::open_in_memory());
    let ctx = LanforgeContext::new(bus, table, None);

    let mut worker = lanforge_db::worker::DbWorker::new(
        DatabaseConfig::default(),
        ctx.clone(),
        db.clone(),
        log_db.clone(),
    );
    let ctx_worker = ctx.clone();
    tokio::spawn(async move {
        let _ = worker.serve(&ctx_worker).await;
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
        db,
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
        }
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

    // Token generation via HTTP is permitted for authenticated admin
    let (status, body) = authed_app.post("/api/v1/auth/tokens", &json!({"name": "test-token"})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Authenticated admin should be able to generate tokens"
    );
    assert!(body["data"]["token"].as_str().unwrap().starts_with("lf_ak_"));

    // Unauthenticated token generation must return 401 Unauthorized
    let (status, _) = unauthed_app.post("/api/v1/auth/tokens", &json!({"name": "test-token"})).await;
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
            "patch with invalid IP — dispatch silently ignores",
            json!({"field": "v4_static", "value": "not-an-ip"}),
            StatusCode::NO_CONTENT,
        ),
        (
            "patch with unknown field — dispatch returns 500",
            json!({"field": "nonexistent_field", "value": "anything"}),
            StatusCode::INTERNAL_SERVER_ERROR,
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

    // --- dev: dynamic rewrite ---
    let (status, _) = app
        .post(
            "/api/v1/dns/rewrites",
            &json!({"domain": "dynamic.lan", "rtype": "CNAME", "answer": "dev:testhost"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "dev: rewrite should be accepted"
    );
    app.delete("/api/v1/dns/rewrites").await; // clean up

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
            StatusCode::BAD_REQUEST, // Ideal contract — current impl returns 500
        ),
    ];

    for (desc, body, expected) in guardrail_cases {
        let (status, _) = app.post("/api/v1/dns/rewrites", body).await;
        assert_eq!(status, *expected, "DNS rewrites guardrail: {desc}");
    }

    // Remove non-existent rule ID — dispatch silently no-ops
    let (status, _) = app.delete("/api/v1/dns/rewrites/99999").await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "Remove non-existent rewrite ID should silently succeed"
    );
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
}

// ---------------------------------------------------------------------------
// Group 5 — System Config import/export contract
// ---------------------------------------------------------------------------

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

    // Verify TOML export via query parameter and via direct /config/toml route
    let (toml_status, toml_str, toml_headers) = app.get_raw("/api/v1/config?format=toml").await;
    assert_eq!(toml_status, StatusCode::OK);
    assert_eq!(
        toml_headers.get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    assert!(toml_str.contains("[[devices]]"), "toml should contain [[devices]] section");
    assert!(toml_str.contains("only-host"), "toml should contain the imported hostname");

    let (toml_status2, toml_str2, _) = app.get_raw("/api/v1/config/toml").await;
    assert_eq!(toml_status2, StatusCode::OK);
    assert!(toml_str2.contains("only-host"));

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
            "db/vacuum",
            "POST",
            "/api/v1/db/vacuum",
            StatusCode::NO_CONTENT,
        ),
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
    let mut config: FirewallConfig =
        serde_json::from_value(body["data"].clone()).unwrap();
    config.flow_offload = false;
    let (status, body) = app.post("/api/v1/firewall/config", &config).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["message"].as_str().unwrap().contains("updated"));

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
    });
    invalid_candidate.port_forwards.push(PortForwardRule {
        comment: Some("Rule 2 colliding".into()),
        src_zone: "external".into(),
        internal_ip: Ipv4Addr::new(192, 168, 1, 60).into(),
        external_port: 8443,
        internal_port: 8443,
        protocol: L4Protocol::Tcp,
        enable_hairpin: true,
    });

    let (status, body) = app.post("/api/v1/firewall/propose", &invalid_candidate).await;
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
    });

    let (status, body) = app.post("/api/v1/firewall/propose", &candidate).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["valid"], true);
    let tx_id = body["data"]["tx_id"].as_str().expect("tx_id must be present").to_string();
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
    assert!(body["data"]["message"].as_str().unwrap().contains("confirmed"));

    // 5. Verify config has the new port forward
    let (status, body) = app.get("/api/v1/firewall/config").await;
    assert_eq!(status, StatusCode::OK);
    let updated_config: FirewallConfig = serde_json::from_value(body["data"].clone()).unwrap();
    assert!(updated_config.port_forwards.iter().any(|pf| pf.external_port == 32400));
}

#[tokio::test]
async fn test_users_contract() {
    let app = TestApp::with_auth().await;

    // 1. List users
    let (status, body) = app.get("/api/v1/users").await;
    assert_eq!(status, StatusCode::OK);
    // body is {"data": {"users": [...]}}
    let users = body["data"]["users"].as_array().expect("users array in data");
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
    assert!(data["timestamp"].as_u64().is_some(), "timestamp must be present");
    assert!(data["interfaces"].as_array().is_some(), "interfaces must be a list");
}

#[tokio::test]
async fn test_events_contract() {
    let state = make_state(false).await;
    let ev1 = lanforge_types::events::TimedEvent::new(
        lanforge_core::bus::LanforgeEvent::System(
            lanforge_types::events::SystemEvent::ReloadConfig,
        ),
    );
    let ev2 = lanforge_types::events::TimedEvent::new(
        lanforge_core::bus::LanforgeEvent::Firewall(
            lanforge_types::events::FirewallEvent::RulesetFlushed,
        ),
    );
    let mut buf = Vec::new();
    state
        .log_db
        .record_logs_batch(&[ev1, ev2], &mut buf)
        .unwrap();

    let router = build_router(state);
    let app = TestApp {
        router,
        token: None,
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

