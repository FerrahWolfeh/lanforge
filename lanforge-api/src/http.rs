use crate::api::{Command, Response};
use crate::server::ClientContext;
use axum::{
    Json, Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::{
    bus::{LanforgeEvent, SystemEvent},
    device::{Device, Ipv6AddrOrSuffix, Origin},
    error::CoreError,
    state::{DeviceUpdate, FieldUpdate},
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceControl};

use crate::config::ApiConfig;

/// State shared across Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ApiConfig>,
    pub ctx: LanforgeContext,
    pub auth: Arc<crate::auth::AuthManager>,
    pub start_time: std::time::Instant,
}

impl axum::extract::FromRef<AppState> for crate::auth::AuthManager {
    fn from_ref(state: &AppState) -> Self {
        (*state.auth).clone()
    }
}

/// Parameters for the /register endpoint (Query or JSON).
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterRequest {
    /// MAC address of the device (required).
    pub mac: String,
    /// Destination hostname (optional).
    pub hostname: Option<String>,
    /// Static IPv4 address (optional).
    pub ip: Option<String>,
    /// IPv6 Interface ID / Suffix (optional).
    pub v6_suffix: Option<String>,
}

#[lanforge_macros::lanforge_service(
    id = "http",
    name = "HTTP API",
    critical = false,
    retries = 3,
    base_backoff = 5,
    max_backoff = 60,
    describe = format!(
        "HTTP API on {}",
        self.cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080")
    )
)]
pub struct HttpService {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
}

impl HttpService {
    pub fn new(cfg: Arc<ApiConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for HttpService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();

        let listen_addr = cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080");
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            CoreError::Generic(format!(
                "Invalid http_listen address '{}': {}",
                listen_addr, e
            ))
        })?;

        let state = AppState {
            cfg: cfg.clone(),
            ctx: self.ctx.clone(),
            auth: Arc::new(crate::auth::AuthManager::new()),
            start_time: std::time::Instant::now(),
        };

        let mut app = Router::new()
            .route(
                "/register",
                get(handle_register_get).post(handle_register_post),
            )
            .route("/devices", get(handle_devices))
            .route("/status", get(handle_status))
            .route("/metrics", get(handle_metrics))
            .route("/login", post(handle_login));

        #[cfg(feature = "doh")]
        {
            app = app.route("/dns-query", get(handle_dns_query).post(handle_dns_query));
        }

        if cfg.auth_password_hash.is_some() {
            info!("🔐 API Authentication enabled. RPC routes active.");
            app = app
                .route("/api/rpc", post(handle_rpc))
                .route("/api/ws", get(handle_ws));
        } else {
            info!("🔓 No password hash set. API RPC routes disabled for safety.");
        }

        let app = app.with_state(state);

        let maybe_tls_config = if let (Some(cert), Some(key)) = (&cfg.tls_cert, &cfg.tls_key) {
            match crate::tls::load_tls_config(cert, key) {
                Ok(config) => Some(config),
                Err(e) => {
                    error!(
                        "❌ Failed to load TLS configuration: {}. Falling back to HTTP.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let ctx_shutdown = self.ctx.clone();
        let shutdown_signal = async move {
            let mut rx = ctx_shutdown.bus().subscribe();
            while let Ok(event) = rx.recv().await {
                if !ctx_shutdown.is_running()
                    || matches!(event.event, LanforgeEvent::System(SystemEvent::Shutdown))
                {
                    info!("HTTP: shutdown signal received");
                    break;
                }
            }
        };

        ctrl.signal_ready();

        if let Some(tls_config) = maybe_tls_config {
            info!("🚀 HTTPS API listening on https://{}", addr);
            let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));
            axum_server::bind_rustls(addr, config)
                .handle(axum_server::Handle::new()) // For graceful shutdown if needed, but we use .serve
                .serve(app.into_make_service())
                .await
                .map_err(|e| CoreError::Generic(format!("HTTPS server error: {}", e)))?;
        } else {
            info!("🚀 HTTP API listening on http://{}", addr);
            let tcp_listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| CoreError::Generic(format!("Failed to bind to {}: {}", addr, e)))?;

            axum::serve(tcp_listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .map_err(|e| CoreError::Generic(format!("Axum server error: {}", e)))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_register_get(
    State(state): State<AppState>,
    Query(payload): Query<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(state.ctx, payload).await
}

async fn handle_register_post(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(state.ctx, payload).await
}

async fn process_registration(ctx: LanforgeContext, req: RegisterRequest) -> impl IntoResponse {
    let mac_addr = match MacAddr::parse(&req.mac) {
        Some(m) => m,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid MAC address format" })),
            );
        }
    };

    let v4_static = req.ip.and_then(|s| s.parse::<Ipv4Addr>().ok());
    let v6_suffix = req.v6_suffix.and_then(|s| Ipv6AddrOrSuffix::parse(&s));

    info!(
        "📝 Pre-registration request for {} (host={:?}, v4={:?}, v6={:?})",
        mac_addr, req.hostname, v4_static, v6_suffix
    );

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_addr,
        hostname: req.hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
        duid: FieldUpdate::NoChange,
        v4_static: FieldUpdate::from(v4_static),
        v6_suffix: FieldUpdate::from(v6_suffix),
        origin: Origin::External,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": format!("Device {} registered with origin External", mac_addr),
            "mac": mac_addr.to_string()
        })),
    )
}

async fn handle_devices(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state.ctx.all_devices();
    Json(devices)
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state.ctx.all_devices();
    let total = devices.len();
    let online = devices
        .iter()
        .filter(|d: &&Arc<Device>| d.is_online())
        .count();
    let static_ct = devices
        .iter()
        .filter(|d: &&Arc<Device>| d.is_static())
        .count();

    Json(serde_json::json!({
        "service": "lanforge",
        "status": "running",
        "interface": state.cfg.lan_iface,
        "counts": {
            "total_devices": total,
            "online": online,
            "static": static_ct,
        },
        "capabilities": {
            "ra": state.cfg.ra_enabled,
            "dhcpv4": state.cfg.dhcp_v4_enabled,
            "dhcpv6": state.cfg.dhcp_v6_enabled,
            "dns": state.cfg.dns_enabled,
        }
    }))
}

async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let body = crate::metrics::generate_metrics(&state.ctx, &state.cfg, uptime);

    axum::response::Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Authentication & RPC Handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

async fn handle_login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let hash = match &state.cfg.auth_password_hash {
        Some(h) => h,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(
                    serde_json::json!({ "error": "Authentication not configured on this daemon" }),
                ),
            );
        }
    };

    if crate::auth::verify_password(hash, &payload.password) {
        match state.auth.generate_token("admin") {
            Ok(token) => (StatusCode::OK, Json(serde_json::json!({ "token": token }))),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Token generation failed: {e}") })),
            ),
        }
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid password" })),
        )
    }
}

async fn handle_rpc(
    State(state): State<AppState>,
    _claims: crate::auth::Claims,
    Json(cmd): Json<Command>,
) -> impl IntoResponse {
    let ctx = ClientContext {
        current_gua: None, // Will fallback to config in handle_status
        uptime_secs: state.start_time.elapsed().as_secs(),
        last_scan_secs_ago: 0,
        cfg: state.cfg.clone(),
        ctx: state.ctx.clone(),
    };

    let resp = cmd.action.dispatch(&ctx).await;
    Json(resp)
}

async fn handle_ws(
    State(state): State<AppState>,
    _claims: crate::auth::Claims,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.ctx.bus().subscribe();

    // In a real implementation, we would also handle incoming messages (e.g. RPC over WS)
    // For now, we just stream events.
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        let json = match serde_json::to_string(&Response::Event(timed_event)) {
                            Ok(j) => j,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // Ignore other incoming messages for now
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH)
// ---------------------------------------------------------------------------

#[cfg(feature = "doh")]
#[derive(Debug, serde::Deserialize)]
pub struct DnsQueryParams {
    pub dns: Option<String>,
}

#[cfg(feature = "doh")]
async fn handle_dns_query(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<DnsQueryParams>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use lanforge_dns::server::{DnsContext, handle_query};

    let query_data = if method == axum::http::Method::GET {
        let Some(dns_base64) = params.dns else {
            return (StatusCode::BAD_REQUEST, "Missing dns parameter").into_response();
        };
        match URL_SAFE_NO_PAD.decode(dns_base64) {
            Ok(d) => d,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64").into_response(),
        }
    } else {
        body.to_vec()
    };

    if query_data.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty query").into_response();
    }

    let dns_ctx_any = match state.ctx.get_dns_context() {
        Some(c) => c,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "DNS engine not ready").into_response(),
    };

    let dns_ctx = match dns_ctx_any.downcast_ref::<DnsContext>() {
        Some(c) => c,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid DNS context").into_response(),
    };

    // For DoH, we don't have a simple source IP like UDP, but we can try to get it from headers
    let _src_ip: std::net::IpAddr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    match handle_query(&query_data, dns_ctx, _src_ip).await {
        Ok(Some(response)) => (
            [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
            response,
        )
            .into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
