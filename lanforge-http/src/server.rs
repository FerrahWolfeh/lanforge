use crate::{
    auth::{AuthManager, Claims},
    error::{HttpError, Result as HttpResult},
};
use axum::{
    Json, Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
#[cfg(feature = "doh")]
use axum::{
    body::Bytes,
    http::{HeaderMap, Method},
};
use axum_server::tls_rustls::RustlsConfig;
use lanforge_api::api::{Command, Response};
use lanforge_api::server::ClientContext;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::{
    bus::{LanforgeEvent, SystemEvent},
    context::state::{CliHostUpdate, DeviceUpdate, FieldUpdate},
    device::{Device, Ipv6AddrOrSuffix, Origin},
    error::CoreError,
};
use lanforge_dns::tls_utils;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{net::Ipv4Addr, time::Instant};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::{error, info};

use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceControl};

use lanforge_api::config::ApiConfig;

/// State shared across Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ApiConfig>,
    pub ctx: LanforgeContext,
    pub auth: Arc<AuthManager>,
    pub start_time: Instant,
}

impl axum::extract::FromRef<AppState> for AuthManager {
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
    /// Custom boot file URL or path (optional).
    pub boot_file: Option<String>,
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
        self.cfg.http_listen.map_or_else(|| "0.0.0.0:8080".to_string(), |a| a.to_string())
    )
)]
pub struct HttpService {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
}

impl HttpService {
    #[must_use]
    pub const fn new(cfg: Arc<ApiConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for HttpService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();

        let addr = cfg
            .http_listen
            .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());

        let state = AppState {
            cfg: cfg.clone(),
            ctx: self.ctx.clone(),
            auth: Arc::new(AuthManager::new()),
            start_time: Instant::now(),
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

        if let Some(boot_dir) = &cfg.boot_dir {
            info!("📂 Serving boot files from {}", boot_dir);
            app = app.nest_service("/boot", ServeDir::new(boot_dir));
        }

        #[cfg(feature = "doh")]
        {
            if cfg.doh_enabled {
                app = app.route("/dns-query", get(handle_dns_query).post(handle_dns_query));
            }
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

        let maybe_tls_config = if cfg.https_enabled
            && let Some(cert) = &cfg.tls_cert
            && let Some(key) = &cfg.tls_key
        {
            match tls_utils::load_tls_config(cert, key) {
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
            if cfg.https_enabled && (cfg.tls_cert.is_none() || cfg.tls_key.is_none()) {
                tracing::warn!(
                    "HTTPS: Enabled in config but tls_cert/tls_key paths are missing. Falling back to HTTP."
                );
            }
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
            let config = RustlsConfig::from_config(Arc::new(tls_config));
            axum_server::bind_rustls(addr, config)
                .handle(axum_server::Handle::new()) // For graceful shutdown if needed, but we use .serve
                .serve(app.into_make_service())
                .await
                .map_err(|e| CoreError::Generic(format!("HTTPS server error: {e}")))?;
        } else {
            info!("🚀 HTTP API listening on http://{}", addr);
            let tcp_listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| CoreError::Generic(format!("Failed to bind to {addr}: {e}")))?;

            axum::serve(tcp_listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .map_err(|e| CoreError::Generic(format!("Axum server error: {e}")))?;
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
    process_registration(&state.ctx, payload)
}

async fn handle_register_post(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(&state.ctx, payload)
}

fn process_registration(ctx: &LanforgeContext, req: RegisterRequest) -> impl IntoResponse + use<> {
    let Some(mac_addr) = MacAddr::parse(&req.mac) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid MAC address format" })),
        );
    };

    let v4_static = req.ip.and_then(|s| s.parse::<Ipv4Addr>().ok());
    let v6_suffix = req.v6_suffix.and_then(|s| Ipv6AddrOrSuffix::parse(&s));

    info!(
        "📝 Pre-registration request for {} (host={:?}, v4={:?}, v6={:?})",
        mac_addr, req.hostname, v4_static, v6_suffix
    );

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: mac_addr,
        update: CliHostUpdate {
            hostname: req.hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::from(v4_static),
            v6_suffix: FieldUpdate::from(v6_suffix),
            origin: Origin::External,
            boot_file: req
                .boot_file
                .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
        },
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

async fn handle_metrics(State(state): State<AppState>) -> HttpResult<impl IntoResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let body = crate::metrics::generate_metrics(&state.ctx, &state.cfg, uptime);

    axum::response::Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .map_err(|e| HttpError::Internal(format!("Failed to build metrics response: {e}")))
}

// Implement IntoResponse for HttpError to provide consistent JSON errors
impl IntoResponse for HttpError {
    fn into_response(self) -> AxumResponse {
        let (status, message) = match self {
            Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Rpc { status, message } => {
                let code =
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (code, message)
            }
            Self::Jwt(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
            Self::Core(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
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
) -> HttpResult<impl IntoResponse> {
    let Some(hash) = &state.cfg.auth_password_hash else {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Authentication not configured on this daemon" })),
        )
            .into_response());
    };

    if lanforge_core::utils::auth::verify_password(hash, &payload.password) {
        let token = state.auth.generate_token("admin")?;
        Ok((StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response())
    } else {
        Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid password" })),
        )
            .into_response())
    }
}

async fn handle_rpc(
    State(state): State<AppState>,
    _claims: Claims,
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
    _claims: Claims,
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
                        let Ok(json) = serde_json::to_string(&Response::Event(timed_event)) else { continue };
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
    Query(params): Query<DnsQueryParams>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use lanforge_dns::server::{DnsContext, handle_query};

    let query_data = if method == Method::GET {
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
