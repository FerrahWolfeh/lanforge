use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::{
    bus::LanforgeEvent,
    device::{Device, Ipv6AddrOrSuffix, Origin},
    error::CoreError,
    state::{DeviceUpdate, FieldUpdate},
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

/// State shared across Axum handlers.
#[derive(Clone)]
struct AppState {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
    start_time: std::time::Instant,
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

use lanforge_core::context::LanforgeContext;
use lanforge_core::service::AsyncService;

use crate::config::ApiConfig;

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
    async fn run(&mut self) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();

        let listen_addr = cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080");
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            CoreError::Generic(format!(
                "Invalid http_listen address '{}': {}",
                listen_addr, e
            ))
        })?;

        let state = AppState {
            cfg,
            ctx: self.ctx.clone(),
            start_time: std::time::Instant::now(),
        };

        let app = Router::new()
            .route(
                "/register",
                get(handle_register_get).post(handle_register_post),
            )
            .route("/devices", get(handle_devices))
            .route("/status", get(handle_status))
            .route("/metrics", get(handle_metrics))
            .with_state(state);

        let tcp_listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| CoreError::Generic(format!("Failed to bind to {}: {}", addr, e)))?;

        let ctx_shutdown = self.ctx.clone();
        axum::serve(tcp_listener, app)
            .with_graceful_shutdown(async move {
                let mut rx = ctx_shutdown.bus().subscribe();
                while let Ok(event) = rx.recv().await {
                    if !ctx_shutdown.is_running() || matches!(event.event, LanforgeEvent::Shutdown)
                    {
                        info!("HTTP: shutdown signal received");
                        break;
                    }
                }
            })
            .await
            .map_err(|e| CoreError::Generic(format!("Axum server error: {}", e)))?;

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

    let _ = ctx.apply(&DeviceUpdate::CliHostUpdated {
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
