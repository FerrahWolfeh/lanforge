use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use lanforge_core::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use lanforge_core::state::update::FieldUpdate;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::info;

/// State shared across Axum handlers.
#[derive(Clone)]
struct AppState {
    cfg: Arc<ApiConfig>,
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
use lanforge_core::service::{AsyncService, LanforgeService};

use crate::config::ApiConfig;

pub struct HttpService {
    cfg: Arc<ApiConfig>,
}

impl HttpService {
    pub fn new(cfg: Arc<ApiConfig>) -> Self {
        Self { cfg }
    }
}

impl LanforgeService for HttpService {
    fn meta(&self) -> lanforge_core::service::ServiceMeta {
        lanforge_core::service::ServiceMeta {
            id: "http",
            display_name: "HTTP API",
            critical: false,
            max_retries: 3,
            base_backoff: std::time::Duration::from_secs(5),
            max_backoff: std::time::Duration::from_secs(60),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!(
            "HTTP API on {}",
            self.cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080")
        )
    }
}

impl AsyncService for HttpService {
    async fn run(&mut self) -> lanforge_core::error::Result<()> {
        let cfg = self.cfg.clone();

        let listen_addr = cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080");
        let addr: SocketAddr = listen_addr.parse().map_err(|e| {
            lanforge_core::error::CoreError::Generic(format!(
                "Invalid http_listen address '{}': {}",
                listen_addr, e
            ))
        })?;

        let state = AppState { cfg };

        let app = Router::new()
            .route(
                "/register",
                get(handle_register_get).post(handle_register_post),
            )
            .route("/devices", get(handle_devices))
            .route("/status", get(handle_status))
            .with_state(state);

        let tcp_listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
            lanforge_core::error::CoreError::Generic(format!("Failed to bind to {}: {}", addr, e))
        })?;

        axum::serve(tcp_listener, app)
            .with_graceful_shutdown(async move {
                let mut rx = LanforgeContext::bus().subscribe();
                while let Ok(event) = rx.recv().await {
                    if !LanforgeContext::is_running()
                        || matches!(event.event, lanforge_core::bus::LanforgeEvent::Shutdown)
                    {
                        info!("HTTP: shutdown signal received");
                        break;
                    }
                }
            })
            .await
            .map_err(|e| {
                lanforge_core::error::CoreError::Generic(format!("Axum server error: {}", e))
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_register_get(
    State(_state): State<AppState>,
    Query(payload): Query<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(payload).await
}

async fn handle_register_post(
    State(_state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(payload).await
}

async fn process_registration(req: RegisterRequest) -> impl IntoResponse {
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

    let _ = LanforgeContext::instance().apply(&DeviceUpdate::CliHostUpdated {
        mac: mac_addr,
        hostname: req.hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
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

async fn handle_devices() -> impl IntoResponse {
    let devices = LanforgeContext::devices();
    Json(devices)
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let devices = LanforgeContext::devices();
    let total = devices.len();
    let online = devices.iter().filter(|d| d.is_online()).count();
    let static_ct = devices.iter().filter(|d| d.is_static()).count();

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
