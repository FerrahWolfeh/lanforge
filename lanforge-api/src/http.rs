use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use lanforge_core::bus::ManagedTable;
use lanforge_core::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::info;

use crate::config::ApiConfig;
use crate::error::Result;

/// State shared across Axum handlers.
#[derive(Clone)]
struct AppState {
    table: Arc<ManagedTable>,
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

/// Starts the HTTP REST API service using Axum.
pub async fn http_service(table: Arc<ManagedTable>, cfg: Arc<ApiConfig>) -> Result<()> {
    let listen_addr = cfg.http_listen.as_deref().unwrap_or("0.0.0.0:8080");
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| crate::error::ApiError::Config {
            message: format!("Invalid http_listen address '{}': {}", listen_addr, e),
        })?;

    let state = AppState { table, cfg };

    let app = Router::new()
        .route(
            "/register",
            get(handle_register_get).post(handle_register_post),
        )
        .route("/devices", get(handle_devices))
        .route("/status", get(handle_status))
        .with_state(state);

    info!("🌐 HTTP API responder pronto em http://{}", addr);

    let listener =
        tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| crate::error::ApiError::Bind {
                path: addr.to_string(),
                source: e,
            })?;

    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::ApiError::Internal {
            message: format!("Axum server error: {}", e),
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_register_get(
    State(state): State<AppState>,
    Query(payload): Query<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(state, payload).await
}

async fn handle_register_post(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    process_registration(state, payload).await
}

async fn process_registration(state: AppState, req: RegisterRequest) -> impl IntoResponse {
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

    let _ = state.table.update(DeviceUpdate::CliHostUpdated {
        mac: mac_addr,
        hostname: req.hostname.map(Some),
        v4_static: Some(v4_static),
        v6_suffix: Some(v6_suffix),
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
    let devices: Vec<_> = state.table.read().devices().cloned().collect();
    Json(devices)
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let table_read = state.table.read();
    let stats = table_read.stats();

    Json(serde_json::json!({
        "service": "lanforge",
        "status": "running",
        "interface": state.cfg.lan_iface,
        "counts": {
            "total_devices": stats.total_devices,
            "online": stats.online_devices,
            "static": stats.static_entries,
        },
        "capabilities": {
            "ra": state.cfg.ra_enabled,
            "dhcpv4": state.cfg.dhcp_v4_enabled,
            "dhcpv6": state.cfg.dhcp_v6_enabled,
            "dns": state.cfg.dns_enabled,
        }
    }))
}
