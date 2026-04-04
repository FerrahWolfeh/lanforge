use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use lanforge_core::bus::LanforgeEvent;
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
    fn name(&self) -> &str {
        "HttpService"
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

        info!("HTTP: listening on {}", addr);
        let _ = LanforgeContext::bus().publish(LanforgeEvent::ServiceReady {
            name: "http".to_string(),
        });

        axum::serve(tcp_listener, app)
            .with_graceful_shutdown(async move {
                while let Ok(event) = LanforgeContext::bus().subscribe().recv().await {
                    if matches!(event, lanforge_core::bus::LanforgeEvent::Shutdown) {
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

    let _ = LanforgeContext::table().update(&DeviceUpdate::CliHostUpdated {
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
    let devices: Vec<_> = LanforgeContext::table().read().devices().collect();
    Json(devices)
}

async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let t = LanforgeContext::table();
    let table_read = t.read();
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
