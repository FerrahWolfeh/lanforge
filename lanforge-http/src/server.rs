use crate::{
    auth::{AuthManager, AuthenticatedUser},
    error::{HttpError, Result as HttpResult},
    routes,
};
use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
};
#[cfg(feature = "doh")]
use axum::{
    body::Bytes,
    extract::Query,
    http::{HeaderMap, Method},
};
use axum_server::tls_rustls::RustlsConfig;
use lanforge_api::api::Response;
use lanforge_core::{
    bus::{LanforgeEvent, SystemEvent},
    error::CoreError,
};
use lanforge_db::{engine::LeaseDb, log_engine::LogDb};
use lanforge_dns::server::transport::tls as tls_utils;
use std::sync::Arc;
use std::time::Instant;
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
    pub db: Arc<LeaseDb>,
    pub log_db: Arc<LogDb>,
    pub auth: Arc<AuthManager>,
    pub start_time: Instant,
}

impl axum::extract::FromRef<AppState> for AuthManager {
    fn from_ref(state: &AppState) -> Self {
        (*state.auth).clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<LeaseDb> {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
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
    db: Arc<LeaseDb>,
    log_db: Arc<LogDb>,
}

impl HttpService {
    #[must_use]
    pub const fn new(
        cfg: Arc<ApiConfig>,
        ctx: LanforgeContext,
        db: Arc<LeaseDb>,
        log_db: Arc<LogDb>,
    ) -> Self {
        Self {
            cfg,
            ctx,
            db,
            log_db,
        }
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
            db: self.db.clone(),
            log_db: self.log_db.clone(),
            auth: Arc::new(AuthManager::new()),
            start_time: Instant::now(),
        };

        let mut app = Router::new()
            .nest("/api", routes::router().layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::middleware)))
            .route("/metrics", get(handle_metrics));

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
            info!("🔐 API Authentication enabled. WebSocket event stream active.");
            app = app.route("/api/ws", get(handle_ws));
        } else {
            info!("🔓 No password hash set. WebSocket event stream disabled for safety.");
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

async fn handle_ws(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.ctx.bus().subscribe();

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
    axum::extract::Query(params): axum::extract::Query<DnsQueryParams>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use lanforge_core::types::TransportProtocol;
    use lanforge_dns::pipeline::DnsPipelineRequest;
    use lanforge_dns::server::DnsContext;
    use lanforge_dns::wire::{WireHeader, WireQuestion};

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

    let _src_ip: std::net::IpAddr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let header = match WireHeader::parse(&query_data) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "Invalid DNS header").into_response(),
    };
    let question = match WireQuestion::parse(&query_data) {
        Some(q) => q,
        None => return (StatusCode::BAD_REQUEST, "Invalid DNS question").into_response(),
    };

    let mut resp_buf = Vec::with_capacity(512);
    let req = DnsPipelineRequest::new(
        &query_data,
        &header,
        &question,
        _src_ip,
        TransportProtocol::Https,
    );

    match dns_ctx.pipeline.run(dns_ctx, req, &mut resp_buf).await {
        Ok(()) => {
            if !resp_buf.is_empty() {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
                    resp_buf,
                )
                    .into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
