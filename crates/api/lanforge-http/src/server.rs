use crate::{
    auth::AuthManager,
    error::{HttpError, Result as HttpResult},
    routes,
};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
};
#[cfg(feature = "doh")]
use axum::{body::Bytes, extract::Query, http::HeaderMap, http::Method};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use lanforge_core::{
    bus::{LanforgeEvent, SystemEvent},
    error::CoreError,
};
use lanforge_db_core::{DatabaseStore, LogStore};
use lanforge_dns::server::transport::tls as tls_utils;
use lanforge_macros::lanforge_service;
use lanforge_types::system::ServiceBanner;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};
use tracing::{error, info};

use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceControl};

use crate::config::HttpConfig;

/// State shared across Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<HttpConfig>,
    pub ctx: LanforgeContext,
    pub db: Arc<dyn DatabaseStore>,
    pub log_db: Arc<dyn LogStore>,
    pub auth: Arc<AuthManager>,
    pub start_time: Instant,
}

impl axum::extract::FromRef<AppState> for AuthManager {
    fn from_ref(state: &AppState) -> Self {
        (*state.auth).clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<HttpConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.cfg.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<dyn DatabaseStore> {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

#[lanforge_service(
    id = "http",
    name = "HTTP API",
    critical = false,
    retries = 3,
    base_backoff = 5,
    max_backoff = 60,
    describe = format!(
        "HTTP API on {}",
        self.cfg.listen
    )
)]
#[derive(Clone)]
pub struct HttpService {
    cfg: Arc<HttpConfig>,
    ctx: LanforgeContext,
    db: Arc<dyn DatabaseStore>,
    log_db: Arc<dyn LogStore>,
}

impl HttpService {
    #[must_use]
    pub fn new(
        cfg: Arc<HttpConfig>,
        ctx: LanforgeContext,
        db: Arc<dyn DatabaseStore>,
        log_db: Arc<dyn LogStore>,
    ) -> Self {
        ctx.register_status_provider(Arc::new(Self {
            cfg: cfg.clone(),
            ctx: ctx.clone(),
            db: db.clone(),
            log_db: log_db.clone(),
        }));
        Self {
            cfg,
            ctx,
            db,
            log_db,
        }
    }
}

impl lanforge_core::service::StatusProvider for HttpService {
    fn banner(&self) -> ServiceBanner {
        let stats = vec![
            (
                std::borrow::Cow::Borrowed("listen"),
                self.cfg.listen.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("https_enabled"),
                self.cfg.https_enabled.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("doh_enabled"),
                self.cfg.doh_enabled.to_string(),
            ),
        ];
        ServiceBanner {
            id: "http".to_string(),
            name: "HTTP API".to_string(),
            state: self.ctx.get_service_state("http"),
            uptime_secs: self.ctx.get_service_uptime("http"),
            stats,
        }
    }
}

impl AsyncService for HttpService {
    #[allow(clippy::too_many_lines)]
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();

        let addr = cfg.listen;

        let state = AppState {
            cfg: cfg.clone(),
            ctx: self.ctx.clone(),
            db: self.db.clone(),
            log_db: self.log_db.clone(),
            auth: Arc::new(AuthManager::new()),
            start_time: Instant::now(),
        };

        let mut app = Router::new()
            .nest(
                "/api",
                routes::router()
                    .layer(CompressionLayer::new())
                    .layer(from_fn_with_state(state.clone(), crate::auth::middleware))
                    .layer(CorsLayer::permissive()),
            )
            .route("/metrics", get(handle_metrics));

        if let Some(boot_dir) = &cfg.boot_dir {
            info!("📂 Serving boot files from {}", boot_dir);
            app = app.nest_service("/boot", ServeDir::new(boot_dir));
        }

        if let Some(webui_dir) = &cfg.webui_dir {
            info!("🌐 Serving WebUI from filesystem: {}", webui_dir);
            let index_file = std::path::Path::new(webui_dir).join("index.html");
            let serve_dir = ServeDir::new(webui_dir).fallback(ServeFile::new(index_file));
            app = app.fallback_service(serve_dir);
        } else {
            #[cfg(feature = "webui")]
            {
                info!("🌐 Serving WebUI from embedded assets");
                app = app.fallback(handle_embedded_webui);
            }
        }

        #[cfg(feature = "doh")]
        {
            if cfg.doh_enabled {
                app = app.route("/dns-query", get(handle_dns_query).post(handle_dns_query));
            }
        }

        if cfg.auth_password_hash.is_some() {
            info!("🔐 API Authentication enabled.");
        } else {
            info!("🔓 No password hash set. API Authentication disabled.");
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
                .handle(Handle::new()) // For graceful shutdown if needed, but we use .serve
                .serve(app.into_make_service())
                .await
                .map_err(|e| CoreError::Generic(format!("HTTPS server error: {e}")))?;
        } else if cfg.allow_plaintext_http {
            info!("🚀 HTTP API listening on http://{}", addr);
            let tcp_listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| CoreError::Generic(format!("Failed to bind to {addr}: {e}")))?;

            axum::serve(tcp_listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .map_err(|e| CoreError::Generic(format!("Axum server error: {e}")))?;
        } else {
            let msg = "❌ TLS configuration missing (tls_cert/tls_key) and plaintext HTTP is not explicitly allowed (allow_plaintext_http = false). Refusing to start unencrypted server in production.";
            error!("{msg}");
            return Err(CoreError::Generic(msg.to_string()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_metrics(State(state): State<AppState>) -> HttpResult<impl IntoResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let body = crate::metrics::generate_metrics(&state.ctx, uptime);

    axum::response::Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
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
            Self::BadRequest(msg) | Self::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
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
    use lanforge_dns::pipeline::DnsPipelineRequest;
    use lanforge_dns::server::DnsContext;
    use lanforge_dns_wire::{WireHeader, WireQuestion};
    use lanforge_types::network::dns::TransportProtocol;

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

    let Some(dns_ctx) = state
        .ctx
        .get_service_state_ref::<DnsContext>("dns::context")
    else {
        return (StatusCode::SERVICE_UNAVAILABLE, "DNS engine not ready").into_response();
    };

    let src_ip: std::net::IpAddr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let Some(header) = WireHeader::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS header").into_response();
    };
    let Some(question) = WireQuestion::parse(&query_data) else {
        return (StatusCode::BAD_REQUEST, "Invalid DNS question").into_response();
    };

    let mut resp_buf = Vec::with_capacity(512);
    let req = DnsPipelineRequest::new(
        &query_data,
        &header,
        &question,
        src_ip,
        TransportProtocol::Https,
    );

    match dns_ctx.pipeline.run(&dns_ctx, req, &mut resp_buf).await {
        Ok(()) => {
            if resp_buf.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
                    resp_buf,
                )
                    .into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(feature = "webui")]
async fn handle_embedded_webui(uri: axum::http::Uri) -> impl IntoResponse {
    match lanforge_webui::WebUiAssets::get_file_or_fallback(uri.path()) {
        Some((mime, content)) => (
            [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
            content.data,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "WebUI index.html not found").into_response(),
    }
}
