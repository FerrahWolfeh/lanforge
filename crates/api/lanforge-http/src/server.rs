use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Body,
    extract::{FromRef, State},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::get,
};
#[cfg(feature = "webui")]
use axum::http::StatusCode;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use lanforge_core::{
    bus::{LanforgeEvent, SystemEvent},
    context::LanforgeContext,
    error::CoreError,
    service::{AsyncService, ServiceDependency},
};
use lanforge_db_core::{DatabaseStore, LogStore};
use lanforge_dns::server::transport::tls as tls_utils;
use lanforge_macros::lanforge_service;
#[cfg(feature = "webui")]
use lanforge_webui::WebUiAssets;
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};
use tracing::{error, info, warn};

use crate::auth::AuthManager;
use crate::config::HttpConfig;
use crate::error::{HttpError, Result as HttpResult};
use crate::routes;

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

impl FromRef<AppState> for AuthManager {
    fn from_ref(state: &AppState) -> Self {
        (*state.auth).clone()
    }
}

impl FromRef<AppState> for Arc<HttpConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.cfg.clone()
    }
}

impl FromRef<AppState> for Arc<dyn DatabaseStore> {
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
    stack = 4096,
    multi_threaded = true,
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
    pub const fn new(
        cfg: Arc<HttpConfig>,
        ctx: LanforgeContext,
        db: Arc<dyn DatabaseStore>,
        log_db: Arc<dyn LogStore>,
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
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database]
    }

    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        vec![
            (Cow::Borrowed("listen"), self.cfg.listen.to_string()),
            (
                Cow::Borrowed("https_enabled"),
                self.cfg.https_enabled.to_string(),
            ),
            (
                Cow::Borrowed("doh_enabled"),
                self.cfg.doh_enabled.to_string(),
            ),
            (
                Cow::Borrowed("auth_enabled"),
                self.cfg.auth_password_hash.is_some().to_string(),
            ),
        ]
    }

    #[allow(clippy::too_many_lines)]
    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
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
            info!(boot_dir = %boot_dir, "HTTP: Serving boot files");
            app = app.nest_service("/boot", ServeDir::new(boot_dir));
        }

        if let Some(webui_dir) = &cfg.webui_dir {
            info!(webui_dir = %webui_dir, "HTTP: Serving WebUI from filesystem");
            let index_file = Path::new(webui_dir).join("index.html");
            let serve_dir = ServeDir::new(webui_dir).fallback(ServeFile::new(index_file));
            app = app.fallback_service(serve_dir);
        } else {
            #[cfg(feature = "webui")]
            {
                info!("HTTP: Serving WebUI from embedded assets");
                app = app.fallback(handle_embedded_webui);
            }
        }

        #[cfg(feature = "doh")]
        {
            if cfg.doh_enabled {
                app = app.route(
                    "/dns-query",
                    get(crate::doh::handle_dns_query).post(crate::doh::handle_dns_query),
                );
            }
        }

        if cfg.auth_password_hash.is_some() {
            info!("HTTP: API authentication enabled");
        }

        let app = app.with_state(state);

        let maybe_tls_config = if cfg.https_enabled
            && let Some(cert) = &cfg.tls_cert
            && let Some(key) = &cfg.tls_key
        {
            match tls_utils::load_tls_config(cert, key) {
                Ok(config) => Some(config),
                Err(e) => {
                    error!(error = %e, "HTTPS: Failed to load TLS configuration, falling back to HTTP");
                    None
                }
            }
        } else {
            if cfg.https_enabled && (cfg.tls_cert.is_none() || cfg.tls_key.is_none()) {
                warn!(
                    "HTTPS: Enabled in config but tls_cert/tls_key paths are missing. Falling back to HTTP."
                );
            }
            None
        };

        let ctx_shutdown = ctx.clone();
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

        if let Some(tls_config) = maybe_tls_config {
            info!(addr = %addr, "HTTPS: API listening");
            let config = RustlsConfig::from_config(Arc::new(tls_config));
            let handle = Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal.await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
            });

            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .map_err(|e| CoreError::Generic(format!("HTTPS server error: {e}")))?;
        } else if cfg.allow_plaintext_http {
            info!(addr = %addr, "HTTP: API listening");
            let tcp_listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| CoreError::Generic(format!("Failed to bind to {addr}: {e}")))?;

            axum::serve(tcp_listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await
                .map_err(|e| CoreError::Generic(format!("Axum server error: {e}")))?;
        } else {
            let msg = "HTTP: TLS configuration missing and allow_plaintext_http is false. Refusing to start unencrypted server.";
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


#[cfg(feature = "webui")]
async fn handle_embedded_webui(uri: axum::http::Uri) -> impl IntoResponse {
    match WebUiAssets::get_file_or_fallback(uri.path()) {
        Some((mime, content)) => {
            ([(axum::http::header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "WebUI index.html not found").into_response(),
    }
}
