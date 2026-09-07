use std::borrow::Cow;
use std::net::SocketAddr;
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
use lanforge_types::system::ServiceState;
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
        if !cfg.enabled {
            info!("HTTP: Service disabled in configuration.");
            ctx.set_service_state("http", ServiceState::Inactive);
            std::future::pending::<()>().await;
            return Ok(());
        }

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

        let addrs = cfg.listen.addrs();
        if addrs.is_empty() {
            let msg = "HTTP: No listen addresses configured.";
            error!("{msg}");
            return Err(CoreError::Generic(msg.to_string()));
        }

        let (shutdown_tx, _) = tokio::sync::watch::channel(());
        let ctx_shutdown = ctx.clone();
        let shutdown_tx_clone = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut rx = ctx_shutdown.bus().subscribe();
            while let Ok(event) = rx.recv().await {
                if !ctx_shutdown.is_running()
                    || matches!(event.event, LanforgeEvent::System(SystemEvent::Shutdown))
                {
                    info!("HTTP: shutdown signal received");
                    let _ = shutdown_tx_clone.send(());
                    break;
                }
            }
        });

        if let Some(tls_config) = maybe_tls_config {
            let config = Arc::new(tls_config);
            let mut server_tasks = Vec::new();

            for addr in addrs {
                let std_listener = bind_tcp_dual_stack(addr)?;
                info!(addr = %addr, "HTTPS: API listening");
                let rustls_cfg = RustlsConfig::from_config(Arc::clone(&config));
                let handle = Handle::new();
                let shutdown_handle = handle.clone();
                let mut shutdown_rx = shutdown_tx.subscribe();

                tokio::spawn(async move {
                    let _ = shutdown_rx.changed().await;
                    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
                });

                let app_service = app.clone().into_make_service();
                let server = axum_server::from_tcp_rustls(std_listener, rustls_cfg)
                    .map_err(|e| CoreError::Generic(format!("Failed to create TLS server: {e}")))?;
                server_tasks.push(tokio::spawn(async move {
                    server
                        .handle(handle)
                        .serve(app_service)
                        .await
                        .map_err(|e| CoreError::Generic(format!("HTTPS server error: {e}")))
                }));
            }

            for res in futures::future::join_all(server_tasks).await {
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(CoreError::Generic(format!("HTTPS server task failed: {e}"))),
                }
            }
        } else if cfg.allow_plaintext_http {
            let mut server_tasks = Vec::new();

            for addr in addrs {
                let std_listener = bind_tcp_dual_stack(addr)?;
                info!(addr = %addr, "HTTP: API listening");
                let tcp_listener = TcpListener::from_std(std_listener)
                    .map_err(|e| CoreError::Generic(format!("Failed to bind to {addr}: {e}")))?;
                let mut shutdown_rx = shutdown_tx.subscribe();
                let app_clone = app.clone();

                server_tasks.push(tokio::spawn(async move {
                    axum::serve(tcp_listener, app_clone)
                        .with_graceful_shutdown(async move {
                            let _ = shutdown_rx.changed().await;
                        })
                        .await
                        .map_err(|e| CoreError::Generic(format!("Axum server error: {e}")))
                }));
            }

            for res in futures::future::join_all(server_tasks).await {
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(CoreError::Generic(format!("Axum server task failed: {e}"))),
                }
            }
        } else {
            let msg = "HTTP: TLS configuration missing and allow_plaintext_http is false. Refusing to start unencrypted server.";
            error!("{msg}");
            return Err(CoreError::Generic(msg.to_string()));
        }

        Ok(())
    }
}

fn bind_tcp_dual_stack(addr: SocketAddr) -> Result<std::net::TcpListener, CoreError> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            let socket_res = (|| -> std::io::Result<socket2::Socket> {
                let s = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                s.set_only_v6(false)?;
                s.set_reuse_address(true)?;
                s.set_nonblocking(true)?;
                s.bind(&socket2::SockAddr::from(addr))?;
                s.listen(1024)?;
                Ok(s)
            })();

            match socket_res {
                Ok(s) => Ok(s.into()),
                Err(e) => {
                    warn!(
                        "HTTP: IPv6 dual-stack TCP bind to {} failed ({}), falling back to 0.0.0.0:{}",
                        addr,
                        e,
                        v6.port()
                    );
                    let v4_addr = SocketAddr::from(([0, 0, 0, 0], v6.port()));
                    let s = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(CoreError::Io)?;
                    s.set_reuse_address(true).map_err(CoreError::Io)?;
                    s.set_nonblocking(true).map_err(CoreError::Io)?;
                    s.bind(&socket2::SockAddr::from(v4_addr))
                        .map_err(CoreError::Io)?;
                    s.listen(1024).map_err(CoreError::Io)?;
                    Ok(s.into())
                }
            }
        }
        SocketAddr::V6(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .map_err(CoreError::Io)?;
            s.set_only_v6(true).map_err(CoreError::Io)?;
            s.set_reuse_address(true).map_err(CoreError::Io)?;
            s.set_nonblocking(true).map_err(CoreError::Io)?;
            s.bind(&socket2::SockAddr::from(addr)).map_err(CoreError::Io)?;
            s.listen(1024).map_err(CoreError::Io)?;
            Ok(s.into())
        }
        SocketAddr::V4(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .map_err(CoreError::Io)?;
            s.set_reuse_address(true).map_err(CoreError::Io)?;
            s.set_nonblocking(true).map_err(CoreError::Io)?;
            s.bind(&socket2::SockAddr::from(addr)).map_err(CoreError::Io)?;
            s.listen(1024).map_err(CoreError::Io)?;
            Ok(s.into())
        }
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
