pub mod system;
pub mod auth;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod db;

use axum::Router;
use crate::server::AppState;
use lanforge_api::server::ClientContext;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/system", system::router())
        .nest("/auth", auth::router())
        .nest("/devices", devices::router())
        .nest("/dhcp", dhcp::router())
        .nest("/dns", dns::router())
        .nest("/db", db::router())
}

#[must_use]
pub fn create_client_ctx(state: &AppState) -> ClientContext {
    ClientContext {
        current_gua: None,
        uptime_secs: state.start_time.elapsed().as_secs(),
        last_scan_secs_ago: state.ctx.last_scan_secs_ago(),
        cfg: state.cfg.clone(),
        ctx: state.ctx.clone(),
        db: state.db.clone(),
        log_db: state.log_db.clone(),
        active_clients: Arc::new(AtomicUsize::new(0)),
    }
}
