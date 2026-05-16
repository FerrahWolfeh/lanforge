pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod system;
pub mod events;
pub mod hosts;

use crate::server::AppState;
use axum::Router;
use lanforge_api_dispatch::ClientContext;

pub fn router() -> Router<AppState> {
    let v1 = Router::new()
        .merge(system::router())
        .nest("/auth", auth::router())
        .nest("/devices", devices::router())
        .nest("/dhcp", dhcp::router())
        .nest("/dns", dns::router())
        .nest("/db", db::router())
        .nest("/events", events::router())
        .nest("/hosts", hosts::router());

    Router::new().nest("/v1", v1)
}

#[must_use]
pub fn create_client_ctx(state: &AppState) -> ClientContext {
    ClientContext {
        current_gua: None,
        uptime_secs: state.start_time.elapsed().as_secs(),
        last_scan_secs_ago: state.ctx.last_scan_secs_ago(),
        ctx: state.ctx.clone(),
        db: state.db.clone(),
        log_db: state.log_db.clone(),
        active_clients: state.ctx.active_clients(),
    }
}
