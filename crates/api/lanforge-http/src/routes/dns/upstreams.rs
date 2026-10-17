use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::{delete, get},
};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamProtocol};
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

fn deserialize_flexible_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let trimmed = s.trim();
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inside = &trimmed[1..trimmed.len() - 1];
        if let Ok(ip) = inside.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, 53));
        }
    }
    trimmed.parse::<SocketAddr>().map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct UpstreamAddRequest {
    #[serde(deserialize_with = "deserialize_flexible_socket_addr")]
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamRemoveRequest {
    #[serde(deserialize_with = "deserialize_flexible_socket_addr")]
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReverseResolverAddRequest {
    pub subnet: String,
    pub resolver_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ReverseResolverRemoveRequest {
    pub subnet: String,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamModeRequest {
    pub mode: UpstreamMode,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/upstreams",
            get(handle_dns_upstreams)
                .post(handle_dns_upstream_add)
                .delete(handle_dns_upstream_remove),
        )
        .route("/upstreams/clear", delete(handle_dns_upstream_clear))
        .route(
            "/upstreams/mode",
            get(handle_dns_upstream_mode_get)
                .put(handle_dns_upstream_mode_set)
                .post(handle_dns_upstream_mode_set),
        )
        .route(
            "/reverse-resolvers",
            get(handle_reverse_resolver_list)
                .post(handle_reverse_resolver_add)
                .delete(handle_reverse_resolver_remove),
        )
}

async fn handle_dns_upstream_mode_get(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_upstream_mode_get().await, DnsUpstreamMode)
}

async fn handle_dns_upstream_mode_set(
    State(state): State<AppState>,
    Json(payload): Json<UpstreamModeRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_mode_set(payload.mode).await,
        DnsUpstreamMode
    )
}

async fn handle_dns_upstreams(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_upstreams().await, DnsUpstreams)
}

async fn handle_dns_upstream_add(
    State(state): State<AppState>,
    Query(params): Query<UpstreamAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_add(params.addr, params.protocol, params.domain).await,
        Success => NoContent
    )
}

async fn handle_dns_upstream_remove(
    State(state): State<AppState>,
    Query(params): Query<UpstreamRemoveRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_remove(params.addr, params.protocol, params.domain).await,
        Success => NoContent
    )
}

async fn handle_dns_upstream_clear(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_upstream_clear().await,
        Success => NoContent
    )
}

async fn handle_reverse_resolver_list(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_list().await,
        DnsReverseResolvers
    )
}

async fn handle_reverse_resolver_add(
    State(state): State<AppState>,
    Query(params): Query<ReverseResolverAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_add(params.subnet, params.resolver_uri).await,
        Success => NoContent
    )
}

async fn handle_reverse_resolver_remove(
    State(state): State<AppState>,
    Query(params): Query<ReverseResolverRemoveRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_reverse_resolver_remove(params.subnet).await,
        Success => NoContent
    )
}
