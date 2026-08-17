use std::net::SocketAddr;

use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct UpstreamAddRequest {
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamRemoveRequest {
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/upstreams",
            get(handle_dns_upstreams)
                .post(handle_dns_upstream_add)
                .delete(handle_dns_upstream_remove),
        )
        .route(
            "/reverse-resolvers",
            get(handle_reverse_resolver_list)
                .post(handle_reverse_resolver_add)
                .delete(handle_reverse_resolver_remove),
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
        ctx.handle_dns_upstream_remove(params.addr, params.protocol).await,
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
