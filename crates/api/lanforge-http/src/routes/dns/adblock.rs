use std::net::{Ipv4Addr, Ipv6Addr};

use axum::{
    Json, Router,
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use lanforge_types::network::dns::adblock::{AdblockUrlKind, BlockingMode};
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct AdblockSetRequest {
    pub enabled: bool,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockUrlRequest {
    pub url: String,
    pub kind: AdblockUrlKind,
}

#[derive(Debug, Deserialize)]
pub struct AdblockConfigSetRequest {
    pub blocking_mode: Option<BlockingMode>,
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockUrlDeleteRequest {
    pub url: String,
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockRuleAddRequest {
    pub domain: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockRuleStatusRequest {
    pub enabled: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/adblock",
            get(handle_adblock_status).put(handle_adblock_set),
        )
        .route("/adblock/config", post(handle_adblock_config_set))
        .route("/adblock/reload", post(handle_adblock_reload))
        .route(
            "/adblock/sources",
            get(handle_adblock_urls)
                .post(handle_adblock_url_add)
                .delete(handle_adblock_url_remove),
        )
        .route("/adblock/allowlist", get(handle_allowlist))
        .route("/adblock/allow", post(handle_allow))
        .route("/adblock/allow/{target}", delete(handle_unallow))
        .route("/adblock/block", post(handle_block))
        .route(
            "/adblock/rules",
            get(handle_adblock_rules).post(handle_adblock_rule_add),
        )
        .route("/adblock/rules/{id}", delete(handle_adblock_rule_remove))
        .route("/adblock/rules/{id}/status", put(handle_adblock_rule_status))
}

async fn handle_adblock_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_status().await, DnsAdblockStatus)
}

async fn handle_adblock_set(
    State(state): State<AppState>,
    Json(payload): Json<AdblockSetRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_set(payload.enabled, payload.duration_secs).await,
        Success => NoContent
    )
}

async fn handle_adblock_config_set(
    State(state): State<AppState>,
    Json(payload): Json<AdblockConfigSetRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_config_set(
            payload.blocking_mode,
            payload.blocking_ip_v4,
            payload.blocking_ip_v6,
        )
        .await,
        Success => NoContent
    )
}

async fn handle_adblock_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_reload().await, Success => NoContent)
}

async fn handle_adblock_urls(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_url_list().await, DnsAdblockUrls)
}

async fn handle_adblock_url_add(
    State(state): State<AppState>,
    Json(payload): Json<AdblockUrlRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_url_add(payload.url, payload.kind).await,
        Success => NoContent
    )
}

async fn handle_adblock_url_remove(
    State(state): State<AppState>,
    Json(payload): Json<AdblockUrlDeleteRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_url_remove(payload.url).await,
        Success => NoContent
    )
}

async fn handle_allowlist(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_allowlist().await, DnsAllowlist)
}

async fn handle_allow(
    State(state): State<AppState>,
    Json(payload): Json<DomainRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_allow(payload.domain).await, Success => NoContent)
}

async fn handle_unallow(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_unallow(target).await, Success => NoContent)
}

async fn handle_block(
    State(state): State<AppState>,
    Json(payload): Json<DomainRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_block(payload.domain).await, Success => NoContent)
}

async fn handle_adblock_rules(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_rules().await, DnsAdblockRules)
}

async fn handle_adblock_rule_add(
    State(state): State<AppState>,
    Json(payload): Json<AdblockRuleAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_add(payload.domain, payload.action).await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_remove(id).await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_status(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(payload): Json<AdblockRuleStatusRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_status(id, payload.enabled).await,
        Success => NoContent
    )
}
