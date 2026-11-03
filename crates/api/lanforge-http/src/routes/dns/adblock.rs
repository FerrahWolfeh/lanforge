use std::net::{Ipv4Addr, Ipv6Addr};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use lanforge_types::network::dns::adblock::rules_file::RulesFile;
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, TimeOfDay,
};
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
    #[serde(default)]
    pub name: Option<String>,
    pub url: String,
    pub kind: AdblockUrlKind,
    #[serde(default)]
    pub format: Option<AdblockSourceFormat>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockCheckQuery {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockConfigSetRequest {
    pub blocking_mode: Option<BlockingMode>,
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
    pub refresh_time: Option<TimeOfDay>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockUrlDeleteRequest {
    pub url: String,
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockRuleAddRequest {
    pub domain: String,
    pub action: String,
}

/// A pasted list: one rule or bare domain per line; `action` applies to bare domains.
#[derive(Debug, Deserialize)]
pub struct AdblockRulesImportRequest {
    pub text: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockRuleStatusRequest {
    pub enabled: bool,
}

/// A rule addressed by its text (the listing's `domain`): the id is a hash of it, and a 63-bit
/// id does not survive a JavaScript client (JSON numbers are doubles there).
#[derive(Debug, Deserialize)]
pub struct AdblockRuleTextRequest {
    pub rule: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockRuleTextStatusRequest {
    pub rule: String,
    pub enabled: bool,
}

/// A pasted list can be a whole public blocklist (a few MB); the default body limit is 2 MB.
const RULES_IMPORT_MAX_BYTES: usize = 16 * 1024 * 1024;

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
            get(handle_adblock_sources)
                .post(handle_adblock_url_add)
                .delete(handle_adblock_url_remove),
        )
        .route("/adblock/urls", get(handle_adblock_urls))
        .route("/adblock/check", get(handle_adblock_check))
        .route("/adblock/allowlist", get(handle_allowlist))
        .route(
            "/adblock/rules",
            get(handle_adblock_rules)
                .post(handle_adblock_rule_add)
                .delete(handle_adblock_rule_remove_text),
        )
        .route(
            "/adblock/rules/import",
            post(handle_adblock_rules_import).layer(DefaultBodyLimit::max(RULES_IMPORT_MAX_BYTES)),
        )
        .route(
            "/adblock/rules/status",
            put(handle_adblock_rule_status_text),
        )
        .route("/adblock/rules/{id}", delete(handle_adblock_rule_remove))
        .route(
            "/adblock/rules/{id}/status",
            put(handle_adblock_rule_status),
        )
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
            payload.refresh_time,
        )
        .await,
        Success => NoContent
    )
}

async fn handle_adblock_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_reload().await, Success => NoContent)
}

async fn handle_adblock_sources(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_sources().await, DnsAdblockSources)
}

async fn handle_adblock_check(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AdblockCheckQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_check(query.domain).await,
        AdblockCheck
    )
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
        ctx.handle_dns_adblock_url_add(payload.name, payload.url, payload.kind, payload.format).await,
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

async fn handle_adblock_rules_import(
    State(state): State<AppState>,
    Json(payload): Json<AdblockRulesImportRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rules_import(payload.text, payload.action)
            .await,
        DnsAdblockRulesImport
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

async fn handle_adblock_rule_remove_text(
    State(state): State<AppState>,
    Json(payload): Json<AdblockRuleTextRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_remove(RulesFile::rule_id(&payload.rule))
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_status_text(
    State(state): State<AppState>,
    Json(payload): Json<AdblockRuleTextStatusRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_status(RulesFile::rule_id(&payload.rule), payload.enabled)
            .await,
        Success => NoContent
    )
}
