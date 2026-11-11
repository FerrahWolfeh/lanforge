use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use lanforge_api::api::AdblockGroupChange;
use lanforge_types::identifiers::MacAddr;
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
    /// Check as this client gets it; absent = the global layer.
    #[serde(default)]
    pub client: Option<IpAddr>,
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

/// `?group=<name>`: the rules file (or the lists) of a group instead of the global layer.
#[derive(Debug, Deserialize)]
pub struct AdblockGroupQuery {
    #[serde(default)]
    pub group: Option<String>,
}

/// A group's lists (source names) and clients (`192.168.1.64/28`, `dev:<name|mac>`).
#[derive(Debug, Deserialize)]
pub struct AdblockGroupRequest {
    #[serde(default)]
    pub lists: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockGroupCreateRequest {
    pub name: String,
    #[serde(default)]
    pub lists: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockBypassRequest {
    pub clients: Vec<String>,
}

/// Clients to add to and take out of `bypass`.
#[derive(Debug, Deserialize)]
pub struct AdblockBypassChangeRequest {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Groups for a device to join and leave; `bypass` absent leaves it as it is.
#[derive(Debug, Deserialize)]
pub struct AdblockDeviceChangeRequest {
    #[serde(default)]
    pub join: Vec<String>,
    #[serde(default)]
    pub leave: Vec<String>,
    #[serde(default)]
    pub bypass: Option<bool>,
}

/// The groups a device is in, and whether it is bypassed.
#[derive(Debug, Deserialize)]
pub struct AdblockDeviceRequest {
    pub groups: Vec<String>,
    #[serde(default)]
    pub bypass: bool,
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
        .route(
            "/adblock/groups",
            get(handle_adblock_groups).post(handle_adblock_group_create),
        )
        .route(
            "/adblock/groups/{name}",
            put(handle_adblock_group_update)
                .patch(handle_adblock_group_change)
                .delete(handle_adblock_group_delete),
        )
        .route(
            "/adblock/bypass",
            put(handle_adblock_bypass_set).patch(handle_adblock_bypass_change),
        )
        .route(
            "/adblock/devices/{mac}",
            put(handle_adblock_device_set).patch(handle_adblock_device_change),
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
    Query(query): Query<AdblockCheckQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_check(query.domain, query.client)
            .await,
        AdblockCheck
    )
}

async fn handle_adblock_urls(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_url_list().await, DnsAdblockUrls)
}

async fn handle_adblock_url_add(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockUrlRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_url_add(
            payload.name,
            payload.url,
            payload.kind,
            payload.format,
            query.group
        )
        .await,
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

async fn handle_allowlist(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_allowlist(query.group).await, DnsAllowlist)
}

async fn handle_adblock_rules(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rules(query.group).await,
        DnsAdblockRules
    )
}

async fn handle_adblock_rule_add(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockRuleAddRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_add(payload.domain, payload.action, query.group).await,
        Success => NoContent
    )
}

async fn handle_adblock_rules_import(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockRulesImportRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rules_import(payload.text, payload.action, query.group)
            .await,
        DnsAdblockRulesImport
    )
}

async fn handle_adblock_rule_remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(query): Query<AdblockGroupQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_remove(id, query.group).await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_status(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockRuleStatusRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_status(id, payload.enabled, query.group).await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_remove_text(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockRuleTextRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_remove(RulesFile::rule_id(&payload.rule), query.group)
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_rule_status_text(
    State(state): State<AppState>,
    Query(query): Query<AdblockGroupQuery>,
    Json(payload): Json<AdblockRuleTextStatusRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_rule_status(
            RulesFile::rule_id(&payload.rule),
            payload.enabled,
            query.group
        )
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_groups(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_adblock_groups().await, DnsAdblockGroups)
}

async fn handle_adblock_group_create(
    State(state): State<AppState>,
    Json(payload): Json<AdblockGroupCreateRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_group_create(payload.name, payload.lists, payload.clients)
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_group_update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<AdblockGroupRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_group_update(name, payload.lists, payload.clients)
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_group_change(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<AdblockGroupChange>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_group_change(name, payload).await,
        Success => NoContent
    )
}

async fn handle_adblock_bypass_change(
    State(state): State<AppState>,
    Json(payload): Json<AdblockBypassChangeRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_bypass_change(payload.add, payload.remove).await,
        Success => NoContent
    )
}

async fn handle_adblock_device_change(
    State(state): State<AppState>,
    Path(mac): Path<MacAddr>,
    Json(payload): Json<AdblockDeviceChangeRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_device_change(mac, payload.join, payload.leave, payload.bypass)
            .await,
        Success => NoContent
    )
}

async fn handle_adblock_group_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_group_delete(name).await,
        Success => NoContent
    )
}

async fn handle_adblock_bypass_set(
    State(state): State<AppState>,
    Json(payload): Json<AdblockBypassRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_bypass_set(payload.clients).await,
        Success => NoContent
    )
}

async fn handle_adblock_device_set(
    State(state): State<AppState>,
    Path(mac): Path<MacAddr>,
    Json(payload): Json<AdblockDeviceRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_adblock_device_set(mac, payload.groups, payload.bypass)
            .await,
        Success => NoContent
    )
}
