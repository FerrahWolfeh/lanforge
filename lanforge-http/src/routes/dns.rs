use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::{delete, get, post},
};
use futures::stream::Stream;
use lanforge_api::api::Response;
use lanforge_core::bus::LanforgeEvent;
use lanforge_types::network::{DnsRecordType, dns::adblock::RewriteRule};
use serde::Deserialize;
use std::convert::Infallible;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DnsQueryRequest {
    pub name: String,
    pub record_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsLogQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub client: Option<String>,
    #[serde(default)]
    pub follow: bool,
}

#[derive(Debug, Deserialize)]
pub struct CacheQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockSetRequest {
    pub enabled: bool,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AdblockUrlRequest {
    pub url: String,
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct AdblockUrlDeleteRequest {
    pub url: String,
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RewriteRequest {
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: String,
}

#[derive(Debug, Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/stats", get(handle_dns_stats))
        .route("/analytics", get(handle_dns_analytics))
        .route("/upstreams", get(handle_dns_upstreams))
        .route("/query", get(handle_dns_query))
        .route(
            "/cache",
            get(handle_dns_cache_dump).delete(handle_dns_cache_flush),
        )
        .route("/cache/stats", get(handle_dns_cache_stats))
        .route("/logs", get(handle_dns_logs))
        .route(
            "/adblock",
            get(handle_adblock_status).put(handle_adblock_set),
        )
        .route("/adblock/reload", post(handle_adblock_reload))
        .route(
            "/adblock/sources",
            get(handle_adblock_urls)
                .post(handle_adblock_url_add)
                .delete(handle_adblock_url_remove),
        )
        .route(
            "/rewrites",
            get(handle_rewrites)
                .post(handle_rewrite_add)
                .delete(handle_rewrite_clear),
        )
        .route("/rewrites/{id}", delete(handle_rewrite_remove))
        .route("/rewrites/export", get(handle_rewrite_export))
        .route("/rewrites/import", post(handle_rewrite_import))
        .route("/adblock/allowlist", get(handle_allowlist))
        .route("/adblock/allow", post(handle_allow))
        .route("/adblock/allow/{target}", delete(handle_unallow))
        .route("/adblock/block", post(handle_block))
}

async fn handle_dns_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_stats().await {
        Response::DnsStats(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_analytics(
    State(state): State<AppState>,
    Query(params): Query<AnalyticsQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_analytics(params.limit).await {
        Response::DnsAnalytics(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_upstreams(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_upstreams().await {
        Response::DnsUpstreams(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_query(
    State(state): State<AppState>,
    Query(params): Query<DnsQueryRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match Box::pin(ctx.handle_dns_query(params.name, params.record_type)).await {
        Response::DnsQuery(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_cache_dump(
    State(state): State<AppState>,
    Query(params): Query<CacheQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_cache_dump(params.limit, params.offset).await {
        Response::DnsCache(res) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "data": res.entries,
                "meta": {
                    "total": res.total,
                    "limit": params.limit.unwrap_or(50),
                    "offset": params.offset.unwrap_or(0),
                }
            })),
        )
            .into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_cache_flush(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_cache_flush().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_cache_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_cache_stats_ext().await {
        Response::DnsCacheStatsExt(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_dns_logs(
    State(state): State<AppState>,
    Query(params): Query<DnsLogQuery>,
) -> impl IntoResponse {
    if params.follow {
        let stream = handle_dns_logs_follow(state, params);
        Sse::new(stream).into_response()
    } else {
        let ctx = create_client_ctx(&state);
        match ctx
            .handle_dns_query_log(params.limit, params.client, false, params.offset)
            .await
        {
            Response::DnsQueryLog(res) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": res.entries,
                    "meta": {
                        "total": res.total,
                        "limit": params.limit.unwrap_or(100),
                        "offset": params.offset.unwrap_or(0),
                    }
                })),
            )
                .into_response(),
            Response::Error { error } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Invalid response type" })),
            )
                .into_response(),
        }
    }
}

fn handle_dns_logs_follow(
    state: AppState,
    params: DnsLogQuery,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let mut rx = state.ctx.bus().subscribe();
    let filter = params.client;
    let ctx_inner = state.ctx;

    async_stream::try_stream! {
        while let Ok(event) = rx.recv().await {
            if let LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::QueryResolved(entry)) = &event.event {
                 let src_hostname = ctx_inner
                    .get_mac_by_ip(entry.src_ip)
                    .and_then(|m| ctx_inner.get_device(&m))
                    .map(|d| d.display_hostname().to_string());

                if let Some(f) = &filter
                    && &entry.src_ip.to_string() != f && src_hostname.as_ref() != Some(f) {
                        continue;
                    }

                let json = serde_json::to_string(&Response::Event(event)).unwrap();
                yield Event::default().data(json);
            }
        }
    }
}

async fn handle_adblock_status(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_adblock_status().await {
        Response::DnsAdblockStatus(res) => {
            (StatusCode::OK, Json(serde_json::json!({ "data": res }))).into_response()
        }
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_adblock_set(
    State(state): State<AppState>,
    Json(payload): Json<AdblockSetRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx
        .handle_dns_adblock_set(payload.enabled, payload.duration_secs)
        .await
    {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_adblock_reload(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_adblock_reload().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_adblock_urls(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_adblock_url_list().await {
        Response::DnsAdblockUrls(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.urls })),
        )
            .into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_adblock_url_add(
    State(state): State<AppState>,
    Json(payload): Json<AdblockUrlRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx
        .handle_dns_adblock_url_add(payload.url, payload.kind)
        .await
    {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_adblock_url_remove(
    State(state): State<AppState>,
    Json(payload): Json<AdblockUrlDeleteRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_adblock_url_remove(payload.url).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrites(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_rewrites().await {
        Response::DnsRewrites(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.rewrites })),
        )
            .into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrite_add(
    State(state): State<AppState>,
    Json(payload): Json<RewriteRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx
        .handle_dns_rewrite_add(RewriteRule {
            id: None,
            domain: payload.domain,
            rtype: payload.rtype,
            answer: payload.answer,
        })
        .await
    {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrite_remove(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_rewrite_remove(id).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrite_clear(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_rewrite_clear().await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrite_export(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_rewrite_export().await {
        Response::DnsRewrites(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.rewrites })),
        )
            .into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_rewrite_import(
    State(state): State<AppState>,
    Json(rules): Json<Vec<RewriteRule>>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_rewrite_import(rules).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_allowlist(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_allowlist().await {
        Response::DnsAllowlist(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "data": res.allowlist })),
        )
            .into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_allow(
    State(state): State<AppState>,
    Json(payload): Json<DomainRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_allow(payload.domain).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_unallow(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_unallow(target).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}

async fn handle_block(
    State(state): State<AppState>,
    Json(payload): Json<DomainRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    match ctx.handle_dns_block(payload.domain).await {
        Response::Success(_) => StatusCode::NO_CONTENT.into_response(),
        Response::Error { error } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Invalid response type" })),
        )
            .into_response(),
    }
}
