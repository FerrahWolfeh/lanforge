use crate::routes::create_client_ctx;
use crate::server::AppState;
use axum::{
    Json as AxumJson, Router,
    extract::{Query, State},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::{get, post},
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
}

#[derive(Debug, Deserialize)]
pub struct RewriteRequest {
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: String,
}

#[derive(Debug, Deserialize)]
pub struct RewriteDeleteRequest {
    pub id: i64,
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
        .route("/cache", get(handle_dns_cache_dump))
        .route("/cache/flush", post(handle_dns_cache_flush))
        .route("/logs", get(handle_dns_logs))
        .route("/adblock/status", get(handle_adblock_status))
        .route("/adblock/set", post(handle_adblock_set))
        .route("/adblock/reload", post(handle_adblock_reload))
        .route(
            "/adblock/urls",
            get(handle_adblock_urls)
                .post(handle_adblock_url_add)
                .delete(handle_adblock_url_remove),
        )
        .route(
            "/rewrites",
            get(handle_rewrites)
                .post(handle_rewrite_add)
                .delete(handle_rewrite_remove),
        )
        .route(
            "/allowlist",
            get(handle_allowlist)
                .post(handle_allow)
                .delete(handle_unallow),
        )
        .route("/blocklist", post(handle_block))
}

async fn handle_dns_stats(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_stats().await)
}

async fn handle_dns_analytics(
    State(state): State<AppState>,
    Query(params): Query<AnalyticsQuery>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_analytics(params.limit).await)
}

async fn handle_dns_upstreams(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_upstreams().await)
}

async fn handle_dns_query(
    State(state): State<AppState>,
    Query(params): Query<DnsQueryRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(Box::pin(ctx.handle_dns_query(params.name, params.record_type)).await)
}

async fn handle_dns_cache_dump(
    State(state): State<AppState>,
    Query(params): Query<CacheQuery>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_cache_dump(params.limit, params.offset).await)
}

async fn handle_dns_cache_flush(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_cache_flush().await)
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
        AxumJson(
            ctx.handle_dns_query_log(params.limit, params.client, false, params.offset)
                .await,
        )
        .into_response()
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
                 // Resolve hostname for filtering if needed
                 let src_hostname = ctx_inner
                    .get_mac_by_ip(entry.src_ip)
                    .and_then(|m| ctx_inner.get_device(&m))
                    .map(|d| d.display_hostname().to_string());

                // Check filter
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

async fn handle_adblock_status(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_adblock_status().await)
}

async fn handle_adblock_set(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<AdblockSetRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(
        ctx.handle_dns_adblock_set(payload.enabled, payload.duration_secs)
            .await,
    )
}

async fn handle_adblock_reload(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_adblock_reload().await)
}

async fn handle_adblock_urls(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_adblock_url_list().await)
}

async fn handle_adblock_url_add(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<AdblockUrlRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(
        ctx.handle_dns_adblock_url_add(payload.url, payload.kind)
            .await,
    )
}

async fn handle_adblock_url_remove(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<AdblockUrlDeleteRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_adblock_url_remove(payload.url).await)
}

async fn handle_rewrites(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_rewrites().await)
}

async fn handle_rewrite_add(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<RewriteRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(
        ctx.handle_dns_rewrite_add(RewriteRule {
            id: None,
            domain: payload.domain,
            rtype: payload.rtype,
            answer: payload.answer,
        })
        .await,
    )
}

async fn handle_rewrite_remove(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<RewriteDeleteRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_rewrite_remove(payload.id).await)
}

async fn handle_allowlist(State(state): State<AppState>) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_allowlist().await)
}

async fn handle_allow(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<DomainRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_allow(payload.domain).await)
}

async fn handle_unallow(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<DomainRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_unallow(payload.domain).await)
}

async fn handle_block(
    State(state): State<AppState>,
    AxumJson(payload): AxumJson<DomainRequest>,
) -> AxumJson<Response> {
    let ctx = create_client_ctx(&state);
    AxumJson(ctx.handle_dns_block(payload.domain).await)
}
