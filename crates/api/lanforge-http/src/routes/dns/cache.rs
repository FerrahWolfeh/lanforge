use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use lanforge_api::api::CacheMeta;
use lanforge_types::network::DnsRecordType;
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CacheQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub q: Option<String>,
    pub kind: Option<DnsRecordType>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/cache",
            get(handle_dns_cache_dump).delete(handle_dns_cache_flush),
        )
        .route("/cache/stats", get(handle_dns_cache_stats))
}

async fn handle_dns_cache_dump(
    State(state): State<AppState>,
    Query(params): Query<CacheQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_cache_dump(params.limit, params.offset, params.q, params.kind).await,
        DnsCache,
        res => res.entries, CacheMeta {
            total: res.total,
            limit: params.limit.unwrap_or(50),
            offset: params.offset.unwrap_or(0),
        }
    )
}

async fn handle_dns_cache_flush(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_cache_flush().await, Success => NoContent)
}

async fn handle_dns_cache_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_cache_stats_ext().await, DnsCacheStatsExt)
}
