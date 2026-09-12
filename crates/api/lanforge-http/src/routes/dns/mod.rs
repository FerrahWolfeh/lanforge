pub mod adblock;
pub mod cache;
pub mod rewrites;
pub mod upstreams;

use std::convert::Infallible;

use axum::{
    Router,
    extract::{Query, State},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
    routing::get,
};
use futures::stream::Stream;
use lanforge_api::api::LogMeta;
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_types::network::DnsRecordType;
use serde::Deserialize;

use crate::routes::create_client_ctx;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub limit: Option<usize>,
    pub client: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsQueryRequest {
    pub name: String,
    #[serde(default, alias = "type", alias = "qtype")]
    pub record_type: Option<DnsRecordType>,
}

#[derive(Debug, Deserialize)]
pub struct DnsLogQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub client: Option<String>,
    #[serde(default)]
    pub follow: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/stats", get(handle_dns_stats))
        .route("/analytics", get(handle_dns_analytics))
        .route("/query", get(handle_dns_query))
        .route("/logs", get(handle_dns_logs))
        .merge(adblock::router())
        .merge(cache::router())
        .merge(rewrites::router())
        .merge(upstreams::router())
}

async fn handle_dns_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(ctx.handle_dns_stats().await, DnsStats)
}

async fn handle_dns_analytics(
    State(state): State<AppState>,
    Query(params): Query<AnalyticsQuery>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        ctx.handle_dns_analytics(params.limit, params.client).await,
        DnsAnalytics
    )
}

async fn handle_dns_query(
    State(state): State<AppState>,
    Query(params): Query<DnsQueryRequest>,
) -> impl IntoResponse {
    let ctx = create_client_ctx(&state);
    crate::http_response!(
        Box::pin(ctx.handle_dns_query(params.name, params.record_type)).await,
        DnsQuery
    )
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
        crate::http_response!(
            ctx.handle_dns_query_log(params.limit, params.client, false, params.offset)
                .await,
            DnsQueryLog,
            res => res.entries, LogMeta {
                total: res.total,
                limit: params.limit.unwrap_or(100),
                offset: params.offset.unwrap_or(0),
            }
        )
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
            if let LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) = &event.event {
                let src_hostname = ctx_inner
                    .get_mac_by_ip(entry.src_ip)
                    .and_then(|m| ctx_inner.get_device(&m))
                    .map(|d| d.display_hostname().to_string());

                if let Some(f) = &filter
                    && &entry.src_ip.to_string() != f
                    && src_hostname.as_deref() != Some(f.as_str())
                {
                    continue;
                }

                if let Ok(json) = serde_json::to_string(&event) {
                    yield Event::default().data(json);
                }
            }
        }
    }
}
