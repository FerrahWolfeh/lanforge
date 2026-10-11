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
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::stream::Stream;
use lanforge_api::api::LogMeta;
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_types::network::{DnsRecordType, QueryResult};
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
    pub domain: Option<String>,
    #[serde(default, alias = "type", alias = "qtype")]
    pub qtype: Option<DnsRecordType>,
    pub result: Option<QueryResult>,
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
        Sse::new(stream)
            .keep_alive(
                KeepAlive::default()
                    .interval(std::time::Duration::from_secs(15))
                    .text("keepalive"),
            )
            .into_response()
    } else {
        let ctx = create_client_ctx(&state);
        crate::http_response!(
            ctx.handle_dns_query_log(
                params.limit,
                params.client,
                params.domain,
                params.qtype,
                params.result,
                false,
                params.offset
            )
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
    let mut rx = state.ctx.bus().subscribe_dns();
    let filter = params.client;
    let filter_ip: Option<std::net::IpAddr> = filter.as_deref().and_then(|f| f.parse().ok());
    let domain_filter = params.domain.map(|d| d.to_lowercase());
    let qtype_filter = params.qtype;
    let result_filter = params.result;
    let ctx_inner = state.ctx;

    async_stream::try_stream! {
        loop {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if let LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) = &event.event {
                let (mac, src_hostname) = ctx_inner.with_state(|s| {
                    let mac = entry.src_mac.or_else(|| s.get_mac_by_ip(entry.src_ip));
                    let hostname = mac.and_then(|m| {
                        if let Some(d) = s.devices.get(&m) {
                            let name = d.display_hostname();
                            if name != "?" && !name.is_empty() {
                                return Some(name.to_string());
                            }
                            if !d.dns_fallback.is_empty() {
                                return Some(d.dns_fallback.clone());
                            }
                        }
                        s.static_entries
                            .get(&m)
                            .filter(|e| !e.hostname.is_empty())
                            .map(|e| e.hostname.clone())
                    });
                    (mac, hostname)
                });

                if let Some(f) = &filter {
                    let f_lower = f.to_lowercase();
                    let ip_matches = filter_ip.is_some_and(|target_ip| entry.src_ip == target_ip)
                        || entry.src_ip.to_string().contains(f);
                    let mac_matches = mac.is_some_and(|m| m.to_string().to_lowercase().contains(&f_lower));
                    let host_matches = src_hostname.as_deref().is_some_and(|h| h.to_lowercase().contains(&f_lower));
                    if !ip_matches && !mac_matches && !host_matches {
                        continue;
                    }
                }

                if let Some(df) = &domain_filter
                    && !entry.domain.to_lowercase().contains(df)
                {
                    continue;
                }

                if let Some(qt) = qtype_filter
                    && entry.qtype != qt
                {
                    continue;
                }

                if let Some(rf) = result_filter
                    && entry.result != rf
                {
                    continue;
                }

                let src_ip_str = entry.src_ip.to_string();
                let src_mac_str = mac.map(|m| m.to_string());

                let payload = serde_json::json!({
                    "timestamp": entry.timestamp,
                    "src_ip": &src_ip_str,
                    "src_mac": &src_mac_str,
                    "src_hostname": &src_hostname,
                    "domain": entry.domain.as_ref(),
                    "qtype": entry.qtype,
                    "result": entry.result,
                    "upstream_us": entry.upstream_us,
                    "cached": entry.cached,
                    "answer": entry.answer,
                    "protocol": entry.protocol,
                    "filter": entry.filter,
                    "event": {
                        "Dns": {
                            "QueryResolved": {
                                "timestamp": entry.timestamp,
                                "src_ip": &src_ip_str,
                                "src_mac": &src_mac_str,
                                "src_hostname": &src_hostname,
                                "domain": entry.domain.as_ref(),
                                "qtype": entry.qtype,
                                "result": entry.result,
                                "upstream_us": entry.upstream_us,
                                "cached": entry.cached,
                                "answer": entry.answer,
                                "filter": entry.filter,
                            }
                        }
                    }
                });

                if let Ok(json) = serde_json::to_string(&payload) {
                    yield Event::default().data(json);
                }
            }
        }
    }
}
