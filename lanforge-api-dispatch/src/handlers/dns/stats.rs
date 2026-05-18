use crate::ClientContext;
use lanforge_api::api::{
    DnsAnalyticsResponse, DnsStatsResponse, DnsUpstreamsResponse, ProtocolStatEntry,
    QueryRateEntry, QueryTypeEntry, Response, TopClientEntry, TopDomainEntry,
};
use lanforge_types::network::dns::DnsRecordType;
use std::time::{SystemTime, UNIX_EPOCH};

impl ClientContext {
    /// Snapshot of DNS resolver statistics.
    pub async fn handle_dns_stats(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::Stats(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::Stats)
                .await
        {
            return Response::DnsStats(DnsStatsResponse {
                total_requests: res.total_requests,
                cache_hits: res.cache_hits,
                cache_misses: res.cache_misses,
                upstream_errors: res.upstream_errors,
                auth_queries: res.auth_queries,
                recursions: res.recursions,
                blocked_queries: res.blocked_queries,
                resolved_total: res.resolved_total,
                failed_total: res.failed_total,
                cache_entries: res.cache_entries,
                cache_capacity: res.cache_capacity,
            });
        }

        Response::DnsStats(DnsStatsResponse {
            total_requests: 0,
            cache_hits: 0,
            cache_misses: 0,
            upstream_errors: 0,
            auth_queries: 0,
            recursions: 0,
            blocked_queries: 0,
            resolved_total: 0,
            failed_total: 0,
            cache_entries: 0,
            cache_capacity: 0,
        })
    }

    pub async fn handle_dns_upstreams(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::Upstreams(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::Upstreams)
                .await
        {
            return Response::DnsUpstreams(DnsUpstreamsResponse { upstreams: res });
        }

        Response::DnsUpstreams(DnsUpstreamsResponse {
            upstreams: Vec::new(),
        })
    }

    pub async fn handle_dns_analytics(&self, limit: Option<usize>) -> Response {
        let limit = limit.unwrap_or(10);
        let top_domains = self
            .log_db
            .get_dns_top_domains(limit)
            .await
            .unwrap_or_default();
        let query_types = self.log_db.get_dns_query_types().await.unwrap_or_default();
        let query_rate = self
            .log_db
            .get_dns_query_rate(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(600),
            )
            .await
            .unwrap_or_default();
        let top_clients = self
            .log_db
            .get_dns_top_clients(limit)
            .await
            .unwrap_or_default();
        let protocol_stats = self
            .log_db
            .get_dns_protocol_stats()
            .await
            .unwrap_or_default();

        Response::DnsAnalytics(DnsAnalyticsResponse {
            top_domains: top_domains
                .into_iter()
                .map(|(domain, count)| TopDomainEntry { domain, count })
                .collect(),
            query_types: query_types
                .into_iter()
                .map(|(qtype, count)| QueryTypeEntry {
                    qtype: DnsRecordType::from(qtype).to_string(),
                    count,
                })
                .collect(),
            query_rate: query_rate
                .into_iter()
                .map(|(timestamp, count)| QueryRateEntry { timestamp, count })
                .collect(),
            top_clients: top_clients
                .into_iter()
                .map(|(ip, count)| {
                    let hostname = self
                        .ctx
                        .get_mac_by_ip(ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()))
                        .and_then(|m| self.ctx.get_device(&m))
                        .map(|d| d.display_hostname().to_string());
                    TopClientEntry {
                        ip,
                        hostname,
                        count,
                    }
                })
                .collect(),
            protocol_stats: {
                let total: u64 = protocol_stats.iter().map(|(_, c)| *c).sum();
                protocol_stats
                    .into_iter()
                    .map(|(protocol, count)| ProtocolStatEntry {
                        protocol,
                        count,
                        percentage: if total > 0 {
                            (count as f64 / total as f64) as f32 * 100.0
                        } else {
                            0.0
                        },
                    })
                    .collect()
            },
        })
    }
}
