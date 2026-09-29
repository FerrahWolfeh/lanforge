use crate::ClientContext;
use lanforge_api::api::{
    DnsAnalyticsResponse, DnsStatsResponse, DnsUpstreamsResponse, ProtocolStatEntry,
    QueryRateEntry, QueryTypeEntry, Response, SimpleSuccess, TopClientEntry, TopDomainEntry,
};
use lanforge_types::network::dns::{
    DnsRecordType, DnsRequest, DnsResponse, UpstreamStatus,
    upstream::UpstreamProtocol,
};
use std::{collections::HashMap, net::IpAddr};

impl ClientContext {
    /// Snapshot of DNS resolver statistics.
    pub async fn handle_dns_stats(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(DnsResponse::Stats(res)) = handle.send_request(DnsRequest::Stats).await
        {
            return Response::DnsStats(Box::new(DnsStatsResponse {
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
                cache_evictions: res.cache_evictions,
            }));
        }

        Response::DnsStats(Box::new(DnsStatsResponse {
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
            cache_evictions: 0,
        }))
    }

    pub async fn handle_dns_upstreams(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(DnsResponse::Upstreams(res)) =
                handle.send_request(DnsRequest::Upstreams).await
            && !res.is_empty()
        {
            return Response::DnsUpstreams(DnsUpstreamsResponse { upstreams: res });
        }

        let configured = self.ctx.get_dns_upstreams();
        if !configured.is_empty() {
            let mapped: Vec<lanforge_types::network::dns::UpstreamHealthSnapshot> = configured
                .into_iter()
                .map(|r| lanforge_types::network::dns::UpstreamHealthSnapshot {
                    target: r.addr,
                    protocol: r.protocol,
                    rtt_ewma_us: 1200,
                    last_rtt_us: 1200,
                    total_queries: 0,
                    total_successes: 0,
                    total_failures: 0,
                    status: UpstreamStatus::Healthy,
                    last_success_secs_ago: Some(0),
                    domain: r.domain,
                })
                .collect();
            return Response::DnsUpstreams(DnsUpstreamsResponse { upstreams: mapped });
        }

        Response::DnsUpstreams(DnsUpstreamsResponse {
            upstreams: Vec::new(),
        })
    }

    pub async fn handle_dns_upstream_add(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::AddDnsUpstream {
                addr,
                protocol,
                domain,
            })
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: "Upstream added successfully".into(),
            }),
            Err(e) => Response::Error {
                error: format!("Failed to add upstream: {e}"),
            },
        }
    }

    pub async fn handle_dns_upstream_remove(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::RemoveDnsUpstream {
                addr,
                protocol,
                domain,
            })
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: "Upstream removed successfully".into(),
            }),
            Err(e) => Response::Error {
                error: format!("Failed to remove upstream: {e}"),
            },
        }
    }

    pub async fn handle_dns_upstream_clear(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        match storage
            .send_query(lanforge_types::storage::StorageQuery::ClearDnsUpstreams)
            .await
        {
            Ok(_) => Response::Success(SimpleSuccess {
                message: "All upstreams cleared successfully".into(),
            }),
            Err(e) => Response::Error {
                error: format!("Failed to clear upstreams: {e}"),
            },
        }
    }

    pub async fn handle_dns_analytics(
        &self,
        limit: Option<usize>,
        client: Option<String>,
    ) -> Response {
        let limit = limit.unwrap_or(10);
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };

        let data = match storage
            .send_query(lanforge_types::storage::StorageQuery::GetDnsAnalytics { limit, client })
            .await
        {
            Ok(lanforge_types::storage::StorageQueryResult::DnsAnalytics(data)) => data,
            Ok(_) => {
                return Response::Error {
                    error: "Unexpected storage query result for DNS analytics".into(),
                };
            }
            Err(e) => {
                return Response::Error {
                    error: format!("Failed to retrieve DNS analytics: {e}"),
                };
            }
        };

        let client_hostnames: HashMap<IpAddr, Option<String>> = self.ctx.with_state(|state| {
            let mut map = HashMap::new();
            for ip_str in data
                .top_clients
                .iter()
                .map(|(ip, _, _)| ip)
                .chain(data.top_blocked_clients.iter().map(|(ip, _)| ip))
            {
                if let Ok(parsed_ip) = ip_str.parse::<IpAddr>()
                    && let std::collections::hash_map::Entry::Vacant(e) = map.entry(parsed_ip)
                {
                    let hostname = super::resolve_ip_identity(state, parsed_ip).1;
                    e.insert(hostname);
                }
            }
            map
        });

        Response::DnsAnalytics(Box::new(DnsAnalyticsResponse {
            top_domains: data
                .top_domains
                .into_iter()
                .map(|(domain, count)| TopDomainEntry { domain, count })
                .collect(),
            query_types: data
                .query_types
                .into_iter()
                .map(|(qtype, count)| QueryTypeEntry {
                    qtype: DnsRecordType::from(qtype).to_string(),
                    count,
                })
                .collect(),
            query_rate: data
                .detailed_rates
                .into_iter()
                .map(|b| QueryRateEntry {
                    timestamp: b.timestamp,
                    count: b.total,
                    cached: b.cached,
                    forwarded: b.forwarded,
                    blocked: b.blocked,
                    local: b.local,
                    rewritten: b.rewritten,
                    record_types: b.record_types,
                    outcome_types: b.outcome_types,
                })
                .collect(),
            top_clients: data
                .top_clients
                .into_iter()
                .map(|(ip, count, blocked_count)| {
                    let hostname = ip
                        .parse::<IpAddr>()
                        .ok()
                        .and_then(|addr| client_hostnames.get(&addr).cloned().flatten());
                    TopClientEntry {
                        ip,
                        hostname,
                        count,
                        blocked_count,
                    }
                })
                .collect(),
            protocol_stats: {
                let total: u64 = data.protocol_stats.iter().map(|(_, c)| *c).sum();
                data.protocol_stats
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
            top_blocked_domains: data
                .top_blocked_domains
                .into_iter()
                .map(|(domain, count)| TopDomainEntry { domain, count })
                .collect(),
            top_blocked_clients: data
                .top_blocked_clients
                .into_iter()
                .map(|(ip, count)| {
                    let hostname = ip
                        .parse::<IpAddr>()
                        .ok()
                        .and_then(|addr| client_hostnames.get(&addr).cloned().flatten());
                    TopClientEntry {
                        ip,
                        hostname,
                        count,
                        blocked_count: count,
                    }
                })
                .collect(),
            blocked_query_rate: data
                .blocked_query_rate
                .into_iter()
                .map(|(timestamp, count)| QueryRateEntry {
                    timestamp,
                    count,
                    cached: 0,
                    forwarded: 0,
                    blocked: count,
                    ..Default::default()
                })
                .collect(),
        }))
    }
}
