use super::rewrite::dns_reply;
use crate::ClientContext;
use lanforge_api::api::{
    DnsAnalyticsResponse, DnsStatsResponse, DnsUpstreamModeResponse, DnsUpstreamsResponse,
    ProtocolStatEntry, QueryRateEntry, QueryTypeEntry, Response, TopClientEntry, TopDomainEntry,
};
use lanforge_api::config_file::NamedUpstream;
use lanforge_types::network::dns::{
    DnsRecordType, DnsRequest, DnsResponse, UpstreamStatus,
    upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget},
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
        // The serving instance's view is the truth, even when empty.
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(DnsResponse::Upstreams(res)) =
                handle.send_request(DnsRequest::Upstreams).await
        {
            return Response::DnsUpstreams(DnsUpstreamsResponse { upstreams: res });
        }

        // DNS is not serving: the configured upstreams, unmeasured.
        let upstreams = self
            .ctx
            .get_dns_upstreams()
            .into_iter()
            .map(|r| lanforge_types::network::dns::UpstreamHealthSnapshot {
                target: r.addr,
                protocol: r.protocol,
                rtt_ewma_us: 0,
                last_rtt_us: 0,
                total_queries: 0,
                total_successes: 0,
                total_failures: 0,
                total_wins: 0,
                status: UpstreamStatus::Unknown,
                last_success_secs_ago: None,
                domain: r.domain,
            })
            .collect();
        Response::DnsUpstreams(DnsUpstreamsResponse { upstreams })
    }

    pub async fn handle_dns_upstream_add(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Response {
        dns_reply(
            self.change_dns(|dns| {
                let known = dns.upstreams.iter().any(|u| {
                    u.target.addr == addr
                        && u.target.protocol == protocol
                        && u.target.domain == domain
                });
                if !known {
                    dns.upstreams.push(NamedUpstream {
                        name: domain.clone().unwrap_or_else(|| "default".to_string()),
                        target: UpstreamTarget {
                            addr,
                            protocol,
                            hostname: None,
                            domain,
                        },
                    });
                }
            }),
            "Upstream added successfully".into(),
        )
    }

    pub async fn handle_dns_upstream_remove(
        &self,
        addr: std::net::SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    ) -> Response {
        let matches =
            |t: &UpstreamTarget| t.addr == addr && t.protocol == protocol && t.domain == domain;
        if !self.ctx.get_dns_upstreams().iter().any(matches) {
            return Response::Error {
                error: "Upstream not found".into(),
            };
        }
        dns_reply(
            self.change_dns(|dns| dns.upstreams.retain(|u| !matches(&u.target))),
            "Upstream removed successfully".into(),
        )
    }

    /// Replaces the default upstreams (those without a `domain`) with plain-DNS `addrs` in one
    /// change; conditional upstreams stay. An empty list is refused: a resolver without upstreams
    /// (local names only) is set in the configuration file.
    pub async fn handle_dns_upstream_set_default(
        &self,
        addrs: Vec<std::net::SocketAddr>,
    ) -> Response {
        if addrs.is_empty() {
            return Response::Rejected {
                error: "At least one upstream is required; a resolver without upstreams \
                        (local names only) is set in the configuration file"
                    .into(),
            };
        }
        dns_reply(
            self.change_dns(|dns| {
                dns.upstreams.retain(|u| u.target.domain.is_some());
                dns.upstreams
                    .extend(addrs.iter().map(|&addr| NamedUpstream {
                        name: "default".to_string(),
                        target: UpstreamTarget {
                            addr,
                            protocol: UpstreamProtocol::Udp,
                            hostname: None,
                            domain: None,
                        },
                    }));
            }),
            "Default upstreams replaced successfully".into(),
        )
    }

    pub async fn handle_dns_upstream_mode_get(&self) -> Response {
        let mode = self.ctx.get_dns_upstream_mode();
        Response::DnsUpstreamMode(DnsUpstreamModeResponse { mode })
    }

    pub async fn handle_dns_upstream_mode_set(&self, mode: UpstreamMode) -> Response {
        match self.change_dns(|dns| dns.upstream_mode = mode) {
            Ok(_) => Response::DnsUpstreamMode(DnsUpstreamModeResponse { mode }),
            Err(e) => e.into(),
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

        let client_clone = client.clone();
        let data = match storage
            .call(move |s: &lanforge_db_core::Stores| {
                s.log().get_dns_analytics(limit, client_clone.as_deref())
            })
            .await
        {
            Ok(data) => data,
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
