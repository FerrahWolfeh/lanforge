#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
use crate::api::{
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheEntry, DnsCacheResponse, DnsQueryResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, ProtocolStatEntry, QueryRateEntry,
    QueryTypeEntry, Response, SimpleSuccess, TopClientEntry, TopDomainEntry,
};

#[cfg(feature = "adblock")]
use crate::api::{AdblockUrlEntry, DnsAdblockStatusResponse, DnsAdblockUrlsResponse};

use crate::server::ClientContext;
use lanforge_core::types::{DnsEvent, DnsRecordEntry, DnsRecordType, LanforgeEvent};
use lanforge_dns::server::DnsContext;
use lanforge_dns::telemetry::DnsStats;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "adblock")]
use lanforge_core::config::AdblockUrlKind;

#[cfg(feature = "adblock")]
use tracing::error;

impl ClientContext {
    /// Snapshot of DNS resolver statistics.
    pub async fn handle_dns_stats(&self) -> Response {
        if let Some(stats_any) = self.ctx.get_dns_stats()
            && let Some(stats) = stats_any.downcast_ref::<DnsStats>()
        {
            return Response::DnsStats(DnsStatsResponse {
                total_requests: stats.requests_total.load(Ordering::Relaxed),
                cache_hits: stats.cache_hits.load(Ordering::Relaxed),
                cache_misses: stats.cache_misses.load(Ordering::Relaxed),
                upstream_errors: stats.upstream_errors.load(Ordering::Relaxed),
                auth_queries: stats.auth_queries.load(Ordering::Relaxed),
                recursions: stats.recursions.load(Ordering::Relaxed),
                #[cfg(feature = "adblock")]
                blocked_queries: stats.blocked_queries.load(Ordering::Relaxed),
                #[cfg(not(feature = "adblock"))]
                blocked_queries: 0,
                resolved_total: stats.resolved_total.load(Ordering::Relaxed),
                failed_total: stats.failed_total.load(Ordering::Relaxed),
                cache_entries: stats.cache_entries.load(Ordering::Relaxed),
                cache_capacity: stats.cache_capacity.load(Ordering::Relaxed),
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
        if let Some(dns_ctx_any) = self.ctx.get_dns_context()
            && let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>()
        {
            return Response::DnsUpstreams(DnsUpstreamsResponse {
                upstreams: dns_ctx.recursive.snapshots(),
            });
        }

        Response::DnsUpstreams(DnsUpstreamsResponse {
            upstreams: Vec::new(),
        })
    }

    /// Toggles the DNS adblocker.
    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Response {
        if duration_secs.is_none() {
            // Persistent change
            let val = if enabled { "true" } else { "false" };
            if let Err(e) = self.db.set_adblock_config_value("enabled", val).await {
                error!("❌ API: Failed to persist adblock enabled status: {e}");
            }
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
        }

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                enabled,
                duration_secs,
            }));

        Response::Success(SimpleSuccess {
            message: if enabled {
                "DNS Adblock enabled".to_string()
            } else if let Some(d) = duration_secs {
                format!("DNS Adblock disabled for {d} seconds")
            } else {
                "DNS Adblock disabled permanently in database".to_string()
            },
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_set(
        &self,
        _enabled: bool,
        _duration_secs: Option<u64>,
    ) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::AdblockReload));
        Response::Success(SimpleSuccess {
            message: "Adblock reload triggered".to_string(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_reload(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        let Some(dns_ctx_any) = self.ctx.get_dns_context() else {
            return Response::Error {
                error: "DNS service not initialized".into(),
            };
        };
        let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>() else {
            return Response::Error {
                error: "Invalid DNS context".into(),
            };
        };
        let Some(adblocker) = &dns_ctx.filter else {
            return Response::Error {
                error: "Adblocker is not enabled in this build".into(),
            };
        };

        Response::DnsAdblockStatus(DnsAdblockStatusResponse {
            enabled: adblocker.is_enabled(),
            disabled_until: {
                let until = adblocker.timer.disabled_until.load(Ordering::Relaxed);
                if until == 0 { None } else { Some(until) }
            },
            remaining_secs: adblocker.timer.remaining_secs(),
            blocklist_size: adblocker.blocklist_size(),
            allowlist_size: adblocker.allowlist_size(),
        })
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_status(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_block(&self, domain: String) -> Response {
        match self.db.upsert_dns_rewrite(&domain, "0.0.0.0").await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!(
                        "Domain '{domain}' blocked persistently via rewrite to 0.0.0.0"
                    ),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_block(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_allow(&self, domain: String) -> Response {
        match self.db.add_dns_allowlist(&domain).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' added to DNS allowlist"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_allow(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_unallow(&self, domain: String) -> Response {
        match self.db.remove_dns_allowlist(&domain).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Domain '{domain}' removed from DNS allowlist"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_unallow(&self, _domain: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    pub async fn handle_dns_rewrite_add(&self, domain: String, answer: String) -> Response {
        match self.db.upsert_dns_rewrite(&domain, &answer).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!("DNS rewrite added: {domain} -> {answer}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrite_remove(&self, domain: String) -> Response {
        match self.db.delete_dns_rewrite(&domain).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
                Response::Success(SimpleSuccess {
                    message: format!("DNS rewrite removed for '{domain}'"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_rewrites(&self) -> Response {
        match self.db.load_dns_rewrites().await {
            Ok(rewrites) => Response::DnsRewrites(DnsRewritesResponse { rewrites }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    pub async fn handle_dns_allowlist(&self) -> Response {
        match self.db.load_dns_allowlist().await {
            Ok(allowlist) => Response::DnsAllowlist(DnsAllowlistResponse { allowlist }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_add(&self, url: String, kind: String) -> Response {
        let kind_enum = AdblockUrlKind::from_str(&kind).unwrap_or(AdblockUrlKind::Blocklist);
        match self.db.add_adblock_url(&url, kind_enum).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Adblock {kind} URL added: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_add(&self, _url: String, _kind: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_url_remove(&self, url: String) -> Response {
        match self.db.remove_adblock_url(&url).await {
            Ok(()) => {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
                Response::Success(SimpleSuccess {
                    message: format!("Adblock URL removed: {url}"),
                })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_url_remove(&self, _url: String) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    #[cfg(feature = "adblock")]
    pub async fn handle_dns_adblock_urls(&self) -> Response {
        match self.db.load_adblock_urls().await {
            Ok(urls) => Response::DnsAdblockUrls(DnsAdblockUrlsResponse {
                urls: urls
                    .into_iter()
                    .map(|(url, kind)| AdblockUrlEntry {
                        url,
                        kind: kind.to_string(),
                    })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }

    #[cfg(not(feature = "adblock"))]
    pub async fn handle_dns_adblock_urls(&self) -> Response {
        Response::Error {
            error: "Adblock support not enabled in this build. Recompile with --features adblock."
                .to_string(),
        }
    }

    pub async fn handle_dns_query(&self, name: String, record_type: Option<String>) -> Response {
        let qtype = record_type
            .as_ref()
            .and_then(|s| DnsRecordType::from_str(s).ok())
            .unwrap_or(DnsRecordType::A);

        let start = Instant::now();
        match self.resolve_diagnostic(&name, qtype).await {
            Ok((records, auth)) => Response::DnsQuery(DnsQueryResponse {
                records,
                latency_ms: start.elapsed().as_millis() as u64,
                authoritative: auth,
            }),
            Err(e) => Response::Error {
                error: format!("DNS resolution failed: {e}"),
            },
        }
    }

    async fn resolve_diagnostic(
        &self,
        name: &str,
        qtype: DnsRecordType,
    ) -> Result<(Vec<DnsRecordEntry>, bool), String> {
        let dns_ctx_any = self.ctx.get_dns_context().ok_or("DNS context not found")?;
        let dns_ctx = dns_ctx_any
            .downcast_ref::<DnsContext>()
            .ok_or("Failed to downcast DNS context")?;

        // 1. Try local resolution
        if let Some(records) = dns_ctx.local.resolve_local(name, qtype) {
            return Ok((
                records
                    .into_iter()
                    .map(|r| DnsRecordEntry {
                        name: r.name.to_string(),
                        kind: r.rtype.to_string(),
                        data: r.rdata.to_string(),
                        ttl: r.ttl,
                    })
                    .collect(),
                true,
            ));
        }

        // 2. Try recursive resolution (simplified for diagnostic)
        // For diagnostic, we just use the recursive resolver directly if available
        match dns_ctx.recursive.resolve_recursive(name, qtype).await {
            Ok(msg) => Ok((
                msg.answers
                    .into_iter()
                    .map(|r| DnsRecordEntry {
                        name: r.name.to_string(),
                        kind: r.rtype.to_string(),
                        data: r.rdata.to_string(),
                        ttl: r.ttl,
                    })
                    .collect(),
                false,
            )),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn handle_dns_cache_flush(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
        Response::Success(SimpleSuccess {
            message: "DNS cache flush triggered".to_string(),
        })
    }

    pub async fn handle_dns_cache_dump(&self) -> Response {
        if let Some(dns_ctx_any) = self.ctx.get_dns_context()
            && let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>()
        {
            let mut entries = Vec::new();
            for (name, kind, data, expires_in_secs) in dns_ctx.cache.dump() {
                entries.push(DnsCacheEntry {
                    name,
                    kind,
                    data,
                    expires_in_secs,
                });
            }
            return Response::DnsCache(DnsCacheResponse { entries });
        }

        Response::Error {
            error: "DNS service or cache not available".into(),
        }
    }

    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
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

    pub async fn handle_dns_query_log(
        &self,
        limit: Option<usize>,
        _client: Option<String>,
        _follow: bool,
    ) -> Response {
        use crate::api::{DnsQueryLogEntry, DnsQueryLogResponse};
        let limit = limit.unwrap_or(100);
        match self.log_db.get_dns_query_history(limit).await {
            Ok(queries) => Response::DnsQueryLog(DnsQueryLogResponse {
                entries: queries
                    .into_iter()
                    .map(|q| {
                        let src_hostname = self
                            .ctx
                            .get_mac_by_ip(q.src_ip)
                            .and_then(|m| self.ctx.get_device(&m))
                            .map(|d| d.display_hostname().to_string());
                        DnsQueryLogEntry {
                            timestamp: q.timestamp,
                            src_ip: q.src_ip.to_string(),
                            src_mac: q.src_mac.map(|m| m.to_string()),
                            src_hostname,
                            domain: q.domain.to_string(),
                            qtype: q.qtype.to_string(),
                            result: format!("{:?}", q.result),
                            upstream_us: q.upstream_us,
                            cached: q.cached,
                            answer: q.answer,
                        }
                    })
                    .collect(),
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }
}
