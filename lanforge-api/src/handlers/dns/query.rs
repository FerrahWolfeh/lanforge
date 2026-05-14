use crate::api::{DnsQueryLogEntry, DnsQueryLogResponse, DnsQueryResponse, Response};
use crate::server::ClientContext;
use lanforge_core::types::{DnsRecordEntry, DnsRecordType};
use lanforge_dns::server::DnsContext;
use std::str::FromStr;
use std::time::Instant;

impl ClientContext {
    pub async fn handle_dns_query(&self, name: String, record_type: Option<String>) -> Response {
        let qtype = record_type
            .as_ref()
            .and_then(|s| DnsRecordType::from_str(s).ok())
            .unwrap_or(DnsRecordType::A);

        let start = Instant::now();
        match self.resolve_diagnostic(&name, qtype).await {
            Ok((records, auth)) => Response::DnsQuery(DnsQueryResponse {
                records,
                latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
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
                        kind: r.rtype,
                        data: r.rdata.to_string(),
                        ttl: r.ttl,
                    })
                    .collect(),
                true,
            ));
        }

        // 2. Try recursive resolution (simplified for diagnostic)
        match dns_ctx.recursive.resolve_recursive(name, qtype).await {
            Ok(msg) => Ok((
                msg.answers
                    .into_iter()
                    .map(|r| DnsRecordEntry {
                        name: r.name.to_string(),
                        kind: r.rtype,
                        data: r.rdata.to_string(),
                        ttl: r.ttl,
                    })
                    .collect(),
                false,
            )),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn handle_dns_query_log(
        &self,
        limit: Option<usize>,
        _client: Option<String>,
        _follow: bool,
    ) -> Response {
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
                            qtype: q.qtype,
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
