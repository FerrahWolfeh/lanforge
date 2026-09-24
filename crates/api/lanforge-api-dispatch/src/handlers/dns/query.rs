use crate::ClientContext;
use lanforge_api::api::{DnsQueryLogEntry, DnsQueryLogResponse, DnsQueryResponse, Response};
use lanforge_types::network::dns::{DnsRecordEntry, DnsRecordType};
use std::{collections::HashMap, net::IpAddr, time::Instant};

impl ClientContext {
    pub async fn handle_dns_query(
        &self,
        name: String,
        record_type: Option<DnsRecordType>,
    ) -> Response {
        let qtype = record_type.unwrap_or(DnsRecordType::A);

        let start = Instant::now();
        match self.resolve_diagnostic(&name, qtype).await {
            Ok((records, auth, result)) => Response::DnsQuery(Box::new(DnsQueryResponse {
                records,
                latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                authoritative: auth,
                result,
            })),
            Err(e) => Response::Error {
                error: format!("DNS resolution failed: {e}"),
            },
        }
    }

    async fn resolve_diagnostic(
        &self,
        name: &str,
        qtype: DnsRecordType,
    ) -> Result<(Vec<DnsRecordEntry>, bool, String), String> {
        let Some(handle) = self.ctx.dns_handle() else {
            return Err("DNS service handle not available".into());
        };

        match handle
            .send_request(lanforge_types::network::dns::DnsRequest::Query {
                name: name.to_string(),
                qtype,
            })
            .await
        {
            Ok(lanforge_types::network::dns::DnsResponse::Query(res)) => res,
            _ => Err("Invalid response from DNS service".into()),
        }
    }

    pub async fn handle_dns_query_log(
        &self,
        n: Option<usize>,
        client: Option<String>,
        _follow: bool,
        offset: Option<usize>,
    ) -> Response {
        let limit = n.unwrap_or(100);
        match self.log_db.get_dns_query_history(limit, offset, client).await {
            Ok((queries, total)) => {
                let entries = self.ctx.with_state(|state| {
                    let mut ip_cache: HashMap<IpAddr, (Option<lanforge_types::identifiers::MacAddr>, Option<String>)> =
                        HashMap::new();
                    queries
                        .into_iter()
                        .map(|q| {
                            let (mac, src_hostname) = match q.src_mac {
                                Some(mac) => {
                                    let hostname = super::resolve_mac_hostname(state, mac);
                                    (Some(mac), hostname)
                                }
                                None => {
                                    ip_cache
                                        .entry(q.src_ip)
                                        .or_insert_with(|| super::resolve_ip_identity(state, q.src_ip))
                                        .clone()
                                }
                            };
                            DnsQueryLogEntry {
                                timestamp: q.timestamp,
                                src_ip: q.src_ip,
                                src_mac: mac,
                                src_hostname,
                                domain: q.domain,
                                qtype: q.qtype,
                                result: q.result,
                                upstream_us: q.upstream_us,
                                cached: q.cached,
                                answer: q.answer,
                            }
                        })
                        .collect()
                });
                Response::DnsQueryLog(DnsQueryLogResponse { entries, total })
            }
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }
}
