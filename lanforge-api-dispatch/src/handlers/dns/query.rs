use crate::ClientContext;
use lanforge_api::api::{DnsQueryLogEntry, DnsQueryLogResponse, DnsQueryResponse, Response};
use lanforge_dns::pipeline::DnsPipelineRequest;
use lanforge_dns::resolver::recursive::cache::CacheKey;
use lanforge_dns::server::DnsContext;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordEntry, DnsRecordType, TransportProtocol,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

impl ClientContext {
    pub async fn handle_dns_query(&self, name: String, record_type: Option<String>) -> Response {
        let qtype = record_type
            .as_ref()
            .and_then(|s| DnsRecordType::from_str(s).ok())
            .unwrap_or(DnsRecordType::A);

        let start = Instant::now();
        match self.resolve_diagnostic(&name, qtype).await {
            Ok((records, auth, result)) => Response::DnsQuery(DnsQueryResponse {
                records,
                latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                authoritative: auth,
                result,
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
    ) -> Result<(Vec<DnsRecordEntry>, bool, String), String> {
        let dns_ctx_any = self.ctx.get_dns_context().ok_or("DNS context not found")?;
        let dns_ctx = dns_ctx_any
            .downcast_ref::<DnsContext>()
            .ok_or("Failed to downcast DNS context")?;

        let mut query = DnsMessage::new();
        query.header.rd = true;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from(name),
            qtype,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let wire_query = encoder.encode_message(&query);

        let mut resp_buf = Vec::new();
        let Some(header) = WireHeader::parse(&wire_query) else {
            return Err("Failed to parse query header".into());
        };
        let Some(question) = WireQuestion::parse(&wire_query) else {
            return Err("Failed to parse query question".into());
        };

        let req = DnsPipelineRequest::new(
            &wire_query,
            &header,
            &question,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            TransportProtocol::Udp,
        );

        if let Err(e) = dns_ctx.pipeline.run(dns_ctx, req, &mut resp_buf).await {
            return Err(format!("Pipeline error: {e}"));
        }

        let mut decoder = WireDecoder::new(&resp_buf);
        let Some(msg) = decoder.decode_message() else {
            return Err("Failed to decode pipeline response".into());
        };

        let auth = msg.header.aa;
        let records = msg
            .answers
            .into_iter()
            .map(|r| DnsRecordEntry {
                name: r.name.to_string(),
                kind: r.rtype,
                data: r.rdata.to_string(),
                ttl: r.ttl,
            })
            .collect();

        let result_str = if let Some(ring) = &dns_ctx.query_log
            && let Some(last) = ring.get_recent(1).into_iter().next()
            && last.domain.as_ref() == name
        {
            format!("{:?}", last.result)
        } else {
            // Fallback logic matching pipeline order
            if let Some(filter) = &dns_ctx.filter
                && filter.should_block(name)
            {
                "Blocked".to_string()
            } else if let Some(filter) = &dns_ctx.filter
                && filter.resolve_rewrite(name).is_some()
            {
                "Rewritten".to_string()
            } else {
                let mut qname = name.as_bytes().to_vec();
                qname.make_ascii_lowercase();
                let key = CacheKey {
                    qname,
                    qtype: u16::from(qtype),
                    qclass: 1, // IN
                };
                if dns_ctx.cache.cache.get(&key).is_some() {
                    "Cached".to_string()
                } else if dns_ctx.local.resolve_local(name, qtype).is_some()
                    || (qtype == DnsRecordType::PTR
                        && dns_ctx
                            .local
                            .resolve_ptr(name)
                            .is_ok_and(|res| res.is_some()))
                {
                    "Local".to_string()
                } else {
                    "Forwarded".to_string()
                }
            }
        };

        Ok((records, auth, result_str))
    }

    pub async fn handle_dns_query_log(
        &self,
        n: Option<usize>,
        _client: Option<String>,
        _follow: bool,
        offset: Option<usize>,
    ) -> Response {
        let limit = n.unwrap_or(100);
        match self.log_db.get_dns_query_history(limit, offset).await {
            Ok((queries, total)) => Response::DnsQueryLog(DnsQueryLogResponse {
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
                total,
            }),
            Err(e) => Response::Error {
                error: e.to_string(),
            },
        }
    }
}
