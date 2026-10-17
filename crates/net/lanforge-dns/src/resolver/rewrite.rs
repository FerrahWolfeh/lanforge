use crate::error::DnsError;
use crate::resolver::ResponseBuilder;
use crate::server::DnsContext;
use globset::{Glob, GlobSet, GlobSetBuilder};
use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{RewriteAnswer, RewriteRule};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;

/// A thread-safe store for DNS rewrite rules compiled into a `GlobSet` for high-performance wildcard matching.
pub struct RewriteStore {
    state: RwLock<RewriteState>,
}

struct RewriteState {
    rules: Arc<Vec<RewriteRule>>,
    glob_set: GlobSet,
    rule_indices: Vec<usize>,
}

impl RewriteStore {
    /// Create a new empty `RewriteStore`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(RewriteState {
                rules: Arc::new(Vec::new()),
                glob_set: GlobSet::empty(),
                rule_indices: Vec::new(),
            }),
        }
    }

    /// Replace the current rules with new ones, compiling them into a `GlobSet`.
    pub fn replace_rules(&self, new_rules: Vec<RewriteRule>) {
        let mut builder = GlobSetBuilder::new();
        let mut rule_indices = Vec::new();

        for (idx, rule) in new_rules.iter().enumerate() {
            let domain = rule.domain.trim();
            if let Some(base) = domain.strip_prefix("*.") {
                if let Ok(glob1) = Glob::new(domain) {
                    builder.add(glob1);
                    rule_indices.push(idx);
                }
                if let Ok(glob2) = Glob::new(base) {
                    builder.add(glob2);
                    rule_indices.push(idx);
                }
            } else {
                if let Ok(glob) = Glob::new(domain) {
                    builder.add(glob);
                    rule_indices.push(idx);
                }
            }
        }

        let glob_set = builder.build().unwrap_or_else(|_| GlobSet::empty());
        *self.state.write() = RewriteState {
            rules: Arc::new(new_rules),
            glob_set,
            rule_indices,
        };
    }

    /// Match the domain query name against the compiled glob patterns.
    #[must_use]
    pub fn resolve_rewrite(&self, qname: &str) -> Option<RewriteAnswer> {
        let state = self.state.read();
        let matches = state.glob_set.matches(qname);
        if let Some(&pattern_idx) = matches.first() {
            let rule_idx = state.rule_indices[pattern_idx];
            return Some(state.rules[rule_idx].parse_answer());
        }
        None
    }

    /// Try resolving rewrite from a raw DNS wire request.
    pub fn try_resolve_rewrite_wire(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion,
        ctx: &DnsContext,
        domain: &str,
        resp: &mut Vec<u8>,
    ) -> bool {
        if let Some(answer) = self.resolve_rewrite(domain) {
            return Self::resolve_rewrite_wire(data, header, question, ctx, &answer, resp);
        }
        false
    }

    fn resolve_rewrite_wire(
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion<'_>,
        ctx: &DnsContext,
        answer: &RewriteAnswer,
        resp: &mut Vec<u8>,
    ) -> bool {
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.recursive.is_empty();
        let qtype = DnsRecordType::from(question.qtype());

        match answer {
            RewriteAnswer::A(ip) => {
                if qtype == DnsRecordType::A || qtype == DnsRecordType::ANY {
                    WireResponseWriter::write_ip_response(
                        data,
                        question,
                        &[IpAddr::V4(*ip)],
                        ctx.cfg.ttl,
                        edns,
                        ra,
                        resp,
                    );
                    true
                } else {
                    false
                }
            }
            RewriteAnswer::Aaaa(ip) => {
                if qtype == DnsRecordType::AAAA || qtype == DnsRecordType::ANY {
                    WireResponseWriter::write_ip_response(
                        data,
                        question,
                        &[IpAddr::V6(*ip)],
                        ctx.cfg.ttl,
                        edns,
                        ra,
                        resp,
                    );
                    true
                } else {
                    false
                }
            }
            RewriteAnswer::Cname(target) => {
                WireResponseWriter::write_cname_response(
                    data,
                    question,
                    target,
                    ctx.cfg.ttl,
                    edns,
                    ra,
                    resp,
                );
                true
            }
            RewriteAnswer::Device {
                identifier,
                fallback,
            } => {
                if let Some(ips) = ctx.local.resolve_device(identifier, qtype) {
                    WireResponseWriter::write_ip_response(
                        data, question, &ips, 5, // Short 5s TTL for dynamic resolves
                        edns, ra, resp,
                    );
                    true
                } else if let Some(fb) = fallback {
                    Self::resolve_rewrite_wire(data, header, question, ctx, fb, resp)
                } else {
                    WireResponseWriter::write_error_response(
                        data, question, 3, // NXDOMAIN
                        edns, ra, resp,
                    );
                    true
                }
            }
            RewriteAnswer::Service {
                service,
                protocol,
                device,
                port,
            } => {
                if qtype == DnsRecordType::SRV || qtype == DnsRecordType::ANY {
                    let target_domain = format!("{}.lan", device);
                    WireResponseWriter::write_srv_response(
                        data,
                        question,
                        service.clone(),
                        *protocol,
                        &target_domain,
                        *port,
                        5, // Short 5s TTL
                        edns,
                        ra,
                        resp,
                    );
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Try resolving rewrite as a fallback/recursive DNS resolver action.
    pub fn try_resolve_rewrite_fallback(
        &self,
        ctx: &DnsContext,
        rb: &ResponseBuilder,
        qname: &str,
        qtype: DnsRecordType,
        _src_addr: IpAddr,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        let mut domain = qname.to_string();
        if domain.ends_with('.') {
            domain.pop();
        }
        domain.make_ascii_lowercase();

        if let Some(answer) = self.resolve_rewrite(&domain) {
            return Self::resolve_rewrite_fallback_internal(ctx, rb, qtype, &answer, resp);
        }
        Ok(false)
    }

    fn resolve_rewrite_fallback_internal(
        ctx: &DnsContext,
        rb: &ResponseBuilder,
        qtype: DnsRecordType,
        answer: &RewriteAnswer,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        use lanforge_types::network::dns::{DnsClass, DnsRData, DnsRecord};

        match answer {
            RewriteAnswer::A(ip) => {
                if qtype == DnsRecordType::A || qtype == DnsRecordType::ANY {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V4(*ip)])?);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            RewriteAnswer::Aaaa(ip) => {
                if qtype == DnsRecordType::AAAA || qtype == DnsRecordType::ANY {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V6(*ip)])?);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            RewriteAnswer::Cname(target) => {
                resp.clear();
                resp.extend_from_slice(&rb.success_cname(target)?);
                Ok(true)
            }
            RewriteAnswer::Device {
                identifier,
                fallback,
            } => {
                if let Some(ips) = ctx.local.resolve_device(identifier, qtype) {
                    resp.clear();
                    let qname = rb.qname();
                    let answers: Vec<DnsRecord> = ips
                        .into_iter()
                        .map(|ip| {
                            let (rtype, rdata) = match ip {
                                IpAddr::V4(v4) => (DnsRecordType::A, DnsRData::A(v4)),
                                IpAddr::V6(v6) => (DnsRecordType::AAAA, DnsRData::AAAA(v6)),
                            };
                            DnsRecord {
                                name: qname.clone(),
                                rtype,
                                rclass: DnsClass::IN,
                                ttl: 5, // Short 5s TTL
                                rdata,
                            }
                        })
                        .collect();
                    resp.extend_from_slice(&rb.success(answers)?);
                    Ok(true)
                } else if let Some(fb) = fallback {
                    Self::resolve_rewrite_fallback_internal(ctx, rb, qtype, fb, resp)
                } else {
                    resp.clear();
                    resp.extend_from_slice(&rb.nxdomain()?);
                    Ok(true)
                }
            }
            RewriteAnswer::Service {
                service: _,
                protocol: _,
                device,
                port,
            } => {
                if qtype == DnsRecordType::SRV || qtype == DnsRecordType::ANY {
                    let target_domain = format!("{}.lan", device);
                    let record = DnsRecord {
                        name: rb.qname(),
                        rtype: DnsRecordType::SRV,
                        rclass: DnsClass::IN,
                        ttl: 5, // Short 5s TTL
                        rdata: DnsRData::SRV {
                            priority: 0,
                            weight: 0,
                            port: *port,
                            target: Arc::from(target_domain),
                        },
                    };
                    resp.clear();
                    resp.extend_from_slice(&rb.success(vec![record])?);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
}

impl Default for RewriteStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn should_match_exact_and_wildcard_domains() {
        let store = RewriteStore::new();
        store.replace_rules(vec![
            RewriteRule {
                id: None,
                domain: "api.local".to_string(),
                rtype: DnsRecordType::A,
                answer: RewriteAnswer::A(Ipv4Addr::new(10, 0, 0, 1)),
            },
            RewriteRule {
                id: None,
                domain: "*.corp.internal".to_string(),
                rtype: DnsRecordType::A,
                answer: RewriteAnswer::A(Ipv4Addr::new(10, 0, 0, 2)),
            },
        ]);

        // Exact match
        let ans = store.resolve_rewrite("api.local").expect("Should match api.local");
        assert_eq!(ans, RewriteAnswer::A(Ipv4Addr::new(10, 0, 0, 1)));

        // Wildcard subdomain
        let ans2 = store
            .resolve_rewrite("service.corp.internal")
            .expect("Should match service.corp.internal");
        assert_eq!(ans2, RewriteAnswer::A(Ipv4Addr::new(10, 0, 0, 2)));

        // Wildcard base domain
        let ans3 = store
            .resolve_rewrite("corp.internal")
            .expect("Should match base corp.internal");
        assert_eq!(ans3, RewriteAnswer::A(Ipv4Addr::new(10, 0, 0, 2)));

        // Non-matching
        assert!(store.resolve_rewrite("other.local").is_none());
    }
}


