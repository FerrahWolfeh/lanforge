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
            return Self::resolve_rewrite_wire(data, header, question, ctx, answer, resp);
        }
        false
    }

    fn resolve_rewrite_wire(
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion<'_>,
        ctx: &DnsContext,
        answer: RewriteAnswer,
        resp: &mut Vec<u8>,
    ) -> bool {
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.recursive.is_empty();
        let qtype = DnsRecordType::from(question.qtype());

        match answer {
            RewriteAnswer::A(ip) if qtype == DnsRecordType::A || qtype == DnsRecordType::ANY => {
                WireResponseWriter::write_ip_response(
                    data,
                    question,
                    &[IpAddr::V4(ip)],
                    ctx.cfg.ttl,
                    edns,
                    ra,
                    resp,
                );
                true
            }
            RewriteAnswer::Aaaa(ip)
                if qtype == DnsRecordType::AAAA || qtype == DnsRecordType::ANY =>
            {
                WireResponseWriter::write_ip_response(
                    data,
                    question,
                    &[IpAddr::V6(ip)],
                    ctx.cfg.ttl,
                    edns,
                    ra,
                    resp,
                );
                true
            }
            RewriteAnswer::Cname(target) => {
                WireResponseWriter::write_cname_response(
                    data,
                    question,
                    &target,
                    ctx.cfg.ttl,
                    edns,
                    ra,
                    resp,
                );
                true
            }
            RewriteAnswer::Device(hostname) => {
                ctx.local.resolve_ip(&hostname, qtype).is_some_and(|ips| {
                    WireResponseWriter::write_ip_response(
                        data,
                        question,
                        &ips,
                        ctx.cfg.ttl,
                        edns,
                        ra,
                        resp,
                    );
                    true
                })
            }
            _ => false,
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
            match answer {
                RewriteAnswer::A(ip)
                    if qtype == DnsRecordType::A || qtype == DnsRecordType::ANY =>
                {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V4(ip)])?);
                    return Ok(true);
                }
                RewriteAnswer::Aaaa(ip)
                    if qtype == DnsRecordType::AAAA || qtype == DnsRecordType::ANY =>
                {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V6(ip)])?);
                    return Ok(true);
                }
                RewriteAnswer::Cname(target) => {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_cname(&target)?);
                    return Ok(true);
                }
                RewriteAnswer::Device(hostname) => {
                    if let Some(ips) = ctx.local.resolve_ip(&hostname, qtype) {
                        resp.clear();
                        resp.extend_from_slice(&rb.success_ips(ips)?);
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }
}

impl Default for RewriteStore {
    fn default() -> Self {
        Self::new()
    }
}
