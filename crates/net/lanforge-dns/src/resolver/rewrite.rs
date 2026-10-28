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

    /// Answers a query whose name a rewrite matches. Every matching rule is tried in order; the
    /// first that answers the query type wins. A matched name never leaves the router: when no
    /// rule answers that type the reply is NODATA (NOERROR, no answer) — never NXDOMAIN, never
    /// the upstream, so a rewritten public domain cannot leak its public records.
    /// Returns `false` only when no rule matches the name.
    pub fn try_resolve_rewrite_wire(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion,
        ctx: &DnsContext,
        domain: &str,
        resp: &mut Vec<u8>,
    ) -> bool {
        let state = self.state.read();
        let mut matched = state
            .glob_set
            .matches(domain)
            .into_iter()
            .map(|pattern| state.rule_indices[pattern])
            .peekable();
        if matched.peek().is_none() {
            return false;
        }
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.recursive.is_empty();
        let qtype = DnsRecordType::from(question.qtype());
        let mut last_rule = None;
        for idx in matched {
            if last_rule == Some(idx) {
                continue; // `*.x` and `x` both match the base name
            }
            last_rule = Some(idx);
            let rule = &state.rules[idx];
            if delimits(rule.rtype, qtype)
                && Self::answer_wire(data, question, ctx, &rule.answer, qtype, edns, ra, resp)
            {
                return true;
            }
        }
        WireResponseWriter::write_error_response(data, question, 0, edns, ra, resp);
        true
    }

    /// Writes `answer` for `qtype`, or returns `false` when it has nothing of that type.
    #[allow(clippy::too_many_arguments)]
    fn answer_wire(
        data: &[u8],
        question: &WireQuestion<'_>,
        ctx: &DnsContext,
        answer: &RewriteAnswer,
        qtype: DnsRecordType,
        edns: Option<WireOptScanner>,
        ra: bool,
        resp: &mut Vec<u8>,
    ) -> bool {
        let any = qtype == DnsRecordType::ANY;
        match answer {
            RewriteAnswer::A(ip) if any || qtype == DnsRecordType::A => {
                let ips = [IpAddr::V4(*ip)];
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
            }
            RewriteAnswer::Aaaa(ip) if any || qtype == DnsRecordType::AAAA => {
                let ips = [IpAddr::V6(*ip)];
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
                    // Short TTL: the answer follows the device's current addresses.
                    WireResponseWriter::write_ip_response(data, question, &ips, 5, edns, ra, resp);
                    true
                } else {
                    fallback.as_deref().is_some_and(|fb| {
                        Self::answer_wire(data, question, ctx, fb, qtype, edns, ra, resp)
                    })
                }
            }
            _ => false,
        }
    }
}

/// Whether a rule of record type `rtype` may answer `qtype`: `A` and `AAAA` delimit the rule to
/// that family; any other type (inferred from the answer) leaves it to the answer.
fn delimits(rtype: DnsRecordType, qtype: DnsRecordType) -> bool {
    match rtype {
        DnsRecordType::A | DnsRecordType::AAAA => qtype == rtype || qtype == DnsRecordType::ANY,
        _ => true,
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
        let ans = store
            .resolve_rewrite("api.local")
            .expect("Should match api.local");
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
