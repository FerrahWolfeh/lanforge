use crate::error::DnsError;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireLabelIter, WireOptScanner, WireQuestion, WireResponseWriter};
use dashmap::DashMap;
use hickory_proto::rr::RecordType;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{error, info};

/// In-memory DNS filtering engine.
///
/// Provides O(1) blocklist lookups and tracks per-IP blocking statistics.
/// Supports transient disabling with automatic re-enabling after a duration.
pub struct AdBlocker {
    /// The actual set of blocked hostnames.
    blocklist: RwLock<Arc<HashSet<String>>>,
    /// Domains that are never blocked.
    allowlist: RwLock<Arc<HashSet<String>>>,
    /// Shared timer state for disabling/enabling.
    pub timer: Arc<AdblockTimerState>,
    /// Manual DNS rewrite rules.
    pub rewrites: RwLock<Vec<crate::config::RewriteRule>>,
    /// Per-IP blocking counters.
    per_ip_stats: DashMap<IpAddr, AtomicU64>,
}

/// Shared atomic state for adblocker status and temporary disabling.
pub struct AdblockTimerState {
    /// Master switch for filtering.
    pub enabled: AtomicBool,
    /// Unix timestamp when filtering should automatically re-enable (0 if no timer).
    pub disabled_until: AtomicU64,
}

impl AdblockTimerState {
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            disabled_until: AtomicU64::new(0),
        }
    }

    /// Returns the number of seconds remaining if a disable timer is active.
    #[must_use]
    pub fn remaining_secs(&self) -> Option<u64> {
        let until = self.disabled_until.load(Ordering::Relaxed);
        if until == 0 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(until.saturating_sub(now))
    }
}

impl AdBlocker {
    /// Creates a new, initially empty and disabled adblocker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocklist: RwLock::new(Arc::new(HashSet::new())),
            allowlist: RwLock::new(Arc::new(HashSet::new())),
            timer: Arc::new(AdblockTimerState::new(false)),
            rewrites: RwLock::new(Vec::new()),
            per_ip_stats: DashMap::new(),
        }
    }

    /// Returns true if filtering is currently active.
    pub fn is_enabled(&self) -> bool {
        self.timer.enabled.load(Ordering::Relaxed)
    }

    /// Sets the enabled state.
    pub fn set_enabled(&self, enabled: bool) {
        self.timer.enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            self.timer.disabled_until.store(0, Ordering::Relaxed);
        }
    }

    /// Checks if a hostname (joined labels) should be blocked.
    ///
    /// Supports wildcards via parent-domain walk and allowlist overrides.
    pub fn should_block(&self, qname: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }

        // 1. Check allowlist (exact or parent)
        {
            let allow = self.allowlist.read();
            if Self::match_recursive(&allow, qname) {
                return false;
            }
        }

        // 2. Check blocklist (exact or parent)
        let block = self.blocklist.read();
        Self::match_recursive(&block, qname)
    }

    fn match_recursive(set: &HashSet<String>, qname: &str) -> bool {
        if set.contains(qname) {
            return true;
        }

        let mut current = qname;
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if current.is_empty() {
                break;
            }
            if set.contains(current) {
                return true;
            }
        }
        false
    }

    /// Increments the block counter for a specific source IP.
    pub fn inc_ip_stats(&self, ip: IpAddr) {
        self.per_ip_stats
            .entry(ip)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Replaces the current blocklist with a new one.
    pub fn replace_blocklist(&self, new_list: HashSet<String>) {
        let count = new_list.len();
        *self.blocklist.write() = Arc::new(new_list);
        info!("AdBlocker: blocklist updated with {} entries", count);
    }

    /// Replaces the current allowlist with a new one.
    pub fn replace_allowlist(&self, new_list: HashSet<String>) {
        let count = new_list.len();
        *self.allowlist.write() = Arc::new(new_list);
        info!("AdBlocker: allowlist updated with {} entries", count);
    }

    /// Adds a single domain to the blocklist dynamically.
    pub fn add_block(&self, domain: &str) {
        let mut list = self.blocklist.write();
        let mut new_set = (**list).clone();
        new_set.insert(domain.to_lowercase());
        *list = Arc::new(new_set);
    }

    /// Adds a single domain to the allowlist dynamically.
    pub fn add_allow(&self, domain: &str) {
        let mut list = self.allowlist.write();
        let mut new_set = (**list).clone();
        new_set.insert(domain.to_lowercase());
        *list = Arc::new(new_set);
    }

    /// Returns the number of entries in the blocklist.
    #[must_use]
    pub fn blocklist_size(&self) -> usize {
        self.blocklist.read().len()
    }

    /// Returns the number of entries in the allowlist.
    #[must_use]
    pub fn allowlist_size(&self) -> usize {
        self.allowlist.read().len()
    }

    pub fn resolve_rewrite(&self, qname: &str) -> Option<crate::config::RewriteAnswer> {
        let rewrites = self.rewrites.read();

        // 1. Try exact match first (qname is already lowercased by caller)
        if let Some(rule) = rewrites.iter().find(|r| r.domain == qname) {
            return Some(rule.parse_answer());
        }

        // 2. Try explicit wildcard matches (*.domain.com)
        rewrites
            .iter()
            .find(|rule| {
                if rule.domain.starts_with("*.") {
                    let base = &rule.domain[2..];
                    // Matches "base.com" and any subdomain "sub.base.com"
                    qname == base || qname.ends_with(&format!(".{base}"))
                } else {
                    false
                }
            })
            .map(super::config::RewriteRule::parse_answer)
    }

    /// Downloads and parses blocklists from the provided URLs.
    ///
    /// This is a blocking operation intended to be run in a background task.
    pub fn load_from_urls(&self, urls: &[String]) -> Result<HashSet<String>, DnsError> {
        let mut new_list = HashSet::new();
        let agent = ureq::Agent::new_with_defaults();

        for url in urls {
            info!("AdBlocker: fetching blocklist from {}", url);
            match agent.get(url).call() {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        error!(
                            "AdBlocker: failed to fetch {}: status {}",
                            url,
                            resp.status()
                        );
                        continue;
                    }
                    let mut line_count = 0;
                    let buf_reader = BufReader::new(resp.into_body().into_reader());

                    for line in buf_reader.lines() {
                        let Ok(line) = line else {
                            continue;
                        };
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }

                        // Handle formats like "0.0.0.0 domain.com" or symbol-prefixed domains
                        let domain = trimmed.split_whitespace().last().unwrap_or("");
                        if !domain.is_empty() {
                            new_list.insert(domain.to_ascii_lowercase());
                            line_count += 1;
                        }
                    }
                    info!("AdBlocker: loaded {} domains from {}", line_count, url);
                }
                Err(e) => {
                    error!("AdBlocker: failed to fetch {}: {}", url, e);
                }
            }
        }

        Ok(new_list)
    }

    /// Attempts to resolve a rewrite rule and writes it to the response via wire formatting.
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
        answer: crate::config::RewriteAnswer,
        resp: &mut Vec<u8>,
    ) -> bool {
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.upstreams.is_empty();
        let qtype = question.qtype();

        match answer {
            crate::config::RewriteAnswer::A(ip) if qtype == 1 || qtype == 255 => {
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
            crate::config::RewriteAnswer::Aaaa(ip) if qtype == 28 || qtype == 255 => {
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
            crate::config::RewriteAnswer::Cname(target) => {
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
            crate::config::RewriteAnswer::Device(hostname) => {
                let resolver = crate::resolver::LocalResolver::new(&ctx.cfg, &ctx.ctx);
                resolver
                    .resolve_ip(&hostname, RecordType::from(qtype))
                    .is_some_and(|ips| {
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

    /// Resolves rewrites in the fallback path.
    pub fn try_resolve_rewrite_fallback(
        &self,
        ctx: &DnsContext,
        rb: &crate::response::ResponseBuilder,
        qname: &hickory_proto::rr::Name,
        qtype: RecordType,
        src_addr: IpAddr,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        let mut domain = qname.to_string();
        if domain.ends_with('.') {
            domain.pop();
        }
        domain.make_ascii_lowercase();

        if let Some(answer) = self.resolve_rewrite(&domain) {
            match answer {
                crate::config::RewriteAnswer::A(ip)
                    if qtype == RecordType::A || qtype == RecordType::ANY =>
                {
                    ctx.stats.inc_auth();
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V4(ip)])?);
                    ctx.record_log(
                        src_addr,
                        domain,
                        qtype.into(),
                        lanforge_core::types::network::QueryResult::Rewritten,
                        0,
                        false,
                    );
                    return Ok(true);
                }
                crate::config::RewriteAnswer::Aaaa(ip)
                    if qtype == RecordType::AAAA || qtype == RecordType::ANY =>
                {
                    ctx.stats.inc_auth();
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips([IpAddr::V6(ip)])?);
                    ctx.record_log(
                        src_addr,
                        domain,
                        qtype.into(),
                        lanforge_core::types::network::QueryResult::Rewritten,
                        0,
                        false,
                    );
                    return Ok(true);
                }
                crate::config::RewriteAnswer::Cname(target) => {
                    ctx.stats.inc_auth();
                    resp.clear();
                    resp.extend_from_slice(&rb.success_cname(&target)?);
                    ctx.record_log(
                        src_addr,
                        domain,
                        qtype.into(),
                        lanforge_core::types::network::QueryResult::Rewritten,
                        0,
                        false,
                    );
                    return Ok(true);
                }
                crate::config::RewriteAnswer::Device(hostname) => {
                    let resolver = crate::resolver::LocalResolver::new(&ctx.cfg, &ctx.ctx);
                    if let Some(ips) = resolver.resolve_ip(&hostname, qtype) {
                        ctx.stats.inc_auth();
                        resp.clear();
                        resp.extend_from_slice(&rb.success_ips(ips)?);
                        ctx.record_log(
                            src_addr,
                            domain,
                            qtype.into(),
                            lanforge_core::types::network::QueryResult::Rewritten,
                            0,
                            false,
                        );
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(false)
    }

    /// Generates a blocking response using the zero-alloc wire builder.
    pub fn apply_adblock_wire(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion,
        ctx: &DnsContext,
        resp: &mut Vec<u8>,
    ) {
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.cfg.upstreams.is_empty();

        match ctx.cfg.blocking_mode {
            crate::config::BlockingMode::NxDomain => {
                WireResponseWriter::write_error_response(data, question, 3, edns, ra, resp);
            }
            crate::config::BlockingMode::NullIp => {
                let ips = if question.qtype() == 28 {
                    vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
                } else {
                    vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)]
                };
                WireResponseWriter::write_ip_response(data, question, &ips, 3600, edns, ra, resp);
            }
            crate::config::BlockingMode::CustomIp => {
                let ips = if question.qtype() == 28 {
                    vec![IpAddr::V6(
                        ctx.cfg.blocking_ip_v6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                    )]
                } else {
                    vec![IpAddr::V4(
                        ctx.cfg
                            .blocking_ip_v4
                            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                    )]
                };
                WireResponseWriter::write_ip_response(data, question, &ips, 3600, edns, ra, resp);
            }
            crate::config::BlockingMode::Refused => {
                WireResponseWriter::write_error_response(data, question, 5, edns, ra, resp);
            }
        }
    }

    /// Fallback path blocking.
    pub fn apply_adblock_fallback(
        &self,
        ctx: &DnsContext,
        rb: &crate::response::ResponseBuilder,
        qname: &hickory_proto::rr::Name,
        qtype: RecordType,
        src_addr: IpAddr,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        if !self.is_enabled() {
            return Ok(false);
        }

        let mut domain = qname.to_string();
        if domain.ends_with('.') {
            domain.pop();
        }
        domain.make_ascii_lowercase();

        if self.should_block(&domain) {
            ctx.stats.inc_blocked();
            ctx.ctx.inc_dns_blocked();
            self.inc_ip_stats(src_addr);
            resp.clear();

            match ctx.cfg.blocking_mode {
                crate::config::BlockingMode::NxDomain => {
                    resp.extend_from_slice(&rb.nxdomain()?);
                }
                crate::config::BlockingMode::NullIp => {
                    let ips = if qtype == RecordType::AAAA {
                        vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
                    } else {
                        vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)]
                    };
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                }
                crate::config::BlockingMode::CustomIp => {
                    let ips = if qtype == RecordType::AAAA {
                        vec![IpAddr::V6(
                            ctx.cfg.blocking_ip_v6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                        )]
                    } else {
                        vec![IpAddr::V4(
                            ctx.cfg
                                .blocking_ip_v4
                                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                        )]
                    };
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                }
                crate::config::BlockingMode::Refused => {
                    resp.extend_from_slice(&rb.refused()?);
                }
            }

            ctx.record_log(
                src_addr,
                domain,
                qtype.into(),
                lanforge_core::types::network::QueryResult::Blocked,
                0,
                false,
            );
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for AdBlocker {
    fn default() -> Self {
        Self::new()
    }
}

/// Joins wire-format labels into a dot-separated domain string.
///
/// Performs a single allocation for the resulting string.
#[must_use]
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn labels_to_domain(labels: WireLabelIter<'_>) -> String {
    let mut domain = String::with_capacity(64);
    for label in labels {
        if !domain.is_empty() {
            domain.push('.');
        }
        if let Ok(s) = std::str::from_utf8(label) {
            domain.push_str(s);
        }
    }
    domain.make_ascii_lowercase();
    domain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adblock_basic() {
        let adblock = AdBlocker::new();
        let mut list = HashSet::new();
        list.insert("doubleclick.net".to_string());
        adblock.replace_blocklist(list);

        // Initially disabled
        assert!(!adblock.should_block("doubleclick.net"));

        adblock.set_enabled(true);
        assert!(adblock.should_block("doubleclick.net"));
        assert!(!adblock.should_block("google.com"));
    }

    #[test]
    fn test_adblock_wildcard() {
        let adblock = AdBlocker::new();
        adblock.set_enabled(true);
        let mut list = HashSet::new();
        list.insert("doubleclick.net".to_string());
        adblock.replace_blocklist(list);

        assert!(adblock.should_block("doubleclick.net"));
        assert!(adblock.should_block("ads.doubleclick.net"));
        assert!(adblock.should_block("very.deep.sub.ads.doubleclick.net"));
        assert!(!adblock.should_block("notdoubleclick.net"));
    }

    #[test]
    fn test_adblock_allowlist() {
        let adblock = AdBlocker::new();
        adblock.set_enabled(true);

        let mut block = HashSet::new();
        block.insert("doubleclick.net".to_string());
        adblock.replace_blocklist(block);

        let mut allow = HashSet::new();
        allow.insert("safe.doubleclick.net".to_string());
        adblock.replace_allowlist(allow);

        assert!(adblock.should_block("doubleclick.net"));
        assert!(adblock.should_block("ads.doubleclick.net"));
        // Allowlist hit
        assert!(!adblock.should_block("safe.doubleclick.net"));
        assert!(!adblock.should_block("sub.safe.doubleclick.net"));
    }
}
