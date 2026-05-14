use crate::config::{BlockingMode, RewriteAnswer};
use crate::error::DnsError;
use crate::resolver::builder::ResponseBuilder;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireLabelIter, WireOptScanner, WireQuestion, WireResponseWriter};
use dashmap::DashMap;
use lanforge_types::DnsRecordType;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, trace};

pub mod blocklist;

pub use blocklist::DiskBlocklist;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct AdBlocker {
    pub blocklist: RwLock<Option<Arc<DiskBlocklist>>>,
    pub allowlist: RwLock<Arc<HashSet<String>>>,
    pub timer: Arc<AdblockTimerState>,
    pub rewrites: RwLock<Arc<Vec<crate::config::RewriteRule>>>,
    pub config: RwLock<Arc<AdblockRuntimeConfig>>,
    per_ip_stats: DashMap<IpAddr, AtomicU64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdblockRuntimeConfig {
    pub mode: BlockingMode,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

pub struct AdblockTimerState {
    pub enabled: AtomicBool,
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

    #[must_use]
    pub fn remaining_secs(&self) -> Option<u64> {
        let until = self.disabled_until.load(Ordering::Relaxed);
        if until == 0 {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(until.saturating_sub(now))
    }
}

impl AdBlocker {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            blocklist: RwLock::new(None),
            allowlist: RwLock::new(Arc::new(HashSet::new())),
            timer: Arc::new(AdblockTimerState::new(enabled)),
            rewrites: RwLock::new(Arc::new(Vec::new())),
            config: RwLock::new(Arc::new(AdblockRuntimeConfig::default())),
            per_ip_stats: DashMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        if !self.timer.enabled.load(Ordering::Relaxed) {
            let until = self.timer.disabled_until.load(Ordering::Relaxed);
            if until > 0 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now < until {
                    return false;
                }
                // Timer expired, auto-re-enable
                self.timer.enabled.store(true, Ordering::Relaxed);
                self.timer.disabled_until.store(0, Ordering::Relaxed);
                return true;
            }
            return false;
        }
        true
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.timer.enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            self.timer.disabled_until.store(0, Ordering::Relaxed);
        }
    }

    pub fn should_block(&self, qname: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        {
            let allow = self.allowlist.read();
            if Self::match_allow(&allow, qname) {
                return false;
            }
        }
        let block = self.blocklist.read();
        if let Some(bl) = block.as_ref() {
            return Self::match_block(bl, qname);
        }
        false
    }

    fn match_allow(set: &HashSet<String>, qname: &str) -> bool {
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

    fn match_block(bl: &DiskBlocklist, qname: &str) -> bool {
        if bl.contains(qname) {
            return true;
        }
        let mut current = qname;
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if current.is_empty() {
                break;
            }
            if bl.contains(current) {
                return true;
            }
        }
        false
    }

    pub fn inc_ip_stats(&self, ip: IpAddr) {
        self.per_ip_stats
            .entry(ip)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn replace_blocklist(&self, new_list: DiskBlocklist) {
        let count = new_list.len();
        *self.blocklist.write() = Some(Arc::new(new_list));
        info!("AdBlocker: blocklist updated with {} entries", count);
    }

    pub fn clear_blocklist(&self) {
        *self.blocklist.write() = None;
        info!("AdBlocker: blocklist cleared");
    }

    pub fn replace_allowlist(&self, new_list: HashSet<String>) {
        let count = new_list.len();
        *self.allowlist.write() = Arc::new(new_list);
        info!("AdBlocker: allowlist updated with {} entries", count);
    }

    pub fn replace_rewrites(&self, new_rules: Vec<crate::config::RewriteRule>) {
        let count = new_rules.len();
        *self.rewrites.write() = Arc::new(new_rules);
        info!("AdBlocker: rewrites updated with {} entries", count);
    }

    pub fn replace_config(
        &self,
        mode: BlockingMode,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) {
        *self.config.write() = Arc::new(AdblockRuntimeConfig { mode, ipv4, ipv6 });
        info!("AdBlocker: runtime config updated (mode: {:?})", mode);
    }

    pub fn add_block(&self, _domain: &str) {
        // We no longer support manual ad-hoc blocks in the DiskBlocklist for now,
        // as it is read-only from mmap. Manual blocks should be added to config.
    }

    pub fn add_allow(&self, domain: &str) {
        let mut list_lock = self.allowlist.write();
        let mut new_set = (**list_lock).clone();
        new_set.insert(domain.to_lowercase());
        *list_lock = Arc::new(new_set);
    }

    #[must_use]
    pub fn blocklist_size(&self) -> usize {
        self.blocklist.read().as_ref().map_or(0, |bl| bl.len())
    }

    #[must_use]
    pub fn allowlist_size(&self) -> usize {
        self.allowlist.read().len()
    }

    pub fn resolve_rewrite(&self, qname: &str) -> Option<RewriteAnswer> {
        let rewrites = Arc::clone(&*self.rewrites.read());
        if let Some(rule) = rewrites.iter().find(|r| r.domain == qname) {
            return Some(rule.parse_answer());
        }
        rewrites
            .iter()
            .find(|rule| {
                if rule.domain.starts_with("*.") {
                    let base = &rule.domain[2..];
                    qname == base || qname.ends_with(&format!(".{base}"))
                } else {
                    false
                }
            })
            .map(crate::config::RewriteRule::parse_answer)
    }

    pub fn load_from_urls(&self, name: &str, urls: &[String]) -> Result<HashSet<String>, DnsError> {
        let mut new_list = HashSet::new();
        let agent = ureq::Agent::new_with_defaults();
        let mut total_domains = 0;
        let mut successful_urls = 0;

        info!(
            "🛡️ AdBlocker: Starting {} update from {} sources",
            name,
            urls.len()
        );

        for url in urls {
            if !self.is_enabled() {
                info!(
                    "🛡️ AdBlocker: stopping {} update — adblock was disabled",
                    name
                );
                return Err(DnsError::Generic(format!(
                    "Adblock disabled during {} update",
                    name
                )));
            }
            trace!("AdBlocker: fetching {}", url);
            match agent.get(url).call() {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        error!(
                            "❌ AdBlocker: source {} returned status {}",
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
                        let domain = line.trim();
                        if domain.is_empty() || domain.starts_with('#') {
                            continue;
                        }

                        // Handle both "domain" and "1.2.3.4 domain" (hosts file) formats
                        let domain = if let Some((_ip, d)) = domain.split_once(char::is_whitespace)
                        {
                            d.trim()
                        } else {
                            domain
                        };

                        if !domain.is_empty() {
                            new_list.insert(domain.to_lowercase());
                            line_count += 1;
                        }
                    }
                    info!("✅ AdBlocker: loaded {} domains from {}", line_count, url);
                    total_domains += line_count;
                    successful_urls += 1;
                }
                Err(e) => {
                    error!("❌ AdBlocker: failed to fetch {}: {}", url, e);
                }
            }
        }
        info!(
            "🎉 AdBlocker: {} update complete. Total unique domains: {} (from {} total lines). Sources: {}/{}",
            name,
            new_list.len(),
            total_domains,
            successful_urls,
            urls.len()
        );
        Ok(new_list)
    }

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

    pub fn apply_adblock_wire(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion,
        ctx: &DnsContext,
        resp: &mut Vec<u8>,
    ) {
        let edns = WireOptScanner::scan(data, header, question);
        let ra = !ctx.recursive.is_empty();
        let config = Arc::clone(&*self.config.read());

        match config.mode {
            BlockingMode::NxDomain => {
                WireResponseWriter::write_error_response(data, question, 3, edns, ra, resp);
            }
            BlockingMode::NullIp => {
                let qtype = DnsRecordType::from(question.qtype());
                let ips = if qtype == DnsRecordType::AAAA {
                    vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
                } else {
                    vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]
                };
                WireResponseWriter::write_ip_response(data, question, &ips, 3600, edns, ra, resp);
            }
            BlockingMode::CustomIp => {
                let qtype = DnsRecordType::from(question.qtype());
                let ips = if qtype == DnsRecordType::AAAA {
                    vec![IpAddr::V6(config.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))]
                } else {
                    vec![IpAddr::V4(config.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED))]
                };
                WireResponseWriter::write_ip_response(data, question, &ips, 3600, edns, ra, resp);
            }
            BlockingMode::Refused => {
                WireResponseWriter::write_error_response(data, question, 5, edns, ra, resp);
            }
        }
    }

    pub fn apply_adblock_fallback(
        &self,
        _ctx: &DnsContext,
        rb: &ResponseBuilder,
        qname: &str,
        qtype: DnsRecordType,
        _src_addr: IpAddr,
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
            resp.clear();
            let config = Arc::clone(&*self.config.read());
            match config.mode {
                BlockingMode::NxDomain => {
                    resp.extend_from_slice(&rb.nxdomain()?);
                }
                BlockingMode::NullIp => {
                    let ips = if qtype == DnsRecordType::AAAA {
                        vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
                    } else {
                        vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)]
                    };
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                }
                BlockingMode::CustomIp => {
                    let ips = if qtype == DnsRecordType::AAAA {
                        vec![IpAddr::V6(config.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))]
                    } else {
                        vec![IpAddr::V4(
                            config.ipv4.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                        )]
                    };
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                }
                BlockingMode::Refused => {
                    resp.extend_from_slice(&rb.refused()?);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for AdBlocker {
    fn default() -> Self {
        Self::new(false)
    }
}

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

#[must_use]
pub fn hash_set_unordered<T: Hash>(set: &HashSet<T>) -> u64 {
    let mut total_hash = 0u64;
    for item in set {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        total_hash = total_hash.wrapping_add(hasher.finish());
    }
    total_hash
}
