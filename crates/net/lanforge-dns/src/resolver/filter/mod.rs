use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::header::LOCATION;
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use parking_lot::RwLock;
use tracing::{debug, error, info, trace};

use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    BlockingMode, FilterAction, FilterMatch, FilterOrigin,
};

use crate::error::DnsError;
use crate::resolver::builder::ResponseBuilder;
use crate::server::DnsContext;

pub mod blocklist;
pub mod engine;
pub mod manifest;
pub mod parse;
pub mod source;
pub use blocklist::DiskBlocklist;

pub struct AdBlocker {
    pub blocklist: RwLock<Option<Arc<DiskBlocklist>>>,
    pub allowlist: RwLock<Arc<HashSet<Box<str>>>>,
    pub custom_blocks: RwLock<Arc<HashSet<Box<str>>>>,
    pub timer: Arc<AdblockTimerState>,
    pub config: RwLock<AdblockRuntimeConfig>,
    per_ip_stats: DashMap<IpAddr, AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
            custom_blocks: RwLock::new(Arc::new(HashSet::new())),
            timer: Arc::new(AdblockTimerState::new(enabled)),
            config: RwLock::new(AdblockRuntimeConfig::default()),
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

    /// Evaluates a domain against custom rules, allowlist, and compiled blocklist, returning match attribution.
    pub fn check_domain(&self, qname: &str) -> Option<FilterMatch> {
        if !self.is_enabled() {
            return None;
        }
        {
            let allow = self.allowlist.read();
            if let Some(rule) = Self::find_matching_rule(&allow, qname) {
                let rule_str = if rule != qname {
                    Some(rule.into())
                } else {
                    None
                };
                return Some(FilterMatch {
                    action: FilterAction::Allow,
                    origin: FilterOrigin::UserAllowlist,
                    rule: rule_str,
                    important: false,
                });
            }
        }
        {
            let custom_blocks = self.custom_blocks.read();
            if let Some(rule) = Self::find_matching_rule(&custom_blocks, qname) {
                let rule_str = if rule != qname {
                    Some(rule.into())
                } else {
                    None
                };
                return Some(FilterMatch {
                    action: FilterAction::Block,
                    origin: FilterOrigin::UserRule,
                    rule: rule_str,
                    important: false,
                });
            }
        }
        let block_guard = self.blocklist.read();
        if let Some(bl) = block_guard.as_ref() {
            let (allow_cand, block_cand) = bl.match_domain_pair(qname);

            match (allow_cand, block_cand) {
                (Some(a), Some(b)) => {
                    if b.flags.is_important() && !a.flags.is_important() {
                        let source_id = bl.resolve_source_id(b.source_idx);
                        return Some(FilterMatch {
                            action: FilterAction::Block,
                            origin: FilterOrigin::List { source_id },
                            rule: None,
                            important: true,
                        });
                    }
                    let source_id = bl.resolve_source_id(a.source_idx);
                    Some(FilterMatch {
                        action: FilterAction::Allow,
                        origin: FilterOrigin::List { source_id },
                        rule: None,
                        important: a.flags.is_important(),
                    })
                }
                (Some(a), None) => {
                    let source_id = bl.resolve_source_id(a.source_idx);
                    Some(FilterMatch {
                        action: FilterAction::Allow,
                        origin: FilterOrigin::List { source_id },
                        rule: None,
                        important: a.flags.is_important(),
                    })
                }
                (None, Some(b)) => {
                    let source_id = bl.resolve_source_id(b.source_idx);
                    Some(FilterMatch {
                        action: FilterAction::Block,
                        origin: FilterOrigin::List { source_id },
                        rule: None,
                        important: b.flags.is_important(),
                    })
                }
                (None, None) => None,
            }
        } else {
            None
        }
    }

    #[inline]
    pub fn should_block(&self, qname: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        {
            let allow = self.allowlist.read();
            if Self::find_matching_rule(&allow, qname).is_some() {
                return false;
            }
        }
        {
            let custom_blocks = self.custom_blocks.read();
            if Self::find_matching_rule(&custom_blocks, qname).is_some() {
                return true;
            }
        }
        let block_guard = self.blocklist.read();
        let Some(bl) = block_guard.as_ref() else {
            return false;
        };
        let mut key_buf = [0u8; 256];
        let Some(len) = engine::encode_reversed_domain(qname, &mut key_buf) else {
            return false;
        };
        let rev_key = &key_buf[..len];
        let Some(b) = bl.block_map.match_reversed(rev_key) else {
            return false;
        };
        if b.flags.is_important() {
            return true;
        }
        bl.allow_map
            .as_ref()
            .and_then(|m| m.match_reversed(rev_key))
            .is_none()
    }

    fn find_matching_rule<'a>(set: &'a HashSet<Box<str>>, qname: &str) -> Option<&'a str> {
        if set.is_empty() {
            return None;
        }
        if let Some(r) = set.get(qname) {
            return Some(r);
        }
        let mut current = qname;
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if current.is_empty() {
                break;
            }
            if let Some(r) = set.get(current) {
                return Some(r);
            }
        }
        None
    }

    pub fn inc_ip_stats(&self, ip: IpAddr) {
        if let Some(counter) = self.per_ip_stats.get(&ip) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.per_ip_stats
            .entry(ip)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn replace_blocklist(&self, new_list: DiskBlocklist) {
        let count = new_list.len();
        *self.blocklist.write() = Some(Arc::new(new_list));
        debug!("Adblock: blocklist updated with {} entries", count);
    }

    pub fn clear_blocklist(&self) {
        *self.blocklist.write() = None;
        debug!("Adblock: blocklist cleared");
    }

    #[must_use]
    pub fn normalize_custom_domain(raw: &str) -> Option<Box<str>> {
        let mut s = raw.trim();
        if let Some(rest) = s.strip_prefix("@@") {
            s = rest;
        }
        if let Some(rest) = s.strip_prefix("||") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("*.") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('|') {
            s = rest;
        }
        if let Some((before_mod, _)) = s.split_once('$') {
            s = before_mod;
        }
        s = s
            .trim_end_matches('^')
            .trim_end_matches('|')
            .trim_end_matches('.');
        if s.is_empty() {
            return None;
        }
        Some(s.to_ascii_lowercase().into_boxed_str())
    }

    pub fn sync_from_context(&self, ctx: &lanforge_core::context::LanforgeContext) {
        let mut allow_set: HashSet<Box<str>> = ctx
            .get_dns_allowlist()
            .into_iter()
            .filter_map(|d| Self::normalize_custom_domain(&d))
            .collect();
        let mut block_set: HashSet<Box<str>> = HashSet::new();
        for rule in ctx.get_dns_adblock_rules() {
            if rule.enabled
                && let Some(norm) = Self::normalize_custom_domain(&rule.domain)
            {
                if rule.is_allow() {
                    allow_set.insert(norm);
                } else if rule.is_block() {
                    block_set.insert(norm);
                }
            }
        }
        *self.allowlist.write() = Arc::new(allow_set);
        *self.custom_blocks.write() = Arc::new(block_set);
    }

    pub fn replace_allowlist(&self, new_list: HashSet<String>) {
        let boxed_set: HashSet<Box<str>> = new_list
            .into_iter()
            .filter_map(|d| Self::normalize_custom_domain(&d))
            .collect();
        let count = boxed_set.len();
        *self.allowlist.write() = Arc::new(boxed_set);
        debug!("Adblock: allowlist updated with {} entries", count);
    }

    pub fn replace_custom_blocks(&self, new_blocks: HashSet<String>) {
        let boxed_set: HashSet<Box<str>> = new_blocks
            .into_iter()
            .filter_map(|d| Self::normalize_custom_domain(&d))
            .collect();
        let count = boxed_set.len();
        *self.custom_blocks.write() = Arc::new(boxed_set);
        debug!("Adblock: custom blocks updated with {} entries", count);
    }

    pub fn replace_config(
        &self,
        mode: BlockingMode,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) {
        *self.config.write() = AdblockRuntimeConfig { mode, ipv4, ipv6 };
        debug!("Adblock: runtime config updated (mode: {:?})", mode);
    }

    pub fn add_block(&self, domain: &str) {
        if let Some(norm) = Self::normalize_custom_domain(domain) {
            let mut list_lock = self.custom_blocks.write();
            let mut new_set = (**list_lock).clone();
            new_set.insert(norm);
            *list_lock = Arc::new(new_set);
        }
    }

    pub fn remove_block(&self, domain: &str) {
        if let Some(norm) = Self::normalize_custom_domain(domain) {
            let mut list_lock = self.custom_blocks.write();
            let mut new_set = (**list_lock).clone();
            new_set.remove(norm.as_ref());
            *list_lock = Arc::new(new_set);
        }
    }

    pub fn add_allow(&self, domain: &str) {
        if let Some(norm) = Self::normalize_custom_domain(domain) {
            let mut list_lock = self.allowlist.write();
            let mut new_set = (**list_lock).clone();
            new_set.insert(norm);
            *list_lock = Arc::new(new_set);
        }
    }

    pub fn remove_allow(&self, domain: &str) {
        if let Some(norm) = Self::normalize_custom_domain(domain) {
            let mut list_lock = self.allowlist.write();
            let mut new_set = (**list_lock).clone();
            new_set.remove(norm.as_ref());
            *list_lock = Arc::new(new_set);
        }
    }

    #[must_use]
    pub fn blocklist_size(&self) -> usize {
        let disk_size = self.blocklist.read().as_ref().map_or(0, |bl| bl.len());
        let custom_size = self.custom_blocks.read().len();
        disk_size + custom_size
    }

    #[must_use]
    pub fn allowlist_size(&self) -> usize {
        self.allowlist.read().len()
    }

    #[must_use]
    pub fn exceptions_size(&self) -> usize {
        self.blocklist
            .read()
            .as_ref()
            .and_then(|bl| {
                bl.allow_map
                    .as_ref()
                    .map(crate::resolver::filter::engine::DiskFilterMap::len)
            })
            .unwrap_or(0)
    }

    pub async fn load_from_urls(
        &self,
        name: &str,
        urls: &[String],
    ) -> Result<HashSet<String>, DnsError> {
        let mut new_list = HashSet::new();
        let client = source::build_adblock_http_client();

        let mut total_domains = 0;

        let mut successful_urls = 0;

        info!(
            "Adblock: Starting {name} update from {} sources",
            urls.len()
        );

        for url in urls {
            if !self.is_enabled() {
                info!("Adblock: stopping {name} update — adblock was disabled");
                return Err(DnsError::Generic(format!(
                    "Adblock disabled during {name} update"
                )));
            }
            trace!("Adblock: fetching {}", url);
            match fetch_url(&client, url.clone()).await {
                Ok(body_bytes) => {
                    let mut line_count = 0;
                    let text = String::from_utf8_lossy(&body_bytes);
                    for line in text.lines() {
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
                    debug!("Adblock: loaded {} domains from {}", line_count, url);
                    total_domains += line_count;
                    successful_urls += 1;
                }
                Err(e) => {
                    error!("Adblock: failed to fetch {}: {}", url, e);
                }
            }
        }
        info!(
            "Adblock: {name} update complete (unique: {}, raw lines: {}, sources: {}/{})",
            new_list.len(),
            total_domains,
            successful_urls,
            urls.len()
        );
        Ok(new_list)
    }
}

async fn fetch_url(
    client: &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    target_url: String,
) -> Result<Bytes, DnsError> {
    tokio::time::timeout(
        Duration::from_secs(120),
        fetch_url_inner(client, target_url),
    )
    .await
    .map_err(|_| DnsError::Generic("Request timed out (120s limit)".to_string()))?
}

async fn fetch_url_inner(
    client: &Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    mut target_url: String,
) -> Result<Bytes, DnsError> {
    const MAX_BODY_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

    for _ in 0..5 {
        let uri: Uri = target_url
            .parse()
            .map_err(|e| DnsError::Generic(format!("Invalid URL: {e}")))?;

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .header("User-Agent", "lanforge-dns")
            .body(Full::default())
            .map_err(|e| DnsError::Generic(e.to_string()))?;

        let resp = client.request(req).await.map_err(|e| {
            DnsError::Generic(format!(
                "HTTP request error: {}",
                source::format_error_chain(&e)
            ))
        })?;

        let status = resp.status();

        if status.is_redirection() {
            if let Some(loc) = resp.headers().get(LOCATION) {
                let loc_str = loc
                    .to_str()
                    .map_err(|e| DnsError::Generic(format!("Invalid redirect location: {e}")))?;
                if loc_str.starts_with("http://") || loc_str.starts_with("https://") {
                    target_url = loc_str.to_string();
                } else if loc_str.starts_with('/') {
                    let authority = uri.authority().map_or("", |a| a.as_str());
                    let scheme = uri.scheme_str().unwrap_or("https");
                    target_url = format!("{scheme}://{authority}{loc_str}");
                } else {
                    target_url = loc_str.to_string();
                }
                continue;
            }
            return Err(DnsError::Generic(
                "Redirect without Location header".to_string(),
            ));
        }

        if !status.is_success() {
            return Err(DnsError::Generic(format!("HTTP status {status}")));
        }

        let mut body = resp.into_body();
        let mut body_bytes = Vec::new();

        while let Some(frame_res) = body.frame().await {
            let frame =
                frame_res.map_err(|e| DnsError::Generic(format!("Body frame error: {e}")))?;
            if let Ok(data) = frame.into_data() {
                if body_bytes.len() + data.len() > MAX_BODY_SIZE {
                    return Err(DnsError::Generic(format!(
                        "Response body exceeded limit of 64 MiB (read {} bytes)",
                        body_bytes.len() + data.len()
                    )));
                }
                body_bytes.extend_from_slice(&data);
            }
        }
        return Ok(Bytes::from(body_bytes));
    }

    Err(DnsError::Generic("Too many redirects".to_string()))
}

impl AdBlocker {
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
        let config = *self.config.read();

        match config.mode {
            BlockingMode::NxDomain => {
                WireResponseWriter::write_error_response(data, question, 3, edns, ra, resp);
            }
            BlockingMode::NullIp => {
                let qtype = DnsRecordType::from(question.qtype());
                let ip = if qtype == DnsRecordType::AAAA {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                };
                WireResponseWriter::write_ip_response(data, question, &[ip], 3600, edns, ra, resp);
            }
            BlockingMode::CustomIp => {
                let qtype = DnsRecordType::from(question.qtype());
                let ip = if qtype == DnsRecordType::AAAA {
                    IpAddr::V6(config.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))
                } else {
                    IpAddr::V4(config.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED))
                };
                WireResponseWriter::write_ip_response(data, question, &[ip], 3600, edns, ra, resp);
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
            let config = *self.config.read();
            match config.mode {
                BlockingMode::NxDomain => {
                    resp.extend_from_slice(&rb.nxdomain()?);
                }
                BlockingMode::NullIp => {
                    let ips = if qtype == DnsRecordType::AAAA {
                        vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
                    } else {
                        vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]
                    };
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                }
                BlockingMode::CustomIp => {
                    let ips = if qtype == DnsRecordType::AAAA {
                        vec![IpAddr::V6(config.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED))]
                    } else {
                        vec![IpAddr::V4(config.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED))]
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
pub fn hash_set_unordered<T: Hash>(set: &HashSet<T>) -> u64 {
    let mut total_hash = 0u64;
    for item in set {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        total_hash = total_hash.wrapping_add(hasher.finish());
    }
    total_hash
}
