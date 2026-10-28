use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::debug;

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
pub mod source;
pub use blocklist::{DiskBlocklist, ListMatches};

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
        block_guard
            .as_ref()
            .and_then(|bl| Self::list_verdict(bl, bl.match_lists(qname)))
    }

    /// The lists' verdict, AdGuard precedence: an important block wins unless an important allow
    /// also matches; otherwise any allow wins over any block. Attributed to the first list.
    fn list_verdict(bl: &DiskBlocklist, m: ListMatches) -> Option<FilterMatch> {
        let (action, mask, important) = if m.block_important != 0 && m.allow_important == 0 {
            (FilterAction::Block, m.block_important, true)
        } else if m.allow != 0 {
            let important = m.allow_important != 0;
            let mask = if important {
                m.allow_important
            } else {
                m.allow
            };
            (FilterAction::Allow, mask, important)
        } else if m.block != 0 {
            (FilterAction::Block, m.block, false)
        } else {
            return None;
        };
        Some(FilterMatch {
            action,
            origin: FilterOrigin::List {
                source_id: bl.source_id(mask.trailing_zeros()),
            },
            rule: None,
            important,
        })
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
        block_guard.as_ref().is_some_and(|bl| {
            Self::list_verdict(bl, bl.match_lists(qname))
                .is_some_and(|m| m.action == FilterAction::Block)
        })
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
            .map(|bl| bl.exceptions_len())
            .unwrap_or(0)
    }
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
