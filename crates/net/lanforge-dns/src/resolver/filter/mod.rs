use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use lanforge_core::context::LanforgeContext;
use parking_lot::RwLock;
use tracing::debug;

use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    BlockingMode, FilterAction, FilterMatch, FilterOrigin,
};

use crate::server::DnsContext;

pub mod blocklist;
pub mod engine;
pub mod manifest;
pub mod manual;
pub mod source;
pub use blocklist::{DiskBlocklist, ListMatches};
pub use manual::ManualRules;

pub struct AdBlocker {
    pub blocklist: RwLock<Option<Arc<DiskBlocklist>>>,
    /// The rules files' rules, checked before the lists.
    pub manual: RwLock<Arc<ManualRules>>,
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
            manual: RwLock::new(Arc::new(ManualRules::default())),
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

    /// Evaluates a domain against the manual rules, then the lists, returning match attribution.
    pub fn check_domain(&self, qname: &str) -> Option<FilterMatch> {
        if !self.is_enabled() {
            return None;
        }
        if let Some(v) = self.manual.read().verdict(qname) {
            return Some(FilterMatch {
                action: v.action,
                origin: if v.action == FilterAction::Allow {
                    FilterOrigin::UserAllowlist
                } else {
                    FilterOrigin::UserRule
                },
                rule: (v.domain != qname).then(|| v.domain.into()),
                important: v.important,
            });
        }
        let block_guard = self.blocklist.read();
        block_guard
            .as_ref()
            .and_then(|bl| Self::list_verdict(bl, bl.match_lists(qname)))
    }

    /// The lists' verdict, `AdGuard` precedence: an important block wins unless an important allow
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
        if let Some(v) = self.manual.read().verdict(qname) {
            return v.action == FilterAction::Block;
        }
        let block_guard = self.blocklist.read();
        block_guard.as_ref().is_some_and(|bl| {
            Self::list_verdict(bl, bl.match_lists(qname))
                .is_some_and(|m| m.action == FilterAction::Block)
        })
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

    /// Loads the manual rules from the context (the global rules file's text).
    pub fn sync_from_context(&self, ctx: &LanforgeContext) {
        ctx.with_config(|c| self.replace_rules(&c.dns_adblock_rules.0));
    }

    /// Replaces the manual rules with those of a rules file's text.
    pub fn replace_rules(&self, text: &str) {
        let rules = ManualRules::from_text(text);
        debug!(
            blocks = rules.block_len(),
            allows = rules.allow_len(),
            "Adblock: manual rules updated"
        );
        *self.manual.write() = Arc::new(rules);
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

    #[must_use]
    pub fn blocklist_size(&self) -> usize {
        let disk_size = self.blocklist.read().as_ref().map_or(0, |bl| bl.len());
        disk_size + self.manual.read().block_len()
    }

    #[must_use]
    pub fn allowlist_size(&self) -> usize {
        self.manual.read().allow_len()
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
}

impl Default for AdBlocker {
    fn default() -> Self {
        Self::new(false)
    }
}
