use std::iter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use lanforge_core::context::LanforgeContext;
use parking_lot::RwLock;
use tracing::{debug, warn};

use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{
    AdblockPolicy, BlockingMode, ClientSelector, FilterAction, FilterMatch, FilterOrigin,
};

use crate::server::DnsContext;

pub mod blocklist;
pub mod engine;
pub mod manifest;
pub mod manual;
pub mod source;
pub use blocklist::{DiskBlocklist, ListMatches};
pub use manual::ManualRules;

/// Most groups the filter runs, the global one included: one bit each in
/// [`ClientLayers::groups`].
pub const MAX_GROUPS: usize = 64;

/// The global layer's bit: group 0, the group every client is in.
const GLOBAL_BIT: u64 = 1;

pub struct AdBlocker {
    /// The loaded lists, every group's, with the bits of each group. Lock after `layers`.
    lists: RwLock<Option<Arc<LoadedLists>>>,
    /// The groups, the global one first. Lock before `lists`.
    layers: RwLock<Arc<Layers>>,
    pub timer: Arc<AdblockTimerState>,
    pub config: RwLock<AdblockRuntimeConfig>,
    per_ip_stats: DashMap<IpAddr, AtomicU64>,
}

/// The groups a client is in, one bit each (bit = position in [`Layers::groups`]): always the
/// global group (bit 0) unless bypassed, plus its `[adblock.groups]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientLayers {
    pub bypass: bool,
    pub groups: u64,
}

impl ClientLayers {
    /// Only the global group: a client in no other group, or one not (yet) known.
    pub const GLOBAL: Self = Self {
        bypass: false,
        groups: GLOBAL_BIT,
    };
}

/// The filter's groups. Group 0 is the global layer: every client is in it, its rules are the
/// global rules file's and its lists every list no other group adds. The others are
/// `[adblock.groups]`, in file order (lists by source id).
#[derive(Clone)]
struct Layers {
    groups: Vec<Group>,
    bypass: Vec<ClientSelector>,
    /// Whether a selector needs the client's device (`dev:`), not only its address.
    by_device: bool,
}

impl Default for Layers {
    fn default() -> Self {
        Self {
            groups: vec![Group::global(Arc::default())],
            bypass: Vec::new(),
            by_device: false,
        }
    }
}

#[derive(Clone)]
struct Group {
    /// `None` for the global group: its matches carry the global origins.
    name: Option<Box<str>>,
    sources: Vec<i64>,
    rules: Arc<ManualRules>,
    clients: Vec<ClientSelector>,
}

impl Group {
    const fn global(rules: Arc<ManualRules>) -> Self {
        Self {
            name: None,
            sources: Vec::new(),
            rules,
            clients: Vec::new(),
        }
    }
}

/// The lists, with the bits of each group's lists in the index.
struct LoadedLists {
    index: Arc<DiskBlocklist>,
    /// One mask per group, in group order; the global group's is every list no other adds.
    groups: Box<[u64]>,
}

impl LoadedLists {
    fn new(index: Arc<DiskBlocklist>, layers: &Layers) -> Self {
        let mut groups: Vec<u64> = layers
            .groups
            .iter()
            .map(|g| index.mask_of(&g.sources))
            .collect();
        groups[0] = !groups[1..].iter().fold(0, |acc, m| acc | m);
        Self {
            groups: groups.into_boxed_slice(),
            index,
        }
    }
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
            lists: RwLock::new(None),
            layers: RwLock::new(Arc::new(Layers::default())),
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

    /// The global layer's verdict for `qname`: what a client in no group gets.
    pub fn check_domain(&self, qname: &str) -> Option<FilterMatch> {
        self.check(qname, ClientLayers::GLOBAL)
    }

    /// The verdict for `qname` asked by a client in `client`'s groups. A bypassed client is
    /// never filtered. Otherwise the groups form a ladder of overrides, from the top: the
    /// client's groups (all on one step; an allow of one wins over a block of another), then
    /// the global group at the base. The highest step with a verdict decides, so a group allow
    /// wins over any global block, `$important` included. In a step, its rules files (the
    /// admin's overrides) decide before its lists (each with its own precedence).
    pub fn check(&self, qname: &str, client: ClientLayers) -> Option<FilterMatch> {
        if client.bypass || !self.is_enabled() {
            return None;
        }
        let layers = self.layers.read().clone();
        let lists = self.lists.read().clone();
        // Every list is walked once, and only when a step's rules leave the name undecided.
        let mut matched: Option<ListMatches> = None;
        for step in [client.groups & !GLOBAL_BIT, client.groups & GLOBAL_BIT] {
            if step == 0 {
                continue;
            }
            if let Some(m) =
                Self::step_verdict(&layers, lists.as_deref(), &mut matched, qname, step)
            {
                return Some(m);
            }
        }
        None
    }

    /// The verdict of one step of the ladder: the groups of `step` (bits), their rules files
    /// first (of several, an allow wins), then their lists.
    fn step_verdict(
        layers: &Layers,
        lists: Option<&LoadedLists>,
        matched: &mut Option<ListMatches>,
        qname: &str,
        step: u64,
    ) -> Option<FilterMatch> {
        let in_step = |bit: usize| step & (1 << bit) != 0;
        let mut block = None;
        for (_, group) in layers
            .groups
            .iter()
            .enumerate()
            .filter(|(bit, _)| in_step(*bit))
        {
            let Some(v) = group.rules.verdict(qname) else {
                continue;
            };
            let allow = v.action == FilterAction::Allow;
            let found = FilterMatch {
                action: v.action,
                origin: match (&group.name, allow) {
                    (None, true) => FilterOrigin::UserAllowlist,
                    (None, false) => FilterOrigin::UserRule,
                    (Some(name), true) => FilterOrigin::GroupAllowlist {
                        group: name.clone(),
                    },
                    (Some(name), false) => FilterOrigin::GroupRule {
                        group: name.clone(),
                    },
                },
                rule: (v.domain != qname).then(|| v.domain.into()),
                important: v.important,
            };
            if allow {
                return Some(found);
            }
            block.get_or_insert(found);
        }
        if block.is_some() {
            return block;
        }

        let l = lists?;
        let mask = l
            .groups
            .iter()
            .enumerate()
            .filter(|(bit, _)| in_step(*bit))
            .fold(0, |acc, (_, m)| acc | m);
        if mask == 0 {
            return None;
        }
        let m = *matched.get_or_insert_with(|| l.index.match_lists(qname));
        let (action, list_bit, important) = Self::list_verdict(m.masked(mask))?;
        let source_id = l.index.source_id(list_bit);
        // Attributed to the first group of the step that has the deciding list.
        let name = layers
            .groups
            .iter()
            .enumerate()
            .find(|(bit, _)| in_step(*bit) && l.groups[*bit] & (1 << list_bit) != 0)
            .and_then(|(_, g)| g.name.clone());
        Some(FilterMatch {
            action,
            origin: match name {
                None => FilterOrigin::List { source_id },
                Some(group) => FilterOrigin::GroupList { group, source_id },
            },
            rule: None,
            important,
        })
    }

    /// The lists' verdict, `AdGuard` precedence: an important block wins unless an important allow
    /// also matches; otherwise any allow wins over any block. With the bit of the first list
    /// deciding it, which the verdict is attributed to.
    fn list_verdict(m: ListMatches) -> Option<(FilterAction, u32, bool)> {
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
        Some((action, mask.trailing_zeros(), important))
    }

    /// Whether the global layer blocks `qname`.
    #[inline]
    pub fn should_block(&self, qname: &str) -> bool {
        self.check_domain(qname)
            .is_some_and(|m| m.action == FilterAction::Block)
    }

    /// The names of the `[adblock.groups]` set in `client`, in group order (not the global one).
    #[must_use]
    pub fn group_names(&self, client: ClientLayers) -> Vec<String> {
        self.layers
            .read()
            .groups
            .iter()
            .enumerate()
            .filter(|(bit, _)| client.groups & (1 << bit) != 0)
            .filter_map(|(_, g)| g.name.as_deref().map(String::from))
            .collect()
    }

    /// The groups of the client at `ip`. Without groups or `bypass` every client is only in the
    /// global group and nothing is looked up; a `dev:` selector looks the client's device up by its
    /// address (lease, static host, neighbour cache). An address no device is known for gets
    /// only what its subnet selectors give, never `bypass` by accident of an unknown name.
    pub fn client_layers(&self, ctx: &LanforgeContext, ip: IpAddr) -> ClientLayers {
        let layers = self.layers.read().clone();
        if layers.bypass.is_empty() && layers.groups.len() == 1 {
            return ClientLayers::GLOBAL;
        }
        let mac = if layers.by_device {
            ctx.get_mac_by_ip(ip)
        } else {
            None
        };
        ctx.with_state(|state| {
            let device = mac.and_then(|m| state.devices.get(&m)).map(|d| &**d);
            let is = |s: &ClientSelector| s.matches(ip, mac, device);
            if layers.bypass.iter().any(is) {
                return ClientLayers {
                    bypass: true,
                    groups: 0,
                };
            }
            let groups = layers
                .groups
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(_, g)| g.clients.iter().any(is))
                .fold(GLOBAL_BIT, |acc, (bit, _)| acc | (1 << bit));
            ClientLayers {
                bypass: false,
                groups,
            }
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
        let layers = self.layers.read();
        *self.lists.write() = Some(Arc::new(LoadedLists::new(Arc::new(new_list), &layers)));
        debug!("Adblock: blocklist updated with {} entries", count);
    }

    pub fn clear_blocklist(&self) {
        *self.lists.write() = None;
        debug!("Adblock: blocklist cleared");
    }

    /// Loads the global rules file's text and the groups from the context.
    pub fn sync_from_context(&self, ctx: &LanforgeContext) {
        ctx.with_config(|c| {
            self.replace_rules(&c.dns_adblock_rules.0);
            self.replace_layers(&c.dns_adblock_policy);
        });
    }

    /// Sets the groups and `bypass`, keeping the global group's rules; the loaded lists stay,
    /// only their group bits change (a list no group adds is global). Groups past
    /// [`MAX_GROUPS`] are left out.
    pub fn replace_layers(&self, policy: &AdblockPolicy) {
        if policy.groups.len() >= MAX_GROUPS {
            warn!(
                configured = policy.groups.len(),
                max = MAX_GROUPS - 1,
                "Adblock: too many groups, the extra ones are ignored"
            );
        }
        let global = Arc::clone(&self.layers.read().groups[0].rules);
        let groups = iter::once(Group::global(global))
            .chain(policy.groups.iter().take(MAX_GROUPS - 1).map(|g| Group {
                name: Some(g.name.as_str().into()),
                sources: g.sources.iter().map(|s| s.source_id()).collect(),
                rules: Arc::new(ManualRules::from_text(&g.rules)),
                clients: g.clients.clone(),
            }))
            .collect();
        self.install(Layers {
            groups,
            bypass: policy.bypass.clone(),
            by_device: policy
                .bypass
                .iter()
                .chain(policy.groups.iter().flat_map(|g| &g.clients))
                .any(ClientSelector::needs_device),
        });
    }

    /// Replaces the global group's rules with those of the global rules file's text.
    pub fn replace_rules(&self, text: &str) {
        let rules = ManualRules::from_text(text);
        debug!(
            blocks = rules.block_len(),
            allows = rules.allow_len(),
            "Adblock: global rules updated"
        );
        let mut layers = (**self.layers.read()).clone();
        layers.groups[0].rules = Arc::new(rules);
        self.install(layers);
    }

    /// Makes `layers` the running groups, with the loaded lists' group bits recomputed.
    fn install(&self, layers: Layers) {
        let mut current = self.layers.write();
        let mut lists = self.lists.write();
        if let Some(l) = lists.as_ref() {
            *lists = Some(Arc::new(LoadedLists::new(Arc::clone(&l.index), &layers)));
        }
        debug!(
            groups = layers.groups.len() - 1,
            bypass = layers.bypass.len(),
            "Adblock: groups updated"
        );
        *current = Arc::new(layers);
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
        let disk_size = self.lists.read().as_ref().map_or(0, |l| l.index.len());
        disk_size + self.layers.read().groups[0].rules.block_len()
    }

    #[must_use]
    pub fn allowlist_size(&self) -> usize {
        self.layers.read().groups[0].rules.allow_len()
    }

    #[must_use]
    pub fn exceptions_size(&self) -> usize {
        self.lists
            .read()
            .as_ref()
            .map_or(0, |l| l.index.exceptions_len())
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
