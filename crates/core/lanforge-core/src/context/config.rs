//! Dynamic subsystem configuration storage and accessors.

use std::sync::Arc;
use tokio::sync::watch;

use lanforge_types::config::{
    ChangeImpact, ConfigSection, DnsAllowlist, DnsListenConfig, DomainSet,
};
use lanforge_types::network::dhcp::{
    DhcpOptionsConfig, Dhcpv4Options, Dhcpv4Pool, Dhcpv6Options, Dhcpv6Pool, TftpOptions,
};
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RaServerConfig, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, TrafficConfig};

use crate::bus::{DnsEvent, FirewallEvent, LanforgeEvent, SystemEvent, TrafficEvent};
use crate::context::LanforgeContext;

/// Operational delta for a configuration subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDelta<T> {
    /// Configuration value before the change.
    pub old: Arc<T>,
    /// New configuration value.
    pub new: Arc<T>,
    /// Evaluated operational impact of the change.
    pub impact: ChangeImpact,
}

/// An active watcher subscription to a specific configuration section.
pub struct ConfigSubscription<T: ConfigSection> {
    rx: watch::Receiver<Arc<T>>,
    applied: Arc<T>,
}

impl<T: ConfigSection> ConfigSubscription<T> {
    /// Creates a subscription from a watch receiver, initializing `applied` to current.
    #[must_use]
    pub fn new(rx: watch::Receiver<Arc<T>>) -> Self {
        let applied = rx.borrow().clone();
        Self { rx, applied }
    }

    /// Returns the most recently applied configuration value.
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        self.applied.clone()
    }

    /// Manually marks a configuration value as applied.
    pub fn mark_applied(&mut self, value: Arc<T>) {
        self.applied = value;
    }

    /// Waits for a configuration change relative to `applied`.
    ///
    /// Skips no-op changes (`impact == ChangeImpact::None`) and coalesces bursts.
    /// Returns `None` only on channel closure (shutdown).
    pub async fn next(&mut self) -> Option<ConfigDelta<T>> {
        loop {
            if self.rx.changed().await.is_err() {
                return None;
            }
            let candidate = self.rx.borrow_and_update().clone();
            let impact = T::classify(&self.applied, &candidate);
            if impact == ChangeImpact::None {
                continue;
            }
            let old = self.applied.clone();
            self.applied = candidate.clone();
            return Some(ConfigDelta {
                old,
                new: candidate,
                impact,
            });
        }
    }
}

/// Subscribable configuration section marker.
pub trait SubscribableSection: ConfigSection {
    /// Extracts the watch receiver for this section from the config store.
    fn extract_receiver(store: &ConfigStore) -> watch::Receiver<Arc<Self>>;
}

macro_rules! impl_subscribable {
    ($type:ty, $field:ident) => {
        impl SubscribableSection for $type {
            fn extract_receiver(store: &ConfigStore) -> watch::Receiver<Arc<Self>> {
                store.$field.1.clone()
            }
        }
    };
}

impl_subscribable!(PppoeConfig, pppoe);
impl_subscribable!(FirewallConfig, firewall);
impl_subscribable!(TrafficConfig, traffic);
impl_subscribable!(Vec<Dhcpv4Pool>, dhcp_v4_pools);
impl_subscribable!(Vec<Dhcpv6Pool>, dhcp_v6_pools);
impl_subscribable!(Dhcpv4Options, dhcp_v4_options);
impl_subscribable!(Dhcpv6Options, dhcp_v6_options);
impl_subscribable!(TftpOptions, tftp);
impl_subscribable!(RaServerConfig, ra_server);
impl_subscribable!(Vec<RAPrefix>, ra_prefixes);
impl_subscribable!(Vec<RdnssConfig>, ra_rdnss);
impl_subscribable!(Vec<DnsslConfig>, ra_dnssl);
impl_subscribable!(Vec<UpstreamTarget>, dns_upstreams);
impl_subscribable!(UpstreamMode, dns_upstream_mode);
impl_subscribable!(Vec<RewriteRule>, dns_rewrites);
impl_subscribable!(DnsAllowlist, dns_allowlist);
impl_subscribable!(AdblockDbConfig, dns_adblock);
impl_subscribable!(Vec<AdblockUrlEntry>, dns_adblock_urls);
impl_subscribable!(Vec<AdblockRuleEntry>, dns_adblock_rules);
impl_subscribable!(Vec<DnsReverseResolver>, dns_reverse);
impl_subscribable!(DnsListenConfig, dns_listen);

/// Type alias for a watch sender/receiver pair.
pub type WatchPair<T> = (watch::Sender<Arc<T>>, watch::Receiver<Arc<T>>);

/// In-memory storage of per-section configuration watch channels.
pub struct ConfigStore {
    pub pppoe: WatchPair<PppoeConfig>,
    pub firewall: WatchPair<FirewallConfig>,
    pub traffic: WatchPair<TrafficConfig>,
    pub dhcp_v4_pools: WatchPair<Vec<Dhcpv4Pool>>,
    pub dhcp_v6_pools: WatchPair<Vec<Dhcpv6Pool>>,
    pub dhcp_v4_options: WatchPair<Dhcpv4Options>,
    pub dhcp_v6_options: WatchPair<Dhcpv6Options>,
    pub tftp: WatchPair<TftpOptions>,
    pub ra_server: WatchPair<RaServerConfig>,
    pub ra_prefixes: WatchPair<Vec<RAPrefix>>,
    pub ra_rdnss: WatchPair<Vec<RdnssConfig>>,
    pub ra_dnssl: WatchPair<Vec<DnsslConfig>>,
    pub dns_upstreams: WatchPair<Vec<UpstreamTarget>>,
    pub dns_upstream_mode: WatchPair<UpstreamMode>,
    pub dns_rewrites: WatchPair<Vec<RewriteRule>>,
    pub dns_allowlist: WatchPair<DnsAllowlist>,
    pub dns_adblock: WatchPair<AdblockDbConfig>,
    pub dns_adblock_urls: WatchPair<Vec<AdblockUrlEntry>>,
    pub dns_adblock_rules: WatchPair<Vec<AdblockRuleEntry>>,
    pub dns_reverse: WatchPair<Vec<DnsReverseResolver>>,
    pub dns_listen: WatchPair<DnsListenConfig>,
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self {
            pppoe: watch::channel(Arc::new(PppoeConfig::default())),
            firewall: watch::channel(Arc::new(FirewallConfig::default())),
            traffic: watch::channel(Arc::new(TrafficConfig::default())),
            dhcp_v4_pools: watch::channel(Arc::new(Vec::new())),
            dhcp_v6_pools: watch::channel(Arc::new(Vec::new())),
            dhcp_v4_options: watch::channel(Arc::new(Dhcpv4Options::default())),
            dhcp_v6_options: watch::channel(Arc::new(Dhcpv6Options::default())),
            tftp: watch::channel(Arc::new(TftpOptions::default())),
            ra_server: watch::channel(Arc::new(RaServerConfig::default())),
            ra_prefixes: watch::channel(Arc::new(Vec::new())),
            ra_rdnss: watch::channel(Arc::new(Vec::new())),
            ra_dnssl: watch::channel(Arc::new(Vec::new())),
            dns_upstreams: watch::channel(Arc::new(Vec::new())),
            dns_upstream_mode: watch::channel(Arc::new(UpstreamMode::default())),
            dns_rewrites: watch::channel(Arc::new(Vec::new())),
            dns_allowlist: watch::channel(Arc::new(DnsAllowlist::default())),
            dns_adblock: watch::channel(Arc::new(AdblockDbConfig::default())),
            dns_adblock_urls: watch::channel(Arc::new(Vec::new())),
            dns_adblock_rules: watch::channel(Arc::new(Vec::new())),
            dns_reverse: watch::channel(Arc::new(Vec::new())),
            dns_listen: watch::channel(Arc::new(DnsListenConfig::default())),
        }
    }
}

/// A multi-section configuration patch applied atomically.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ConfigPatch {
    pub pppoe: Option<PppoeConfig>,
    pub firewall: Option<FirewallConfig>,
    pub traffic: Option<TrafficConfig>,
    pub dhcp_v4_pools: Option<Vec<Dhcpv4Pool>>,
    pub dhcp_v6_pools: Option<Vec<Dhcpv6Pool>>,
    pub dhcp_v4_options: Option<Dhcpv4Options>,
    pub dhcp_v6_options: Option<Dhcpv6Options>,
    pub tftp: Option<TftpOptions>,
    pub ra_server: Option<RaServerConfig>,
    pub ra_prefixes: Option<Vec<RAPrefix>>,
    pub ra_rdnss: Option<Vec<RdnssConfig>>,
    pub ra_dnssl: Option<Vec<DnsslConfig>>,
    pub dns_upstreams: Option<Vec<UpstreamTarget>>,
    pub dns_upstream_mode: Option<UpstreamMode>,
    pub dns_rewrites: Option<Vec<RewriteRule>>,
    pub dns_allowlist: Option<Vec<String>>,
    pub dns_adblock: Option<AdblockDbConfig>,
    pub dns_adblock_urls: Option<Vec<AdblockUrlEntry>>,
    pub dns_adblock_rules: Option<Vec<AdblockRuleEntry>>,
    pub dns_reverse: Option<Vec<DnsReverseResolver>>,
    pub dns_listen: Option<DnsListenConfig>,
}

impl ConfigPatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pppoe.is_none()
            && self.firewall.is_none()
            && self.traffic.is_none()
            && self.dhcp_v4_pools.is_none()
            && self.dhcp_v6_pools.is_none()
            && self.dhcp_v4_options.is_none()
            && self.dhcp_v6_options.is_none()
            && self.tftp.is_none()
            && self.ra_server.is_none()
            && self.ra_prefixes.is_none()
            && self.ra_rdnss.is_none()
            && self.ra_dnssl.is_none()
            && self.dns_upstreams.is_none()
            && self.dns_upstream_mode.is_none()
            && self.dns_rewrites.is_none()
            && self.dns_allowlist.is_none()
            && self.dns_adblock.is_none()
            && self.dns_adblock_urls.is_none()
            && self.dns_adblock_rules.is_none()
            && self.dns_reverse.is_none()
            && self.dns_listen.is_none()
    }

    #[must_use]
    pub fn with_pppoe(mut self, cfg: PppoeConfig) -> Self {
        self.pppoe = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_firewall(mut self, cfg: FirewallConfig) -> Self {
        self.firewall = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_traffic(mut self, cfg: TrafficConfig) -> Self {
        self.traffic = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_dhcp_v4_pools(mut self, pools: Vec<Dhcpv4Pool>) -> Self {
        self.dhcp_v4_pools = Some(pools);
        self
    }

    #[must_use]
    pub fn with_dhcp_v6_pools(mut self, pools: Vec<Dhcpv6Pool>) -> Self {
        self.dhcp_v6_pools = Some(pools);
        self
    }

    #[must_use]
    pub fn with_dhcp_v4_options(mut self, opts: Dhcpv4Options) -> Self {
        self.dhcp_v4_options = Some(opts);
        self
    }

    #[must_use]
    pub fn with_dhcp_v6_options(mut self, opts: Dhcpv6Options) -> Self {
        self.dhcp_v6_options = Some(opts);
        self
    }

    #[must_use]
    pub fn with_dhcp_options(mut self, opts: DhcpOptionsConfig) -> Self {
        self.dhcp_v4_options = Some(opts.v4);
        self.dhcp_v6_options = Some(opts.v6);
        self.tftp = Some(opts.tftp);
        self
    }

    #[must_use]
    pub fn with_tftp(mut self, opts: TftpOptions) -> Self {
        self.tftp = Some(opts);
        self
    }

    #[must_use]
    pub fn with_ra_server(mut self, cfg: RaServerConfig) -> Self {
        self.ra_server = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_ra_prefixes(mut self, prefixes: Vec<RAPrefix>) -> Self {
        self.ra_prefixes = Some(prefixes);
        self
    }

    #[must_use]
    pub fn with_ra_rdnss(mut self, rdnss: Vec<RdnssConfig>) -> Self {
        self.ra_rdnss = Some(rdnss);
        self
    }

    #[must_use]
    pub fn with_ra_dnssl(mut self, dnssl: Vec<DnsslConfig>) -> Self {
        self.ra_dnssl = Some(dnssl);
        self
    }

    #[must_use]
    pub fn with_dns_upstreams(mut self, upstreams: Vec<UpstreamTarget>) -> Self {
        self.dns_upstreams = Some(upstreams);
        self
    }

    #[must_use]
    pub const fn with_dns_upstream_mode(mut self, mode: UpstreamMode) -> Self {
        self.dns_upstream_mode = Some(mode);
        self
    }

    #[must_use]
    pub fn with_dns_rewrites(mut self, rewrites: Vec<RewriteRule>) -> Self {
        self.dns_rewrites = Some(rewrites);
        self
    }

    #[must_use]
    pub fn with_dns_allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.dns_allowlist = Some(allowlist);
        self
    }

    #[must_use]
    pub const fn with_dns_adblock(mut self, adblock: AdblockDbConfig) -> Self {
        self.dns_adblock = Some(adblock);
        self
    }

    #[must_use]
    pub fn with_dns_adblock_urls(mut self, urls: Vec<AdblockUrlEntry>) -> Self {
        self.dns_adblock_urls = Some(urls);
        self
    }

    #[must_use]
    pub fn with_dns_adblock_rules(mut self, rules: Vec<AdblockRuleEntry>) -> Self {
        self.dns_adblock_rules = Some(rules);
        self
    }

    #[must_use]
    pub fn with_dns_reverse(mut self, reverse: Vec<DnsReverseResolver>) -> Self {
        self.dns_reverse = Some(reverse);
        self
    }

    #[must_use]
    pub fn with_dns_listen(mut self, listen: DnsListenConfig) -> Self {
        self.dns_listen = Some(listen);
        self
    }

    /// Applies configured fields to a [`DynamicConfig`] instance.
    pub fn apply_to_dynamic(&self, target: &mut DynamicConfig) {
        if let Some(ref p) = self.pppoe {
            target.pppoe = Some(p.clone());
        }
        if let Some(ref fw) = self.firewall {
            target.firewall = Some(fw.clone());
        }
        if let Some(ref tr) = self.traffic {
            target.traffic = Some(tr.clone());
        }
        if let Some(ref pools) = self.dhcp_v4_pools {
            target.dhcp_v4_pools.clone_from(pools);
        }
        if let Some(ref pools) = self.dhcp_v6_pools {
            target.dhcp_v6_pools.clone_from(pools);
        }
        if let Some(ref v4) = self.dhcp_v4_options {
            target.dhcp_options.v4.clone_from(v4);
        }
        if let Some(ref v6) = self.dhcp_v6_options {
            target.dhcp_options.v6.clone_from(v6);
        }
        if let Some(ref tftp) = self.tftp {
            target.dhcp_options.tftp.clone_from(tftp);
        }
        if let Some(ref ra) = self.ra_server {
            target.ra.clone_from(ra);
        }
        if let Some(ref pref) = self.ra_prefixes {
            target.ra.prefixes.clone_from(pref);
        }
        if let Some(ref rdnss) = self.ra_rdnss {
            target.ra.rdnss.clone_from(rdnss);
        }
        if let Some(ref dnssl) = self.ra_dnssl {
            target.ra.dnssl.clone_from(dnssl);
        }
        if let Some(ref upstreams) = self.dns_upstreams {
            target.dns_upstreams.clone_from(upstreams);
        }
        if let Some(mode) = self.dns_upstream_mode {
            target.dns_upstream_mode = mode;
        }
        if let Some(ref rewrites) = self.dns_rewrites {
            target.dns_rewrites.clone_from(rewrites);
        }
        if let Some(ref allowlist) = self.dns_allowlist {
            target.dns_allowlist.clone_from(allowlist);
        }
        if let Some(ref adblock) = self.dns_adblock {
            target.dns_adblock.clone_from(adblock);
        }
        if let Some(ref urls) = self.dns_adblock_urls {
            target.dns_adblock_urls.clone_from(urls);
        }
        if let Some(ref rules) = self.dns_adblock_rules {
            target.dns_adblock_rules.clone_from(rules);
        }
    }
}

/// Report returned by [`LanforgeContext::apply_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Domain bitset of all sections that actually changed.
    pub changed: DomainSet,
    /// Highest operational impact among all changed sections.
    pub max_impact: ChangeImpact,
}

/// Runtime subsystem configurations dynamically updateable via RPC/CLI/WebUI.
#[derive(Debug, Clone, Default)]
pub struct DynamicConfig {
    /// Configured `DHCPv4` pools.
    pub dhcp_v4_pools: Vec<Dhcpv4Pool>,
    /// Configured `DHCPv6` pools.
    pub dhcp_v6_pools: Vec<Dhcpv6Pool>,
    /// Configured DHCP and TFTP scope options.
    pub dhcp_options: DhcpOptionsConfig,
    /// Configured Router Advertisement server runtime configuration.
    pub ra: RaServerConfig,
    /// Configured DNS upstreams.
    pub dns_upstreams: Vec<UpstreamTarget>,
    /// Configured DNS upstream resolution strategy mode.
    pub dns_upstream_mode: UpstreamMode,
    /// Configured DNS rewrites.
    pub dns_rewrites: Vec<RewriteRule>,
    /// Configured DNS allowlist.
    pub dns_allowlist: Vec<String>,
    /// Configured DNS adblock config.
    pub dns_adblock: AdblockDbConfig,
    /// Configured DNS adblock source URLs.
    pub dns_adblock_urls: Vec<AdblockUrlEntry>,
    /// Configured DNS custom adblock rules (allowlist & blocklist).
    pub dns_adblock_rules: Vec<AdblockRuleEntry>,
    /// Configured `PPPoE` client runtime configuration.
    pub pppoe: Option<PppoeConfig>,
    /// Configured firewall runtime configuration.
    pub firewall: Option<FirewallConfig>,
    /// Configured traffic management and SQM configuration.
    pub traffic: Option<TrafficConfig>,
}

impl LanforgeContext {
    /// Subscribes to changes of a specific configuration section.
    #[must_use]
    pub fn config_subscription<T: SubscribableSection>(&self) -> ConfigSubscription<T> {
        let rx = T::extract_receiver(&self.inner.config_store);
        ConfigSubscription::new(rx)
    }

    /// Atomically applies a multi-section configuration patch.
    ///
    /// Diffs each section against the currently stored configuration.
    /// Broadcasts on watch channels ONLY for sections that changed.
    /// Emits derived legacy events and exactly one [`SystemEvent::ConfigChanged`].
    #[must_use]
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn apply_config(&self, patch: ConfigPatch) -> ApplyReport {
        let _guard = self.inner.config_mutex.lock();
        let current_cfg = self.inner.config.load();
        let mut changed = DomainSet::empty();
        let mut max_impact = ChangeImpact::None;

        macro_rules! check_and_apply_opt {
            ($field:ident, $store_pair:expr, $domain:ident) => {
                if let Some(ref new_val) = patch.$field {
                    let is_first_init = current_cfg.$field.is_none();
                    let current = $store_pair.1.borrow().clone();
                    let mut impact = ConfigSection::classify(&*current, new_val);
                    if is_first_init && impact == ChangeImpact::None {
                        impact = ChangeImpact::Hot;
                    }
                    if impact != ChangeImpact::None {
                        changed |= DomainSet::$domain;
                        max_impact = max_impact.max(impact);
                        let _ = $store_pair.0.send(Arc::new(new_val.clone()));
                    }
                }
            };
        }

        macro_rules! check_and_apply {
            ($field:ident, $store_pair:expr, $domain:ident) => {
                if let Some(ref new_val) = patch.$field {
                    let current = $store_pair.1.borrow().clone();
                    let impact = ConfigSection::classify(&*current, new_val);
                    if impact != ChangeImpact::None {
                        changed |= DomainSet::$domain;
                        max_impact = max_impact.max(impact);
                        let _ = $store_pair.0.send(Arc::new(new_val.clone()));
                    }
                }
            };
        }

        check_and_apply_opt!(pppoe, self.inner.config_store.pppoe, PPPOE);
        check_and_apply_opt!(firewall, self.inner.config_store.firewall, FIREWALL);
        check_and_apply_opt!(traffic, self.inner.config_store.traffic, TRAFFIC);
        check_and_apply!(dhcp_v4_pools, self.inner.config_store.dhcp_v4_pools, DHCP_V4_POOLS);
        check_and_apply!(dhcp_v6_pools, self.inner.config_store.dhcp_v6_pools, DHCP_V6_POOLS);
        check_and_apply!(dhcp_v4_options, self.inner.config_store.dhcp_v4_options, DHCP_V4_OPTIONS);
        check_and_apply!(dhcp_v6_options, self.inner.config_store.dhcp_v6_options, DHCP_V6_OPTIONS);
        check_and_apply!(tftp, self.inner.config_store.tftp, TFTP);
        check_and_apply!(ra_server, self.inner.config_store.ra_server, RA_SERVER);
        check_and_apply!(ra_prefixes, self.inner.config_store.ra_prefixes, RA_PREFIXES);
        check_and_apply!(ra_rdnss, self.inner.config_store.ra_rdnss, RA_RDNSS);
        check_and_apply!(ra_dnssl, self.inner.config_store.ra_dnssl, RA_DNSSL);
        check_and_apply!(dns_upstreams, self.inner.config_store.dns_upstreams, DNS_UPSTREAMS);
        check_and_apply!(dns_upstream_mode, self.inner.config_store.dns_upstream_mode, DNS_UPSTREAM_MODE);
        check_and_apply!(dns_rewrites, self.inner.config_store.dns_rewrites, DNS_REWRITES);

        if let Some(ref new_val) = patch.dns_allowlist {
            let allowlist = DnsAllowlist(new_val.clone());
            let current = self.inner.config_store.dns_allowlist.1.borrow().clone();
            let impact = ConfigSection::classify(&*current, &allowlist);
            if impact != ChangeImpact::None {
                changed |= DomainSet::DNS_ALLOWLIST;
                max_impact = max_impact.max(impact);
                let _ = self.inner.config_store.dns_allowlist.0.send(Arc::new(allowlist));
            }
        }

        check_and_apply!(dns_adblock, self.inner.config_store.dns_adblock, DNS_ADBLOCK);
        check_and_apply!(dns_adblock_urls, self.inner.config_store.dns_adblock_urls, DNS_ADBLOCK_URLS);
        check_and_apply!(dns_adblock_rules, self.inner.config_store.dns_adblock_rules, DNS_ADBLOCK_RULES);
        check_and_apply!(dns_reverse, self.inner.config_store.dns_reverse, DNS_REVERSE);
        check_and_apply!(dns_listen, self.inner.config_store.dns_listen, DNS_LISTEN);

        if !changed.is_empty() {
            // Synchronize DynamicConfig
            let current_cfg = self.inner.config.load();
            let mut next_cfg = (**current_cfg).clone();
            patch.apply_to_dynamic(&mut next_cfg);
            self.inner.config.store(Arc::new(next_cfg));

            // Derived notifications for legacy listeners & db worker
            let bus = self.bus_ref();
            if changed.contains(DomainSet::PPPOE) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigPppoeChanged));
            }
            if changed.contains(DomainSet::FIREWALL) {
                let _ = bus.publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
            }
            if changed.contains(DomainSet::TRAFFIC) {
                let _ = bus.publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::RulesetChanged)));
            }
            if changed.contains(DomainSet::DHCP_V4_POOLS) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed));
            }
            if changed.contains(DomainSet::DHCP_V6_POOLS) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV6Changed));
            }
            if changed.contains(DomainSet::DHCP_V4_OPTIONS) || changed.contains(DomainSet::DHCP_V6_OPTIONS) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigDhcpOptionsChanged));
            }
            if changed.contains(DomainSet::TFTP) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigTftpChanged));
            }
            if changed.intersects(DomainSet::RA_SERVER | DomainSet::RA_PREFIXES | DomainSet::RA_RDNSS | DomainSet::RA_DNSSL) {
                let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
            }
            if changed.contains(DomainSet::DNS_UPSTREAMS) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged));
            }
            if changed.contains(DomainSet::DNS_UPSTREAM_MODE) {
                let mode = **self.inner.config_store.dns_upstream_mode.1.borrow();
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamModeChanged(mode)));
            }
            if changed.contains(DomainSet::DNS_REWRITES) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
            }
            if changed.contains(DomainSet::DNS_ALLOWLIST) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged));
            }
            if changed.intersects(DomainSet::DNS_ADBLOCK | DomainSet::DNS_ADBLOCK_URLS) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
            }
            if changed.contains(DomainSet::DNS_ADBLOCK_RULES) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockRulesChanged));
            }
            if changed.contains(DomainSet::DNS_REVERSE) {
                let _ = bus.publish(LanforgeEvent::Dns(DnsEvent::ConfigReverseResolversChanged));
            }

            // Exactly ONE ConfigChanged event for UI/CLI observers
            let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigChanged { sections: changed }));
        }

        ApplyReport { changed, max_impact }
    }

    /// Hydrates the context configuration silently without publishing events or waking subscribers.
    ///
    /// Must be called during bootstrap before services are spawned.
    #[allow(clippy::needless_pass_by_value)]
    pub fn hydrate_config(&self, patch: ConfigPatch) {
        let _guard = self.inner.config_mutex.lock();

        macro_rules! hydrate_val {
            ($field:ident, $store_pair:expr) => {
                if let Some(ref new_val) = patch.$field {
                    let _ = $store_pair.0.send(Arc::new(new_val.clone()));
                }
            };
        }

        hydrate_val!(pppoe, self.inner.config_store.pppoe);
        hydrate_val!(firewall, self.inner.config_store.firewall);
        hydrate_val!(traffic, self.inner.config_store.traffic);
        hydrate_val!(dhcp_v4_pools, self.inner.config_store.dhcp_v4_pools);
        hydrate_val!(dhcp_v6_pools, self.inner.config_store.dhcp_v6_pools);
        hydrate_val!(dhcp_v4_options, self.inner.config_store.dhcp_v4_options);
        hydrate_val!(dhcp_v6_options, self.inner.config_store.dhcp_v6_options);
        hydrate_val!(tftp, self.inner.config_store.tftp);
        hydrate_val!(ra_server, self.inner.config_store.ra_server);
        hydrate_val!(ra_prefixes, self.inner.config_store.ra_prefixes);
        hydrate_val!(ra_rdnss, self.inner.config_store.ra_rdnss);
        hydrate_val!(ra_dnssl, self.inner.config_store.ra_dnssl);
        hydrate_val!(dns_upstreams, self.inner.config_store.dns_upstreams);
        hydrate_val!(dns_upstream_mode, self.inner.config_store.dns_upstream_mode);
        hydrate_val!(dns_rewrites, self.inner.config_store.dns_rewrites);
        if let Some(ref new_val) = patch.dns_allowlist {
            let _ = self.inner.config_store.dns_allowlist.0.send(Arc::new(DnsAllowlist(new_val.clone())));
        }
        hydrate_val!(dns_adblock, self.inner.config_store.dns_adblock);
        hydrate_val!(dns_adblock_urls, self.inner.config_store.dns_adblock_urls);
        hydrate_val!(dns_adblock_rules, self.inner.config_store.dns_adblock_rules);
        hydrate_val!(dns_reverse, self.inner.config_store.dns_reverse);
        hydrate_val!(dns_listen, self.inner.config_store.dns_listen);

        let current_cfg = self.inner.config.load();
        let mut next_cfg = (**current_cfg).clone();
        patch.apply_to_dynamic(&mut next_cfg);
        self.inner.config.store(Arc::new(next_cfg));
    }

    /// Returns a guard to the current dynamic subsystem configurations.
    #[must_use]
    pub fn config_guard(&self) -> arc_swap::Guard<Arc<DynamicConfig>> {
        self.inner.config.load()
    }

    /// Returns a copy of the current dynamic subsystem configurations.
    #[must_use]
    pub fn config(&self) -> DynamicConfig {
        (**self.inner.config.load()).clone()
    }

    /// Executes a closure with read access to the dynamic configurations.
    pub fn with_config<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&DynamicConfig) -> R,
    {
        f(&self.inner.config.load())
    }

    /// Executes a closure with write access to the dynamic configurations.
    pub fn update_config<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DynamicConfig) -> R,
    {
        let _guard = self.inner.config_mutex.lock();
        let current = self.inner.config.load();
        let mut next = (**current).clone();
        let res = f(&mut next);
        self.inner.config.store(Arc::new(next));
        res
    }

    #[must_use]
    pub fn get_dhcp_v4_pools(&self) -> Vec<Dhcpv4Pool> {
        self.with_config(|c| c.dhcp_v4_pools.clone())
    }

    #[must_use]
    pub fn get_dhcp_v6_pools(&self) -> Vec<Dhcpv6Pool> {
        self.with_config(|c| c.dhcp_v6_pools.clone())
    }

    #[must_use]
    pub fn get_dhcp_options(&self) -> DhcpOptionsConfig {
        self.with_config(|c| c.dhcp_options.clone())
    }

    #[must_use]
    pub fn get_ra_prefixes(&self) -> Vec<RAPrefix> {
        self.with_config(|c| c.ra.prefixes.clone())
    }

    #[must_use]
    pub fn get_ra_rdnss(&self) -> Vec<RdnssConfig> {
        self.with_config(|c| c.ra.rdnss.clone())
    }

    #[must_use]
    pub fn get_ra_dnssl(&self) -> Vec<DnsslConfig> {
        self.with_config(|c| c.ra.dnssl.clone())
    }

    #[must_use]
    pub fn get_ra_server_config(&self) -> RaServerConfig {
        self.with_config(|c| c.ra.clone())
    }

    /// Returns the current dynamic `PPPoE` configuration, if configured.
    #[must_use]
    pub fn get_pppoe_config(&self) -> Option<PppoeConfig> {
        self.with_config(|c| c.pppoe.clone())
    }

    /// Returns the current dynamic firewall configuration, if configured.
    #[must_use]
    pub fn get_firewall_config(&self) -> Option<FirewallConfig> {
        self.with_config(|c| c.firewall.clone())
    }

    /// Returns the current dynamic traffic and SQM configuration, if configured.
    #[must_use]
    pub fn get_traffic_config(&self) -> Option<TrafficConfig> {
        self.with_config(|c| c.traffic.clone())
    }

    #[must_use]
    pub fn get_dns_upstreams(&self) -> Vec<UpstreamTarget> {
        self.with_config(|c| c.dns_upstreams.clone())
    }

    #[must_use]
    pub fn get_dns_rewrites(&self) -> Vec<RewriteRule> {
        self.with_config(|c| c.dns_rewrites.clone())
    }

    #[must_use]
    pub fn get_dns_allowlist(&self) -> Vec<String> {
        self.with_config(|c| c.dns_allowlist.clone())
    }

    #[must_use]
    pub fn get_dns_adblock(&self) -> AdblockDbConfig {
        self.with_config(|c| c.dns_adblock.clone())
    }

    #[must_use]
    pub fn get_dns_adblock_urls(&self) -> Vec<AdblockUrlEntry> {
        self.with_config(|c| c.dns_adblock_urls.clone())
    }

    #[must_use]
    pub fn get_dns_adblock_rules(&self) -> Vec<AdblockRuleEntry> {
        self.with_config(|c| c.dns_adblock_rules.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;
    use crate::context::state::State;

    fn create_test_context() -> LanforgeContext {
        let bus = Arc::new(EventBus::new());
        LanforgeContext::new(bus, State::default(), None)
    }

    #[tokio::test]
    async fn test_apply_config_noop() {
        let ctx = create_test_context();
        let initial_pppoe = PppoeConfig::default();
        ctx.hydrate_config(ConfigPatch::new().with_pppoe(initial_pppoe.clone()));

        let mut sub = ctx.config_subscription::<PppoeConfig>();

        // Applying identical config (defaults) must produce zero changes
        let report = ctx.apply_config(ConfigPatch::new().with_pppoe(initial_pppoe));
        assert!(report.changed.is_empty());
        assert_eq!(report.max_impact, ChangeImpact::None);

        // Ensure subscription is not woken
        tokio::select! {
            _ = sub.next() => panic!("Subscription must not wake on noop"),
            () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }

    #[tokio::test]
    async fn test_apply_config_isolation() {
        let ctx = create_test_context();
        let mut pppoe_sub = ctx.config_subscription::<PppoeConfig>();
        let mut ra_sub = ctx.config_subscription::<RaServerConfig>();

        // Change RA config only
        let mut ra_cfg = RaServerConfig::default();
        ra_cfg.hop_limit = 128;

        let report = ctx.apply_config(ConfigPatch::new().with_ra_server(ra_cfg.clone()));
        assert_eq!(report.changed, DomainSet::RA_SERVER);
        assert_eq!(report.max_impact, ChangeImpact::Hot);

        // RA subscription must wake with Hot impact
        let delta = tokio::time::timeout(std::time::Duration::from_millis(200), ra_sub.next())
            .await
            .expect("RA sub timed out")
            .expect("RA sub closed");
        assert_eq!(delta.impact, ChangeImpact::Hot);
        assert_eq!(delta.new.hop_limit, 128);

        // PPPoE subscription must NOT wake up
        tokio::select! {
            _ = pppoe_sub.next() => panic!("PPPoE subscription must not wake on RA change"),
            () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }

    #[tokio::test]
    async fn test_apply_config_burst_coalescing() {
        let ctx = create_test_context();
        let mut sub = ctx.config_subscription::<PppoeConfig>();

        // Apply two rapid changes
        let mut cfg1 = PppoeConfig::default();
        cfg1.lcp_echo_interval_secs = 25; // Hot
        let _ = ctx.apply_config(ConfigPatch::new().with_pppoe(cfg1));

        let mut cfg2 = PppoeConfig::default();
        cfg2.password = "new_secret".into(); // Reconnect
        let _ = ctx.apply_config(ConfigPatch::new().with_pppoe(cfg2));

        // Sub should receive the latest state with Reconnect impact
        let delta = tokio::time::timeout(std::time::Duration::from_millis(200), sub.next())
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(delta.impact, ChangeImpact::Reconnect);
        assert_eq!(delta.new.password, "new_secret");
    }

    #[tokio::test]
    async fn test_hydrate_config_silence() {
        let ctx = create_test_context();

        let mut pppoe_cfg = PppoeConfig::default();
        pppoe_cfg.username = "hydrated_user".into();

        ctx.hydrate_config(ConfigPatch::new().with_pppoe(pppoe_cfg));

        // Subscription taken after hydrate sees hydrated state as current
        let mut sub = ctx.config_subscription::<PppoeConfig>();
        assert_eq!(sub.current().username, "hydrated_user");

        // And no event is triggered
        tokio::select! {
            _ = sub.next() => panic!("Sub must not wake after hydration"),
            () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }
}
