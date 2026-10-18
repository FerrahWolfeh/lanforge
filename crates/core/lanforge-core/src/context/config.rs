//! Dynamic subsystem configuration storage and accessors.

use std::sync::Arc;

use lanforge_types::network::TrafficConfig;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RaServerConfig, RdnssConfig};

use crate::bus::LanforgeEvent;
use crate::context::LanforgeContext;

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

    pub(crate) fn update_config_and_notify<F>(&self, f: F, event: LanforgeEvent)
    where
        F: FnOnce(&mut DynamicConfig),
    {
        self.update_config(f);
        let _ = self.bus_ref().publish(event);
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
