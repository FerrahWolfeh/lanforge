//! Storage and lifecycle state management.

use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig, RaServerConfig};
use lanforge_types::network::TrafficConfig;
use lanforge_types::update::DeviceUpdate;

use crate::bus::{DnsEvent, FirewallEvent, LanforgeEvent, SystemEvent, TrafficEvent};
use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Updates the configured `DHCPv4` pools and publishes the change event.
    pub fn update_dhcp_v4_pools(&self, pools: Vec<Dhcpv4Pool>) {
        self.inner.config.write().dhcp_v4_pools = pools;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed));
    }

    /// Updates the configured `DHCPv6` pools and publishes the change event.
    pub fn update_dhcp_v6_pools(&self, pools: Vec<Dhcpv6Pool>) {
        self.inner.config.write().dhcp_v6_pools = pools;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV6Changed));
    }

    /// Updates the configured DHCP & TFTP options and broadcasts config change events.
    pub fn update_dhcp_options(&self, options: DhcpOptionsConfig) {
        self.inner.config.write().dhcp_options = options;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigTftpChanged));
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpOptionsChanged));
    }

    /// Updates the configured RA prefix/DNS/domain search lists and publishes the change event.
    pub fn update_ra_config(
        &self,
        prefixes: Vec<RAPrefix>,
        rdnss: Vec<RdnssConfig>,
        dnssl: Vec<DnsslConfig>,
    ) {
        {
            let mut cfg = self.inner.config.write();
            cfg.ra_prefixes = prefixes;
            cfg.ra_rdnss = rdnss;
            cfg.ra_dnssl = dnssl;
        }
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
    }

    /// Updates the full RA server configuration and publishes the change event.
    pub fn update_ra_server_config(&self, config: RaServerConfig) {
        {
            let mut cfg = self.inner.config.write();
            cfg.ra_prefixes.clone_from(&config.prefixes);
            cfg.ra_rdnss.clone_from(&config.rdnss);
            cfg.ra_dnssl.clone_from(&config.dnssl);
            cfg.ra_config = Some(config);

        }
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
    }

    /// Updates the dynamic `PPPoE` configuration in context and publishes change event.
    pub fn update_pppoe_config(&self, config: PppoeConfig) {
        self.inner.config.write().pppoe = Some(config);
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigPppoeChanged));
    }

    /// Updates the dynamic firewall configuration in context and publishes change event.
    pub fn update_firewall_config(&self, config: FirewallConfig) {
        self.inner.config.write().firewall = Some(config);
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
    }

    /// Updates the dynamic traffic and SQM configuration in context and publishes change event.
    pub fn update_traffic_config(&self, config: TrafficConfig) {
        self.inner.config.write().traffic = Some(config);
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::RulesetChanged)));
    }

    /// Updates the configured DNS upstreams and publishes the change event.
    pub fn update_dns_upstreams(&self, upstreams: Vec<UpstreamTarget>) {
        self.inner.config.write().dns_upstreams = upstreams;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged));
    }

    /// Returns the currently configured DNS upstream resolution mode.
    #[must_use]
    pub fn get_dns_upstream_mode(&self) -> UpstreamMode {
        self.inner.config.read().dns_upstream_mode
    }

    /// Updates the configured DNS upstream resolution mode and publishes the change event.
    pub fn update_dns_upstream_mode(&self, mode: UpstreamMode) {
        self.inner.config.write().dns_upstream_mode = mode;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamModeChanged(mode)));
    }

    /// Updates the configured DNS rewrites and publishes the change event.
    pub fn update_dns_rewrites(&self, rewrites: Vec<RewriteRule>) {
        self.inner.config.write().dns_rewrites = rewrites;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
    }

    /// Updates the configured DNS allowlist and publishes the change event.
    pub fn update_dns_allowlist(&self, allowlist: Vec<String>) {
        self.inner.config.write().dns_allowlist = allowlist;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged));
    }

    /// Updates the configured DNS adblock config and publishes the change event.
    pub fn update_dns_adblock(&self, adblock: AdblockDbConfig) {
        self.inner.config.write().dns_adblock = adblock;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    }

    /// Updates the configured DNS adblock URLs and publishes the change event.
    pub fn update_dns_adblock_urls(&self, urls: Vec<AdblockUrlEntry>) {
        self.inner.config.write().dns_adblock_urls = urls;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    }

    /// Updates the configured DNS custom adblock rules and publishes the change event.
    pub fn update_dns_adblock_rules(&self, rules: Vec<AdblockRuleEntry>) {
        self.inner.config.write().dns_adblock_rules = rules;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockRulesChanged));
    }

    /// Completely resets the in-memory state.
    pub fn reset(&self) {
        let _ = self.apply(DeviceUpdate::Reset);
        *self.inner.runtime.last_db_flush.write() = None;
    }
}
