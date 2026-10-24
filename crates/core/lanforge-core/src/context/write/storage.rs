//! Storage and lifecycle state management.

use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig, RaServerConfig};
use lanforge_types::events::EventVec;
use lanforge_types::network::{DnsReverseResolver, IpSubnet, TrafficConfig};

use crate::bus::{DnsEvent, FirewallEvent, LanforgeEvent, SystemEvent, TrafficEvent};
use crate::context::state::State;
use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Updates the configured `DHCPv4` pools and publishes the change event.
    pub fn update_dhcp_v4_pools(&self, pools: Vec<Dhcpv4Pool>) {
        self.update_config_and_notify(
            |cfg| cfg.dhcp_v4_pools = pools,
            LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed),
        );
    }

    /// Updates the configured `DHCPv6` pools and publishes the change event.
    pub fn update_dhcp_v6_pools(&self, pools: Vec<Dhcpv6Pool>) {
        self.update_config_and_notify(
            |cfg| cfg.dhcp_v6_pools = pools,
            LanforgeEvent::System(SystemEvent::ConfigDhcpV6Changed),
        );
    }

    /// Updates the configured DHCP & TFTP options and broadcasts config change events.
    pub fn update_dhcp_options(&self, options: DhcpOptionsConfig) {
        self.update_config(|cfg| cfg.dhcp_options = options);
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
        self.update_config_and_notify(
            |cfg| {
                cfg.ra.prefixes = prefixes;
                cfg.ra.rdnss = rdnss;
                cfg.ra.dnssl = dnssl;
            },
            LanforgeEvent::System(SystemEvent::ConfigRaChanged),
        );
    }

    /// Updates the full RA server configuration and publishes the change event.
    pub fn update_ra_server_config(&self, config: RaServerConfig) {
        self.update_config_and_notify(
            |cfg| cfg.ra = config,
            LanforgeEvent::System(SystemEvent::ConfigRaChanged),
        );
    }

    /// Updates the dynamic `PPPoE` configuration in context and publishes change event.
    pub fn update_pppoe_config(&self, config: PppoeConfig) {
        self.update_config_and_notify(
            |cfg| cfg.pppoe = Some(config),
            LanforgeEvent::System(SystemEvent::ConfigPppoeChanged),
        );
    }

    /// Updates the dynamic firewall configuration in context and publishes change event.
    pub fn update_firewall_config(&self, config: FirewallConfig) {
        self.update_config_and_notify(
            |cfg| cfg.firewall = Some(config),
            LanforgeEvent::Firewall(FirewallEvent::RulesetChanged),
        );
    }

    /// Updates the dynamic traffic and SQM configuration in context and publishes change event.
    pub fn update_traffic_config(&self, config: TrafficConfig) {
        self.update_config_and_notify(
            |cfg| cfg.traffic = Some(config),
            LanforgeEvent::Traffic(Box::new(TrafficEvent::RulesetChanged)),
        );
    }

    /// Updates the configured DNS upstreams and publishes the change event.
    pub fn update_dns_upstreams(&self, upstreams: Vec<UpstreamTarget>) {
        self.update_config_and_notify(
            |cfg| cfg.dns_upstreams = upstreams,
            LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged),
        );
    }

    /// Returns the currently configured DNS upstream resolution mode.
    #[must_use]
    pub fn get_dns_upstream_mode(&self) -> UpstreamMode {
        self.with_config(|cfg| cfg.dns_upstream_mode)
    }

    /// Updates the configured DNS upstream resolution mode and publishes the change event.
    pub fn update_dns_upstream_mode(&self, mode: UpstreamMode) {
        self.update_config_and_notify(
            |cfg| cfg.dns_upstream_mode = mode,
            LanforgeEvent::Dns(DnsEvent::ConfigUpstreamModeChanged(mode)),
        );
    }

    /// Updates the configured DNS rewrites and publishes the change event.
    pub fn update_dns_rewrites(&self, rewrites: Vec<RewriteRule>) {
        self.update_config_and_notify(
            |cfg| cfg.dns_rewrites = rewrites,
            LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged),
        );
    }

    /// Updates the configured DNS allowlist and publishes the change event.
    pub fn update_dns_allowlist(&self, allowlist: Vec<String>) {
        self.update_config_and_notify(
            |cfg| cfg.dns_allowlist = allowlist,
            LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged),
        );
    }

    /// Updates the configured DNS adblock config and publishes the change event.
    pub fn update_dns_adblock(&self, adblock: AdblockDbConfig) {
        self.update_config_and_notify(
            |cfg| cfg.dns_adblock = adblock,
            LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged),
        );
    }

    /// Updates the configured DNS adblock URLs and publishes the change event.
    pub fn update_dns_adblock_urls(&self, urls: Vec<AdblockUrlEntry>) {
        self.update_config_and_notify(
            |cfg| cfg.dns_adblock_urls = urls,
            LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged),
        );
    }

    /// Updates the configured DNS custom adblock rules and publishes the change event.
    pub fn update_dns_adblock_rules(&self, rules: Vec<AdblockRuleEntry>) {
        self.update_config_and_notify(
            |cfg| cfg.dns_adblock_rules = rules,
            LanforgeEvent::Dns(DnsEvent::ConfigAdblockRulesChanged),
        );
    }

    /// Prunes stale discovery caches, transient hosts, and inactive zombie devices.
    #[must_use]
    pub fn prune_zombies(&self) -> EventVec {
        let events = self.with_state_mut(|state| state.prune_zombies(&self.inner.discovery));
        let bus = self.bus_ref();
        for event in &events {
            let _ = bus.publish(event.clone());
        }
        events
    }

    /// Rebuilds all device and DNS resolution indices.
    pub fn rebuild_dns_indices(&self) {
        self.with_state_mut(State::rebuild_indices);
    }

    /// Completely resets the in-memory state.
    pub fn reset(&self) {
        self.with_state_mut(|state| state.reset(&self.inner.discovery));
        self.inner.runtime.reset_lifecycle();
        *self.inner.runtime.last_db_flush.write() = None;
    }

    /// Adds or updates a custom reverse DNS resolver for a subnet.
    pub fn add_reverse_resolver(&self, resolver: DnsReverseResolver) {
        self.with_state_mut(|state| state.add_reverse_resolver(resolver));
        let _ = self.bus().publish(LanforgeEvent::Dns(DnsEvent::ConfigReverseResolversChanged));
    }

    /// Removes a custom reverse DNS resolver for a subnet.
    pub fn remove_reverse_resolver(&self, subnet: IpSubnet) {
        self.with_state_mut(|state| state.remove_reverse_resolver(subnet));
        let _ = self.bus().publish(LanforgeEvent::Dns(DnsEvent::ConfigReverseResolversChanged));
    }

    /// Sets or replaces all custom reverse DNS resolvers.
    pub fn set_reverse_resolvers(&self, resolvers: Vec<DnsReverseResolver>) {
        self.with_state_mut(|state| state.set_reverse_resolvers(resolvers));
        let _ = self.bus().publish(LanforgeEvent::Dns(DnsEvent::ConfigReverseResolversChanged));
    }
}
