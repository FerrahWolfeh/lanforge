//! Storage and lifecycle state management.

use lanforge_types::events::EventVec;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RaServerConfig, RdnssConfig};
use lanforge_types::network::{DnsReverseResolver, IpSubnet, TrafficConfig};

use crate::context::config::ConfigPatch;
use crate::context::state::State;
use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Updates the configured `DHCPv4` pools and publishes the change event.
    pub fn update_dhcp_v4_pools(&self, pools: Vec<Dhcpv4Pool>) {
        let _ = self.apply_config(ConfigPatch::new().with_dhcp_v4_pools(pools));
    }

    /// Updates the configured `DHCPv6` pools and publishes the change event.
    pub fn update_dhcp_v6_pools(&self, pools: Vec<Dhcpv6Pool>) {
        let _ = self.apply_config(ConfigPatch::new().with_dhcp_v6_pools(pools));
    }

    /// Updates the configured DHCP & TFTP options and broadcasts config change events.
    pub fn update_dhcp_options(&self, options: DhcpOptionsConfig) {
        let _ = self.apply_config(
            ConfigPatch::new()
                .with_dhcp_v4_options(options.v4)
                .with_dhcp_v6_options(options.v6)
                .with_tftp(options.tftp),
        );
    }

    /// Updates the configured RA prefix/DNS/domain search lists and publishes the change event.
    pub fn update_ra_config(
        &self,
        prefixes: Vec<RAPrefix>,
        rdnss: Vec<RdnssConfig>,
        dnssl: Vec<DnsslConfig>,
    ) {
        let _ = self.apply_config(
            ConfigPatch::new()
                .with_ra_prefixes(prefixes)
                .with_ra_rdnss(rdnss)
                .with_ra_dnssl(dnssl),
        );
    }

    /// Updates the full RA server configuration and publishes the change event.
    pub fn update_ra_server_config(&self, config: RaServerConfig) {
        let _ = self.apply_config(
            ConfigPatch::new()
                .with_ra_server(config.clone())
                .with_ra_prefixes(config.prefixes)
                .with_ra_rdnss(config.rdnss)
                .with_ra_dnssl(config.dnssl),
        );
    }

    /// Updates the dynamic `PPPoE` configuration in context and publishes change event.
    pub fn update_pppoe_config(&self, config: PppoeConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_pppoe(config));
    }

    /// Updates the dynamic firewall configuration in context and publishes change event.
    pub fn update_firewall_config(&self, config: FirewallConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_firewall(config));
    }

    /// Updates the dynamic traffic and SQM configuration in context and publishes change event.
    pub fn update_traffic_config(&self, config: TrafficConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_traffic(config));
    }

    /// Updates the configured DNS upstreams and publishes the change event.
    pub fn update_dns_upstreams(&self, upstreams: Vec<UpstreamTarget>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_upstreams(upstreams));
    }

    /// Returns the currently configured DNS upstream resolution mode.
    #[must_use]
    pub fn get_dns_upstream_mode(&self) -> UpstreamMode {
        self.with_config(|cfg| cfg.dns_upstream_mode)
    }

    /// Updates the configured DNS upstream resolution mode and publishes the change event.
    pub fn update_dns_upstream_mode(&self, mode: UpstreamMode) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_upstream_mode(mode));
    }

    /// Updates the configured DNS rewrites and publishes the change event.
    pub fn update_dns_rewrites(&self, rewrites: Vec<RewriteRule>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_rewrites(rewrites));
    }

    /// Updates the configured DNS allowlist and publishes the change event.
    pub fn update_dns_allowlist(&self, allowlist: Vec<String>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_allowlist(allowlist));
    }

    /// Updates the configured DNS adblock config and publishes the change event.
    pub fn update_dns_adblock(&self, adblock: AdblockDbConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock(adblock));
    }

    /// Updates the configured DNS adblock URLs and publishes the change event.
    pub fn update_dns_adblock_urls(&self, urls: Vec<AdblockUrlEntry>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock_urls(urls));
    }

    /// Updates the configured DNS custom adblock rules and publishes the change event.
    pub fn update_dns_adblock_rules(&self, rules: Vec<AdblockRuleEntry>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock_rules(rules));
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
        let resolvers = self.with_state_mut(|state| {
            state.add_reverse_resolver(resolver);
            state.reverse_resolvers.clone()
        });
        let _ = self.apply_config(ConfigPatch::new().with_dns_reverse(resolvers));
    }

    /// Removes a custom reverse DNS resolver for a subnet.
    pub fn remove_reverse_resolver(&self, subnet: IpSubnet) {
        let resolvers = self.with_state_mut(|state| {
            state.remove_reverse_resolver(subnet);
            state.reverse_resolvers.clone()
        });
        let _ = self.apply_config(ConfigPatch::new().with_dns_reverse(resolvers));
    }

    /// Sets or replaces all custom reverse DNS resolvers.
    pub fn set_reverse_resolvers(&self, resolvers: Vec<DnsReverseResolver>) {
        self.with_state_mut(|state| state.set_reverse_resolvers(resolvers.clone()));
        let _ = self.apply_config(ConfigPatch::new().with_dns_reverse(resolvers));
    }
}
