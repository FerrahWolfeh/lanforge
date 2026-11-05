//! Storage and lifecycle state management.

use lanforge_types::DnsListenConfig;
use lanforge_types::events::EventVec;
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::AdblockDbConfig;
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::RaServerConfig;
use lanforge_types::network::{DnsReverseResolver, IpSubnet, TrafficConfig};

use crate::context::LanforgeContext;
use crate::context::config::ConfigPatch;
use crate::context::state::State;

/// The `update_*` methods are one-section shortcuts over [`LanforgeContext::apply_config`] for
/// tests and simple callers; production paths that change several sections build one
/// [`ConfigPatch`] (one `ConfigChanged`, one wake-up per subscriber).
impl LanforgeContext {
    /// Updates the configured `DHCPv4` pools and publishes the change event.
    pub fn update_dhcp_v4_pools(&self, pools: Vec<Dhcpv4Pool>) {
        let _ = self.apply_config(ConfigPatch::new().with_dhcp_v4_pools(pools));
    }

    /// Updates the configured `DHCPv6` pools and publishes the change event.
    pub fn update_dhcp_v6_pools(&self, pools: Vec<Dhcpv6Pool>) {
        let _ = self.apply_config(ConfigPatch::new().with_dhcp_v6_pools(pools));
    }

    /// Updates the full RA server configuration and publishes the change event.
    pub fn update_ra_server_config(&self, config: RaServerConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_ra(config));
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

    /// Updates the DNS listeners (UDP/TCP, `DoT`, `DoQ`, TLS identity): restarts the DNS service.
    pub fn update_dns_listen(&self, listen: DnsListenConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_listen(listen));
    }

    /// Updates the configured DNS adblock config and publishes the change event.
    pub fn update_dns_adblock(&self, adblock: AdblockDbConfig) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock(adblock));
    }

    /// Updates the configured DNS adblock URLs and publishes the change event.
    pub fn update_dns_adblock_urls(&self, urls: Vec<AdblockUrlEntry>) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock_urls(urls));
    }

    /// Updates the global adblock rules file's text and publishes the change event.
    pub fn update_dns_adblock_rules(&self, text: String) {
        let _ = self.apply_config(ConfigPatch::new().with_dns_adblock_rules(text));
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
