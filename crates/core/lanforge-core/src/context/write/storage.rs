//! Storage and lifecycle state management.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::update::DeviceUpdate;

use crate::bus::{DnsEvent, LanforgeEvent, SystemEvent};
use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Sets the system lifecycle to shutdown mode for this instance.
    pub fn terminate(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Resets the lifecycle flags (`running`, `db_ready`, `if_ready`, `pppoe_ready`) to `true`/`false`/`false`/`false`.
    /// Used during soft-reboot.
    pub fn reset_lifecycle(&self) {
        self.inner.running.store(true, Ordering::SeqCst);
        self.inner.db_ready.store(false, Ordering::SeqCst);
        self.inner.if_ready.store(false, Ordering::SeqCst);
        self.inner.pppoe_ready.store(false, Ordering::SeqCst);
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(&self, ready: bool) {
        self.inner.db_ready.store(ready, Ordering::SeqCst);
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(&self, ready: bool) {
        self.inner.if_ready.store(ready, Ordering::SeqCst);
    }

    /// Sets the `PPPoE` session readiness state.
    pub fn set_pppoe_ready(&self, ready: bool) {
        self.inner.pppoe_ready.store(ready, Ordering::SeqCst);
    }

    /// Registers a shared service state or context.
    pub fn register_service_state<T: Any + Send + Sync + 'static>(&self, key: &str, state: Arc<T>) {
        self.inner
            .shared_services
            .write()
            .insert(key.to_string(), state as Arc<dyn Any + Send + Sync>);
    }

    /// Updates the configured `DHCPv4` pools and publishes the change event.
    pub fn update_dhcp_v4_pools(&self, pools: Vec<Dhcpv4Pool>) {
        *self.inner.dhcp_v4_pools.write() = pools;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed));
    }

    /// Updates the configured `DHCPv6` pools and publishes the change event.
    pub fn update_dhcp_v6_pools(&self, pools: Vec<Dhcpv6Pool>) {
        *self.inner.dhcp_v6_pools.write() = pools;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigDhcpV6Changed));
    }

    /// Updates the configured RA prefix/DNS/domain search lists and publishes the change event.
    pub fn update_ra_config(
        &self,
        prefixes: Vec<RAPrefix>,
        rdnss: Vec<RdnssConfig>,
        dnssl: Vec<DnsslConfig>,
    ) {
        *self.inner.ra_prefixes.write() = prefixes;
        *self.inner.ra_rdnss.write() = rdnss;
        *self.inner.ra_dnssl.write() = dnssl;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
    }

    /// Updates the configured DNS upstreams and publishes the change event.
    pub fn update_dns_upstreams(&self, upstreams: Vec<UpstreamTarget>) {
        *self.inner.dns_upstreams.write() = upstreams;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigUpstreamsChanged));
    }

    /// Updates the configured DNS rewrites and publishes the change event.
    pub fn update_dns_rewrites(&self, rewrites: Vec<RewriteRule>) {
        *self.inner.dns_rewrites.write() = rewrites;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigRewritesChanged));
    }

    /// Updates the configured DNS allowlist and publishes the change event.
    pub fn update_dns_allowlist(&self, allowlist: Vec<String>) {
        *self.inner.dns_allowlist.write() = allowlist;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged));
    }

    /// Updates the configured DNS adblock config and publishes the change event.
    pub fn update_dns_adblock(&self, adblock: AdblockDbConfig) {
        *self.inner.dns_adblock.write() = adblock;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    }

    /// Updates the configured DNS adblock URLs and publishes the change event.
    pub fn update_dns_adblock_urls(&self, urls: Vec<AdblockUrlEntry>) {
        *self.inner.dns_adblock_urls.write() = urls;
        let _ = self
            .bus_ref()
            .publish(LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged));
    }

    /// Completely resets the in-memory state.
    pub fn reset(&self) {
        let _ = self.apply(DeviceUpdate::Reset);
        *self.inner.last_db_flush.write() = None;
    }
}
