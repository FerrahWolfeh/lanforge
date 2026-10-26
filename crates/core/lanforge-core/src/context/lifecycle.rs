//! Lifecycle, readiness, service telemetry, and status coordination.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use lanforge_types::network::snapshot::{InterfaceSnapshot, WanSnapshot};
use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::system::{
    Cap, PppoeStatusResponse, RaStatusResponse, ServerCapabilities, ServiceBanner, ServiceId,
    ServiceState, SystemStatus, TrafficStatusResponse,
};
use lanforge_types::update::{DhcpV4PoolUpdate, DhcpV6PoolUpdate};
use smallvec::SmallVec;

use crate::context::state::network::DhcpPoolStats;
use crate::context::{DnsHandle, LanforgeContext, StorageHandle};
use crate::error::CoreError;
use crate::service::StatusProvider;

impl LanforgeContext {
    /// Sets the global system status.
    pub fn set_status(&self, status: SystemStatus) {
        *self.inner.runtime.status.write() = Some(status);
    }

    /// Returns a copy of the current system status, if set.
    #[must_use]
    pub fn get_status(&self) -> Option<SystemStatus> {
        self.inner.runtime.status.read().clone()
    }

    /// Sets the compiled capabilities for this daemon binary.
    pub fn set_compiled_caps(&self, caps: SmallVec<[Cap; 32]>) {
        *self.inner.runtime.compiled_caps.write() = caps;
    }

    /// Returns the compiled capabilities for this daemon binary.
    #[must_use]
    pub fn compiled_caps(&self) -> SmallVec<[Cap; 32]> {
        self.inner.runtime.compiled_caps.read().clone()
    }

    /// Evaluates compiled vs enabled server capabilities based on runtime configuration.
    #[must_use]
    pub fn server_capabilities(&self) -> ServerCapabilities {
        let compiled = self.compiled_caps();
        let mut enabled = SmallVec::new();
        let status = self.get_status();

        for &cap in &compiled {
            let is_enabled = match cap {
                Cap::Dns => status.as_ref().is_none_or(|s| s.dns_enabled),
                Cap::UpstreamUdpTcp | Cap::UpstreamDoT | Cap::UpstreamDoQ | Cap::UpstreamDoH => {
                    status.as_ref().is_none_or(|s| s.dns_enabled)
                }
                Cap::DohDownstream => status
                    .as_ref()
                    .is_none_or(|s| s.dns_enabled && s.http_enabled),
                Cap::DhcpV4 => status.as_ref().is_none_or(|s| s.dhcp_v4_enabled),
                Cap::DhcpV6 => status.as_ref().is_none_or(|s| s.dhcp_v6_enabled),
                Cap::Ra => {
                    let from_status = status.as_ref().is_none_or(|s| s.ra_enabled);
                    let from_config = self.with_config(|c| c.ra.enabled);
                    from_status && from_config
                }
                Cap::NdpDiscovery
                | Cap::MdnsProbe
                | Cap::Uds
                | Cap::Zstd
                | Cap::Storage
                | Cap::Ebpf => true,
                Cap::Http => status.as_ref().is_none_or(|s| s.http_enabled),
                Cap::Webui => status.as_ref().is_none_or(|s| s.http_enabled),
                Cap::Pppoe => {
                    let from_status = status.as_ref().is_none_or(|s| s.pppoe_enabled);
                    let from_config =
                        self.with_config(|c| c.pppoe.as_ref().is_none_or(|p| p.enabled));
                    from_status && from_config
                }
                Cap::Tftp => status.as_ref().and_then(|s| s.boot_dir.as_ref()).is_some(),
                Cap::Firewall => {
                    let from_status = status.as_ref().is_none_or(|s| s.firewall_enabled);
                    let from_config =
                        self.with_config(|c| c.firewall.as_ref().is_none_or(|f| f.enabled));
                    from_status && from_config
                }
                Cap::Traffic => {
                    let from_status = status.as_ref().is_none_or(|s| s.traffic_enabled);
                    let from_config = self.with_config(|c| {
                        c.traffic
                            .as_ref()
                            .is_none_or(|t| t.tuning.enabled || t.sqm.enabled)
                    });
                    from_status && from_config
                }
                Cap::Adblock => self.with_config(|c| c.dns_adblock.enabled),
            };

            if is_enabled {
                enabled.push(cap);
            }
        }

        ServerCapabilities { compiled, enabled }
    }

    /// Stores the latest traffic telemetry snapshot.
    pub fn set_traffic_telemetry(&self, telemetry: TrafficTelemetryResponse) {
        self.inner.runtime.set_traffic_telemetry(telemetry);
    }

    /// Retrieves the latest traffic telemetry snapshot, if available.
    #[must_use]
    pub fn traffic_telemetry(&self) -> Option<Arc<TrafficTelemetryResponse>> {
        self.inner.runtime.traffic_telemetry()
    }

    /// Registers a decoupled status provider.
    pub fn register_status_provider(&self, provider: Arc<dyn StatusProvider>) {
        self.inner.runtime.register_status_provider(self, provider);
    }

    /// Returns a list of all registered service status banners.
    #[must_use]
    pub fn service_banners(&self) -> Vec<ServiceBanner> {
        self.inner.runtime.service_banners(self)
    }

    /// Returns a list of all registered status providers.
    #[must_use]
    pub fn status_providers(&self) -> Vec<Arc<dyn StatusProvider>> {
        self.inner.runtime.status_providers()
    }

    /// Sets the decoupled DNS handle.
    pub fn set_dns_handle(&self, handle: DnsHandle) {
        *self.inner.runtime.dns_handle.write() = Some(handle);
    }

    /// Returns the decoupled DNS handle, if available.
    #[must_use]
    pub fn dns_handle(&self) -> Option<DnsHandle> {
        self.inner.runtime.dns_handle.read().clone()
    }

    /// Sets the decoupled storage handle.
    pub fn set_storage_handle(&self, handle: StorageHandle) {
        *self.inner.runtime.storage_handle.write() = Some(handle);
    }

    /// Returns the decoupled storage handle, if available.
    #[must_use]
    pub fn storage_handle(&self) -> Option<StorageHandle> {
        self.inner.runtime.storage_handle.read().clone()
    }

    /// Triggers an immediate commit of pending batches and live config to disk, awaiting completion.
    ///
    /// # Errors
    /// Returns an error if the database worker channel is closed or if the worker failed to flush.
    pub async fn flush_now(&self) -> Result<(), String> {
        if let Some(storage) = self.storage_handle() {
            storage.flush_now().await
        } else {
            Ok(())
        }
    }

    /// Sets the dynamic state of a service.
    pub fn set_service_state(&self, id: ServiceId, state: ServiceState) {
        self.inner.runtime.set_service_state(id, state);
    }

    /// Sets the state detail explanation of a service.
    pub fn set_service_detail(
        &self,
        id: ServiceId,
        detail: Option<lanforge_types::system::StateDetail>,
    ) {
        self.inner.runtime.set_service_detail(id, detail);
    }

    /// Returns the state detail of a service if any.
    #[must_use]
    pub fn get_service_detail(&self, id: ServiceId) -> Option<lanforge_types::system::StateDetail> {
        self.inner.runtime.get_service_detail(id)
    }

    /// Sets the start time of a service.
    pub fn set_service_start(&self, id: ServiceId, start: Instant) {
        self.inner.runtime.set_service_start(id, start);
    }

    /// Clears the start time of a service.
    pub fn clear_service_start(&self, id: ServiceId) {
        self.inner.runtime.clear_service_start(id);
    }

    /// Returns the dynamic state of a service, defaulting to Offline.
    #[must_use]
    pub fn get_service_state(&self, id: ServiceId) -> ServiceState {
        self.inner.runtime.get_service_state(id)
    }

    /// Returns the uptime of a service in seconds, or 0 if not running.
    #[must_use]
    pub fn get_service_uptime(&self, id: ServiceId) -> u64 {
        self.inner.runtime.get_service_uptime(id)
    }

    /// Registers an arbitrary typed shared service state.
    pub fn provide_shared<T: std::any::Any + Send + Sync + 'static>(&self, instance: Arc<T>) {
        self.inner.runtime.provide_shared(instance);
    }

    /// Retrieves an arbitrary typed shared service state by type.
    #[must_use]
    pub fn get_shared<T: std::any::Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.inner.runtime.get_shared::<T>()
    }

    /// Stores the active `PPPoE` WAN status response.
    pub fn set_pppoe_status(&self, status: Option<PppoeStatusResponse>) {
        self.inner.runtime.set_pppoe_status(status);
    }

    /// Retrieves the active `PPPoE` WAN status response.
    #[must_use]
    pub fn pppoe_status(&self) -> Option<Arc<PppoeStatusResponse>> {
        self.inner.runtime.pppoe_status()
    }

    /// Stores the active RA status response and synchronizes fallback prefixes with State.
    pub fn set_ra_status(&self, status: Option<RaStatusResponse>) {
        let (new_ula, new_gua) = status
            .as_ref()
            .map_or((None, None), |s| (s.active_ula_prefix, s.active_gua_prefix));
        let prefixes_changed = self.with_state_mut(|state| {
            let changed = state.interfaces.ra_ula_fallback != new_ula
                || state.interfaces.ra_gua_fallback != new_gua;
            state.interfaces.ra_ula_fallback = new_ula;
            state.interfaces.ra_gua_fallback = new_gua;
            changed
        });
        if prefixes_changed {
            self.rebuild_dns_indices();
        }
        self.inner.runtime.set_ra_status(status);
    }

    /// Retrieves the active RA status response.
    #[must_use]
    pub fn ra_status(&self) -> Option<Arc<RaStatusResponse>> {
        self.inner.runtime.ra_status()
    }

    /// Stores the active Traffic & SQM status response.
    pub fn set_traffic_status(&self, status: Option<TrafficStatusResponse>) {
        self.inner.runtime.set_traffic_status(status);
    }

    /// Retrieves the active Traffic & SQM status response.
    #[must_use]
    pub fn traffic_status(&self) -> Option<Arc<TrafficStatusResponse>> {
        self.inner.runtime.traffic_status()
    }

    /// Stores the active `DHCPv4` pool stats.
    pub fn set_dhcp_v4_pool_stats(&self, stats: Option<DhcpPoolStats>) {
        self.inner.runtime.set_dhcp_v4_pool_stats(stats);
    }

    /// Updates active `DHCPv4` pool stats from a pool update struct.
    pub fn set_dhcp_v4_pool_update(&self, update: &DhcpV4PoolUpdate) {
        self.inner.runtime.set_dhcp_v4_pool_update(update);
    }

    /// Retrieves the active `DHCPv4` pool stats.
    #[must_use]
    pub fn dhcp_v4_pool_stats(&self) -> Option<Arc<DhcpPoolStats>> {
        self.inner.runtime.dhcp_v4_pool_stats()
    }

    /// Stores `DHCPv6` pool stats for an IAID.
    pub fn set_dhcp_v6_pool_stats(&self, iaid: u32, stats: DhcpPoolStats) {
        self.inner.runtime.set_dhcp_v6_pool_stats(iaid, stats);
    }

    /// Updates active `DHCPv6` pool stats from a pool update struct.
    pub fn set_dhcp_v6_pool_update(&self, update: &DhcpV6PoolUpdate) {
        self.inner.runtime.set_dhcp_v6_pool_update(update);
    }

    /// Retrieves all active `DHCPv6` pool stats.
    #[must_use]
    pub fn dhcp_v6_pool_stats(&self) -> HashMap<u32, DhcpPoolStats> {
        self.inner.runtime.dhcp_v6_pool_stats()
    }

    /// Clears all active `DHCPv6` pool stats.
    pub fn clear_dhcp_v6_pool_stats(&self) {
        self.inner.runtime.clear_dhcp_v6_pool_stats();
    }

    /// Blocks until the network interfaces are ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_interfaces(&self) -> Result<(), CoreError> {
        self.inner.runtime.wait_for_interfaces().await
    }

    /// Blocks until the database is ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_db(&self) -> Result<(), CoreError> {
        self.inner.runtime.wait_for_db().await
    }

    /// Blocks until the specified service is `Online`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down before the service is online.
    pub async fn wait_for_service(&self, id: ServiceId) -> Result<(), CoreError> {
        self.inner.runtime.wait_for_service(id).await
    }

    /// Returns true if this instance is currently running.
    ///
    /// When false, the system is in shutdown mode and services should exit.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.runtime.is_running()
    }

    /// Sets the system lifecycle to shutdown mode for this instance.
    pub fn terminate(&self) {
        self.inner.runtime.terminate();
    }

    /// Resets the lifecycle flags (`running`, `db_ready`, `if_ready`, `pppoe_ready`) to initial state.
    pub fn reset_lifecycle(&self) {
        self.inner.runtime.reset_lifecycle();
    }

    /// Returns true if the database is ready.
    ///
    /// This flag is set by the database worker after successful initialization.
    #[must_use]
    pub fn is_db_ready(&self) -> bool {
        self.inner.runtime.is_db_ready()
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(&self, ready: bool) {
        self.inner.runtime.set_db_ready(ready);
    }

    /// Returns true if the system is running in recovery mode (in-memory fallback due to database unavailability).
    #[must_use]
    pub fn is_recovery_mode(&self) -> bool {
        self.inner.runtime.is_recovery_mode()
    }

    /// Sets the recovery mode state.
    pub fn set_recovery_mode(&self, recovery: bool) {
        self.inner.runtime.set_recovery_mode(recovery);
    }

    /// Returns a point-in-time snapshot of the effective WAN L3 connectivity.
    #[must_use]
    pub fn wan_snapshot(&self) -> WanSnapshot {
        self.inner.runtime.wan_snapshot()
    }

    /// Subscribes to changes in effective WAN L3 connectivity.
    #[must_use]
    pub fn watch_wan(&self) -> tokio::sync::watch::Receiver<WanSnapshot> {
        self.inner.runtime.watch_wan()
    }

    /// Sets the current WAN snapshot.
    pub fn set_wan_snapshot(&self, snapshot: WanSnapshot) {
        self.inner.runtime.set_wan_snapshot(snapshot);
    }

    /// Returns a point-in-time snapshot of discovered network interfaces.
    #[must_use]
    pub fn interfaces_snapshot(&self) -> InterfaceSnapshot {
        self.inner.runtime.interfaces_snapshot()
    }

    /// Subscribes to changes in discovered network interfaces.
    #[must_use]
    pub fn watch_interfaces(&self) -> tokio::sync::watch::Receiver<InterfaceSnapshot> {
        self.inner.runtime.watch_interfaces()
    }

    /// Sets the current network interface snapshot.
    pub fn set_interfaces_snapshot(&self, snapshot: InterfaceSnapshot) {
        self.inner.runtime.set_interfaces_snapshot(snapshot);
    }
}
