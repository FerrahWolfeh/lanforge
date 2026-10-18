//! `LanforgeContext` — Thread-safe central state and event coordination.
//!
//! This module provides the main entry point for all system state mutations
//! and event publishing. It wraps the device [`State`](state::State) in a
//! `parking_lot::RwLock` and provides a unified API for reading and writing.
//!
//! # Architecture
//!
//! ```mermaid
//! graph TD
//!     A[LanforgeContext] --> B[Arc&lt;LanforgeContextInner&gt;]
//!     B --> C[EventBus]
//!     B --> D[RwLock&lt;State&gt;]
//!     B --> E[Atomic Flags]
//!     B --> F[target_ifindex]
//! ```
//!
//! # Key Components
//!
//! | Submodule | Purpose |
//! |-----------|---------|
//! | [`read`]  | Read-only queries (get device by MAC, IP, hostname) |
//! | [`write`] | State mutations (apply updates, allocate leases) |
//! | [`state`] | Raw device state and interface storage |
//!
//! # Usage Pattern
//!
//! ```rust
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::bus::EventBus;
//! use std::sync::Arc;
//!
//! let bus = Arc::new(EventBus::new());
//! // State is usually initialized via State::new() or from DB
//! let ctx = LanforgeContext::new(bus, Default::default(), None);
//!
//! // Read
//! let devices = ctx.all_devices();
//!
//! // Write
//! // ctx.apply(DeviceUpdate::...);
//! ```
//!
//! # Thread Safety
//!
//! All operations are thread-safe. Multiple readers can access state
//! concurrently, while writes acquire an exclusive lock.
//!
//! # Lifecycle Management
//!
//! The context tracks readiness states:
//! - **DB Ready**: Database worker is active
//! - **Interface Ready**: Network interfaces are configured
//! - **Running**: System is operational (false = shutdown)

use crate::bus::{EventBus, LanforgeEvent, SystemEvent, TimedEvent};
use crate::context::state::network::DhcpPoolStats;
use crate::context::state::State;
use crate::error::CoreError;
use crate::service::{ServiceDependency, StatusProvider};
use lanforge_types::device::Device;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::events::FirewallEvent;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::{UpstreamMode, UpstreamTarget};
use lanforge_types::network::firewall::{
    validate_firewall_candidate, DynamicPortRequest, FirewallConfig, FirewallTransactionState,
    FirewallValidationReport, L4Protocol,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig, RaServerConfig};
use lanforge_types::network::TrafficConfig;
use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::system::{
    Cap, PppoeStatusResponse, RaStatusResponse, ServerCapabilities, ServiceBanner, ServiceState,
    SystemStatus, TrafficStatusResponse,
};
use lanforge_types::update::{DhcpV4PoolUpdate, DhcpV6PoolUpdate};
use smallvec::SmallVec;

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

pub mod caps;
pub mod dns_handle;
pub mod read;
pub mod runtime;
pub mod state;
pub mod storage_handle;
#[cfg(test)]
pub mod tests;
pub mod write;

pub use self::caps::CompiledCaps;
pub use self::dns_handle::DnsHandle;
pub use self::runtime::ServiceRuntime;
pub use self::storage_handle::StorageHandle;

use std::sync::atomic::AtomicU64;

/// Internal counters for tracking transient network events.
///
/// These are exported via Prometheus to monitor discovery rates.
#[derive(Debug, Default)]
pub struct EventCounters {
    pub arp_seen: AtomicU64,
    pub ndp_seen: AtomicU64,
    pub slaac_observed: AtomicU64,
    pub dhcp_v4_leases: AtomicU64,
    pub dhcp_v6_leases: AtomicU64,
    pub dns_auth_hits: AtomicU64,
    #[cfg(feature = "adblock")]
    pub dns_blocked: AtomicU64,
}

/// Lightweight handle for service interaction with the event bus.
///
/// Provides bus subscription and shutdown detection without requiring
/// manual `bus().subscribe()` + `is_running()` checks.
/// Created via [`LanforgeContext::service_handle()`].
///
/// # Usage
///
/// ```rust,ignore
/// let mut handle = ctx.service_handle();
/// loop {
///     let Some(event) = handle.next_event().await else { break; };
///     // handle event...
/// }
/// ```
pub struct ServiceHandle {
    rx: Receiver<TimedEvent>,
    ctx: LanforgeContext,
}

impl ServiceHandle {
    /// Returns the next event, or `None` if the system is shutting down.
    ///
    /// Automatically handles:
    /// - `Shutdown` event detection → returns `None`
    /// - `is_running()` check → returns `None`
    /// - Broadcast lag recovery → skips lagged events, continues
    pub async fn next_event(&mut self) -> Option<TimedEvent> {
        loop {
            if !self.ctx.is_running() {
                return None;
            }
            match self.rx.recv().await {
                Ok(te) => {
                    if matches!(te.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                        return None;
                    }
                    return Some(te);
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Publishes an event to the bus.
    #[must_use]
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.ctx.bus().publish(event)
    }
}

/// Lightweight snapshot of the state for persistence.
///
/// Contains only the data necessary for the database worker to flush
/// state to disk, avoiding the need to clone the entire `State` struct.
pub struct PersistenceSnapshot {
    pub devices: HashMap<MacAddr, Arc<Device>>,
    pub timestamp: SystemTime,
}

#[derive(Clone)]
pub struct LanforgeContext {
    inner: Arc<LanforgeContextInner>,
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
    /// Configured RA prefixes.
    pub ra_prefixes: Vec<RAPrefix>,
    /// Configured RA RDNSS.
    pub ra_rdnss: Vec<RdnssConfig>,
    /// Configured RA DNSSL.
    pub ra_dnssl: Vec<DnsslConfig>,
    /// Full RA server runtime configuration.
    pub ra_config: Option<RaServerConfig>,
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

/// Internal state shared behind an `Arc`.
///
/// This is intentionally private to enforce access patterns — all interaction
/// goes through the typed methods on [`LanforgeContext`].
struct LanforgeContextInner {
    /// The event bus for broadcasting state changes.
    bus: Arc<EventBus>,
    /// The device and interface state, protected by an `ArcSwap` for wait-free reads.
    state: ArcSwap<state::State>,
    /// Serializes state mutations without blocking readers.
    writer_mutex: Mutex<()>,
    /// Volatile network discovery store (NDP cache, orphaned v6 leases).
    discovery: Arc<state::cache::DiscoveryStore>,
    /// The network interface index to monitor for RA/DHCP.
    target_ifindex: Option<u32>,
    /// The primary LAN interface name (e.g. "lan0").
    target_ifname: RwLock<Option<String>>,
    /// Consolidated dynamic subsystem configurations.
    config: RwLock<DynamicConfig>,
    /// Central service execution runtime and status container.
    pub runtime: ServiceRuntime,
}

#[allow(clippy::missing_panics_doc)] // Temporary
impl LanforgeContext {
    /// Creates a new isolated context instance.
    ///
    /// # Parameters
    ///
    /// - `bus`: The shared event bus for publishing state changes
    /// - `state`: The initial device state (can be empty via [`State::new()`])
    /// - `target_ifindex`: Optional interface index to monitor for RA/DHCP events.
    ///   If `None`, the system will auto-detect the primary interface.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::context::LanforgeContext;
    /// use lanforge_core::bus::EventBus;
    /// use std::sync::Arc;
    ///
    /// let bus = Arc::new(EventBus::new());
    /// let ctx = LanforgeContext::new(bus, Default::default(), None);
    ///
    /// assert!(ctx.is_running());
    /// assert!(ctx.target_ifindex().is_none());
    /// ```
    #[must_use]
    pub fn new(bus: Arc<EventBus>, state: State, target_ifindex: Option<u32>) -> Self {
        let inner = Arc::new(LanforgeContextInner {
            bus: bus.clone(),
            state: ArcSwap::from_pointee(state),
            writer_mutex: Mutex::new(()),
            discovery: Arc::new(state::cache::DiscoveryStore::default()),
            target_ifindex,
            target_ifname: RwLock::new(None),
            config: RwLock::new(DynamicConfig::default()),
            runtime: ServiceRuntime::new(bus),
        });
        Self { inner }
    }

    /// Access the underlying `ServiceRuntime` coordinator.
    #[must_use]
    pub fn runtime(&self) -> &ServiceRuntime {
        &self.inner.runtime
    }

    /// Returns a reference to the volatile discovery store.
    #[must_use]
    pub fn discovery(&self) -> &Arc<state::cache::DiscoveryStore> {
        &self.inner.discovery
    }

    /// Executes a closure with exclusive write access to the state via Copy-on-Write.
    pub fn with_state_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut State) -> R,
    {
        let _guard = self.inner.writer_mutex.lock();
        let current = self.inner.state.load_full();
        let mut new_state = (*current).clone();
        let result = f(&mut new_state);
        self.inner.state.store(Arc::new(new_state));
        result
    }

    /// Sets the path to the active TOML configuration file.
    pub fn set_config_path(&self, path: impl Into<std::path::PathBuf>) {
        *self.inner.runtime.config_path.write() = Some(path.into());
    }

    /// Returns the path to the active TOML configuration file, if set.
    #[must_use]
    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        self.inner.runtime.config_path.read().clone()
    }

    /// Returns the uptime of this context in seconds.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.inner.runtime.start_time.elapsed().as_secs()
    }

    /// Returns the target interface index for this context.
    ///
    /// This is the interface monitored for router advertisements and DHCP events.
    /// Returns `None` if no specific interface is configured.
    #[must_use]
    pub fn target_ifindex(&self) -> Option<u32> {
        self.inner.target_ifindex
    }

    /// Returns the primary LAN interface name (e.g. "lan0") for this context.
    #[must_use]
    pub fn target_interface_name(&self) -> Option<String> {
        self.inner.target_ifname.read().clone()
    }

    /// Sets the primary LAN interface name for this context.
    pub fn set_target_interface_name(&self, name: String) {
        *self.inner.target_ifname.write() = Some(name);
    }

    /// Returns the shared event bus for this instance.
    ///
    /// The bus can be used to subscribe to or publish events.
    #[must_use]
    pub fn bus(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Returns a reference to the shared event bus.
    ///
    /// Useful for publishing events without cloning the Arc.
    #[must_use]
    pub fn bus_ref(&self) -> &EventBus {
        &self.inner.bus
    }

    /// Records a new database flush timestamp.
    ///
    /// Call this after a successful database write to track staleness.
    pub fn record_db_flush(&self) {
        *self.inner.runtime.last_db_flush.write() = Some(SystemTime::now());
    }

    /// Returns the last database flush time, if any.
    ///
    /// Used to determine if the in-memory state is synced to disk.
    #[must_use]
    pub fn last_db_flush(&self) -> Option<SystemTime> {
        *self.inner.runtime.last_db_flush.read()
    }

    /// Access the global active API clients counter.
    #[must_use]
    pub fn active_clients(&self) -> Arc<AtomicUsize> {
        self.inner.runtime.active_clients.clone()
    }

    /// Returns the internal event counters.
    #[must_use]
    pub fn counters(&self) -> &EventCounters {
        &self.inner.runtime.event_counters
    }

    /// Returns the database worker metrics.
    #[must_use]
    pub fn db_metrics(&self) -> &DbWorkerMetrics {
        &self.inner.runtime.db_metrics
    }

    /// Creates a lightweight service handle for event-driven services.
    ///
    /// The handle provides `next_event()` for the service main loop and
    /// `publish()` for emitting events. Use this instead of manually calling
    /// `bus().subscribe()` + `is_running()` in a loop.
    ///
    /// **NOTE**: The supervisor (`supervise_async`) still uses its own
    /// `bus().subscribe()` for the outer shutdown select. This handle is
    /// for use INSIDE `service.run()`.
    #[must_use]
    pub fn service_handle(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to network events.
    #[must_use]
    pub fn service_handle_network(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_network(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to DNS events.
    #[must_use]
    pub fn service_handle_dns(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_dns(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to device events.
    #[must_use]
    pub fn service_handle_device(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_device(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to storage events.
    #[must_use]
    pub fn service_handle_storage(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_storage(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to `PPPoE` events.
    #[must_use]
    pub fn service_handle_pppoe(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_pppoe(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to firewall events.
    #[must_use]
    pub fn service_handle_firewall(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_firewall(),
            ctx: self.clone(),
        }
    }

    /// Creates a dedicated `ServiceHandle` subscribing only to traffic events.
    #[must_use]
    pub fn service_handle_traffic(&self) -> ServiceHandle {
        ServiceHandle {
            rx: self.inner.bus.subscribe_traffic(),
            ctx: self.clone(),
        }
    }

    /// Registers a dynamic port requirement for an internal service (e.g. HTTP `WebUI`, DNS, DHCP).
    ///
    /// Stores the port in context and broadcasts a `FirewallEvent::PortOpenRequested` on the bus.
    pub fn register_service_port(&self, request: DynamicPortRequest) {
        let added = {
            let mut ports = self.inner.runtime.firewall_ports.write();
            if ports.iter().any(|p| {
                p.service == request.service && p.port == request.port && p.protocol == request.protocol
            }) {
                false
            } else {
                ports.push(request.clone());
                true
            }
        };
        if added {
            let _ = self
                .inner
                .bus
                .publish(LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(
                    Box::new(request),
                )));
        }
    }

    /// Releases a previously registered dynamic port requirement.
    pub fn release_service_port(&self, service: &str, port: u16, protocol: L4Protocol) {
        let removed = {
            let mut ports = self.inner.runtime.firewall_ports.write();
            let initial = ports.len();
            ports.retain(|p| !(p.service == service && p.port == port && p.protocol == protocol));
            ports.len() != initial
        };
        if removed {
            let _ = self
                .inner
                .bus
                .publish(LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested {
                    service: service.to_string(),
                    port,
                    protocol,
                }));
        }
    }

    /// Returns all registered dynamic service ports.
    #[must_use]
    pub fn registered_service_ports(&self) -> Vec<DynamicPortRequest> {
        self.inner.runtime.firewall_ports.read().clone()
    }

    /// Returns a copy of the current dynamic subsystem configurations.
    #[must_use]
    pub fn config(&self) -> DynamicConfig {
        self.inner.config.read().clone()
    }

    /// Executes a closure with read access to the dynamic configurations.
    pub fn with_config<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&DynamicConfig) -> R,
    {
        f(&self.inner.config.read())
    }

    /// Executes a closure with write access to the dynamic configurations.
    pub fn update_config<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DynamicConfig) -> R,
    {
        f(&mut self.inner.config.write())
    }

    /// Increments the DNS blocked queries counter.
    #[cfg(feature = "adblock")]
    pub fn inc_dns_blocked(&self) {
        self.inner
            .runtime
            .event_counters
            .dns_blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Captures a snapshot of the device registry for database persistence.
    ///
    /// This acquires a read lock on the state and clones only the device map
    /// (shallow clone of Arcs).
    #[must_use]
    pub fn snapshot_for_persistence(&self) -> PersistenceSnapshot {
        let state = self.read();
        PersistenceSnapshot {
            devices: state.devices.clone(),
            timestamp: SystemTime::now(),
        }
    }

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
                Cap::DohDownstream => {
                    status.as_ref().is_none_or(|s| s.dns_enabled && s.http_enabled)
                }
                Cap::DhcpV4 => status.as_ref().is_none_or(|s| s.dhcp_v4_enabled),
                Cap::DhcpV6 => status.as_ref().is_none_or(|s| s.dhcp_v6_enabled),
                Cap::Ra => {
                    let from_status = status.as_ref().is_none_or(|s| s.ra_enabled);
                    let from_config = self.with_config(|c| c.ra_config.as_ref().is_none_or(|r| r.enabled));
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
                    let from_config = self.with_config(|c| c.pppoe.as_ref().is_none_or(|p| p.enabled));
                    from_status && from_config
                }
                Cap::Tftp => status.as_ref().and_then(|s| s.boot_dir.as_ref()).is_some(),
                Cap::Firewall => {
                    let from_status = status.as_ref().is_none_or(|s| s.firewall_enabled);
                    let from_config = self.with_config(|c| c.firewall.as_ref().is_none_or(|f| f.enabled));
                    from_status && from_config
                }
                Cap::Traffic => {
                    let from_status = status.as_ref().is_none_or(|s| s.traffic_enabled);
                    let from_config = self.with_config(|c| {
                        c.traffic.as_ref().is_none_or(|t| t.tuning.enabled || t.sqm.enabled)
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

    #[must_use]
    pub fn get_dhcp_v4_pools(&self) -> Vec<Dhcpv4Pool> {
        self.inner.config.read().dhcp_v4_pools.clone()
    }

    #[must_use]
    pub fn get_dhcp_v6_pools(&self) -> Vec<Dhcpv6Pool> {
        self.inner.config.read().dhcp_v6_pools.clone()
    }

    #[must_use]
    pub fn get_dhcp_options(&self) -> DhcpOptionsConfig {
        self.inner.config.read().dhcp_options.clone()
    }

    #[must_use]
    pub fn get_ra_prefixes(&self) -> Vec<RAPrefix> {
        self.inner.config.read().ra_prefixes.clone()
    }

    #[must_use]
    pub fn get_ra_rdnss(&self) -> Vec<RdnssConfig> {
        self.inner.config.read().ra_rdnss.clone()
    }

    #[must_use]
    pub fn get_ra_dnssl(&self) -> Vec<DnsslConfig> {
        self.inner.config.read().ra_dnssl.clone()
    }

    #[must_use]
    pub fn get_ra_server_config(&self) -> RaServerConfig {
        let cfg = self.inner.config.read();
        cfg.ra_config.as_ref().map_or_else(
            || RaServerConfig {
                prefixes: cfg.ra_prefixes.clone(),
                rdnss: cfg.ra_rdnss.clone(),
                dnssl: cfg.ra_dnssl.clone(),
                ..Default::default()
            },
            |ra_cfg| {
                let mut c = ra_cfg.clone();
                c.prefixes.clone_from(&cfg.ra_prefixes);
                c.rdnss.clone_from(&cfg.ra_rdnss);
                c.dnssl.clone_from(&cfg.ra_dnssl);
                c
            },
        )
    }

    /// Returns the current dynamic `PPPoE` configuration, if configured.
    #[must_use]
    pub fn get_pppoe_config(&self) -> Option<PppoeConfig> {
        self.inner.config.read().pppoe.clone()
    }

    /// Returns the current dynamic firewall configuration, if configured.
    #[must_use]
    pub fn get_firewall_config(&self) -> Option<FirewallConfig> {
        self.inner.config.read().firewall.clone()
    }

    /// Returns the current dynamic traffic and SQM configuration, if configured.
    #[must_use]
    pub fn get_traffic_config(&self) -> Option<TrafficConfig> {
        self.inner.config.read().traffic.clone()
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

    /// Evaluates a candidate firewall configuration, runs pre-flight sanity checks,
    /// and stages it as an active pending transaction if valid.
    #[must_use]
    pub fn stage_firewall_transaction(&self, candidate: FirewallConfig) -> FirewallValidationReport {
        let current = self.get_firewall_config().unwrap_or_default();
        let dynamic_ports = self.registered_service_ports();

        let report = validate_firewall_candidate(
            &candidate,
            &current,
            &dynamic_ports,
            || {
                let id = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                format!("tx-{id:x}")
            },
        );

        if let Some(ref tx_id) = report.tx_id {
            let now = Instant::now();
            let mut tx_lock = self.inner.runtime.firewall_tx.write();
            *tx_lock = Some(FirewallTransactionState {
                tx_id: tx_id.clone(),
                candidate_config: candidate,
                previous_config: Some(current),
                created_at: now,
                expires_at: now + std::time::Duration::from_secs(300),
                auto_rollback_deadline: None,
            });
        }

        report
    }

    /// Retrieves the staged firewall transaction if not expired.
    #[must_use]
    pub fn get_staged_firewall_transaction(&self) -> Option<FirewallTransactionState> {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref tx) = *tx_lock
            && Instant::now() > tx.expires_at
        {
            *tx_lock = None;
            return None;
        }
        tx_lock.clone()
    }

    /// Sets an auto-rollback deadline for the active staged transaction.
    #[must_use]
    pub fn set_firewall_transaction_rollback(&self, tx_id: &str, deadline: Instant) -> bool {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref mut tx) = *tx_lock
            && tx.tx_id == tx_id
        {
            tx.auto_rollback_deadline = Some(deadline);
            return true;
        }
        drop(tx_lock);
        false
    }

    /// Clears the staged firewall transaction.
    #[must_use]
    pub fn clear_staged_firewall_transaction(&self, tx_id: Option<&str>) -> Option<FirewallTransactionState> {
        let mut tx_lock = self.inner.runtime.firewall_tx.write();
        if let Some(ref tx) = *tx_lock
            && (tx_id.is_none() || tx_id == Some(tx.tx_id.as_str()))
        {
            return tx_lock.take();
        }
        None
    }

    #[must_use]
    pub fn get_dns_upstreams(&self) -> Vec<UpstreamTarget> {
        self.inner.config.read().dns_upstreams.clone()
    }

    #[must_use]
    pub fn get_dns_rewrites(&self) -> Vec<RewriteRule> {
        self.inner.config.read().dns_rewrites.clone()
    }

    #[must_use]
    pub fn get_dns_allowlist(&self) -> Vec<String> {
        self.inner.config.read().dns_allowlist.clone()
    }

    #[must_use]
    pub fn get_dns_adblock(&self) -> AdblockDbConfig {
        self.inner.config.read().dns_adblock.clone()
    }

    #[must_use]
    pub fn get_dns_adblock_urls(&self) -> Vec<AdblockUrlEntry> {
        self.inner.config.read().dns_adblock_urls.clone()
    }

    #[must_use]
    pub fn get_dns_adblock_rules(&self) -> Vec<AdblockRuleEntry> {
        self.inner.config.read().dns_adblock_rules.clone()
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

    /// Sets the dynamic state of a service.
    pub fn set_service_state(&self, id: &str, state: ServiceState) {
        self.inner.runtime.set_service_state(id, state);
    }

    /// Sets the start time of a service.
    pub fn set_service_start(&self, id: &str, start: Instant) {
        self.inner.runtime.set_service_start(id, start);
    }

    /// Clears the start time of a service.
    pub fn clear_service_start(&self, id: &str) {
        self.inner.runtime.clear_service_start(id);
    }

    /// Returns the dynamic state of a service, defaulting to Offline.
    #[must_use]
    pub fn get_service_state(&self, id: &str) -> ServiceState {
        self.inner.runtime.get_service_state(id)
    }

    /// Returns the uptime of a service in seconds, or 0 if not running.
    #[must_use]
    pub fn get_service_uptime(&self, id: &str) -> u64 {
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
        let (new_ula, new_gua) = status.as_ref().map_or((None, None), |s| {
            (s.active_ula_prefix, s.active_gua_prefix)
        });
        let prefixes_changed = self.with_state_mut(|state| {
            let changed = state.interfaces.ra_ula_fallback != new_ula
                || state.interfaces.ra_gua_fallback != new_gua;
            state.interfaces.ra_ula_fallback = new_ula;
            state.interfaces.ra_gua_fallback = new_gua;
            changed
        });
        if prefixes_changed {
            let _ = self.apply(lanforge_types::update::DeviceUpdate::RebuildDnsIndices);
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
}

// ---------------------------------------------------------------------------
// Lifecycle & Coordination
// ---------------------------------------------------------------------------

impl LanforgeContext {
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

    /// Blocks until the `PPPoE` session is established (or short-circuits if `PPPoE` is disabled/ready).
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_pppoe(&self) -> Result<(), CoreError> {
        self.inner.runtime.wait_for_pppoe().await
    }

    /// Blocks until the specified dependency is satisfied.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down before the dependency is ready.
    pub async fn wait_for_dependency(&self, dep: ServiceDependency) -> Result<(), CoreError> {
        self.inner.runtime.wait_for_dependency(dep).await
    }

    /// Blocks until the specified service is `Online`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down before the service is online.
    pub async fn wait_for_service(&self, id: &str) -> Result<(), CoreError> {
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

    /// Returns true if the network interfaces are ready.
    ///
    /// This flag is set after interface discovery completes successfully.
    #[must_use]
    pub fn is_if_ready(&self) -> bool {
        self.inner.runtime.is_if_ready()
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(&self, ready: bool) {
        self.inner.runtime.set_if_ready(ready);
    }

    /// Returns true if the `PPPoE` session is ready.
    ///
    /// This flag is set when `PPPoE` session is established or if `PPPoE` is disabled.
    #[must_use]
    pub fn is_pppoe_ready(&self) -> bool {
        self.inner.runtime.is_pppoe_ready()
    }

    /// Sets the `PPPoE` session readiness state.
    pub fn set_pppoe_ready(&self, ready: bool) {
        self.inner.runtime.set_pppoe_ready(ready);
    }
}

/// Thread-safe metrics collected by the database worker.
#[derive(Debug)]
pub struct DbWorkerMetrics {
    pub last_flush_ts: AtomicU64,
    pub flush_count: AtomicU64,
    pub devices_written: AtomicU64,
    pub last_error: AtomicBool,
}

impl Default for DbWorkerMetrics {
    fn default() -> Self {
        Self {
            last_flush_ts: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            devices_written: AtomicU64::new(0),
            last_error: AtomicBool::new(false),
        }
    }
}
