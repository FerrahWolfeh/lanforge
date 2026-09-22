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

use crate::bus::{EventBus, LanforgeEvent, PppoeEvent, SystemEvent, TimedEvent};
use crate::context::state::State;
use crate::error::CoreError;
use crate::firewall::FirewallTransactionState;
use crate::service::{ServiceDependency, StatusProvider};
use lanforge_types::device::Device;
use lanforge_types::dhcp::{Dhcpv4Stats, Dhcpv6Stats};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::events::FirewallEvent;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallValidationReport, L4Protocol,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig, RaServerConfig};
use lanforge_types::network::TrafficConfig;
use lanforge_types::system::{ServiceBanner, ServiceState, SystemStatus};

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

pub mod caps;
pub mod dns_handle;
pub mod read;
pub mod state;
#[cfg(test)]
pub mod tests;
pub mod write;

pub use self::caps::CompiledCaps;
pub use self::dns_handle::DnsHandle;

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
    /// System running flag — set to false on shutdown.
    running: AtomicBool,
    /// Database readiness flag.
    db_ready: AtomicBool,
    /// Recovery mode flag (in-memory fallback without disk persistence).
    recovery_mode: AtomicBool,
    /// Network interface readiness flag.
    if_ready: AtomicBool,
    /// `PPPoE` session readiness flag.
    pppoe_ready: AtomicBool,
    /// Generic registry for shared service states/contexts.
    shared_services: RwLock<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
    /// Consolidated dynamic subsystem configurations.
    config: RwLock<DynamicConfig>,
    /// Shared `DHCPv4` statistics.
    dhcpv4_stats: Arc<Dhcpv4Stats>,
    /// Shared `DHCPv6` statistics.
    dhcpv6_stats: Arc<Dhcpv6Stats>,
    /// Timestamp of the last successful database flush.
    last_db_flush: RwLock<Option<SystemTime>>,
    /// Internal counters for event rates.
    event_counters: EventCounters,
    /// Dynamic port requests from internal services (HTTP, DNS, DHCP, etc.).
    firewall_ports: RwLock<Vec<DynamicPortRequest>>,
    /// Staged candidate firewall transaction.
    firewall_tx: RwLock<Option<FirewallTransactionState>>,

    /// Global system status for reporting.
    status: RwLock<Option<SystemStatus>>,
    /// Global counter for active API clients (Control UDS, HTTP, etc.).
    pub active_clients: Arc<AtomicUsize>,
    /// Decoupled status providers.
    status_providers: RwLock<BTreeMap<String, Arc<dyn StatusProvider>>>,
    /// Decoupled DNS handle.
    dns_handle: RwLock<Option<DnsHandle>>,
    /// Dynamic service states.
    service_states: RwLock<HashMap<String, ServiceState>>,
    /// Dynamic service start times.
    service_starts: RwLock<HashMap<String, Instant>>,
    /// Context creation timestamp for calculating uptime.
    start_time: Instant,
    /// Database worker metrics.
    db_metrics: DbWorkerMetrics,
    /// Path to the active TOML configuration file on disk.
    config_path: RwLock<Option<std::path::PathBuf>>,
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
            bus,
            state: ArcSwap::from_pointee(state),
            writer_mutex: Mutex::new(()),
            discovery: Arc::new(state::cache::DiscoveryStore::default()),
            target_ifindex,
            target_ifname: RwLock::new(None),
            running: AtomicBool::new(true),
            db_ready: AtomicBool::new(false),
            recovery_mode: AtomicBool::new(false),
            if_ready: AtomicBool::new(false),
            pppoe_ready: AtomicBool::new(false),
            shared_services: RwLock::new(HashMap::new()),
            config: RwLock::new(DynamicConfig::default()),
            dhcpv4_stats: Arc::new(Dhcpv4Stats::new()),
            dhcpv6_stats: Arc::new(Dhcpv6Stats::new()),
            last_db_flush: RwLock::new(None),
            event_counters: EventCounters::default(),
            firewall_ports: RwLock::new(Vec::new()),
            firewall_tx: RwLock::new(None),

            status: RwLock::new(None),
            active_clients: Arc::new(AtomicUsize::new(0)),
            status_providers: RwLock::new(BTreeMap::new()),
            dns_handle: RwLock::new(None),
            service_states: RwLock::new(HashMap::new()),
            service_starts: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
            db_metrics: DbWorkerMetrics::default(),
            config_path: RwLock::new(None),
        });
        Self { inner }
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
        *self.inner.config_path.write() = Some(path.into());
    }

    /// Returns the path to the active TOML configuration file, if set.
    #[must_use]
    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        self.inner.config_path.read().clone()
    }

    /// Returns the uptime of this context in seconds.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.inner.start_time.elapsed().as_secs()
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
        *self.inner.last_db_flush.write() = Some(SystemTime::now());
    }

    /// Returns the last database flush time, if any.
    ///
    /// Used to determine if the in-memory state is synced to disk.
    #[must_use]
    pub fn last_db_flush(&self) -> Option<SystemTime> {
        *self.inner.last_db_flush.read()
    }

    /// Access the global active API clients counter.
    #[must_use]
    pub fn active_clients(&self) -> Arc<AtomicUsize> {
        self.inner.active_clients.clone()
    }

    /// Returns the internal event counters.
    #[must_use]
    pub fn counters(&self) -> &EventCounters {
        &self.inner.event_counters
    }

    /// Returns the database worker metrics.
    #[must_use]
    pub fn db_metrics(&self) -> &DbWorkerMetrics {
        &self.inner.db_metrics
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
        {
            let mut ports = self.inner.firewall_ports.write();
            if !ports.iter().any(|p| {
                p.service == request.service && p.port == request.port && p.protocol == request.protocol
            }) {
                ports.push(request.clone());
            }
        }
        let _ = self
            .inner
            .bus
            .publish(LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(
                Box::new(request),
            )));
    }

    /// Releases a previously registered dynamic port requirement.
    pub fn release_service_port(&self, service: &str, port: u16, protocol: L4Protocol) {
        {
            let mut ports = self.inner.firewall_ports.write();
            ports.retain(|p| !(p.service == service && p.port == port && p.protocol == protocol));
        }
        let _ = self
            .inner
            .bus
            .publish(LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested {
                service: service.to_string(),
                port,
                protocol,
            }));
    }

    /// Returns all registered dynamic service ports.
    #[must_use]
    pub fn registered_service_ports(&self) -> Vec<DynamicPortRequest> {
        self.inner.firewall_ports.read().clone()
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
            .event_counters
            .dns_blocked
            .fetch_add(1, Ordering::Relaxed);
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
        *self.inner.status.write() = Some(status);
    }

    /// Returns a copy of the current system status, if set.
    #[must_use]
    pub fn get_status(&self) -> Option<SystemStatus> {
        self.inner.status.read().clone()
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

    /// Evaluates a candidate firewall configuration, runs pre-flight sanity checks,
    /// and stages it as an active pending transaction if valid.
    #[must_use]
    pub fn stage_firewall_transaction(&self, candidate: FirewallConfig) -> FirewallValidationReport {
        let current = self.get_firewall_config().unwrap_or_default();
        let dynamic_ports = self.registered_service_ports();

        let report = crate::firewall::validate_firewall_candidate(
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
            let mut tx_lock = self.inner.firewall_tx.write();
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
        let mut tx_lock = self.inner.firewall_tx.write();
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
        let mut tx_lock = self.inner.firewall_tx.write();
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
        let mut tx_lock = self.inner.firewall_tx.write();
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
        let banner = provider.banner(self);
        self.inner
            .status_providers
            .write()
            .insert(banner.id, provider);
    }

    /// Returns a list of all registered service status banners.
    #[must_use]
    pub fn service_banners(&self) -> Vec<ServiceBanner> {
        let providers = self.inner.status_providers.read();
        providers.values().map(|p| p.banner(self)).collect()
    }

    /// Returns a list of all registered status providers.
    #[must_use]
    pub fn status_providers(&self) -> Vec<Arc<dyn StatusProvider>> {
        self.inner
            .status_providers
            .read()
            .values()
            .cloned()
            .collect()
    }

    /// Sets the decoupled DNS handle.
    pub fn set_dns_handle(&self, handle: DnsHandle) {
        *self.inner.dns_handle.write() = Some(handle);
    }

    /// Returns the decoupled DNS handle, if available.
    #[must_use]
    pub fn dns_handle(&self) -> Option<DnsHandle> {
        self.inner.dns_handle.read().clone()
    }

    /// Sets the dynamic state of a service.
    pub fn set_service_state(&self, id: &str, state: ServiceState) {
        self.inner
            .service_states
            .write()
            .insert(id.to_string(), state);
    }

    /// Sets the start time of a service.
    pub fn set_service_start(&self, id: &str, start: Instant) {
        self.inner
            .service_starts
            .write()
            .insert(id.to_string(), start);
    }

    /// Clears the start time of a service.
    pub fn clear_service_start(&self, id: &str) {
        self.inner.service_starts.write().remove(id);
    }

    /// Returns the dynamic state of a service, defaulting to Offline.
    #[must_use]
    pub fn get_service_state(&self, id: &str) -> ServiceState {
        self.inner
            .service_states
            .read()
            .get(id)
            .copied()
            .unwrap_or(ServiceState::Offline)
    }

    /// Returns the uptime of a service in seconds, or 0 if not running.
    #[must_use]
    pub fn get_service_uptime(&self, id: &str) -> u64 {
        if self.get_service_state(id) == ServiceState::Online {
            self.inner
                .service_starts
                .read()
                .get(id)
                .map_or(0, |start| start.elapsed().as_secs())
        } else {
            0
        }
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
        self.wait_for_condition(Self::is_if_ready, |event| {
            matches!(event, LanforgeEvent::System(SystemEvent::InterfaceReady))
        })
        .await
    }

    /// Blocks until the database is ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_db(&self) -> Result<(), CoreError> {
        self.wait_for_condition(Self::is_db_ready, |event| {
            matches!(event, LanforgeEvent::System(SystemEvent::DbReady))
        })
        .await
    }

    /// Blocks until the `PPPoE` session is established (or short-circuits if `PPPoE` is disabled/ready).
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if the wait condition cannot be met or the system shuts down.
    pub async fn wait_for_pppoe(&self) -> Result<(), CoreError> {
        self.wait_for_condition(Self::is_pppoe_ready, |event| {
            matches!(event, LanforgeEvent::Pppoe(PppoeEvent::SessionUp(_)))
        })
        .await
    }

    /// Blocks until the specified dependency is satisfied.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down before the dependency is ready.
    pub async fn wait_for_dependency(&self, dep: ServiceDependency) -> Result<(), CoreError> {
        match dep {
            ServiceDependency::Database => self.wait_for_db().await,
            ServiceDependency::Interfaces => self.wait_for_interfaces().await,
            ServiceDependency::PppoeWan => self.wait_for_pppoe().await,
            ServiceDependency::Service(id) => self.wait_for_service(id).await,
        }
    }

    /// Blocks until the specified service is `Online`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down before the service is online.
    pub async fn wait_for_service(&self, id: &str) -> Result<(), CoreError> {
        self.wait_for_condition(
            |ctx| ctx.get_service_state(id) == ServiceState::Online,
            |event| {
                matches!(
                    event,
                    LanforgeEvent::System(SystemEvent::ServiceReady { name }) if name == id
                )
            },
        )
        .await
    }

    /// Generic async wait helper. Blocks until `is_ready()` returns true
    /// or a matching event arrives on the bus.
    async fn wait_for_condition(
        &self,
        is_ready: impl Fn(&Self) -> bool,
        event_matches: impl Fn(&LanforgeEvent) -> bool,
    ) -> Result<(), CoreError> {
        if !self.is_running() {
            return Err(CoreError::Shutdown);
        }
        if is_ready(self) {
            return Ok(());
        }
        let mut rx = self.inner.bus.subscribe();
        loop {
            // Re-check after subscribing to avoid race
            if is_ready(self) {
                return Ok(());
            }
            match rx.recv().await {
                Ok(timed_event) => {
                    if !self.is_running()
                        || matches!(
                            timed_event.event,
                            LanforgeEvent::System(SystemEvent::Shutdown)
                        )
                    {
                        return Err(CoreError::Shutdown);
                    }
                    if event_matches(&timed_event.event) {
                        return Ok(());
                    }
                }
                Err(_) => return Err(CoreError::Shutdown),
            }
        }
    }

    /// Returns true if this instance is currently running.
    ///
    /// When false, the system is in shutdown mode and services should exit.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Returns true if the database is ready.
    ///
    /// This flag is set by the database worker after successful initialization.
    #[must_use]
    pub fn is_db_ready(&self) -> bool {
        self.inner.db_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the system is running in recovery mode (in-memory fallback due to database unavailability).
    #[must_use]
    pub fn is_recovery_mode(&self) -> bool {
        self.inner.recovery_mode.load(Ordering::Relaxed)
    }

    /// Sets the recovery mode state.
    pub fn set_recovery_mode(&self, recovery: bool) {
        self.inner.recovery_mode.store(recovery, Ordering::Relaxed);
    }

    /// Returns true if the network interfaces are ready.
    ///
    /// This flag is set after interface discovery completes successfully.
    #[must_use]
    pub fn is_if_ready(&self) -> bool {
        self.inner.if_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the `PPPoE` session is ready.
    ///
    /// This flag is set when `PPPoE` session is established or if `PPPoE` is disabled.
    #[must_use]
    pub fn is_pppoe_ready(&self) -> bool {
        self.inner.pppoe_ready.load(Ordering::SeqCst)
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
