use crate::bus::{EventBus, LanforgeEvent, SystemEvent};
use crate::context::caps::CompiledCaps;
use crate::context::state::network::DhcpPoolStats;
use crate::context::{DbWorkerMetrics, DnsHandle, EventCounters, LanforgeContext, StorageHandle};
use crate::error::CoreError;
use crate::service::StatusProvider;
use arc_swap::ArcSwapOption;
use lanforge_types::dhcp::{Dhcpv4Stats, Dhcpv6Stats};
use lanforge_types::network::firewall::{DynamicPortRequest, FirewallTransactionState};
use lanforge_types::network::traffic::TrafficTelemetryResponse;
use lanforge_types::system::{
    Cap, PppoeStatusResponse, RaStatusResponse, ServiceBanner, ServiceId, ServiceState,
    SystemStatus, TrafficStatusResponse,
};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;

use lanforge_types::network::snapshot::{InterfaceSnapshot, WanSnapshot};
use lanforge_types::system::StateDetail;

/// Registered service runtime slot tracking state and status provider.
pub struct ServiceSlot {
    pub state_tx: watch::Sender<ServiceState>,
    pub detail: Option<StateDetail>,
    pub started_at: Option<Instant>,
    pub provider: Option<Arc<dyn StatusProvider>>,
}

/// Central service execution coordinator and status container.
pub struct ServiceRuntime {
    pub bus: Arc<EventBus>,
    running_tx: watch::Sender<bool>,
    wan_tx: watch::Sender<WanSnapshot>,
    interfaces_tx: watch::Sender<InterfaceSnapshot>,
    recovery_mode: AtomicBool,
    services: RwLock<BTreeMap<ServiceId, ServiceSlot>>,
    shared_by_type: RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,

    // Operational telemetries (decoupled from State)
    pub pppoe_status: ArcSwapOption<PppoeStatusResponse>,
    pub ra_status: ArcSwapOption<RaStatusResponse>,
    pub traffic_status: ArcSwapOption<TrafficStatusResponse>,
    pub traffic_telemetry: ArcSwapOption<TrafficTelemetryResponse>,
    pub v4_pool_stats: ArcSwapOption<DhcpPoolStats>,
    pub v6_pool_stats: RwLock<HashMap<u32, DhcpPoolStats>>,
    pub dhcpv4_stats: Arc<Dhcpv4Stats>,
    pub dhcpv6_stats: Arc<Dhcpv6Stats>,
    pub db_metrics: DbWorkerMetrics,
    pub event_counters: EventCounters,
    pub active_clients: Arc<AtomicUsize>,
    pub firewall_ports: RwLock<Vec<DynamicPortRequest>>,
    pub firewall_tx: RwLock<Option<FirewallTransactionState>>,
    pub status: RwLock<Option<SystemStatus>>,
    pub last_db_flush: RwLock<Option<SystemTime>>,
    pub start_time: Instant,
    pub dns_handle: RwLock<Option<DnsHandle>>,
    pub storage_handle: RwLock<Option<StorageHandle>>,
    pub config_path: RwLock<Option<PathBuf>>,
    pub config_writable: AtomicBool,
    pub compiled_caps: RwLock<SmallVec<[Cap; 32]>>,
}

impl ServiceRuntime {
    #[must_use]
    pub fn new(bus: Arc<EventBus>) -> Self {
        let (running_tx, _) = watch::channel(true);
        let (wan_tx, _) = watch::channel(WanSnapshot::default());
        let (interfaces_tx, _) = watch::channel(InterfaceSnapshot::default());

        Self {
            bus,
            running_tx,
            wan_tx,
            interfaces_tx,
            recovery_mode: AtomicBool::new(false),
            services: RwLock::new(BTreeMap::new()),
            shared_by_type: RwLock::new(HashMap::new()),
            pppoe_status: ArcSwapOption::empty(),
            ra_status: ArcSwapOption::empty(),
            traffic_status: ArcSwapOption::empty(),
            traffic_telemetry: ArcSwapOption::empty(),
            v4_pool_stats: ArcSwapOption::empty(),
            v6_pool_stats: RwLock::new(HashMap::new()),
            dhcpv4_stats: Arc::new(Dhcpv4Stats::default()),
            dhcpv6_stats: Arc::new(Dhcpv6Stats::default()),
            db_metrics: DbWorkerMetrics::default(),
            event_counters: EventCounters::default(),
            active_clients: Arc::new(AtomicUsize::new(0)),
            firewall_ports: RwLock::new(Vec::new()),
            firewall_tx: RwLock::new(None),
            status: RwLock::new(None),
            last_db_flush: RwLock::new(None),
            start_time: Instant::now(),
            dns_handle: RwLock::new(None),
            storage_handle: RwLock::new(None),
            config_path: RwLock::new(None),
            config_writable: AtomicBool::new(true),
            compiled_caps: RwLock::new(CompiledCaps::detect_default_compiled()),
        }
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        *self.running_tx.borrow()
    }

    pub fn terminate(&self) {
        self.running_tx.send_replace(false);
    }

    pub fn reset_lifecycle(&self) {
        self.running_tx.send_replace(true);
        self.wan_tx.send_replace(WanSnapshot::default());
        self.interfaces_tx
            .send_replace(InterfaceSnapshot::default());
        let mut services = self.services.write();
        for slot in services.values_mut() {
            slot.state_tx.send_replace(ServiceState::Offline);
            slot.started_at = None;
        }
    }

    #[must_use]
    pub fn wan_snapshot(&self) -> WanSnapshot {
        self.wan_tx.borrow().clone()
    }

    #[must_use]
    pub fn watch_wan(&self) -> watch::Receiver<WanSnapshot> {
        self.wan_tx.subscribe()
    }

    pub fn set_wan_snapshot(&self, snapshot: WanSnapshot) {
        self.wan_tx.send_replace(snapshot);
    }

    #[must_use]
    pub fn interfaces_snapshot(&self) -> InterfaceSnapshot {
        self.interfaces_tx.borrow().clone()
    }

    #[must_use]
    pub fn watch_interfaces(&self) -> watch::Receiver<InterfaceSnapshot> {
        self.interfaces_tx.subscribe()
    }

    pub fn set_interfaces_snapshot(&self, snapshot: InterfaceSnapshot) {
        self.interfaces_tx.send_replace(snapshot);
    }

    #[must_use]
    pub fn is_recovery_mode(&self) -> bool {
        self.recovery_mode.load(Ordering::Relaxed)
    }

    pub fn set_recovery_mode(&self, recovery: bool) {
        self.recovery_mode.store(recovery, Ordering::Relaxed);
    }

    /// Waits until network interfaces are ready.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down while waiting.
    pub async fn wait_for_interfaces(&self) -> Result<(), CoreError> {
        self.wait_for_service(ServiceId::Interfaces).await
    }

    /// Waits until a specific service becomes `Online`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Shutdown` if the system shuts down or channel is closed.
    pub async fn wait_for_service(&self, id: ServiceId) -> Result<(), CoreError> {
        if !self.is_running() {
            return Err(CoreError::Shutdown);
        }
        let (is_online, rx) = {
            let mut services = self.services.write();
            let slot = services.entry(id).or_insert_with(|| {
                let (tx, _) = watch::channel(ServiceState::Offline);
                ServiceSlot {
                    state_tx: tx,
                    detail: None,
                    started_at: None,
                    provider: None,
                }
            });
            let online = *slot.state_tx.borrow() == ServiceState::Online;
            let rx = slot.state_tx.subscribe();
            drop(services);
            (online, rx)
        };
        if is_online {
            return Ok(());
        }
        let mut rx = rx;
        let mut stop_rx = self.running_tx.subscribe();
        let mut sys_rx = self.bus.subscribe_system();
        loop {
            tokio::select! {
                res = rx.changed() => {
                    res.map_err(|_| CoreError::Shutdown)?;
                    if *rx.borrow() == ServiceState::Online {
                        return Ok(());
                    }
                }
                _ = stop_rx.changed() => {
                    if !*stop_rx.borrow() {
                        return Err(CoreError::Shutdown);
                    }
                }
                event = sys_rx.recv() => {
                    match event {
                        Ok(evt) => {
                            if matches!(evt.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                                self.terminate();
                                return Err(CoreError::Shutdown);
                            }
                        }
                        // A lagged receiver only missed events; keep waiting.
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => return Err(CoreError::Shutdown),
                    }
                }
            }
        }
    }

    pub fn set_service_state(&self, id: ServiceId, state: ServiceState) {
        self.services
            .write()
            .entry(id)
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ServiceState::Offline);
                ServiceSlot {
                    state_tx: tx,
                    detail: None,
                    started_at: None,
                    provider: None,
                }
            })
            .state_tx
            .send_replace(state);
    }

    pub fn set_service_detail(&self, id: ServiceId, detail: Option<StateDetail>) {
        self.services
            .write()
            .entry(id)
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ServiceState::Offline);
                ServiceSlot {
                    state_tx: tx,
                    detail: None,
                    started_at: None,
                    provider: None,
                }
            })
            .detail = detail;
    }

    #[must_use]
    pub fn get_service_detail(&self, id: ServiceId) -> Option<StateDetail> {
        self.services
            .read()
            .get(&id)
            .and_then(|slot| slot.detail.clone())
    }

    #[must_use]
    pub fn get_service_state(&self, id: ServiceId) -> ServiceState {
        self.services
            .read()
            .get(&id)
            .map_or(ServiceState::Offline, |slot| *slot.state_tx.borrow())
    }

    pub fn set_service_start(&self, id: ServiceId, start: Instant) {
        self.services
            .write()
            .entry(id)
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ServiceState::Offline);
                ServiceSlot {
                    state_tx: tx,
                    detail: None,
                    started_at: None,
                    provider: None,
                }
            })
            .started_at = Some(start);
    }

    pub fn clear_service_start(&self, id: ServiceId) {
        if let Some(slot) = self.services.write().get_mut(&id) {
            slot.started_at = None;
        }
    }

    #[must_use]
    pub fn get_service_uptime(&self, id: ServiceId) -> u64 {
        let services = self.services.read();
        services
            .get(&id)
            .and_then(|slot| {
                if *slot.state_tx.borrow() == ServiceState::Online {
                    slot.started_at.map(|s| s.elapsed().as_secs())
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    pub fn register_status_provider(
        &self,
        ctx: &LanforgeContext,
        provider: Arc<dyn StatusProvider>,
    ) {
        let banner = provider.banner(ctx);
        self.services
            .write()
            .entry(banner.id)
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ServiceState::Offline);
                ServiceSlot {
                    state_tx: tx,
                    detail: None,
                    started_at: None,
                    provider: None,
                }
            })
            .provider = Some(provider);
    }

    #[must_use]
    pub fn service_banners(&self, ctx: &LanforgeContext) -> Vec<ServiceBanner> {
        let services = self.services.read();
        services
            .values()
            .filter_map(|slot| slot.provider.as_ref().map(|p| p.banner(ctx)))
            .collect()
    }

    #[must_use]
    pub fn status_providers(&self) -> Vec<Arc<dyn StatusProvider>> {
        let services = self.services.read();
        services
            .values()
            .filter_map(|slot| slot.provider.clone())
            .collect()
    }

    pub fn provide_shared<T: Any + Send + Sync>(&self, instance: Arc<T>) {
        self.shared_by_type
            .write()
            .insert(TypeId::of::<T>(), instance);
    }

    #[must_use]
    pub fn get_shared<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.shared_by_type
            .read()
            .get(&TypeId::of::<T>())
            .and_then(|any| any.clone().downcast::<T>().ok())
    }

    // Telemetry getters / setters
    pub fn set_pppoe_status(&self, status: Option<PppoeStatusResponse>) {
        self.pppoe_status.store(status.map(Arc::new));
    }

    #[must_use]
    pub fn pppoe_status(&self) -> Option<Arc<PppoeStatusResponse>> {
        self.pppoe_status.load_full()
    }

    pub fn set_ra_status(&self, status: Option<RaStatusResponse>) {
        self.ra_status.store(status.map(Arc::new));
    }

    #[must_use]
    pub fn ra_status(&self) -> Option<Arc<RaStatusResponse>> {
        self.ra_status.load_full()
    }

    pub fn set_traffic_status(&self, status: Option<TrafficStatusResponse>) {
        self.traffic_status.store(status.map(Arc::new));
    }

    #[must_use]
    pub fn traffic_status(&self) -> Option<Arc<TrafficStatusResponse>> {
        self.traffic_status.load_full()
    }

    pub fn set_traffic_telemetry(&self, telemetry: TrafficTelemetryResponse) {
        self.traffic_telemetry.store(Some(Arc::new(telemetry)));
    }

    #[must_use]
    pub fn traffic_telemetry(&self) -> Option<Arc<TrafficTelemetryResponse>> {
        self.traffic_telemetry.load_full()
    }

    pub fn set_dhcp_v4_pool_stats(&self, stats: Option<DhcpPoolStats>) {
        self.v4_pool_stats.store(stats.map(Arc::new));
    }

    pub fn set_dhcp_v4_pool_update(&self, update: &lanforge_types::update::DhcpV4PoolUpdate) {
        self.v4_pool_stats.store(Some(Arc::new(DhcpPoolStats {
            range_start: Some(std::net::IpAddr::V4(update.range_start)),
            range_end: Some(std::net::IpAddr::V4(update.range_end)),
            prefix: None,
            prefix_len: None,
            total: update.total,
            used: update.used,
            available: update.available,
            utilization_percent: update.utilization_percent,
        })));
    }

    #[must_use]
    pub fn dhcp_v4_pool_stats(&self) -> Option<Arc<DhcpPoolStats>> {
        self.v4_pool_stats.load_full()
    }

    pub fn set_dhcp_v6_pool_stats(&self, iaid: u32, stats: DhcpPoolStats) {
        self.v6_pool_stats.write().insert(iaid, stats);
    }

    pub fn set_dhcp_v6_pool_update(&self, update: &lanforge_types::update::DhcpV6PoolUpdate) {
        self.v6_pool_stats.write().insert(
            update.pool_id,
            DhcpPoolStats {
                range_start: None,
                range_end: None,
                prefix: Some(std::net::IpAddr::V6(update.prefix)),
                prefix_len: Some(update.prefix_len),
                total: update.total,
                used: update.used,
                available: update.available,
                utilization_percent: update.utilization_percent,
            },
        );
    }

    #[must_use]
    pub fn dhcp_v6_pool_stats(&self) -> HashMap<u32, DhcpPoolStats> {
        self.v6_pool_stats.read().clone()
    }

    pub fn clear_dhcp_v6_pool_stats(&self) {
        self.v6_pool_stats.write().clear();
    }
}

impl Default for ServiceRuntime {
    fn default() -> Self {
        Self::new(Arc::new(EventBus::new()))
    }
}
