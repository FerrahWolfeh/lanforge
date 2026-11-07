use std::time::Duration;

use crate::collector::get_traffic_history_snapshot;
use crate::tuning::cpu::resolve_effective_cpu_mask;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, Edge, LanforgeService, LossPolicy, RestartPolicy,
    RuntimeClass, ServiceCommand, ServiceHandle, ServiceSpec,
};
use lanforge_types::config::ConfigDomain;
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::events::{LanforgeEvent, StorageEvent};
use lanforge_types::network::TrafficConfig;
use lanforge_types::network::snapshot::WanSnapshot;
use lanforge_types::system::{DormantReason, ServiceId, ServiceState, TrafficStatusResponse};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info};

#[cfg(any(test, feature = "inert"))]
use crate::host::InertTraffic;
use crate::host::{KernelTraffic, TrafficHost};

const TRAFFIC_DEPS: &[Edge] = &[
    Edge::requires(ServiceId::Interfaces, LossPolicy::Continue),
    Edge::wants(ServiceId::Wan),
];

#[derive(Clone)]
pub struct TrafficService<H: TrafficHost = KernelTraffic> {
    cfg: TrafficConfig,
    active_wan: Option<String>,
    active_ifb: Option<String>,
    is_pppoe_active: bool,
    tuned_interfaces: Vec<String>,
    effective_cpu_mask: String,
    /// NIC tuning, `tc` queues and counters: the kernel, or nothing in rootless tests.
    host: H,
}

impl TrafficService<KernelTraffic> {
    /// The production service: tunes NICs and shapes the WAN through the kernel.
    #[must_use]
    pub fn new(cfg: TrafficConfig) -> Self {
        Self::with_host(cfg, KernelTraffic)
    }
}

#[cfg(any(test, feature = "inert"))]
impl TrafficService<InertTraffic> {
    /// A service that tracks tuning and SQM state without touching the machine (rootless).
    #[must_use]
    pub fn inert(cfg: TrafficConfig) -> Self {
        Self::with_host(cfg, InertTraffic)
    }
}

impl<H: TrafficHost> TrafficService<H> {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Traffic;

    /// A service acting on the machine through `host`.
    #[must_use]
    pub fn with_host(cfg: TrafficConfig, host: H) -> Self {
        let cpu_mask = resolve_effective_cpu_mask(&cfg.tuning.cpu_mask);
        Self {
            cfg,
            active_wan: None,
            active_ifb: None,
            is_pppoe_active: false,
            tuned_interfaces: Vec::new(),
            effective_cpu_mask: cpu_mask,
            host,
        }
    }

    fn publish_status(&self, ctx: &LanforgeContext, state: ServiceState) {
        let status = TrafficStatusResponse {
            service_state: state,
            tuning_applied: !self.tuned_interfaces.is_empty(),
            tuned_interfaces: self.tuned_interfaces.clone(),
            effective_cpu_mask: self.effective_cpu_mask.clone(),
            sqm_active: self.active_wan.is_some() && self.cfg.sqm.enabled,
            wan_interface: self.active_wan.clone(),
            ingress_device: self.active_ifb.clone(),
            download_mbps: self.cfg.sqm.download_mbps,
            upload_mbps: self.cfg.sqm.upload_mbps,
            overhead: self.cfg.sqm.overhead,
            diffserv: self.cfg.sqm.diffserv,
            flow_offload_suppressed: self.cfg.sqm.enabled,
        };
        ctx.set_traffic_status(Some(status));
    }

    /// Resolves default LAN and WAN interfaces from context.
    fn resolve_default_interfaces(ctx: &LanforgeContext) -> Vec<String> {
        let mut ifaces = Vec::with_capacity(2);
        if let Some(lan) = ctx.target_interface_name() {
            ifaces.push(lan);
        }
        if let Some(pppoe_cfg) = ctx.get_pppoe_config()
            && !pppoe_cfg.wan_iface.is_empty()
            && !ifaces.contains(&pppoe_cfg.wan_iface)
        {
            ifaces.push(pppoe_cfg.wan_iface);
        }
        ifaces
    }

    /// Resolves target WAN interface for SQM based on auto-detection or config.
    fn resolve_wan_interface(&self, ctx: &LanforgeContext) -> Option<(String, bool)> {
        let configured = self.cfg.sqm.interface.trim();
        if !configured.is_empty() && !configured.eq_ignore_ascii_case("auto") {
            return Some((configured.to_string(), self.is_pppoe_active));
        }

        // If PPPoE is active, prefer PPPoE interface
        if let Some(ref ppp_iface) = self.active_wan {
            return Some((ppp_iface.clone(), true));
        }

        // Check if PPPoE config exists in context
        if let Some(pppoe_cfg) = ctx.get_pppoe_config() {
            if pppoe_cfg.enabled {
                // PPPoE is configured; wait for session
                return None;
            }
            if !pppoe_cfg.wan_iface.is_empty() {
                return Some((pppoe_cfg.wan_iface, false));
            }
        }

        // Fallback to primary host interface if configured
        ctx.target_interface_name().map(|name| (name, false))
    }

    /// Applies SQM on the resolved interface.
    async fn apply_sqm_internal(&mut self, ctx: &LanforgeContext, iface: &str, is_pppoe: bool) {
        if !self.cfg.sqm.enabled {
            return;
        }

        // Clean up existing if on different interface
        if let Some(ref current) = self.active_wan
            && current != iface
        {
            self.host
                .clear_sqm(current, &self.cfg.sqm.ingress_device)
                .await;
        }
        let ifb = self.host.apply_sqm(iface, &self.cfg.sqm, is_pppoe).await;

        self.active_wan = Some(iface.to_string());
        self.active_ifb.clone_from(&ifb);

        let _ = ctx
            .bus()
            .publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::SqmApplied {
                interface: iface.to_string(),
                ingress_device: ifb,
                download_mbps: self.cfg.sqm.download_mbps,
                upload_mbps: self.cfg.sqm.upload_mbps,
            })));
    }

    /// Clears any active SQM configuration.
    async fn clear_sqm_internal(&mut self, ctx: &LanforgeContext) {
        if let Some(wan) = self.active_wan.take() {
            self.host
                .clear_sqm(&wan, &self.cfg.sqm.ingress_device)
                .await;
            self.active_ifb = None;
            let _ = ctx
                .bus()
                .publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::SqmCleared {
                    interface: wan,
                })));
        }
    }

    /// Updates the service state and publishes it to the event bus.
    fn update_service_state(&self, ctx: &LanforgeContext) {
        let next_state = if !self.tuned_interfaces.is_empty() || self.active_wan.is_some() {
            ServiceState::Online
        } else {
            ServiceState::Inactive
        };
        ctx.set_service_state(Self::SERVICE_ID, next_state);
        self.publish_status(ctx, next_state);
    }

    /// Initializes tuning, SQM, and telemetry. Returns false if both features are disabled.
    async fn initialize(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> bool {
        if let Some(dynamic_cfg) = ctx.get_traffic_config() {
            self.cfg = dynamic_cfg;
        }

        let is_tuning_enabled = self.cfg.tuning.enabled;
        let is_sqm_enabled = self.cfg.sqm.enabled;

        if !is_tuning_enabled && !is_sqm_enabled {
            info!("Both NIC tuning and SQM are disabled, service entering inactive state");
            self.publish_status(ctx, ServiceState::Inactive);
            h.dormant(DormantReason::disabled("traffic.enabled"));
            return false;
        }

        ctx.set_service_state(Self::SERVICE_ID, ServiceState::Starting);

        if is_tuning_enabled {
            let default_ifaces = Self::resolve_default_interfaces(ctx);
            let tuned = self
                .host
                .apply_tuning(&self.cfg.tuning, &default_ifaces)
                .await;
            self.effective_cpu_mask = resolve_effective_cpu_mask(&self.cfg.tuning.cpu_mask);
            self.tuned_interfaces.clone_from(&tuned);
            let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(
                TrafficEvent::TuningApplied {
                    interfaces: tuned,
                    cpu_mask: self.effective_cpu_mask.clone(),
                },
            )));
        }

        if is_sqm_enabled {
            if let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx) {
                self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
            } else {
                debug!("Waiting for active WAN interface / PPPoE session before attaching SQM");
            }
        }

        self.update_service_state(ctx);
        h.ready();

        let wan = self.active_wan.as_deref();
        let ifb = self.active_ifb.as_deref();
        let initial_snapshot = self.host.telemetry(wan, ifb).await;
        ctx.set_traffic_telemetry(initial_snapshot);
        true
    }

    async fn handle_traffic_config_change(&mut self, ctx: &LanforgeContext) {
        let new_cfg = ctx.get_traffic_config().unwrap_or_default();
        let tuning_changed = self.cfg.tuning != new_cfg.tuning;
        let sqm_changed = self.cfg.sqm != new_cfg.sqm;

        info!(
            tuning_changed,
            sqm_changed, "Configuration changed, applying updates in-place"
        );

        if tuning_changed {
            if new_cfg.tuning.enabled {
                let default_ifaces = Self::resolve_default_interfaces(ctx);
                let tuned = self
                    .host
                    .apply_tuning(&new_cfg.tuning, &default_ifaces)
                    .await;
                self.effective_cpu_mask = resolve_effective_cpu_mask(&new_cfg.tuning.cpu_mask);
                self.tuned_interfaces = tuned;
            } else {
                self.tuned_interfaces.clear();
            }
        }

        if sqm_changed {
            self.cfg.sqm = new_cfg.sqm.clone();
            if new_cfg.sqm.enabled {
                if let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx) {
                    info!(wan = %wan_iface, "Reapplying SQM parameters in-place");
                    self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
                }
            } else if self.active_wan.is_some() {
                info!("SQM disabled, clearing queues");
                self.clear_sqm_internal(ctx).await;
            }
        }

        self.cfg = new_cfg;
        self.update_service_state(ctx);
    }

    async fn handle_wan_snapshot(&mut self, ctx: &LanforgeContext, snap: &WanSnapshot) {
        if snap.is_up() {
            if let Some(ref ifname) = snap.ifname {
                let is_pppoe = ifname.starts_with("ppp");
                self.is_pppoe_active = is_pppoe;
                if self.active_wan.as_deref() != Some(ifname.as_str()) {
                    info!(
                        interface = %ifname,
                        generation = snap.generation,
                        "WAN Up/changed, applying SQM"
                    );
                    self.active_wan = Some(ifname.clone());
                    if self.cfg.sqm.enabled {
                        self.apply_sqm_internal(ctx, ifname, is_pppoe).await;
                    }
                    ctx.set_service_state(Self::SERVICE_ID, ServiceState::Online);
                    self.publish_status(ctx, ServiceState::Online);
                }
            }
        } else if self.active_wan.is_some() {
            info!(generation = snap.generation, "WAN Down, pausing SQM queues");
            self.active_wan = None;
            self.is_pppoe_active = false;
            self.clear_sqm_internal(ctx).await;
            self.update_service_state(ctx);
        }
    }

    async fn handle_pppoe_event(&mut self, ctx: &LanforgeContext, event: &PppoeEvent) {
        match event {
            PppoeEvent::SessionUp(session) => {
                info!(
                    interface = %session.interface,
                    "Detected PPPoE SessionUp, updating SQM binding"
                );
                self.is_pppoe_active = true;
                self.active_wan = Some(session.interface.clone());
                if self.cfg.sqm.enabled {
                    self.apply_sqm_internal(ctx, &session.interface, true).await;
                }
                ctx.set_service_state(Self::SERVICE_ID, ServiceState::Online);
                self.publish_status(ctx, ServiceState::Online);
            }
            PppoeEvent::SessionDown { reason } => {
                info!(reason = %reason, "PPPoE SessionDown, removing session SQM queues");
                self.is_pppoe_active = false;
                self.clear_sqm_internal(ctx).await;
                self.update_service_state(ctx);
            }
            _ => {}
        }
    }

    async fn handle_interface_ready(&mut self, ctx: &LanforgeContext) {
        let mut changed = false;
        if self.cfg.tuning.enabled {
            let default_ifaces = Self::resolve_default_interfaces(ctx);
            if default_ifaces != self.tuned_interfaces {
                let tuned = self
                    .host
                    .apply_tuning(&self.cfg.tuning, &default_ifaces)
                    .await;
                if tuned != self.tuned_interfaces {
                    self.tuned_interfaces = tuned;
                    changed = true;
                }
            }
        }
        if self.cfg.sqm.enabled
            && self.active_wan.is_none()
            && let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx)
        {
            self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
            changed = true;
        }
        if changed {
            self.update_service_state(ctx);
        }
    }

    async fn run_event_loop(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) {
        let mut sys_rx = ctx.bus().subscribe_system();
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut traffic_rx = ctx.bus().subscribe_traffic();
        let mut if_rx = ctx.watch_interfaces();
        let mut wan_rx = ctx.watch_wan();

        let mut telemetry_tick = interval(Duration::from_millis(2500));
        telemetry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            debug!("Stop/shutdown command received");
                            let history = get_traffic_history_snapshot().await;
                            if !history.is_empty() {
                                let _ = ctx.bus().publish(LanforgeEvent::Storage(
                                    StorageEvent::SaveTrafficHistory(history),
                                ));
                            }
                            break;
                        }
                        ServiceCommand::Restart => {
                            debug!("Restart command received");
                            h.request_restart();
                            let history = get_traffic_history_snapshot().await;
                            if !history.is_empty() {
                                let _ = ctx.bus().publish(LanforgeEvent::Storage(
                                    StorageEvent::SaveTrafficHistory(history),
                                ));
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(()) = if_rx.changed() => {
                    self.handle_interface_ready(ctx).await;
                }

                Ok(()) = wan_rx.changed() => {
                    let snap = wan_rx.borrow().clone();
                    self.handle_wan_snapshot(ctx, &snap).await;
                }

                _ = telemetry_tick.tick() => {
                    let wan = self.active_wan.as_deref();
                    let ifb = self.active_ifb.as_deref();
                    let snapshot = self.host.telemetry(wan, ifb).await;
                    ctx.set_traffic_telemetry(snapshot);
                }

                traffic_event = traffic_rx.recv() => {
                    match traffic_event {
                        Ok(te) => {
                            if matches!(te.event, LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::RulesetChanged)) {
                                self.handle_traffic_config_change(ctx).await;
                            }
                        }
                        Err(RecvError::Closed) => break,
                        Err(RecvError::Lagged(_)) => {}
                    }
                }

                timed_event = pppoe_rx.recv() => {
                    match timed_event {
                        Ok(te) => {
                            if let LanforgeEvent::Pppoe(ref pe) = te.event {
                                self.handle_pppoe_event(ctx, pe).await;
                            }
                        }
                        Err(RecvError::Closed) => break,
                        Err(RecvError::Lagged(_)) => {}
                    }
                }

                sys_event = sys_rx.recv() => {
                    match sys_event {
                        Ok(te) => {
                            if matches!(te.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                                debug!("Shutdown signal received");
                                let history = get_traffic_history_snapshot().await;
                                if !history.is_empty() {
                                    let _ = ctx.bus().publish(LanforgeEvent::Storage(
                                        StorageEvent::SaveTrafficHistory(history),
                                    ));
                                }
                                break;
                            }
                        }
                        Err(RecvError::Closed) => break,
                        Err(RecvError::Lagged(_)) => {}
                    }
                }
            }
        }
    }
}

impl<H: TrafficHost> LanforgeService for TrafficService<H> {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "Traffic & SQM Manager",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(10),
                max_retries: 3,
                healthy_uptime: Duration::from_secs(30),
            },
            shutdown_timeout: Duration::from_secs(3),
            deps: TRAFFIC_DEPS,
            condition: Condition {
                sections: &[ConfigDomain::Traffic],
                eval: |ctx| {
                    if ctx
                        .get_traffic_config()
                        .is_none_or(|c| c.tuning.enabled || c.sqm.enabled)
                    {
                        Activation::Active
                    } else {
                        Activation::Dormant(DormantReason::disabled("traffic.enabled"))
                    }
                },
            },
        }
    }

    fn describe(&self) -> String {
        "NIC Hardware Tuning & CAKE Bufferbloat SQM".to_string()
    }
}

impl<H: TrafficHost> AsyncService for TrafficService<H> {
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if !self.initialize(ctx, h).await {
            return Ok(());
        }

        self.run_event_loop(ctx, h).await;

        if self.cfg.sqm.enabled {
            self.clear_sqm_internal(ctx).await;
        }

        ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
        self.publish_status(ctx, ServiceState::Inactive);
        Ok(())
    }

    async fn cleanup(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if self.cfg.sqm.enabled {
            self.clear_sqm_internal(ctx).await;
        }
        ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
        self.publish_status(ctx, ServiceState::Inactive);
        Ok(())
    }
}
