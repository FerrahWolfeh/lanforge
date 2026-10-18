use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::events::LanforgeEvent;
use lanforge_types::network::TrafficConfig;
use lanforge_types::system::{ServiceState, TrafficStatusResponse};
use tracing::{debug, info};

use crate::sqm::{apply_sqm, clear_sqm};
use crate::tuning::apply_tuning;

#[lanforge_macros::lanforge_service(
    id = "traffic",
    name = "Traffic & SQM Manager",
    critical = false,
    retries = 3,
    base_backoff = 2,
    max_backoff = 10,
    shutdown_timeout = 3,
    describe = "NIC Hardware Tuning & CAKE Bufferbloat SQM".to_string()
)]
#[derive(Clone)]
pub struct TrafficService {
    cfg: TrafficConfig,
    active_wan: Option<String>,
    active_ifb: Option<String>,
    is_pppoe_active: bool,
    tuned_interfaces: Vec<String>,
    effective_cpu_mask: String,
    inert: bool,
}

impl TrafficService {
    #[must_use]
    pub fn new(cfg: TrafficConfig) -> Self {
        let cpu_mask = crate::tuning::cpu::resolve_effective_cpu_mask(&cfg.tuning.cpu_mask);
        Self {
            cfg,
            active_wan: None,
            active_ifb: None,
            is_pppoe_active: false,
            tuned_interfaces: Vec::new(),
            effective_cpu_mask: cpu_mask,
            inert: false,
        }
    }

    /// Creates an inert instance of `TrafficService` for rootless testing and dry-run execution.
    #[must_use]
    pub fn inert(cfg: TrafficConfig) -> Self {
        let cpu_mask = crate::tuning::cpu::resolve_effective_cpu_mask(&cfg.tuning.cpu_mask);
        Self {
            cfg,
            active_wan: None,
            active_ifb: None,
            is_pppoe_active: false,
            tuned_interfaces: Vec::new(),
            effective_cpu_mask: cpu_mask,
            inert: true,
        }
    }

    #[must_use]
    pub const fn with_inert(mut self, inert: bool) -> Self {
        self.inert = inert;
        self
    }

    #[must_use]
    pub const fn is_inert(&self) -> bool {
        self.inert
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

        let ifb = if self.inert {
            let dev = if self.cfg.sqm.ingress_device.trim().is_empty() {
                "ifb4lanforge".to_string()
            } else {
                self.cfg.sqm.ingress_device.clone()
            };
            Some(dev)
        } else {
            // Clean up existing if on different interface
            if let Some(ref current) = self.active_wan
                && current != iface
            {
                clear_sqm(current, &self.cfg.sqm.ingress_device).await;
            }
            apply_sqm(iface, &self.cfg.sqm, is_pppoe).await
        };

        self.active_wan = Some(iface.to_string());
        self.active_ifb.clone_from(&ifb);

        let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::SqmApplied {
            interface: iface.to_string(),
            ingress_device: ifb,
            download_mbps: self.cfg.sqm.download_mbps,
            upload_mbps: self.cfg.sqm.upload_mbps,
        })));
    }

    /// Clears any active SQM configuration.
    async fn clear_sqm_internal(&mut self, ctx: &LanforgeContext) {
        if let Some(wan) = self.active_wan.take() {
            if !self.inert {
                clear_sqm(&wan, &self.cfg.sqm.ingress_device).await;
            }
            self.active_ifb = None;
            let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::SqmCleared {
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
        ctx.set_service_state("traffic", next_state);
        self.publish_status(ctx, next_state);
    }

    /// Initializes tuning, SQM, and telemetry. Returns false if both features are disabled.
    async fn initialize(&mut self, ctx: &LanforgeContext) -> bool {
        if let Some(dynamic_cfg) = ctx.get_traffic_config() {
            self.cfg = dynamic_cfg;
        }

        let is_tuning_enabled = self.cfg.tuning.enabled;
        let is_sqm_enabled = self.cfg.sqm.enabled;

        if !is_tuning_enabled && !is_sqm_enabled {
            info!("Traffic: Both NIC tuning and SQM are disabled, service entering inactive state");
            self.publish_status(ctx, ServiceState::Inactive);
            ctx.set_service_state("traffic", ServiceState::Inactive);
            return false;
        }

        ctx.set_service_state("traffic", ServiceState::Starting);

        if is_tuning_enabled {
            let default_ifaces = Self::resolve_default_interfaces(ctx);
            let tuned = if self.inert {
                default_ifaces.clone()
            } else {
                apply_tuning(&self.cfg.tuning, &default_ifaces).await
            };
            self.effective_cpu_mask =
                crate::tuning::cpu::resolve_effective_cpu_mask(&self.cfg.tuning.cpu_mask);
            self.tuned_interfaces.clone_from(&tuned);
            let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::TuningApplied {
                interfaces: tuned,
                cpu_mask: self.effective_cpu_mask.clone(),
            })));
        }

        if is_sqm_enabled {
            if let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx) {
                self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
            } else {
                debug!("Traffic: Waiting for active WAN interface / PPPoE session before attaching SQM");
            }
        }

        self.update_service_state(ctx);

        let wan = self.active_wan.as_deref();
        let ifb = self.active_ifb.as_deref();
        let initial_snapshot = if self.inert {
            crate::TrafficTelemetryResponse::default()
        } else {
            crate::collect_traffic_telemetry(wan, ifb).await
        };
        ctx.set_traffic_telemetry(initial_snapshot);
        true
    }

    async fn handle_traffic_config_change(&mut self, ctx: &LanforgeContext) {
        let new_cfg = ctx.get_traffic_config().unwrap_or_default();
        let tuning_changed = self.cfg.tuning != new_cfg.tuning;
        let sqm_changed = self.cfg.sqm != new_cfg.sqm;

        info!(
            tuning_changed,
            sqm_changed, "Traffic: Configuration changed, applying updates in-place"
        );

        if tuning_changed {
            if new_cfg.tuning.enabled {
                let default_ifaces = Self::resolve_default_interfaces(ctx);
                let tuned = if self.inert {
                    default_ifaces
                } else {
                    apply_tuning(&new_cfg.tuning, &default_ifaces).await
                };
                self.effective_cpu_mask =
                    crate::tuning::cpu::resolve_effective_cpu_mask(&new_cfg.tuning.cpu_mask);
                self.tuned_interfaces = tuned;
            } else {
                self.tuned_interfaces.clear();
            }
        }

        if sqm_changed {
            self.cfg.sqm = new_cfg.sqm.clone();
            if new_cfg.sqm.enabled {
                if let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx) {
                    info!(wan = %wan_iface, "Traffic: Reapplying SQM parameters in-place");
                    self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
                }
            } else if self.active_wan.is_some() {
                info!("Traffic: SQM disabled, clearing queues");
                self.clear_sqm_internal(ctx).await;
            }
        }

        self.cfg = new_cfg;
        self.update_service_state(ctx);
    }

    async fn handle_pppoe_event(&mut self, ctx: &LanforgeContext, event: &PppoeEvent) {
        match event {
            PppoeEvent::SessionUp(session) => {
                info!(
                    interface = %session.interface,
                    "Traffic: Detected PPPoE SessionUp, updating SQM binding"
                );
                self.is_pppoe_active = true;
                self.active_wan = Some(session.interface.clone());
                if self.cfg.sqm.enabled {
                    self.apply_sqm_internal(ctx, &session.interface, true).await;
                }
                ctx.set_service_state("traffic", ServiceState::Online);
                self.publish_status(ctx, ServiceState::Online);
            }
            PppoeEvent::SessionDown { reason } => {
                info!(reason = %reason, "Traffic: PPPoE SessionDown, removing session SQM queues");
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
            let tuned = if self.inert {
                default_ifaces
            } else {
                apply_tuning(&self.cfg.tuning, &default_ifaces).await
            };
            if tuned != self.tuned_interfaces {
                self.tuned_interfaces = tuned;
                changed = true;
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

    async fn run_event_loop(&mut self, ctx: &LanforgeContext) {
        let mut sys_rx = ctx.bus().subscribe_system();
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut traffic_rx = ctx.bus().subscribe_traffic();

        let mut telemetry_tick = tokio::time::interval(std::time::Duration::from_millis(2500));
        telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = telemetry_tick.tick() => {
                    if !self.inert {
                        let wan = self.active_wan.as_deref();
                        let ifb = self.active_ifb.as_deref();
                        let snapshot = crate::collect_traffic_telemetry(wan, ifb).await;
                        ctx.set_traffic_telemetry(snapshot);
                    }
                }

                traffic_event = traffic_rx.recv() => {
                    match traffic_event {
                        Ok(te) => {
                            if matches!(te.event, LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::RulesetChanged)) {
                                self.handle_traffic_config_change(ctx).await;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }

                timed_event = pppoe_rx.recv() => {
                    match timed_event {
                        Ok(te) => {
                            if let LanforgeEvent::Pppoe(ref pe) = te.event {
                                self.handle_pppoe_event(ctx, pe).await;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }

                sys_event = sys_rx.recv() => {
                    match sys_event {
                        Ok(te) => match te.event {
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                debug!("Traffic: Shutdown signal received");
                                break;
                            }
                            LanforgeEvent::System(SystemEvent::InterfaceReady) => {
                                self.handle_interface_ready(ctx).await;
                            }
                            _ => {}
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }
            }
        }
    }
}

impl AsyncService for TrafficService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.initialize(ctx).await {
            return Ok(());
        }

        self.run_event_loop(ctx).await;

        if self.cfg.sqm.enabled {
            self.clear_sqm_internal(ctx).await;
        }

        ctx.set_service_state("traffic", ServiceState::Inactive);
        self.publish_status(ctx, ServiceState::Inactive);
        Ok(())
    }

    async fn cleanup(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if self.cfg.sqm.enabled {
            self.clear_sqm_internal(ctx).await;
        }
        ctx.set_service_state("traffic", ServiceState::Inactive);
        self.publish_status(ctx, ServiceState::Inactive);
        Ok(())
    }
}
