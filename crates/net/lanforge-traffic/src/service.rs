use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::events::LanforgeEvent;
use lanforge_types::network::TrafficConfig;
use lanforge_types::system::{ServiceState, TrafficStatusResponse};
use lanforge_types::update::DeviceUpdate;
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
pub struct TrafficService {
    cfg: TrafficConfig,
    active_wan: Option<String>,
    active_ifb: Option<String>,
    is_pppoe_active: bool,
    tuned_interfaces: Vec<String>,
    effective_cpu_mask: String,
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
        let _ = ctx.apply(DeviceUpdate::TrafficStatusUpdated {
            status: Some(Box::new(status)),
        });
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
            clear_sqm(current, &self.cfg.sqm.ingress_device).await;
        }

        let ifb = apply_sqm(iface, &self.cfg.sqm, is_pppoe).await;
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
        if let Some(ref wan) = self.active_wan.take() {
            clear_sqm(wan, &self.cfg.sqm.ingress_device).await;
            self.active_ifb = None;
            let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::SqmCleared {
                interface: wan.clone(),
            })));
        }
    }
}

impl AsyncService for TrafficService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }

    #[allow(clippy::too_many_lines)]
    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if let Some(dynamic_cfg) = ctx.get_traffic_config() {
            self.cfg = dynamic_cfg;
        }

        let is_tuning_enabled = self.cfg.tuning.enabled;
        let is_sqm_enabled = self.cfg.sqm.enabled;

        if !is_tuning_enabled && !is_sqm_enabled {
            info!("Traffic: Both NIC tuning and SQM are disabled, service entering inactive state");
            self.publish_status(ctx, ServiceState::Inactive);
            ctx.set_service_state("traffic", ServiceState::Inactive);
            return Ok(());
        }

        ctx.set_service_state("traffic", ServiceState::Starting);

        // 1. Initial NIC Hardware & Sysfs Tuning
        if is_tuning_enabled {
            let default_ifaces = {
                let mut ifaces = Vec::new();
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
            };

            let tuned = apply_tuning(&self.cfg.tuning, &default_ifaces).await;
            self.effective_cpu_mask = crate::tuning::cpu::resolve_effective_cpu_mask(&self.cfg.tuning.cpu_mask);
            self.tuned_interfaces.clone_from(&tuned);
            let _ = ctx.bus().publish(LanforgeEvent::Traffic(Box::new(TrafficEvent::TuningApplied {
                interfaces: tuned,
                cpu_mask: self.effective_cpu_mask.clone(),
            })));
        }

        // 2. Initial SQM Setup (if WAN is already resolved)
        if is_sqm_enabled {
            if let Some((wan_iface, is_pppoe)) = self.resolve_wan_interface(ctx) {
                self.apply_sqm_internal(ctx, &wan_iface, is_pppoe).await;
            } else {
                debug!("Traffic: Waiting for active WAN interface / PPPoE session before attaching SQM");
            }
        }

        let initial_state = if !self.tuned_interfaces.is_empty() || self.active_wan.is_some() {
            ServiceState::Online
        } else {
            ServiceState::Inactive
        };
        ctx.set_service_state("traffic", initial_state);
        self.publish_status(ctx, initial_state);

        // 3. Event Loop for reactive dynamic adjustments
        let mut sys_rx = ctx.bus().subscribe_system();
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut traffic_rx = ctx.bus().subscribe_traffic();

        let mut telemetry_tick = tokio::time::interval(std::time::Duration::from_millis(2500));
        telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Periodic telemetry background collector (populates ring buffer for instant WebUI graphs)
                _ = telemetry_tick.tick() => {
                    let wan = self.active_wan.as_deref();
                    let ifb = self.active_ifb.as_deref();
                    let _ = crate::collect_traffic_telemetry(wan, ifb).await;
                }

                // Listen to in-place traffic configuration updates
                traffic_event = traffic_rx.recv() => {
                    match traffic_event {
                        Ok(te) => {
                            if matches!(te.event, LanforgeEvent::Traffic(ref e) if matches!(**e, TrafficEvent::RulesetChanged)) {
                                let new_cfg = ctx.get_traffic_config().unwrap_or_default();
                                let tuning_changed = self.cfg.tuning != new_cfg.tuning;
                                let sqm_changed = self.cfg.sqm != new_cfg.sqm;

                                info!(
                                    tuning_changed,
                                    sqm_changed,
                                    "Traffic: Configuration changed, applying updates in-place"
                                );

                                if tuning_changed {
                                    if new_cfg.tuning.enabled {
                                        let default_ifaces = {
                                            let mut ifaces = Vec::new();
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
                                        };
                                        let tuned = apply_tuning(&new_cfg.tuning, &default_ifaces).await;
                                        self.effective_cpu_mask = crate::tuning::cpu::resolve_effective_cpu_mask(&new_cfg.tuning.cpu_mask);
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
                                let next_state = if !self.tuned_interfaces.is_empty() || self.active_wan.is_some() {
                                    ServiceState::Online
                                } else {
                                    ServiceState::Inactive
                                };
                                ctx.set_service_state("traffic", next_state);
                                self.publish_status(ctx, next_state);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }

                // Listen to PPPoE session events
                timed_event = pppoe_rx.recv() => {
                    match timed_event {
                        Ok(te) => match te.event {
                            LanforgeEvent::Pppoe(PppoeEvent::SessionUp(session)) => {
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
                            LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) => {
                                info!(reason = %reason, "Traffic: PPPoE SessionDown, removing session SQM queues");
                                self.is_pppoe_active = false;
                                self.clear_sqm_internal(ctx).await;
                                let next_state = if self.tuned_interfaces.is_empty() {
                                    ServiceState::Inactive
                                } else {
                                    ServiceState::Online
                                };
                                ctx.set_service_state("traffic", next_state);
                                self.publish_status(ctx, next_state);
                            }
                            _ => {}
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }

                // Listen to system events (shutdown, reloads)
                sys_event = sys_rx.recv() => {
                    match sys_event {
                        Ok(te) => match te.event {
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                debug!("Traffic: Shutdown signal received");
                                break;
                            }
                            LanforgeEvent::System(SystemEvent::InterfaceReady) if is_tuning_enabled => {
                                let default_ifaces = ctx.target_interface_name().map(|lan| vec![lan]).unwrap_or_default();
                                let tuned = apply_tuning(&self.cfg.tuning, &default_ifaces).await;
                                self.tuned_interfaces.clone_from(&tuned);
                                self.publish_status(ctx, ServiceState::Online);
                            }
                            _ => {}
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }
            }
        }

        // 4. Cooperative Teardown
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
