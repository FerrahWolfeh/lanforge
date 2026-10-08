//! Lanforge Firewall & Router Orchestrator Service.
//!
//! Subscribes to dynamic port registrations, `PPPoE` session events, and configuration
//! updates to atomically compile and apply `table inet lanforge` via `nftables-rs`.

use std::future::Future;
use std::io::ErrorKind;

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::events::firewall::{FirewallAppliedSummary, FirewallEvent};
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::events::LanforgeEvent;
use lanforge_types::network::firewall::{DynamicPortRequest, FirewallConfig, FirewallMode};
use tracing::{error, info, trace, warn};

use crate::ruleset::RulesetBuilder;

#[lanforge_macros::lanforge_service(
    id = "firewall",
    name = "Firewall & NAT Orchestrator",
    critical = false,
    retries = 0,
    base_backoff = 5,
    max_backoff = 10,
    shutdown_timeout = 5,
    describe = "nftables Host & Gateway Firewall".to_string()
)]
#[derive(Clone)]
pub struct NftService {
    active_wan: Option<String>,
    inert: bool,
    last_ruleset: std::sync::Arc<parking_lot::RwLock<Option<String>>>,
}

impl NftService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_wan: None,
            inert: false,
            last_ruleset: std::sync::Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Creates an inert instance of the firewall service that compiles and validates
    /// rulesets in-memory without applying them to the Linux kernel via netlink.
    #[must_use]
    pub fn inert() -> Self {
        Self {
            active_wan: None,
            inert: true,
            last_ruleset: std::sync::Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Sets whether the service runs in inert mode.
    #[must_use]
    pub const fn with_inert(mut self, inert: bool) -> Self {
        self.inert = inert;
        self
    }

    /// Returns whether the service is running in inert mode.
    #[must_use]
    pub const fn is_inert(&self) -> bool {
        self.inert
    }

    /// Returns the last compiled ruleset JSON payload, if available.
    #[must_use]
    pub fn last_applied_payload(&self) -> Option<String> {
        self.last_ruleset.read().clone()
    }

    /// Flushes and removes the configured table cleanly.
    pub async fn cleanup_table(table_name: &str) {
        Self::cleanup_table_internal(table_name, false).await;
    }

    async fn cleanup_table_internal(table_name: &str, inert: bool) {
        let table = {
            let t = table_name.trim();
            if t.is_empty() {
                "lanforge"
            } else {
                t
            }
        };

        if inert {
            info!(table, "Inert mode: skipping kernel firewall table deletion");
            return;
        }

        let mut batch = nftables::batch::Batch::new();
        batch.delete(nftables::schema::NfListObject::Table(nftables::schema::Table {
            family: nftables::types::NfFamily::INet,
            name: table.to_string().into(),
            handle: None,
        }));
        let ruleset = batch.to_nftables();

        let table_owned = table.to_string();
        let result = tokio::task::spawn_blocking(move || nftables::helper::apply_ruleset(&ruleset)).await;
        match result {
            Ok(Ok(())) => {
                info!(table = table_owned, "Flushed and removed firewall table");
            }
            Ok(Err(nftables::helper::NftablesError::NftFailed { .. })) => {
                // Table may not exist or was already removed; ignore silently.
            }
            Ok(Err(nftables::helper::NftablesError::NftExecution { inner, .. }))
                if inner.kind() == ErrorKind::NotFound => {}
            Ok(Err(e)) => {
                warn!(table = table_owned, error = %e, "Failed to delete firewall table");
            }
            Err(e) => {
                warn!(table = table_owned, error = %e, "Firewall cleanup task panicked");
            }
        }
    }

    async fn reapply(&self, ctx: &LanforgeContext) {
        let cfg = ctx.get_firewall_config().unwrap_or_default();
        let dynamic_ports = ctx.registered_service_ports();
        self.apply_ruleset_internal(ctx, &cfg, &dynamic_ports).await;
    }

    async fn apply_ruleset_internal(
        &self,
        ctx: &LanforgeContext,
        cfg: &FirewallConfig,
        dynamic_ports: &[DynamicPortRequest],
    ) {
        if !cfg.enabled || cfg.mode == FirewallMode::Disabled {
            info!("Firewall is disabled in configuration, flushing and removing nftables table");
            Self::cleanup_table_internal(&cfg.table_name, self.inert).await;
            return;
        }

        let primary_lan = ctx.target_interface_name();
        let ruleset = RulesetBuilder::new(cfg)
            .with_active_wan(self.active_wan.as_deref())
            .with_primary_lan(primary_lan.as_deref())
            .with_dynamic_ports(dynamic_ports)
            .build();

        let json_payload = serde_json::to_string_pretty(&ruleset).unwrap_or_default();
        if !json_payload.is_empty() && tracing::enabled!(tracing::Level::TRACE) {
            trace!(payload = %json_payload, "Applying nftables ruleset payload");
        }

        let table = cfg.table_name.clone();
        let active_wan = self.active_wan.clone();
        let flow_offload = cfg.flow_offload;
        #[allow(clippy::cast_possible_truncation)]
        let rules_count = (cfg.port_forwards.len() + dynamic_ports.len()) as u32;

        let inert = self.inert;
        let last_ruleset = self.last_ruleset.clone();

        let result = if inert {
            *last_ruleset.write() = Some(json_payload.clone());
            Ok(())
        } else {
            let res = tokio::task::spawn_blocking(move || {
                let res = nftables::helper::apply_ruleset(&ruleset);
                if let Err(e) = res {
                    let payload = if json_payload.is_empty() {
                        serde_json::to_string_pretty(&ruleset).unwrap_or_default()
                    } else {
                        json_payload
                    };
                    Err((e, payload))
                } else {
                    Ok(json_payload)
                }
            })
            .await;

            match res {
                Ok(Ok(payload)) => {
                    *last_ruleset.write() = Some(payload);
                    Ok(())
                }
                Ok(Err((e, payload))) => Err((e, payload)),
                Err(e) => {
                    let err_msg = format!("Firewall task panicked: {e}");
                    error!(error = %err_msg, "Firewall worker panicked (soft error)");
                    let _ = ctx.bus().publish(LanforgeEvent::Firewall(
                        FirewallEvent::ApplyFailed { error: err_msg },
                    ));
                    return;
                }
            }
        };

        match result {
            Ok(()) => {
                info!(
                    table = %table,
                    zones = cfg.zones.len(),
                    ports = dynamic_ports.len(),
                    wan = ?self.active_wan,
                    inert = inert,
                    "Successfully applied firewall ruleset{}",
                    if inert { " (inert mode)" } else { " to kernel" }
                );
                let summary = FirewallAppliedSummary {
                    table,
                    wan_iface: active_wan,
                    rules_count,
                    flow_offload,
                };
                let _ = ctx.bus().publish(LanforgeEvent::Firewall(
                    FirewallEvent::RulesetApplied(Box::new(summary)),
                ));
            }
            Err((e, payload)) => {
                let err_msg = format!("Failed to apply nftables ruleset: {e}");
                warn!(
                    error = %err_msg,
                    payload = %payload,
                    "Firewall ruleset application failed (soft error)"
                );
                let _ = ctx.bus().publish(LanforgeEvent::Firewall(
                    FirewallEvent::ApplyFailed { error: err_msg },
                ));
            }
        }
    }
}

impl Default for NftService {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncService for NftService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }

    fn init(&mut self, ctx: &LanforgeContext) -> impl Future<Output = Result<(), CoreError>> + Send {
        let ctx_clone = ctx.clone();
        async move {
            self.reapply(&ctx_clone).await;
            let fw_cfg = ctx_clone.get_firewall_config().unwrap_or_default();
            if fw_cfg.enabled && fw_cfg.mode != FirewallMode::Disabled {
                ctx_clone.set_service_state("firewall", lanforge_types::system::ServiceState::Online);
            } else {
                ctx_clone.set_service_state("firewall", lanforge_types::system::ServiceState::Inactive);
            }
            Ok(())
        }
    }

    fn serve(&mut self, ctx: &LanforgeContext) -> impl Future<Output = Result<(), CoreError>> + Send {
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut fw_rx = ctx.bus().subscribe_firewall();
        let mut sys_rx = ctx.bus().subscribe_system();
        let ctx = ctx.clone();

        async move {
            let fw_cfg = ctx.get_firewall_config().unwrap_or_default();
            if fw_cfg.enabled && fw_cfg.mode != FirewallMode::Disabled {
                ctx.set_service_state("firewall", lanforge_types::system::ServiceState::Online);
            } else {
                ctx.set_service_state("firewall", lanforge_types::system::ServiceState::Inactive);
            }

            loop {
                tokio::select! {
                    // PPPoE WAN state updates
                    Ok(event) = pppoe_rx.recv() => {
                        match event.event {
                            LanforgeEvent::Pppoe(PppoeEvent::SessionUp(session)) => {
                                info!(wan = %session.interface, "Active WAN interface up, updating firewall ruleset");
                                self.active_wan = Some(session.interface.clone());
                                self.reapply(&ctx).await;
                            }
                            LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) => {
                                info!(%reason, "Active WAN interface down, updating firewall ruleset");
                                self.active_wan = None;
                                self.reapply(&ctx).await;
                            }
                            _ => {}
                        }
                    }

                    // Firewall events: dynamic port open/release requests or config changes
                    Ok(event) = fw_rx.recv() => {
                        match event.event {
                            LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(req)) => {
                                info!(
                                    service = %req.service,
                                    zone = %req.zone,
                                    port = req.port,
                                    proto = ?req.protocol,
                                    "Dynamic port open requested, updating firewall ruleset"
                                );
                                self.reapply(&ctx).await;
                            }
                            LanforgeEvent::Firewall(FirewallEvent::RulesetChanged) => {
                                info!("Firewall configuration changed, reapplying ruleset in-place");
                                self.reapply(&ctx).await;
                            }
                            LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { service, port, protocol }) => {
                                info!(
                                    %service,
                                    port,
                                    proto = ?protocol,
                                    "Dynamic port release requested, updating firewall ruleset"
                                );
                                self.reapply(&ctx).await;
                            }
                            _ => {}
                        }
                    }

                    // System events: config reloads or shutdown
                    Ok(event) = sys_rx.recv() => {
                        match event.event {
                            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                                info!("Firewall service reloading configuration");
                                self.reapply(&ctx).await;
                            }
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                info!("Firewall service received shutdown signal, terminating event loop");
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }

            Ok(())
        }
    }

    fn cleanup(
        &mut self,
        ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        let table = ctx
            .get_firewall_config()
            .map_or_else(|| "lanforge".into(), |c| c.table_name);
        let inert = self.inert;
        async move {
            info!(table = %table, "Firewall service shutting down, removing nftables table from kernel");
            Self::cleanup_table_internal(&table, inert).await;
            Ok(())
        }
    }
}
