//! Lanforge Firewall & Router Orchestrator Service.
//!
//! Subscribes to dynamic port registrations, `PPPoE` session events, and configuration
//! updates to atomically compile and apply `table inet lanforge` via `nftables-rs`.

use std::future::Future;
use std::io::ErrorKind;
use std::process::{Command, Stdio};

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::events::firewall::{FirewallAppliedSummary, FirewallEvent};
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::events::LanforgeEvent;
use lanforge_types::network::firewall::{DynamicPortRequest, FirewallConfig, FirewallMode};
use tracing::{debug, error, info, trace, warn};

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
pub struct NftService {
    active_wan: Option<String>,
}

impl NftService {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_wan: None,
        }
    }

    /// Flushes and removes the configured table cleanly.
    pub async fn cleanup_table(table_name: &str) {
        let table: String = {
            let t = table_name.trim();
            if t.is_empty() {
                "lanforge".into()
            } else {
                t.into()
            }
        };

        let table_clone = table.clone();
        let table_exists = tokio::task::spawn_blocking(move || {
            Command::new("nft")
                .args(["list", "table", "inet", &table_clone])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
        .await
        .unwrap_or(false);

        if !table_exists {
            debug!(table, "Firewall table does not exist in kernel, skipping cleanup");
            return;
        }

        let mut batch = nftables::batch::Batch::new();
        batch.delete(nftables::schema::NfListObject::Table(nftables::schema::Table {
            family: nftables::types::NfFamily::INet,
            name: table.clone().into(),
            handle: None,
        }));
        let ruleset = batch.to_nftables();

        let result = tokio::task::spawn_blocking(move || nftables::helper::apply_ruleset(&ruleset)).await;
        match result {
            Ok(Ok(())) => {
                info!(table, "Flushed and removed firewall table");
            }
            Ok(Err(nftables::helper::NftablesError::NftFailed { .. })) => {
                // Table may not exist or was already removed; ignore silently.
            }
            Ok(Err(nftables::helper::NftablesError::NftExecution { inner, .. }))
                if inner.kind() == ErrorKind::NotFound => {}
            Ok(Err(e)) => {
                warn!(table, error = %e, "Failed to delete firewall table");
            }
            Err(e) => {
                warn!(table, error = %e, "Firewall cleanup task panicked");
            }
        }
    }

    async fn apply_ruleset_internal(
        &self,
        ctx: &LanforgeContext,
        cfg: &FirewallConfig,
        dynamic_ports: &[DynamicPortRequest],
    ) {
        if !cfg.enabled || cfg.mode == FirewallMode::Disabled {
            info!("Firewall is disabled in configuration, flushing and removing nftables table");
            Self::cleanup_table(&cfg.table_name).await;
            return;
        }

        let primary_lan = ctx.target_interface_name();
        let ruleset = RulesetBuilder::new(cfg)
            .with_active_wan(self.active_wan.as_deref())
            .with_primary_lan(primary_lan.as_deref())
            .with_dynamic_ports(dynamic_ports)
            .build();

        let json_payload = serde_json::to_string_pretty(&ruleset).unwrap_or_default();
        trace!(payload = %json_payload, "Applying nftables ruleset payload to kernel");

        let table = cfg.table_name.clone();
        let active_wan = self.active_wan.clone();
        let flow_offload = cfg.flow_offload;
        #[allow(clippy::cast_possible_truncation)]
        let rules_count = (cfg.port_forwards.len() + dynamic_ports.len()) as u32;

        let result = tokio::task::spawn_blocking(move || {
            nftables::helper::apply_ruleset(&ruleset)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                info!(
                    table = %table,
                    zones = cfg.zones.len(),
                    ports = dynamic_ports.len(),
                    wan = ?self.active_wan,
                    "Successfully applied firewall ruleset to kernel"
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
            Ok(Err(e)) => {
                let err_msg = format!("Failed to apply nftables ruleset: {e}");
                warn!(
                    error = %err_msg,
                    payload = %json_payload,
                    "Firewall ruleset application failed (soft error)"
                );
                let _ = ctx.bus().publish(LanforgeEvent::Firewall(
                    FirewallEvent::ApplyFailed { error: err_msg },
                ));
            }
            Err(e) => {
                let err_msg = format!("Firewall task panicked: {e}");
                error!(error = %err_msg, "Firewall worker panicked (soft error)");
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
        let cfg = ctx.get_firewall_config().unwrap_or_default();
        let dynamic_ports = ctx.registered_service_ports();
        let ctx_clone = ctx.clone();
        async move {
            self.apply_ruleset_internal(&ctx_clone, &cfg, &dynamic_ports).await;
            Ok(())
        }
    }

    fn serve(&mut self, ctx: &LanforgeContext) -> impl Future<Output = Result<(), CoreError>> + Send {
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut fw_rx = ctx.bus().subscribe_firewall();
        let mut sys_rx = ctx.bus().subscribe_system();
        let ctx = ctx.clone();

        async move {
            loop {
                tokio::select! {
                    // PPPoE WAN state updates
                    Ok(event) = pppoe_rx.recv() => {
                        match event.event {
                            LanforgeEvent::Pppoe(PppoeEvent::SessionUp(session)) => {
                                info!(wan = %session.interface, "Active WAN interface up, updating firewall ruleset");
                                self.active_wan = Some(session.interface.clone());
                                let cfg = ctx.get_firewall_config().unwrap_or_default();
                                let dynamic_ports = ctx.registered_service_ports();
                                self.apply_ruleset_internal(&ctx, &cfg, &dynamic_ports).await;
                            }
                            LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) => {
                                info!(%reason, "Active WAN interface down, updating firewall ruleset");
                                self.active_wan = None;
                                let cfg = ctx.get_firewall_config().unwrap_or_default();
                                let dynamic_ports = ctx.registered_service_ports();
                                self.apply_ruleset_internal(&ctx, &cfg, &dynamic_ports).await;
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
                                let cfg = ctx.get_firewall_config().unwrap_or_default();
                                let dynamic_ports = ctx.registered_service_ports();
                                self.apply_ruleset_internal(&ctx, &cfg, &dynamic_ports).await;
                            }
                            LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { service, port, protocol }) => {
                                info!(
                                    %service,
                                    port,
                                    proto = ?protocol,
                                    "Dynamic port release requested, updating firewall ruleset"
                                );
                                let cfg = ctx.get_firewall_config().unwrap_or_default();
                                let dynamic_ports = ctx.registered_service_ports();
                                self.apply_ruleset_internal(&ctx, &cfg, &dynamic_ports).await;
                            }
                            _ => {}
                        }
                    }

                    // System events: config reloads or shutdown
                    Ok(event) = sys_rx.recv() => {
                        match event.event {
                            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                                info!("Firewall service reloading configuration");
                                let cfg = ctx.get_firewall_config().unwrap_or_default();
                                let dynamic_ports = ctx.registered_service_ports();
                                self.apply_ruleset_internal(&ctx, &cfg, &dynamic_ports).await;
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
        async move {
            info!(table = %table, "Firewall service shutting down, removing nftables table from kernel");
            Self::cleanup_table(&table).await;
            Ok(())
        }
    }
}
