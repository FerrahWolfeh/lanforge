//! Lanforge Firewall & Router Orchestrator Service.
//!
//! Subscribes to dynamic port registrations, `PPPoE` session events, and configuration
//! updates to atomically compile and apply `table inet lanforge` via `nftables-rs`.

use std::future::Future;
use std::io::ErrorKind;

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, Edge, LanforgeService, RestartPolicy, RuntimeClass,
    ServiceCommand, ServiceHandle, ServiceSpec,
};
use lanforge_types::events::LanforgeEvent;
use lanforge_types::events::firewall::{FirewallAppliedSummary, FirewallEvent};
use lanforge_types::events::pppoe::PppoeEvent;
use lanforge_types::events::system::SystemEvent;
use lanforge_types::network::firewall::{DynamicPortRequest, FirewallConfig, FirewallMode};
use lanforge_types::system::{DormantReason, ServiceAction, ServiceId};
use tracing::{debug, error, info, trace, warn};

use crate::ruleset::RulesetBuilder;

const FIREWALL_DEPS: &[Edge] = &[Edge::after(ServiceId::Db), Edge::wants(ServiceId::Pppoe)];

#[derive(Clone)]
pub struct NftService {
    active_wan: Option<String>,
    inert: bool,
    last_ruleset: std::sync::Arc<parking_lot::RwLock<Option<String>>>,
}

impl NftService {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Nft;
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
            if t.is_empty() { "lanforge" } else { t }
        };

        if inert {
            info!(table, "Inert mode: skipping kernel firewall table deletion");
            return;
        }

        let mut batch = nftables::batch::Batch::new();
        batch.delete(nftables::schema::NfListObject::Table(
            nftables::schema::Table {
                family: nftables::types::NfFamily::INet,
                name: table.to_string().into(),
                handle: None,
            },
        ));
        let ruleset = batch.to_nftables();

        let table_owned = table.to_string();
        let result =
            tokio::task::spawn_blocking(move || nftables::helper::apply_ruleset(&ruleset)).await;
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

    async fn reapply(&self, ctx: &LanforgeContext, reason: &'static str) {
        let cfg = ctx.get_firewall_config().unwrap_or_default();
        let dynamic_ports = ctx.registered_service_ports();
        self.apply_ruleset_internal(ctx, &cfg, &dynamic_ports, reason)
            .await;
    }

    fn publish_ruleset_applied(
        ctx: &LanforgeContext,
        reason: &'static str,
        zones: usize,
        inert: bool,
        summary: FirewallAppliedSummary,
    ) {
        info!(
            reason,
            table = %summary.table,
            zones,
            port_rules = summary.rules_count,
            wan = ?summary.wan_iface,
            inert,
            "Firewall ruleset applied"
        );
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(
                Box::new(summary),
            )));
    }

    async fn apply_ruleset_internal(
        &self,
        ctx: &LanforgeContext,
        cfg: &FirewallConfig,
        dynamic_ports: &[DynamicPortRequest],
        reason: &'static str,
    ) {
        if !cfg.enabled || cfg.mode == FirewallMode::Disabled {
            info!(reason, table = %cfg.table_name, "Firewall disabled; removing nftables table");
            ctx.set_service_state(
                Self::SERVICE_ID,
                lanforge_types::system::ServiceState::Inactive,
            );
            Self::cleanup_table_internal(&cfg.table_name, self.inert).await;
            return;
        }

        let primary_lan = ctx.target_interface_name();
        let ruleset = RulesetBuilder::new(cfg)
            .with_active_wan(self.active_wan.as_deref())
            .with_primary_lan(primary_lan.as_deref())
            .with_dynamic_ports(dynamic_ports)
            .build();

        let should_serialize = self.inert || tracing::enabled!(tracing::Level::TRACE);
        let json_payload = if should_serialize {
            serde_json::to_string_pretty(&ruleset).unwrap_or_default()
        } else {
            String::new()
        };
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

        let result =
            if inert {
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
                        if !payload.is_empty() {
                            *last_ruleset.write() = Some(payload);
                        }
                        Ok(())
                    }
                    Ok(Err((e, payload))) => Err((e, payload)),
                    Err(e) => {
                        let err_msg = format!("Firewall task panicked: {e}");
                        error!(reason, error = %err_msg, "Firewall worker panicked");
                        let _ = ctx.bus().publish(LanforgeEvent::Firewall(
                            FirewallEvent::ApplyFailed { error: err_msg },
                        ));
                        return;
                    }
                }
            };

        match result {
            Ok(()) => {
                ctx.set_service_state(
                    Self::SERVICE_ID,
                    lanforge_types::system::ServiceState::Online,
                );
                Self::publish_ruleset_applied(
                    ctx,
                    reason,
                    cfg.zones.len(),
                    inert,
                    FirewallAppliedSummary {
                        table,
                        wan_iface: active_wan,
                        rules_count,
                        flow_offload,
                    },
                );
            }
            Err((e, payload)) => {
                let err_msg = format!("Failed to apply nftables ruleset: {e}");
                warn!(
                    reason,
                    table = %table,
                    payload_bytes = payload.len(),
                    error = %err_msg,
                    "Firewall ruleset application failed"
                );
                let _ = ctx
                    .bus()
                    .publish(LanforgeEvent::Firewall(FirewallEvent::ApplyFailed {
                        error: err_msg,
                    }));
            }
        }
    }
}

impl Default for NftService {
    fn default() -> Self {
        Self::new()
    }
}

impl LanforgeService for NftService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "Firewall & NAT Orchestrator",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: std::time::Duration::from_secs(5),
                max_backoff: std::time::Duration::from_secs(10),
                max_retries: 0,
                healthy_uptime: std::time::Duration::from_secs(30),
            },
            shutdown_timeout: std::time::Duration::from_secs(5),
            deps: FIREWALL_DEPS,
            condition: Condition {
                sections: &[lanforge_types::config::ConfigDomain::Firewall],
                eval: |ctx| {
                    if ctx.get_firewall_config().is_none_or(|c| c.enabled) {
                        Activation::Active
                    } else {
                        Activation::Dormant(DormantReason::disabled("firewall.enabled"))
                    }
                },
            },
        }
    }

    fn describe(&self) -> String {
        "nftables Host & Gateway Firewall".to_string()
    }
}

impl AsyncService for NftService {
    fn init(
        &mut self,
        ctx: &LanforgeContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        let ctx = ctx.clone();
        async move {
            let fw_cfg = ctx.get_firewall_config().unwrap_or_default();
            if fw_cfg.enabled && fw_cfg.mode != FirewallMode::Disabled {
                self.reapply(&ctx, "startup").await;
            }
            Ok(())
        }
    }

    #[allow(clippy::too_many_lines)]
    fn serve(
        &mut self,
        ctx: &LanforgeContext,
        h: &ServiceHandle,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut fw_rx = ctx.bus().subscribe_firewall();
        let mut sys_rx = ctx.bus().subscribe_system();
        let ctx = ctx.clone();
        let h = h.clone();

        async move {
            let fw_cfg = ctx.get_firewall_config().unwrap_or_default();
            if !fw_cfg.enabled || fw_cfg.mode == FirewallMode::Disabled {
                h.dormant(DormantReason::disabled("firewall.enabled"));
                return Ok(());
            }

            if self.last_applied_payload().is_none() {
                self.reapply(&ctx, "startup").await;
            }
            h.ready();

            loop {
                tokio::select! {
                    cmd = h.next_command() => {
                        match cmd {
                            ServiceCommand::Stop => {
                                info!("Firewall service received Stop command, flushing table and marking Inactive");
                                let table = ctx
                                    .get_firewall_config()
                                    .map_or_else(|| "lanforge".into(), |c| c.table_name);
                                Self::cleanup_table_internal(&table, self.inert).await;
                                ctx.set_service_state(Self::SERVICE_ID, lanforge_types::system::ServiceState::Inactive);
                            }
                            ServiceCommand::Start | ServiceCommand::Restart => {
                                info!("Firewall service received Start/Restart command");
                                self.reapply(&ctx, "service_control").await;
                                h.ready();
                            }
                            ServiceCommand::Shutdown => break,
                            _ => {}
                        }
                    }
                    // PPPoE WAN state updates
                    Ok(event) = pppoe_rx.recv() => {
                        match event.event {
                            LanforgeEvent::Pppoe(PppoeEvent::SessionUp(session)) => {
                                debug!(wan = %session.interface, "WAN session is up; applying firewall ruleset");
                                self.active_wan = Some(session.interface.clone());
                                self.reapply(&ctx, "wan_up").await;
                            }
                            LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }) => {
                                debug!(%reason, "WAN session is down; applying firewall ruleset");
                                self.active_wan = None;
                                self.reapply(&ctx, "wan_down").await;
                            }
                            _ => {}
                        }
                    }

                    // Firewall events: dynamic port open/release requests or config changes
                    Ok(event) = fw_rx.recv() => {
                        match event.event {
                            LanforgeEvent::Firewall(FirewallEvent::PortOpenRequested(req)) => {
                                debug!(
                                    service = %req.service,
                                    zone = %req.zone,
                                    port = req.port,
                                    proto = ?req.protocol,
                                    "Dynamic port open requested"
                                );
                                self.reapply(&ctx, "port_open").await;
                            }
                            LanforgeEvent::Firewall(FirewallEvent::RulesetChanged) => {
                                debug!("Firewall configuration changed; applying ruleset in-place");
                                self.reapply(&ctx, "config_changed").await;
                            }
                            LanforgeEvent::Firewall(FirewallEvent::PortReleaseRequested { service, port, protocol }) => {
                                debug!(
                                    %service,
                                    port,
                                    proto = ?protocol,
                                    "Dynamic port release requested"
                                );
                                self.reapply(&ctx, "port_release").await;
                            }
                            _ => {}
                        }
                    }

                    // System events: config reloads or shutdown
                    Ok(event) = sys_rx.recv() => {
                        match event.event {
                            LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) if id == Self::SERVICE_ID => {
                                match action {
                                    ServiceAction::Stop => {
                                        info!("Firewall service received Stop command, flushing table and marking Inactive");
                                        let table = ctx
                                            .get_firewall_config()
                                            .map_or_else(|| "lanforge".into(), |c| c.table_name);
                                        Self::cleanup_table_internal(&table, self.inert).await;
                                        ctx.set_service_state(Self::SERVICE_ID, lanforge_types::system::ServiceState::Inactive);
                                    }
                                    ServiceAction::Start | ServiceAction::Restart => {
                                        info!("Firewall service received Start/Restart command");
                                        self.reapply(&ctx, "service_control").await;
                                    }
                                }
                            }
                            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                                debug!("Firewall configuration reload requested");
                                self.reapply(&ctx, "config_reload").await;
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
        let ctx_clone = ctx.clone();
        async move {
            info!(table = %table, "Firewall service shutting down, removing nftables table from kernel");
            ctx_clone.set_service_state(
                Self::SERVICE_ID,
                lanforge_types::system::ServiceState::Inactive,
            );
            Self::cleanup_table_internal(&table, inert).await;
            Ok(())
        }
    }
}
