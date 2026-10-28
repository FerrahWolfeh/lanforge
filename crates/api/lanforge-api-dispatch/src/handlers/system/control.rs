use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_api::config_file::SectionSet;
use lanforge_core::bus::{FirewallEvent, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_types::{
    network::{
        TrafficConfig,
        firewall::{FirewallCommitRequest, FirewallCommitResponse, FirewallConfig},
        pppoe::PppoeConfig,
        ra::RaServerConfig,
    },
    system::{ServiceAction, ServiceId},
};

impl ClientContext {
    pub async fn handle_service_control(&self, id: String, action: ServiceAction) -> Response {
        let service_id = match id.parse::<ServiceId>() {
            Ok(sid) => sid,
            Err(e) => {
                return Response::Error {
                    error: format!("Invalid service id '{id}': {e}"),
                };
            }
        };
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: service_id,
                action,
            }));
        Response::Success(SimpleSuccess {
            message: format!("Service control action {action:?} sent for service {service_id}"),
        })
    }

    pub async fn handle_shutdown(&self) -> Response {
        self.ctx.terminate();
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));
        Response::Success(SimpleSuccess {
            message: "Daemon shutdown initiated".to_string(),
        })
    }

    pub async fn handle_pppoe_reconnect(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: ServiceId::Pppoe,
                action: ServiceAction::Restart,
            }));
        Response::Success(SimpleSuccess {
            message: "PPPoE reconnection triggered".to_string(),
        })
    }

    pub async fn handle_pppoe_disconnect(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: ServiceId::Pppoe,
                action: ServiceAction::Stop,
            }));
        Response::Success(SimpleSuccess {
            message: "PPPoE disconnection triggered".to_string(),
        })
    }

    pub async fn handle_pppoe_config(&self) -> Response {
        match self.ctx.get_pppoe_config() {
            Some(cfg) => Response::PppoeConfig(Box::new(cfg)),
            None => Response::Error {
                error: "PPPoE configuration not found".to_string(),
            },
        }
    }

    pub async fn handle_update_pppoe_config(&self, cfg: PppoeConfig) -> Response {
        tracing::info!(
            wan_iface = %cfg.wan_iface,
            username = %cfg.username,
            enabled = cfg.enabled,
            "PPPoE configuration updated via API"
        );

        let persisted = match self
            .persist_config_sections(SectionSet::PPPOE, |file| file.pppoe = cfg.clone())
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("PPPoE configuration not saved: {e}");
                return Response::Error {
                    error: format!("PPPoE configuration not saved: {e}"),
                };
            }
        };
        self.ctx.update_pppoe_config(cfg);

        Response::Success(SimpleSuccess {
            message: persisted.message("PPPoE configuration"),
        })
    }

    pub async fn handle_ra_config(&self) -> Response {
        let cfg = self.ctx.get_ra_server_config();
        Response::RaConfig(Box::new(cfg))
    }

    pub async fn handle_update_ra_config(&self, cfg: RaServerConfig) -> Response {
        self.ctx.update_ra_server_config(cfg);

        Response::Success(SimpleSuccess {
            message: "Router Advertisement configuration updated successfully".to_string(),
        })
    }

    pub async fn handle_ra_trigger(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::RaTriggerRequested));

        Response::Success(SimpleSuccess {
            message: "Immediate Router Advertisement burst triggered".to_string(),
        })
    }

    pub async fn handle_traffic_config(&self) -> Response {
        let cfg = self.ctx.get_traffic_config().unwrap_or_default();
        Response::TrafficConfig(Box::new(cfg))
    }

    pub async fn handle_update_traffic_config(&self, cfg: TrafficConfig) -> Response {
        let persisted = match self
            .persist_config_sections(SectionSet::TRAFFIC, |file| file.traffic = cfg.clone())
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Traffic configuration not saved: {e}");
                return Response::Error {
                    error: format!("Traffic configuration not saved: {e}"),
                };
            }
        };
        self.ctx.update_traffic_config(cfg);

        Response::Success(SimpleSuccess {
            message: persisted.message("Traffic and SQM configuration"),
        })
    }

    pub async fn handle_firewall_config(&self) -> Response {
        let mut cfg = self.ctx.get_firewall_config().unwrap_or_default();

        // If external zone exists but has no interfaces assigned, auto-populate with active or configured WAN
        if let Some(ext) = cfg
            .zones
            .iter_mut()
            .find(|z| z.name == "external" || z.name == "wan")
            && ext.interfaces.is_empty()
        {
            let pppoe_wan = self
                .ctx
                .pppoe_status()
                .as_ref()
                .and_then(|p| p.interface.clone().or_else(|| p.wan_iface.clone()));
            let wan = pppoe_wan.or_else(|| self.ctx.get_pppoe_config().map(|p| p.wan_iface));
            if let Some(w) = wan {
                ext.interfaces.push(w);
            }
        }

        Response::FirewallConfig(Box::new(cfg))
    }

    pub async fn handle_update_firewall_config(&self, cfg: FirewallConfig) -> Response {
        let persisted = match self.persist_firewall(&cfg) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Firewall configuration not saved: {e}");
                return Response::Error {
                    error: format!("Firewall configuration not saved: {e}"),
                };
            }
        };
        self.ctx.update_firewall_config(cfg);

        Response::Success(SimpleSuccess {
            message: persisted.message("Firewall configuration"),
        })
    }

    pub async fn handle_firewall_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));

        Response::Success(SimpleSuccess {
            message: "Firewall reload requested".to_string(),
        })
    }

    pub async fn handle_firewall_propose(&self, candidate: FirewallConfig) -> Response {
        let report = self.ctx.stage_firewall_transaction(candidate);
        Response::FirewallValidation(Box::new(report))
    }

    pub async fn handle_firewall_commit(&self, req: FirewallCommitRequest) -> Response {
        let Some(staged) = self.ctx.get_staged_firewall_transaction() else {
            return Response::Error {
                error: "No active staged firewall transaction found or transaction expired"
                    .to_string(),
            };
        };

        if staged.tx_id != req.tx_id {
            return Response::Error {
                error: format!(
                    "Transaction ID mismatch: expected '{}', got '{}'",
                    staged.tx_id, req.tx_id
                ),
            };
        }

        let candidate = staged.candidate_config.clone();
        let previous = staged.previous_config.clone().unwrap_or_default();

        if let Some(rollback_secs) = req.auto_rollback_secs {
            // On trial: applied in memory only. The file keeps the previous config until the
            // admin confirms, so a restart during the trial window also rolls back.
            self.ctx.update_firewall_config(candidate);
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));

            let deadline = std::time::Instant::now()
                + std::time::Duration::from_secs(u64::from(rollback_secs));
            let _ = self
                .ctx
                .set_firewall_transaction_rollback(&req.tx_id, deadline);

            // Spawn background auto-rollback worker
            let ctx = self.ctx.clone();
            let tx_id = req.tx_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(u64::from(rollback_secs))).await;
                // If transaction is still active with this tx_id, rollback!
                if let Some(current_staged) = ctx.get_staged_firewall_transaction()
                    && current_staged.tx_id == tx_id
                {
                    tracing::warn!(
                        tx_id = %tx_id,
                        "Firewall transaction auto-rollback triggered after timeout without confirmation"
                    );
                    ctx.update_firewall_config(previous);
                    let _ = ctx
                        .bus()
                        .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
                    let _ = ctx.clear_staged_firewall_transaction(Some(&tx_id));
                }
            });

            Response::FirewallCommit(Box::new(FirewallCommitResponse {
                success: true,
                message: format!(
                    "Candidate firewall rules applied with {rollback_secs}s auto-rollback window"
                ),
                auto_rollback_active: true,
                rollback_deadline_secs: Some(rollback_secs),
            }))
        } else {
            // Permanent commit without rollback
            let persisted = match self.persist_firewall(&candidate) {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        error: format!("Firewall configuration not saved: {e}"),
                    };
                }
            };
            self.ctx.update_firewall_config(candidate);
            let _ = self.ctx.clear_staged_firewall_transaction(Some(&req.tx_id));

            Response::FirewallCommit(Box::new(FirewallCommitResponse {
                success: true,
                message: persisted.message("Firewall configuration"),
                auto_rollback_active: false,
                rollback_deadline_secs: None,
            }))
        }
    }

    pub async fn handle_firewall_confirm(&self, tx_id: String) -> Response {
        let Some(staged) = self
            .ctx
            .get_staged_firewall_transaction()
            .filter(|s| s.tx_id == tx_id)
        else {
            return Response::Error {
                error: format!("No active transaction found with ID '{tx_id}' to confirm"),
            };
        };
        // Saved before the transaction ends: if the file cannot take it, the trial stays
        // under its auto-rollback.
        if let Err(e) = self.persist_firewall(&staged.candidate_config) {
            return Response::Error {
                error: format!(
                    "Firewall transaction '{tx_id}' not confirmed, configuration not saved: {e}"
                ),
            };
        }
        let Some(staged) = self.ctx.clear_staged_firewall_transaction(Some(&tx_id)) else {
            return Response::Error {
                error: format!("Firewall transaction '{tx_id}' expired before it was confirmed"),
            };
        };

        self.ctx.update_firewall_config(staged.candidate_config);

        Response::Success(SimpleSuccess {
            message: format!("Firewall transaction '{tx_id}' confirmed permanently"),
        })
    }

    pub async fn handle_firewall_abort(&self, tx_id: String) -> Response {
        let Some(staged) = self.ctx.clear_staged_firewall_transaction(Some(&tx_id)) else {
            return Response::Error {
                error: format!("No active transaction found with ID '{tx_id}' to abort"),
            };
        };

        // If it had a previous config and was active with auto_rollback, revert immediately
        if staged.auto_rollback_deadline.is_some()
            && let Some(prev) = staged.previous_config
        {
            self.ctx.update_firewall_config(prev);
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
        }

        Response::Success(SimpleSuccess {
            message: format!("Firewall transaction '{tx_id}' aborted and discarded"),
        })
    }
}
