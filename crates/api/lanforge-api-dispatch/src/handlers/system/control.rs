use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::bus::{FirewallEvent, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_types::{
    network::{
        firewall::{FirewallCommitRequest, FirewallCommitResponse, FirewallConfig},
        pppoe::PppoeConfig,
        ra::RaServerConfig,
        TrafficConfig,
    },
    system::ServiceAction,
};


impl ClientContext {
    pub async fn handle_service_control(&self, id: String, action: ServiceAction) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: id.clone(),
                action,
            }));
        Response::Success(SimpleSuccess {
            message: format!("Service control action {action:?} sent for service {id}"),
        })
    }

    pub async fn handle_reload(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
        Response::Success(SimpleSuccess {
            message: "Configuration reload triggered".to_string(),
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
                id: "pppoe".to_string(),
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
                id: "pppoe".to_string(),
                action: ServiceAction::Stop,
            }));
        Response::Success(SimpleSuccess {
            message: "PPPoE disconnection triggered".to_string(),
        })
    }

    pub async fn handle_pppoe_config(&self) -> Response {
        match self.db.load_pppoe_config().await {
            Ok(Some(cfg)) => Response::PppoeConfig(Box::new(cfg)),
            Ok(None) => Response::Error {
                error: "PPPoE configuration not found in database".to_string(),
            },
            Err(e) => Response::Error {
                error: format!("Database error: {e}"),
            },
        }
    }

    pub async fn handle_update_pppoe_config(&self, cfg: PppoeConfig) -> Response {
        if let Err(e) = self.db.save_pppoe_config(&cfg).await {
            return Response::Error {
                error: format!("Failed to save PPPoE configuration: {e}"),
            };
        }

        self.ctx.update_pppoe_config(cfg);

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: "pppoe".to_string(),
                action: ServiceAction::Restart,
            }));

        Response::Success(SimpleSuccess {
            message: "PPPoE configuration updated successfully".to_string(),
        })
    }

    pub async fn handle_ra_config(&self) -> Response {
        let cfg = self.ctx.get_ra_server_config();
        Response::RaConfig(Box::new(cfg))
    }

    pub async fn handle_update_ra_config(&self, cfg: RaServerConfig) -> Response {
        // Save dynamic RA components to database
        let _ = self.db.save_ra_prefixes(&cfg.prefixes).await;
        let _ = self.db.save_ra_rdnss(&cfg.rdnss).await;
        let _ = self.db.save_ra_dnssl(&cfg.dnssl).await;

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
        let cfg = match self.db.load_traffic_config().await {
            Ok(Some(cfg)) => cfg,
            _ => self.ctx.get_traffic_config().unwrap_or_default(),
        };
        Response::TrafficConfig(Box::new(cfg))
    }

    pub async fn handle_update_traffic_config(&self, cfg: TrafficConfig) -> Response {
        if let Err(e) = self.db.save_traffic_config(&cfg).await {
            return Response::Error {
                error: format!("Failed to save traffic configuration: {e}"),
            };
        }

        self.ctx.update_traffic_config(cfg);

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceControl {
                id: "traffic".to_string(),
                action: ServiceAction::Restart,
            }));

        Response::Success(SimpleSuccess {
            message: "Traffic and SQM configuration updated successfully".to_string(),
        })
    }

    pub async fn handle_firewall_config(&self) -> Response {
        let mut cfg = match self.db.load_firewall_config().await {
            Ok(Some(cfg)) => cfg,
            Ok(None) => self.ctx.get_firewall_config().unwrap_or_default(),
            Err(e) => {
                return Response::Error {
                    error: format!("Database error loading firewall config: {e}"),
                };
            }
        };

        // If external zone exists but has no interfaces assigned, auto-populate with active or configured WAN
        if let Some(ext) = cfg.zones.iter_mut().find(|z| z.name == "external" || z.name == "wan")
            && ext.interfaces.is_empty()
        {
            let wan = self
                .ctx
                .read()
                .interfaces
                .pppoe_status
                .as_ref()
                .and_then(|p| p.interface.clone().or_else(|| p.wan_iface.clone()))
                .or_else(|| self.ctx.get_pppoe_config().map(|p| p.wan_iface));
            if let Some(w) = wan {
                ext.interfaces.push(w);
            }
        }

        Response::FirewallConfig(Box::new(cfg))
    }

    pub async fn handle_update_firewall_config(&self, cfg: FirewallConfig) -> Response {
        if let Err(e) = self.db.save_firewall_config(&cfg).await {
            return Response::Error {
                error: format!("Failed to save firewall configuration: {e}"),
            };
        }

        self.ctx.update_firewall_config(cfg);

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));

        Response::Success(SimpleSuccess {
            message: "Firewall configuration updated successfully".to_string(),
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
                error: "No active staged firewall transaction found or transaction expired".to_string(),
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
            // Apply candidate to runtime context and reload kernel ruleset
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
            if let Err(e) = self.db.save_firewall_config(&candidate).await {
                return Response::Error {
                    error: format!("Failed to persist firewall configuration: {e}"),
                };
            }

            self.ctx.update_firewall_config(candidate);
            let _ = self
                .ctx
                .clear_staged_firewall_transaction(Some(&req.tx_id));

            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));

            Response::FirewallCommit(Box::new(FirewallCommitResponse {
                success: true,
                message: "Firewall configuration committed and persisted successfully".to_string(),
                auto_rollback_active: false,
                rollback_deadline_secs: None,
            }))
        }
    }

    pub async fn handle_firewall_confirm(&self, tx_id: String) -> Response {
        let Some(staged) = self.ctx.clear_staged_firewall_transaction(Some(&tx_id)) else {
            return Response::Error {
                error: format!("No active transaction found with ID '{tx_id}' to confirm"),
            };
        };

        if let Err(e) = self.db.save_firewall_config(&staged.candidate_config).await {
            return Response::Error {
                error: format!("Failed to persist confirmed firewall configuration: {e}"),
            };
        }

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

