use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_types::{
    network::{pppoe::PppoeConfig, ra::RaServerConfig},
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
}

