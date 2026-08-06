use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_types::{network::pppoe::PppoeConfig, system::ServiceAction};

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

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ReloadConfig));

        Response::Success(SimpleSuccess {
            message: "PPPoE configuration updated successfully".to_string(),
        })
    }
}
