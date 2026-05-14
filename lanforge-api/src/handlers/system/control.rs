use crate::api::{Response, SimpleSuccess};
use crate::server::ClientContext;
use lanforge_core::types::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::utils::auth::hash_password;

impl ClientContext {
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

    pub async fn handle_scan(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Network(NetworkEvent::ScanRequested));
        Response::Success(SimpleSuccess {
            message: "Network scan triggered".to_string(),
        })
    }

    pub async fn handle_config_set_password(&self, password: String) -> Response {
        let hash = hash_password(&password);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ConfigUpdate {
                password_hash: hash,
            }));
        Response::Success(SimpleSuccess {
            message: "API password updated and persisted to database".to_string(),
        })
    }
}
