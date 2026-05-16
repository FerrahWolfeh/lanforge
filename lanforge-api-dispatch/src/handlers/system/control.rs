use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};

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
}

