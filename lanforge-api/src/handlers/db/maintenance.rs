use crate::api::{Response, SimpleSuccess};
use crate::server::ClientContext;
use lanforge_core::types::{LanforgeEvent, StorageEvent};

impl ClientContext {
    pub async fn handle_db_vacuum(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbVacuum));
        Response::Success(SimpleSuccess {
            message: "Database VACUUM task queued".to_string(),
        })
    }

    pub async fn handle_db_log_clean(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbLogClean));
        Response::Success(SimpleSuccess {
            message: "Transient log cleanup task queued".to_string(),
        })
    }

    pub async fn handle_db_prune(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbPrune));
        Response::Success(SimpleSuccess {
            message: "Database pruning task queued".to_string(),
        })
    }

    pub async fn handle_db_reset(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbReset));
        Response::Success(SimpleSuccess {
            message: "Factory reset initiated. Database will be cleared and daemon restarted."
                .to_string(),
        })
    }
}
