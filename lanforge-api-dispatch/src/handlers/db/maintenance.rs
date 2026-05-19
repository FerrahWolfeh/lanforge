use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::bus::{LanforgeEvent, StorageEvent};
use std::time::{SystemTime, UNIX_EPOCH};

impl ClientContext {
    pub async fn handle_db_vacuum(&self) -> Response {
        if let Err(e) = self.db.vacuum().await {
            return Response::Error {
                error: format!("Database VACUUM failed: {e}"),
            };
        }
        Response::Success(SimpleSuccess {
            message: "Database VACUUM completed successfully".to_string(),
        })
    }

    pub async fn handle_db_log_clean(&self) -> Response {
        if let Err(e) = self.log_db.clear_logs().await {
            return Response::Error {
                error: format!("Transient log cleanup failed: {e}"),
            };
        }
        Response::Success(SimpleSuccess {
            message: "Transient logs cleared successfully".to_string(),
        })
    }

    pub async fn handle_db_prune(&self) -> Response {
        let pruned_zombies = match self.db.prune_zombies().await {
            Ok(n) => n,
            Err(e) => {
                return Response::Error {
                    error: format!("Failed to prune zombie entries: {e}"),
                };
            }
        };

        let cutoff = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64)
            - (24 * 3600);

        if let Err(e) = self.log_db.prune_logs(cutoff).await {
            return Response::Error {
                error: format!("Failed to prune transient logs: {e}"),
            };
        }

        Response::Success(SimpleSuccess {
            message: format!(
                "Database pruned successfully. Removed {pruned_zombies} zombie records and transient logs older than 24h."
            ),
        })
    }

    pub async fn handle_db_reset(&self) -> Response {
        // 1. Synchronously reset database and log tables
        if let Err(e) = self.db.reset().await {
            return Response::Error {
                error: format!("Database reset failed: {e}"),
            };
        }
        if let Err(e) = self.log_db.clear_logs().await {
            return Response::Error {
                error: format!("Transient logs cleanup during reset failed: {e}"),
            };
        }

        // 2. Clear in-memory state
        self.ctx.reset();

        // 3. Publish completion event to let worker know to clear its queues
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Storage(StorageEvent::DbResetCompleted));

        Response::Success(SimpleSuccess {
            message: "Factory reset completed. Database and transient logs have been cleared.".to_string(),
        })
    }
}
