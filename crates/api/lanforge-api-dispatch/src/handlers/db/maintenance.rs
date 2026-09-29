use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_types::storage::{StorageQuery, StorageQueryResult};
use std::time::{SystemTime, UNIX_EPOCH};

impl ClientContext {
    pub async fn handle_db_vacuum(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        if let Err(e) = storage.send_query(StorageQuery::Vacuum).await {
            return Response::Error {
                error: format!("Database VACUUM failed: {e}"),
            };
        }
        Response::Success(SimpleSuccess {
            message: "Database VACUUM completed successfully".to_string(),
        })
    }

    pub async fn handle_db_log_clean(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        if let Err(e) = storage.send_query(StorageQuery::ClearLogs).await {
            return Response::Error {
                error: format!("Transient log cleanup failed: {e}"),
            };
        }
        Response::Success(SimpleSuccess {
            message: "Transient logs cleared successfully".to_string(),
        })
    }

    pub async fn handle_db_prune(&self) -> Response {
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        let pruned_zombies = match storage.send_query(StorageQuery::PruneZombies).await {
            Ok(StorageQueryResult::Count(n)) => n,
            Ok(_) => 0,
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

        if let Err(e) = storage
            .send_query(StorageQuery::PruneLogs { before: cutoff })
            .await
        {
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
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service handle is not available".to_string(),
            };
        };

        if let Err(e) = storage.send_query(StorageQuery::ResetDb).await {
            return Response::Error {
                error: format!("Database reset failed: {e}"),
            };
        }

        Response::Success(SimpleSuccess {
            message: "Factory reset completed. Database and transient logs have been cleared."
                .to_string(),
        })
    }
}
