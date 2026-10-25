use crate::ClientContext;
use lanforge_api::api::{DbEngineSwitchRequest, Response, SimpleSuccess};
use lanforge_types::system::StorageMode;
use std::fs;
use tracing::info;

impl ClientContext {
    /// Switches the database storage mode between persistent and in-memory, performing configuration migration.
    pub async fn handle_db_switch_engine(&self, req: DbEngineSwitchRequest) -> Response {
        let target_path = match self.resolve_config_path() {
            Some(p) => p,
            None => {
                if std::path::Path::new("/etc/lanforge").exists() {
                    std::path::PathBuf::from("/etc/lanforge/lanforge.toml")
                } else {
                    std::path::PathBuf::from("lanforge.toml")
                }
            }
        };

        match req.mode {
            StorageMode::Persistent => {
                let url = match req.path {
                    Some(ref u) if !u.trim().is_empty() => {
                        let trimmed = u.trim();
                        trimmed
                            .strip_prefix("redb://")
                            .or_else(|| trimmed.strip_prefix("file://"))
                            .unwrap_or(trimmed)
                            .to_string()
                    }
                    _ => "/var/lib/lanforge/config.redb".to_string(),
                };

                // 1. Gather all current static configurations
                let export = self.export_system_config_data().await;

                // 2. Format updated TOML configuration with the new storage path
                let existing_content = fs::read_to_string(&target_path).ok();
                let toml_str = crate::handlers::system::toml_sync::generate_toml_from_export(
                    &export,
                    &url,
                    existing_content.as_deref(),
                );

                // 3. Atomically write updated configuration to disk
                if let Err(e) = crate::handlers::system::toml_sync::write_toml_atomically(
                    &target_path,
                    &toml_str,
                ) {
                    return Response::Error {
                        error: format!(
                            "Failed to write updated configuration to {}: {e}",
                            target_path.display()
                        ),
                    };
                }

                info!(
                    "Database migration: successfully updated {} with persistent storage path ({url}).",
                    target_path.display()
                );

                Response::Success(SimpleSuccess {
                    message: format!(
                        "Database switched to persistent storage ({url}). Configuration saved to {}.",
                        target_path.display()
                    ),
                })
            }
            StorageMode::InMemory => {
                // 1. Export the latest static configurations from the active database
                let export = self.export_system_config_data().await;

                // 2. Format updated TOML configuration with database url = "memory"
                let existing_content = fs::read_to_string(&target_path).ok();
                let toml_str = crate::handlers::system::toml_sync::generate_toml_from_export(
                    &export,
                    "memory",
                    existing_content.as_deref(),
                );

                // 3. Atomically write to disk
                if let Err(e) = crate::handlers::system::toml_sync::write_toml_atomically(
                    &target_path,
                    &toml_str,
                ) {
                    return Response::Error {
                        error: format!(
                            "Failed to write configuration to {}: {e}",
                            target_path.display()
                        ),
                    };
                }

                info!(
                    "Database migration: successfully flushed static configurations to {} and switched to in-memory mode.",
                    target_path.display()
                );

                Response::Success(SimpleSuccess {
                    message: format!(
                        "Database switched to In-Memory mode. Static configuration flushed to {}.",
                        target_path.display()
                    ),
                })
            }
        }
    }
}
