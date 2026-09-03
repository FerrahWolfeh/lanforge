use crate::ClientContext;
use lanforge_api::api::{DbEngineSwitchRequest, Response, SimpleSuccess};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use std::fs;
use std::time::Duration;
use tracing::info;

impl ClientContext {
    /// Switches the database engine between PostgreSQL and in-memory, performing configuration migration.
    pub async fn handle_db_switch_engine(&self, req: DbEngineSwitchRequest) -> Response {
        let engine = req.engine.to_lowercase();
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

        match engine.as_str() {
            "postgres" | "postgresql" => {
                let url = match req.url {
                    Some(ref u) if !u.trim().is_empty() => u.trim().to_string(),
                    _ => {
                        return Response::Error {
                            error: "Database URL is required when switching to PostgreSQL"
                                .to_string(),
                        };
                    }
                };

                if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
                    return Response::Error {
                        error:
                            "Invalid PostgreSQL URL scheme. Must start with postgres:// or postgresql://"
                                .to_string(),
                    };
                }

                // 1. Gather all current static configurations
                let export = self.export_system_config_data().await;

                // 2. Format updated TOML configuration with the new PostgreSQL URL
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
                    "Database migration: successfully updated {} with PostgreSQL connection. Triggering soft-reboot...",
                    target_path.display()
                );

                // 4. Trigger soft-reboot to rebind services and run bootstrap seeding into PostgreSQL
                let bus = self.ctx.bus().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
                });

                Response::Success(SimpleSuccess {
                    message: format!(
                        "Database switched to PostgreSQL. Configuration saved to {}. Daemon is soft-rebooting to connect.",
                        target_path.display()
                    ),
                })
            }
            "memory" | "none" | "mock" => {
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
                    "Database migration: successfully flushed static configurations to {} and switched to in-memory mode. Triggering soft-reboot...",
                    target_path.display()
                );

                // 4. Trigger soft-reboot to rebind services with in-memory store
                let bus = self.ctx.bus().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
                });

                Response::Success(SimpleSuccess {
                    message: format!(
                        "Database switched to In-Memory mode. Static configuration flushed to {}. Daemon is soft-rebooting.",
                        target_path.display()
                    ),
                })
            }
            other => Response::Error {
                error: format!(
                    "Unsupported database engine: '{other}'. Supported engines are 'postgres' and 'memory'."
                ),
            },
        }
    }
}
