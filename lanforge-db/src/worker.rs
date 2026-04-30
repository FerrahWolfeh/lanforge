//! `DbWorker` — Background service for database persistence and logging.
//!
//! Listens for events on the global `EventBus` and performs batch updates
//! to the `LeaseDb` (persistent) and `LogDb` (transient).
//!
//! ## Batching
//!
//! To avoid excessive disk I/O, the worker batches `DeviceTableDirty` events
//! and only flushes the entire table to disk once every 5 seconds or when
//! a high-priority event occurs.
//!
//! ## Logging
//!
//! All loggable events are immediately recorded in the in-memory `LogDb`.

use std::time::Duration;
use tokio::time::{Interval, interval};
use tracing::{debug, error, info, warn};

use lanforge_core::bus::{DnsEvent, LanforgeEvent, StorageEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};

use crate::engine::LeaseDb;
use crate::log_engine::LogDb;

/// Background worker for database operations.
#[lanforge_macros::lanforge_service(
    id = "db",
    name = "Database Worker",
    critical = true,
    retries = 5,
    base_backoff = 1,
    max_backoff = 30,
    describe = format!("Database Worker ({})", self.db_url)
)]
pub struct DbWorker {
    db_url: String,
    log_db_url: String,
    ctx: LanforgeContext,
    dirty: bool,
}

impl DbWorker {
    /// Creates a new `DbWorker` for the specified databases.
    pub fn new(db_url: String, log_db_url: String, ctx: LanforgeContext) -> Self {
        Self {
            db_url,
            log_db_url,
            ctx,
            dirty: false,
        }
    }

    /// Flushes the current device table to the persistent database.
    async fn flush_batch(&mut self, db: &LeaseDb) {
        if !self.dirty {
            return;
        }

        let snapshot = self.ctx.snapshot_for_persistence();
        if let Err(e) = db.save_snapshot(&snapshot).await {
            error!("Failed to save device table to database: {e}");
        } else {
            debug!("Device table persisted to database");
            self.dirty = false;
        }
    }
}

impl AsyncService for DbWorker {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let db = LeaseDb::open(&self.db_url).await.map_err(|e| {
            error!("Failed to open lease database: {e}");
            CoreError::Generic(e.to_string())
        })?;

        let log_db = LogDb::open(&self.log_db_url).await.map_err(|e| {
            error!("Failed to open log database {}: {e}", self.log_db_url);
            CoreError::Generic(e.to_string())
        })?;

        let mut bus_rx = self.ctx.bus().subscribe();
        let mut flush_interval: Interval = interval(Duration::from_secs(5));

        info!("Database worker started");
        self.ctx.set_db_ready(true);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::DbReady));

        // Explicitly signal readiness to the event loop
        ctrl.signal_ready();

        loop {
            tokio::select! {
                // Event handling
                res = bus_rx.recv() => {
                    let Ok(timed_event) = res else {
                        if matches!(res, Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) {
                            warn!("DbWorker: Event bus lagged, continuing");
                            continue;
                        }
                        break;
                    };
                    // 1. Record in log database if loggable
                    if timed_event.is_loggable()
                        && let Err(e) = log_db.record_log(&timed_event).await {
                            error!("Log record error: {e}");
                        }

                    // 2. Process specific events
                    let mut break_loop = false;
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Storage(StorageEvent::TableDirty) => {
                            self.dirty = true;
                        }
                        LanforgeEvent::Storage(StorageEvent::DbVacuum) => {
                            if let Err(e) = db.vacuum().await {
                                error!("Vacuum error: {e}");
                            }
                        }
                        LanforgeEvent::Storage(StorageEvent::DbLogClean) => {
                            if let Err(e) = log_db.clear_logs().await {
                                error!("Log clear error: {e}");
                            }
                        }
                        LanforgeEvent::Storage(StorageEvent::DbPrune) => {
                            if let Err(e) = db.prune_zombies().await {
                                error!("Prune error: {e}");
                            }
                        }
                        LanforgeEvent::Storage(StorageEvent::DbReset) => {
                            info!("Full database reset requested...");
                            self.ctx.set_db_ready(false);
                            if let Err(e) = db.reset().await {
                                error!("LeaseDb reset error: {e}");
                            }
                            if let Err(e) = log_db.clear_logs().await {
                                error!("LogDb reset error: {e}");
                            }
                            self.dirty = false;
                            self.ctx.set_db_ready(true);
                            let _ = self.ctx.bus().publish(LanforgeEvent::Storage(StorageEvent::DbResetCompleted));
                        }
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("Database worker shutting down...");
                            self.flush_batch(&db).await;
                            break_loop = true;
                        }
                        #[cfg(feature = "adblock")]
                        LanforgeEvent::Dns(DnsEvent::QueryBlocked { src_addr, ref domain }) => {
                            let src_mac = self
                                .ctx
                                .read()
                                .get_mac_by_ip(src_addr)
                                .map(|m| m.to_string());
                            if let Err(e) = log_db
                                .record_dns_block(&timed_event, src_addr, domain, src_mac)
                                .await
                            {
                                error!("DNS log record error: {e}");
                            }
                        }
                    });

                    if break_loop {
                        break;
                    }
                }

                // Periodic flush
                _ = flush_interval.tick() => {
                    self.flush_batch(&db).await;
                }
            }
        }

        Ok(())
    }
}
