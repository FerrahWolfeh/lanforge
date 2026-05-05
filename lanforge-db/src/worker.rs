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

use lanforge_core::device::Device;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Interval, interval};
use tracing::{debug, error, info, warn};

use lanforge_core::bus::{
    DeviceEvent, DnsEvent, LanforgeEvent, StorageEvent, SystemEvent, TimedEvent,
};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::service::{AsyncService, ServiceControl};
use std::collections::HashSet;

use crate::config::DatabaseConfig;
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
    describe = format!("Database Worker ({})", self.cfg.url)
)]
pub struct DbWorker {
    cfg: DatabaseConfig,
    ctx: LanforgeContext,
    dirty: bool,
    dirty_macs: HashSet<MacAddr>,
    log_buffer: Vec<TimedEvent>,
}

impl DbWorker {
    /// Creates a new `DbWorker` for the specified databases.
    pub fn new(cfg: DatabaseConfig, ctx: LanforgeContext) -> Self {
        Self {
            cfg,
            ctx,
            dirty: false,
            dirty_macs: HashSet::new(),
            log_buffer: Vec::with_capacity(128),
        }
    }

    /// Flushes the current device table to the persistent database.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn flush_batch(&mut self, db: &LeaseDb, log_db: &LogDb) {
        // 1. Flush Logs
        if !self.log_buffer.is_empty() {
            if let Err(e) = log_db.record_logs_batch(&self.log_buffer).await {
                error!("Failed to flush log batch: {e}");
            } else {
                self.log_buffer.clear();
            }
        }

        // 2. Flush Main DB
        if !self.dirty && self.dirty_macs.is_empty() {
            return;
        }

        let res = if self.dirty {
            // Full flush requested
            let snapshot = self.ctx.snapshot_for_persistence();
            let len = snapshot.devices.len();
            db.save_snapshot(&snapshot).await.map(|()| len)
        } else {
            // Incremental flush
            let dirty_devices: Vec<Arc<Device>> = {
                let state = self.ctx.read();
                self.dirty_macs
                    .iter()
                    .filter_map(|mac| state.devices.get(mac).cloned())
                    .collect()
            };

            let count = dirty_devices.len();
            let mut result = Ok(());
            for device in dirty_devices {
                if let Err(e) = db.upsert_device(&device).await {
                    result = Err(e);
                    break;
                }
            }
            result.map(|()| count)
        };

        match res {
            Err(e) => {
                error!("Failed to save device table to database: {e}");
            }
            Ok(count) => {
                if count > 0 {
                    let _ = self
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::Storage(StorageEvent::DbWrite {
                            devices: count,
                        }));
                    debug!(
                        "Main DB flushed ({} devices)",
                        if self.dirty {
                            "all".to_string()
                        } else {
                            count.to_string()
                        }
                    );
                }
                self.dirty = false;
                self.dirty_macs.clear();
            }
        }
    }
}

impl AsyncService for DbWorker {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let db = LeaseDb::open(&self.cfg).await.map_err(|e| {
            error!("Failed to open lease database: {e}");
            CoreError::Generic(e.to_string())
        })?;

        let log_db = LogDb::open(&self.cfg.log_url).await.map_err(|e| {
            error!("Failed to open log database {}: {e}", self.cfg.log_url);
            CoreError::Generic(e.to_string())
        })?;

        let mut bus_rx = self.ctx.bus().subscribe();
        let mut flush_interval: Interval = interval(Duration::from_secs(self.cfg.flush_interval));

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
                        if let Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) = res {
                            warn!(service = "DbWorker", lost = n, "Event bus lagged");
                            continue;
                        }
                        break;
                    };
                    // 1. Record in log database if loggable
                    if timed_event.is_loggable() {
                        self.log_buffer.push(timed_event.clone());
                        if self.log_buffer.len() >= 100 {
                            if let Err(e) = log_db.record_logs_batch(&self.log_buffer).await {
                                error!("Immediate log flush error: {e}");
                            } else {
                                self.log_buffer.clear();
                            }
                        }
                    }

                    // 2. Process specific events
                    let mut break_loop = false;
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Device(DeviceEvent::Updated { mac, ref change, .. }) => {
                            if change.is_persistent() {
                                self.dirty_macs.insert(mac);
                            }
                        }
                        LanforgeEvent::Device(DeviceEvent::Discovered { mac, .. })
                        | LanforgeEvent::Device(DeviceEvent::Expired { mac, .. }) => {
                            self.dirty_macs.insert(mac);
                        }
                        LanforgeEvent::Device(DeviceEvent::Purged { mac }) => {
                            // Removing a device requires a full sync or special handling in the DB
                            // For now, let's just trigger a full sync if a device is purged
                            self.dirty = true;
                            self.dirty_macs.remove(&mac);
                        }
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
                            self.flush_batch(&db, &log_db).await;
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
                    self.flush_batch(&db, &log_db).await;
                }
            }
        }

        Ok(())
    }
}
