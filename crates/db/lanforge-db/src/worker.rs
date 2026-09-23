//! `DbWorker` — Background service for database persistence and logging.
//!
//! Listens for events on the global `EventBus` and performs batch updates
//! to the `LanforgeDb` (persistent) and `LogDb` (transient).
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

use lanforge_core::bus::{
    DeviceEvent, DnsEvent, LanforgeEvent, StorageEvent, SystemEvent, TimedEvent,
};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::QueryLogEntry;
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Interval, interval};
use tracing::{debug, error, info, warn};

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::AsyncService;
use std::collections::HashSet;

use crate::config::DatabaseConfig;
use crate::engine::LanforgeDb;
use crate::log_engine::LogDb;

/// Background worker for database operations.
#[lanforge_macros::lanforge_service(
    id = "db",
    name = "Database Worker",
    critical = true,
    retries = 5,
    base_backoff = 1,
    max_backoff = 30,
    describe = format!("Database Worker ({})", self.cfg.config_path)
)]
pub struct DbWorker {
    cfg: DatabaseConfig,
    ctx: LanforgeContext,
    db: Arc<LanforgeDb>,
    log_db: Arc<LogDb>,
    dirty: bool,
    dirty_macs: HashSet<MacAddr>,
    dirty_lease_macs: HashSet<MacAddr>,
    purged_macs: HashSet<MacAddr>,
    log_buffer: Vec<TimedEvent>,
    dns_log_buffer: Vec<QueryLogEntry>,
    bytes_buf: Vec<u8>,
}

impl DbWorker {
    /// Creates a new `DbWorker` for the specified databases.
    pub fn new(
        cfg: DatabaseConfig,
        ctx: LanforgeContext,
        db: Arc<LanforgeDb>,
        log_db: Arc<LogDb>,
    ) -> Self {
        Self {
            cfg,
            ctx,
            db,
            log_db,
            dirty: false,
            dirty_macs: HashSet::new(),
            dirty_lease_macs: HashSet::new(),
            purged_macs: HashSet::new(),
            log_buffer: Vec::with_capacity(128),
            dns_log_buffer: Vec::with_capacity(128),
            bytes_buf: Vec::with_capacity(4096),
        }
    }

    /// Flushes the current device table to the persistent database.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn flush_batch(&mut self, db: &LanforgeDb, log_db: &LogDb) {
        let metrics = self.ctx.db_metrics();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut had_error = false;
        let mut written_devices_count = 0;

        // 1. Flush Logs
        if !self.log_buffer.is_empty() {
            if let Err(e) = log_db
                .record_logs_batch(&self.log_buffer, &mut self.bytes_buf)
                .await
            {
                error!("Failed to flush log batch: {e}");
                had_error = true;
            } else {
                self.log_buffer.clear();
            }
        }

        let had_dns_queries = !self.dns_log_buffer.is_empty();
        if had_dns_queries {
            if let Err(e) = log_db.record_dns_queries_batch(&self.dns_log_buffer).await {
                error!("Failed to flush DNS log batch: {e}");
                had_error = true;
            } else {
                self.dns_log_buffer.clear();
            }
        }

        // 2. Flush DNS Lifetime Stats (only when new queries were processed)
        if had_dns_queries
            && let Some(handle) = self.ctx.dns_handle()
            && let Ok(DnsResponse::LifetimeStats(stats)) = handle.send_request(DnsRequest::LifetimeStats).await
            && let Err(e) = log_db.save_dns_lifetime_stats(&stats).await
        {
            error!("Failed to flush DNS lifetime stats: {e}");
        }

        // 3. Flush Main DB
        if !self.dirty && self.dirty_macs.is_empty() && self.purged_macs.is_empty() {
            metrics.last_flush_ts.store(now, Ordering::Relaxed);
            metrics.flush_count.fetch_add(1, Ordering::Relaxed);
            metrics.last_error.store(had_error, Ordering::Relaxed);
            return;
        }

        let res = if self.dirty {
            // Full flush requested (rare)
            let snapshot = self.ctx.snapshot_for_persistence();
            let len = snapshot.devices.len();
            db.save_snapshot(&snapshot).await.map(|()| len)
        } else {
            // Incremental flush (common)
            let (lease_devices, base_devices) = {
                let state = self.ctx.read();
                let mut lease = Vec::new();
                let mut base = Vec::new();
                for mac in &self.dirty_macs {
                    if let Some(device) = state.devices.get(mac).cloned() {
                        if self.dirty_lease_macs.contains(mac) {
                            lease.push(device);
                        } else {
                            base.push(device);
                        }
                    }
                }
                (lease, base)
            };

            let purges: Vec<MacAddr> = self.purged_macs.iter().copied().collect();
            let count = lease_devices.len() + base_devices.len() + purges.len();

            let result = db.batch_sync_devices(&lease_devices, &base_devices, &purges).await;
            result.map(|()| count)
        };

        match res {
            Err(e) => {
                error!("Failed to save device table to database: {e}");
                had_error = true;
            }
            Ok(count) => {
                written_devices_count = count;
                let was_full_flush = self.dirty;
                self.dirty = false;
                self.dirty_macs.clear();
                self.dirty_lease_macs.clear();
                self.purged_macs.clear();

                if count > 0 {
                    let _ = self
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::Storage(StorageEvent::DbWrite {
                            devices: count,
                        }));
                    if was_full_flush {
                        debug!("Main DB flushed (all devices)");
                    } else {
                        debug!("Main DB flushed ({count} devices)");
                    }
                }
            }
        }

        metrics.last_flush_ts.store(now, Ordering::Relaxed);
        metrics.flush_count.fetch_add(1, Ordering::Relaxed);
        metrics
            .devices_written
            .fetch_add(written_devices_count as u64, Ordering::Relaxed);
        metrics.last_error.store(had_error, Ordering::Relaxed);
    }
}

impl AsyncService for DbWorker {
    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let metrics = ctx.db_metrics();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_flush_ts = metrics.last_flush_ts.load(Ordering::Relaxed);
        let last_flush_ago = if last_flush_ts > 0 && now >= last_flush_ts {
            format!("{}s ago", now - last_flush_ts)
        } else {
            "—".to_string()
        };
        let error_str = if metrics.last_error.load(Ordering::Relaxed) {
            "error".to_string()
        } else {
            "ok".to_string()
        };

        vec![
            (
                std::borrow::Cow::Borrowed("flush_count"),
                metrics.flush_count.load(Ordering::Relaxed).to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("devices_written"),
                metrics.devices_written.load(Ordering::Relaxed).to_string(),
            ),
            (std::borrow::Cow::Borrowed("last_flush"), last_flush_ago),
            (
                std::borrow::Cow::Borrowed("log_buffer"),
                self.log_buffer.len().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("dns_log_buffer"),
                self.dns_log_buffer.len().to_string(),
            ),
            (std::borrow::Cow::Borrowed("status"), error_str),
        ]
    }

    async fn init(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let mode = if ctx.is_recovery_mode() {
            "RECOVERY MODE (in-memory)"
        } else if self.db.is_in_memory() {
            "in-memory"
        } else {
            "redb (persistent)"
        };
        info!("Database worker initialized (mode: {mode})");
        ctx.set_db_ready(true);
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::DbReady));
        Ok(())
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let db = self.db.clone();
        let log_db = self.log_db.clone();

        let mut bus_rx = ctx.bus().subscribe();
        let mut flush_interval: Interval = interval(Duration::from_secs(self.cfg.flush_interval));
        let mut last_prune = tokio::time::Instant::now();

        loop {
            tokio::select! {
                // Event handling
                res = bus_rx.recv() => {
                    let Ok(timed_event) = res else {
                        if let Err(RecvError::Lagged(n)) = res {
                            warn!(service = "DbWorker", lost = n, "Event bus lagged");
                            continue;
                        }
                        break;
                    };
                    // 1. Record in log database if loggable
                    if timed_event.is_loggable() {
                        self.log_buffer.push(timed_event.clone());
                        if self.log_buffer.len() >= 100 {
                            if let Err(e) = log_db.record_logs_batch(&self.log_buffer, &mut self.bytes_buf).await {
                                error!("Immediate log flush error: {e}");
                            } else {
                                self.log_buffer.clear();
                            }
                        }
                    }

                    // 2. Process specific events
                    let mut break_loop = false;
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Device(DeviceEvent::NetworkUpdate { mac, change, .. }) => {
                            if change.is_persistent() {
                                self.dirty_macs.insert(*mac);
                                if change.is_lease_change() {
                                    self.dirty_lease_macs.insert(*mac);
                                }
                                // If it was previously purged, it's now alive again
                                self.purged_macs.remove(mac);
                            }
                        }
                        LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, .. }) => {
                            self.dirty_macs.insert(*mac);
                            self.purged_macs.remove(mac);
                        }
                        LanforgeEvent::Device(DeviceEvent::Discovered { mac, .. })
                        | LanforgeEvent::Device(DeviceEvent::Expired { mac, .. }) => {
                            self.dirty_macs.insert(*mac);
                            self.dirty_lease_macs.insert(*mac);
                            self.purged_macs.remove(mac);
                        }
                        LanforgeEvent::Device(DeviceEvent::Purged { mac }) => {
                            self.purged_macs.insert(*mac);
                            self.dirty_macs.remove(mac);
                            self.dirty_lease_macs.remove(mac);

                            // Flush immediately for administrative host removal
                            self.flush_batch(&db, &log_db).await;
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
                            warn!("Legacy DbReset event received in worker (ignored as reset is now synchronous)");
                        }
                        LanforgeEvent::Storage(StorageEvent::DbResetCompleted) => {
                            info!("Database reset completed. Clearing internal buffers.");
                            self.dirty = false;
                            self.dirty_macs.clear();
                            self.dirty_lease_macs.clear();
                            self.purged_macs.clear();
                            self.log_buffer.clear();
                            self.dns_log_buffer.clear();
                        }
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("Database worker shutting down...");
                            self.flush_batch(&db, &log_db).await;
                            if let Some(handle) = self.ctx.dns_handle()
                                && let Ok(DnsResponse::LifetimeStats(stats)) = handle.send_request(DnsRequest::LifetimeStats).await
                            {
                                let _ = log_db.save_dns_lifetime_stats(&stats).await;
                            }
                            break_loop = true;
                        }
                        #[cfg(feature = "adblock")]
                        LanforgeEvent::Dns(DnsEvent::QueryBlocked { src_addr, domain }) => {
                            let src_mac = ctx
                                .read()
                                .get_mac_by_ip(*src_addr)
                                .map(|m| m.to_string());
                            if let Err(e) = log_db
                                .record_dns_block(&timed_event, *src_addr, domain, src_mac)
                                .await
                            {
                                error!("DNS log record error: {e}");
                            }
                        }
                        LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) => {
                            self.dns_log_buffer.push((**entry).clone());
                            if self.dns_log_buffer.len() >= 100 {
                                if let Err(e) = log_db.record_dns_queries_batch(&self.dns_log_buffer).await {
                                    error!("Immediate DNS query log flush error: {e}");
                                } else {
                                    self.dns_log_buffer.clear();
                                }
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

                    if last_prune.elapsed() >= Duration::from_secs(600) {
                        if let Err(e) = db.prune_zombies().await {
                            error!("Background db prune failed: {e}");
                        }
                        last_prune = tokio::time::Instant::now();
                    }
                }
            }
        }

        Ok(())
    }

    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        info!("Database worker flushing pending state and logs on cleanup...");
        let db = self.db.clone();
        let log_db = self.log_db.clone();
        self.flush_batch(&db, &log_db).await;
        Ok(())
    }
}
