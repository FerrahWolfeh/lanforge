//! `DbWorker` — Synchronous persistence service.
//!
//! Runs on a dedicated thread, consuming events from the [`EventBus`](lanforge_core::bus::EventBus)
//! via a [`SyncBusReceiver`](lanforge_core::service::SyncBusReceiver) and translating
//! them into SQLite operations.
//!
//! ## Write Strategy
//!
//! The worker implements **trailing edge debounce** to protect SD cards from micro-writes:
//!
//! | Event | Action | Flush? |
//! | :--- | :--- | :---: |
//! | `DeviceUpdated` / `DeviceDiscovered` | Accumulate in `pending_upserts` HashMap | ❌ |
//! | `DeviceExpired` / `DevicePurged` | Immediate `remove_device(mac)` | ✅ |
//! | `DeviceTableDirty` | Full `save_table(snapshot)` | ✅ |
//! | `DbVacuum` / `DbPrune` / `DbLogClean` | Maintenance operation | ✅ |
//! | `Shutdown` | Final batch flush, then exit | ✅ |
//!
//! ## Batch Upsert
//!
//! Instead of writing each device individually, `DeviceUpdated` events are
//! accumulated in a `HashMap<MacAddr, Arc<Device>>` and flushed as a single
//! `upsert_many()` transaction — either when a non-device event arrives, when
//! 2 seconds have elapsed since the last flush, or when the worker goes idle.
//!
//! ## Lifecycle
//!
//! 1. Opens `LeaseDb` and `LogDb`
//! 2. Signals `DbReady` to unblock dependent services
//! 3. Enters event loop with 200ms `recv_timeout`
//! 4. On `Shutdown`: final flush and clean exit

use crate::engine::LeaseDb;
use crate::log_engine::LogDb;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Device;
use lanforge_core::error::CoreError;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::service::{LanforgeService, ServiceMeta, SyncBusReceiver, SyncService};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// A synchronous service that persists Lanforge state to SQLite.
///
/// Listens to the event bus, batches device updates, and flushes them
/// to disk with debounce protection. Also manages transient event logs
/// via `LogDb`.
///
/// # Example
///
/// ```ignore
/// let worker = DbWorker::new(
///     "/var/lib/lanforge/leases.db".into(),
///     "/tmp/lanforge/logs.db".into(),
///     context,
/// );
/// // Run on a dedicated thread:
/// std::thread::spawn(|| worker.run(&bus_rx));
/// ```
pub struct DbWorker {
    db_path: PathBuf,
    log_db_path: PathBuf,
    ctx: LanforgeContext,
}

impl DbWorker {
    /// Creates a new `DbWorker` with the given database paths and context.
    ///
    /// The databases are **not** opened until [`run`](SyncService::run) is called.
    #[must_use]
    pub fn new(db_path: PathBuf, log_db_path: PathBuf, ctx: LanforgeContext) -> Self {
        Self {
            db_path,
            log_db_path,
            ctx,
        }
    }
}

impl LanforgeService for DbWorker {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "db",
            display_name: "DB Worker",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!("DB Worker (leases: {})", self.db_path.display())
    }
}

impl SyncService for DbWorker {
    /// Runs the main event loop on a dedicated thread.
    ///
    /// Opens both databases, signals `DbReady`, then enters a 200ms-polling
    /// loop that dispatches events to SQLite operations. Exits on `Shutdown`
    /// or when `ctx.is_running()` returns false.
    fn run(&mut self, bus_rx: &SyncBusReceiver) -> Result<(), CoreError> {
        let db = LeaseDb::open(&self.db_path).map_err(|e| CoreError::Generic(e.to_string()))?;
        let log_db =
            LogDb::open(&self.log_db_path).map_err(|e| CoreError::Generic(e.to_string()))?;

        let db = Rc::new(db);
        let log_db = Rc::new(log_db);

        self.ctx.set_db_ready(true);
        let _ = self.ctx.bus().publish(LanforgeEvent::DbReady);

        let mut pending_upserts: HashMap<MacAddr, Arc<Device>> = HashMap::new();
        let mut last_flush = Instant::now();

        loop {
            let event = bus_rx.recv_timeout(Duration::from_millis(200));

            if let Some(ref event) = event {
                // First, record as a system log if applicable
                if event.is_loggable()
                    && let Err(err) = log_db.record_log(event)
                {
                    warn!("DB worker: failed to record log: {err}");
                }

                // If we have a non-upsert event, flush pending upserts first to ensure consistency
                if !matches!(
                    event.event,
                    LanforgeEvent::DeviceUpdated { .. } | LanforgeEvent::DeviceDiscovered { .. }
                ) {
                    Self::flush_batch(&db, &self.ctx, &mut pending_upserts, &mut last_flush);
                }

                // Second, dispatch to specialized handlers
                match event.event {
                    LanforgeEvent::DeviceUpdated { mac, .. }
                    | LanforgeEvent::DeviceDiscovered { mac, .. } => {
                        if let Some(device) = self.ctx.get_device(&mac) {
                            pending_upserts.insert(mac, device);
                        }
                    }
                    LanforgeEvent::DeviceExpired { mac } | LanforgeEvent::DevicePurged { mac } => {
                        if let Err(e) = db.remove_device(mac) {
                            warn!("DB worker: failed to remove device {mac}: {e}");
                        } else {
                            debug!("DB worker: device {mac} removed from DB");
                            self.ctx.record_db_flush();
                        }
                    }
                    LanforgeEvent::DeviceTableDirty => {
                        // Periodic full-sync fallback
                        let snapshot = self.ctx.read().clone();
                        if let Err(e) = db.save_table(&snapshot) {
                            warn!("DB worker: failed to save snapshot: {e}");
                        } else {
                            debug!("DB worker: full snapshot persisted");
                            self.ctx.record_db_flush();
                        }
                    }
                    LanforgeEvent::DbLogClean => {
                        if let Err(e) = log_db.clear_logs() {
                            warn!("DB worker: failed to clear logs: {e}");
                        } else {
                            info!("DB worker: system logs cleared manually");
                            self.ctx.record_db_flush();
                        }
                    }
                    LanforgeEvent::DbVacuum => {
                        if let Err(e) = db.vacuum() {
                            warn!("DB worker: failed to execute VACUUM: {e}");
                        } else {
                            info!("DB worker: VACUUM completed");
                            self.ctx.record_db_flush();
                        }
                    }
                    LanforgeEvent::DbPrune => match db.prune_zombies() {
                        Ok(count) => {
                            info!("DB worker: pruned {count} zombie entries");
                            self.ctx.record_db_flush();
                        }
                        Err(e) => warn!("DB worker: failed to prune zombies: {e}"),
                    },
                    LanforgeEvent::Shutdown => {
                        break;
                    }
                    _ => {}
                }
            }

            // Periodic flush or flush when idle
            if !pending_upserts.is_empty()
                && (event.is_none() || last_flush.elapsed() >= Duration::from_secs(2))
            {
                Self::flush_batch(&db, &self.ctx, &mut pending_upserts, &mut last_flush);
            }

            if !self.ctx.is_running() {
                break;
            }
        }

        // Final flush on exit
        Self::flush_batch(&db, &self.ctx, &mut pending_upserts, &mut last_flush);

        Ok(())
    }
}

impl DbWorker {
    /// Flushes all pending device upserts as a single batch transaction.
    ///
    /// Called when:
    /// - A non-device event arrives (forces consistency before handling other events)
    /// - 2 seconds have elapsed since the last flush (debounce timeout)
    /// - The worker is shutting down (final flush)
    fn flush_batch(
        db: &LeaseDb,
        ctx: &LanforgeContext,
        pending: &mut HashMap<MacAddr, Arc<Device>>,
        last_flush: &mut Instant,
    ) {
        if pending.is_empty() {
            return;
        }

        let count = pending.len();
        if let Err(e) = db.upsert_many(pending.values().map(|a| &**a)) {
            warn!("DB worker: failed to execute batch upsert of {count} devices: {e}");
        } else {
            debug!("DB worker: persisted {count} devices (batch)");
            ctx.record_db_flush();
        }

        pending.clear();
        *last_flush = Instant::now();
    }
}
