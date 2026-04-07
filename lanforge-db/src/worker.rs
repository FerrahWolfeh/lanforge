use crate::engine::LeaseDb;
use crate::log_engine::LogDb;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{LanforgeService, ServiceMeta, SyncBusReceiver, SyncService};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct DbWorker {
    db_path: PathBuf,
    log_db_path: PathBuf,
    ctx: LanforgeContext,
}

impl DbWorker {
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
    fn run(&mut self, bus_rx: &SyncBusReceiver) -> Result<(), CoreError> {
        let db = LeaseDb::open(&self.db_path).map_err(|e| CoreError::Generic(e.to_string()))?;
        let log_db =
            LogDb::open(&self.log_db_path).map_err(|e| CoreError::Generic(e.to_string()))?;

        let db = Rc::new(db);
        let log_db = Rc::new(log_db);

        self.ctx.set_db_ready(true);
        let _ = self.ctx.bus().publish(LanforgeEvent::DbReady);

        loop {
            let event = bus_rx.recv_timeout(Duration::from_millis(500));

            if let Some(event) = event {
                // First, record as a system log if applicable
                if event.is_loggable()
                    && let Err(err) = log_db.record_log(&event)
                {
                    warn!("DB worker: failed to record log: {err}");
                }

                // Second, dispatch to specialized handlers
                match event.event {
                    LanforgeEvent::DeviceUpdated { mac, .. }
                    | LanforgeEvent::DeviceDiscovered { mac, .. } => {
                        if let Some(device) = self.ctx.get_device(&mac) {
                            if let Err(e) = db.upsert_device(&device) {
                                warn!("DB worker: failed to upsert device {mac}: {e}");
                            } else {
                                debug!("DB worker: device {mac} persisted (granular)");
                                self.ctx.record_db_flush();
                            }
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
                    LanforgeEvent::Shutdown => {
                        break;
                    }
                    _ => {}
                }
            }

            if !self.ctx.is_running() {
                break;
            }
        }

        Ok(())
    }
}
