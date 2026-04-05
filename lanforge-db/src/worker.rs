use crate::engine::LeaseDb;
use crate::log_engine::LogDb;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::{CoreError, Result};
use lanforge_core::service::{LanforgeService, SyncService};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct DbWorker {
    db_path: PathBuf,
    log_db_path: PathBuf,
}

impl DbWorker {
    #[must_use]
    pub fn new(db_path: PathBuf, log_db_path: PathBuf) -> Self {
        Self {
            db_path,
            log_db_path,
        }
    }
}

impl LanforgeService for DbWorker {
    fn meta(&self) -> lanforge_core::service::ServiceMeta {
        lanforge_core::service::ServiceMeta {
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
    fn run(&mut self, bus_rx: &lanforge_core::service::SyncBusReceiver) -> Result<()> {
        let db = LeaseDb::open(&self.db_path).map_err(|e| CoreError::Generic(e.to_string()))?;
        let log_db =
            LogDb::open(&self.log_db_path).map_err(|e| CoreError::Generic(e.to_string()))?;

        let db = Rc::new(db);
        let log_db = Rc::new(log_db);

        lanforge_core::context::LanforgeContext::set_db_ready(true);
        let _ = LanforgeContext::bus().publish(LanforgeEvent::DbReady);

        loop {
            let event = bus_rx.recv_timeout(Duration::from_millis(500));

            if let Some(event) = event {
                match event {
                    LanforgeEvent::DeviceTableDirty => {
                        let snapshot = Box::new((*LanforgeContext::table().read()).clone());
                        if let Err(e) = db.save_table(&snapshot) {
                            warn!("DB worker: failed to save snapshot: {e}");
                        } else {
                            debug!("DB worker: snapshot persisted");
                        }
                    }
                    LanforgeEvent::DbVacuum => {
                        if let Err(e) = db.vacuum() {
                            warn!("DB worker: failed to execute VACUUM: {e}");
                        } else {
                            info!("DB worker: VACUUM completed");
                        }
                    }
                    LanforgeEvent::Shutdown => {
                        break;
                    }
                    e if e.is_loggable() => {
                        if let Err(err) = log_db.record_log(&e) {
                            warn!("DB worker: failed to record log: {err}");
                        }
                    }
                    _ => {}
                }
            }

            if !LanforgeContext::is_running() {
                break;
            }
        }

        Ok(())
    }
}
