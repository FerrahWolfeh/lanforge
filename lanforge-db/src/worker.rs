use crate::engine::LeaseDb;
use crate::log_engine::LogDb;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::{CoreError, Result};
use lanforge_core::service::{LanforgeService, SyncService};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

pub struct DbWorker {
    db_path: PathBuf,
    log_db_path: PathBuf,
    cmd_rx: Arc<Mutex<Receiver<LanforgeEvent>>>,
}

impl DbWorker {
    pub fn new(
        db_path: PathBuf,
        log_db_path: PathBuf,
        cmd_rx: Arc<Mutex<Receiver<LanforgeEvent>>>,
    ) -> Self {
        Self {
            db_path,
            log_db_path,
            cmd_rx,
        }
    }
}

impl LanforgeService for DbWorker {
    fn name(&self) -> &str {
        "DbWorker"
    }
}

impl SyncService for DbWorker {
    fn run(&mut self) -> Result<()> {
        info!("DB worker started (sync, path: {})", self.db_path.display());

        let db = LeaseDb::open(&self.db_path).map_err(|e| CoreError::Generic(e.to_string()))?;
        let log_db =
            LogDb::open(&self.log_db_path).map_err(|e| CoreError::Generic(e.to_string()))?;

        let db = Rc::new(db);
        let log_db = Rc::new(log_db);

        let rx = self
            .cmd_rx
            .lock()
            .map_err(|e| CoreError::Generic(format!("Mutex poison: {e}")))?;

        while let Ok(event) = rx.recv() {
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
                    info!("DB worker: shutting down gracefully");
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

        info!("DB worker: stopped");
        Ok(())
    }
}
