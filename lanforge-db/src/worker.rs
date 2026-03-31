//! `db_worker` — Reactive async task with debounce for persistence.
//!
//! Listens for `DeviceTableDirty` on the `EventBus` and persists state to SQLite
//! with debounce, protecting the SD card from excessive writes.

use std::path::PathBuf;

use tracing::{debug, info, warn};

use lanforge_core::bus::LanforgeEvent;
use lanforge_core::state::DeviceTable;

use crate::engine::LeaseDb;
use crate::log_engine::LogDb;

// ---------------------------------------------------------------------------
// db_worker — task reativa
// ---------------------------------------------------------------------------

/// Synchronous worker that persists the `ManagedTable` to SQLite.
///
/// This worker runs in its own OS thread without a Tokio runtime. It waits
/// for commands on a standard `mpsc` channel and executes them sequentially.
pub fn db_worker(
    db_path: PathBuf,
    log_db_path: PathBuf,
    cmd_rx: std::sync::mpsc::Receiver<DbWorkerCmd>,
) {
    info!("DB worker síncrono iniciado (path: {})", db_path.display());

    let db = match LeaseDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("DB worker: falha fatal ao abrir leases SQLite: {e}");
            return;
        }
    };

    let log_db = match LogDb::open(&log_db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("DB worker: falha fatal ao abrir logs SQLite: {e}");
            return;
        }
    };

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            DbWorkerCmd::Save(snapshot) => {
                if let Err(e) = db.save_table(&snapshot) {
                    warn!("DB worker: falha ao salvar snapshot: {e}");
                } else {
                    debug!("DB worker: snapshot persistido");
                }
            }
            DbWorkerCmd::Vacuum => {
                if let Err(e) = db.vacuum() {
                    warn!("DB worker: falha ao executar VACUUM: {e}");
                } else {
                    info!("DB worker: VACUUM concluído");
                }
            }
            DbWorkerCmd::RecordLog(event) => {
                if let Err(e) = log_db.record_log(&event) {
                    warn!("DB worker: falha ao gravar log: {e}");
                }
            }
            DbWorkerCmd::Shutdown => {
                break;
            }
        }
    }

    info!("DB worker: encerrando graciosamente");
}

// ---------------------------------------------------------------------------
// Tipos internos
// ---------------------------------------------------------------------------

/// Comandos enviados para o worker síncrono do SQLite.
pub enum DbWorkerCmd {
    Save(Box<DeviceTable>),
    RecordLog(LanforgeEvent),
    Vacuum,
    Shutdown,
}
