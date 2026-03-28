//! `db_worker` — Reactive async task with debounce for persistence.
//!
//! Listens for `DeviceTableDirty` on the `EventBus` and persists state to SQLite
//! with debounce, protecting the SD card from excessive writes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::state::DeviceTable;

use crate::engine::LeaseDb;

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/// Debounce duration after a `DeviceTableDirty` event before persisting.
pub(crate) const DEBOUNCE_SILENCE: Duration = Duration::from_secs(5);
/// Maximum time to wait for a quiet window before forcing a save.
const MAX_DEBOUNCE_WAIT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// db_worker — task reativa com debounce
// ---------------------------------------------------------------------------

/// Reactive async task that persists the `ManagedTable` over time.
///
/// Implements a trailing-edge debounce loop to avoid micro-writes to disk.
/// The worker listens for `DeviceTableDirty` events and, after a quiet window,
/// triggers a dedicated blocking thread to save the snapshot to SQLite.
///
/// Also processes `DbVacuum` events for periodic database optimization.
///
/// ```mermaid
/// sequenceDiagram
///     participant Bus as EventBus
///     participant Worker as db_worker (Async)
///     participant SQLite as LeaseDb (Blocking)
///
///     Bus->>Worker: DeviceTableDirty
///     Worker->>Worker: Debounce Silence Starts (5s)
///     Note over Worker: Coalescing multiple dirty signals...
///     Worker->>SQLite: Send Save(Snapshot)
///     SQLite-->>Worker: Commit & Return
/// ```
pub async fn db_worker(db_path: PathBuf, table: Arc<ManagedTable>, bus: Arc<EventBus>) {
    let mut rx = bus.subscribe();

    info!(
        "DB worker iniciado (debounce: {}s, path: {})",
        DEBOUNCE_SILENCE.as_secs(),
        db_path.display()
    );

    // 1. Cria o canal MPSC para enviar comandos para a thread síncrona.
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<DbWorkerCmd>(4);

    // 2. Start a dedicated blocking thread for SQLite (Open once, keep alive)
    let db_path_clone = db_path.clone();
    tokio::task::spawn_blocking(move || {
        let db = match LeaseDb::open(&db_path_clone) {
            Ok(db) => db,
            Err(e) => {
                warn!("DB thread: fatal failure opening SQLite: {e}");
                return;
            }
        };

        while let Some(cmd) = cmd_rx.blocking_recv() {
            match cmd {
                DbWorkerCmd::Save(snapshot) => {
                    if let Err(e) = db.save_table(&snapshot) {
                        warn!("DB thread: falha ao salvar snapshot: {e}");
                    } else {
                        debug!("DB worker: snapshot persistido");
                    }
                }
                DbWorkerCmd::Vacuum => {
                    if let Err(e) = db.vacuum() {
                        warn!("DB thread: falha ao executar VACUUM: {e}");
                    } else {
                        info!("DB worker: VACUUM concluído");
                    }
                }
            }
        }
        info!("DB thread: encerrando graciosamente");
    });

    // 3. Main reactive async loop
    loop {
        let action = wait_for_db_action(&mut rx).await;

        match action {
            DbAction::Save => {
                let shutdown_during_debounce = drain_with_debounce(&mut rx).await;

                let snapshot = {
                    let t = table.read();
                    t.clone()
                };

                if cmd_tx
                    .send(DbWorkerCmd::Save(Box::new(snapshot)))
                    .await
                    .is_err()
                {
                    warn!("DB worker: falha ao enviar snapshot - a thread do DB morreu");
                    break;
                }

                if shutdown_during_debounce {
                    info!("DB worker encerrando após flush de shutdown");
                    return;
                }
            }
            DbAction::Vacuum => {
                if cmd_tx.send(DbWorkerCmd::Vacuum).await.is_err() {
                    warn!("DB worker: falha ao enviar comando de vacuum");
                    break;
                }
            }
            DbAction::Shutdown => {
                info!("DB worker encerrando (shutdown recebido)");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tipos internos
// ---------------------------------------------------------------------------

/// Comandos internos enviados para a thread síncrona do SQLite.
enum DbWorkerCmd {
    Save(Box<DeviceTable>),
    Vacuum,
}

/// Ações que o loop assíncrono do `db_worker` deve tomar.
enum DbAction {
    Save,
    Vacuum,
    Shutdown,
}

// ---------------------------------------------------------------------------
// Helpers assíncronos
// ---------------------------------------------------------------------------

/// Waits for the next database action or a `Shutdown` signal.
async fn wait_for_db_action(rx: &mut broadcast::Receiver<LanforgeEvent>) -> DbAction {
    loop {
        match rx.recv().await {
            Ok(LanforgeEvent::DeviceTableDirty) => return DbAction::Save,
            Ok(LanforgeEvent::DbVacuum) => return DbAction::Vacuum,
            Ok(LanforgeEvent::Shutdown) => return DbAction::Shutdown,
            Ok(_) => {} // outros eventos — ignora
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("DB worker atrasado, pulou {n} eventos — forçando flush");
                return DbAction::Save;
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("DB worker: barramento encerrado");
                return DbAction::Shutdown;
            }
        }
    }
}

/// Drains the event channel using a Trailing Edge Debounce strategy.
/// Returns `true` if a `Shutdown` event was received during the wait.
async fn drain_with_debounce(rx: &mut broadcast::Receiver<LanforgeEvent>) -> bool {
    let start_time = tokio::time::Instant::now();
    let max_deadline = start_time + MAX_DEBOUNCE_WAIT;
    let mut current_deadline = start_time + DEBOUNCE_SILENCE;

    loop {
        match tokio::time::timeout_at(current_deadline, rx.recv()).await {
            Ok(Ok(LanforgeEvent::Shutdown)) => return true,

            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                let new_deadline = tokio::time::Instant::now() + DEBOUNCE_SILENCE;
                current_deadline = std::cmp::min(new_deadline, max_deadline);
            }

            Ok(Err(broadcast::error::RecvError::Closed)) => return false,

            Err(_) => return false,
        }
    }
}
