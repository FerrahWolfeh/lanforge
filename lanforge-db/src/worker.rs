//! `db_worker` — task async reativa com debounce para persistência.
//!
//! Escuta `DeviceTableDirty` no `EventBus` e persiste o estado no SQLite
//! com debounce, protegendo o SD card de escritas excessivas.

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

/// Duração do debounce antes de persistir após um `DeviceTableDirty`.
pub(crate) const DEBOUNCE_SILENCE: Duration = Duration::from_secs(5);
const MAX_DEBOUNCE_WAIT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// db_worker — task reativa com debounce
// ---------------------------------------------------------------------------

/// Task async que persiste o `ManagedTable` reativamente.
///
/// Implementa um loop de debounce para evitar micro-escritas no disco.
/// Escuta eventos `DeviceTableDirty` e, após uma janela de calma,
/// dispara uma thread separada para salvar o estado atual no `SQLite`.
///
/// Também processa `DbVacuum` para otimização do banco.
pub async fn db_worker(db_path: PathBuf, table: Arc<ManagedTable>, bus: Arc<EventBus>) {
    let mut rx = bus.subscribe();

    info!(
        "DB worker iniciado (debounce: {}s, path: {})",
        DEBOUNCE_SILENCE.as_secs(),
        db_path.display()
    );

    // 1. Cria o canal MPSC para enviar comandos para a thread síncrona.
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<DbWorkerCmd>(4);

    // 2. Inicia a thread síncrona dedicada ao SQLite (Abre o banco APENAS UMA VEZ)
    let db_path_clone = db_path.clone();
    tokio::task::spawn_blocking(move || {
        let db = match LeaseDb::open(&db_path_clone) {
            Ok(db) => db,
            Err(e) => {
                warn!("DB thread: falha fatal ao abrir SQLite: {e}");
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

    // 3. Loop principal assíncrono reativo
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

/// Aguarda o próximo evento de DB ou `Shutdown`.
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

/// Drena o canal aplicando um "Trailing Edge Debounce".
/// Retorna `true` se um `Shutdown` chegou durante a espera.
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
