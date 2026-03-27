use std::path::PathBuf;
use thiserror::Error;

/// Erros específicos do motor de banco de dados do Lanforge.
#[derive(Debug, Error)]
pub enum LeaseDbError {
    #[error("falha de I/O em {0}: {1}")]
    PathAccess(PathBuf, #[source] std::io::Error),

    #[error("falha de I/O genérica: {0}")]
    Io(#[from] std::io::Error),

    #[error("falha ao abrir SQLite em {0}: {1}")]
    ConnectionOpen(PathBuf, #[source] rusqlite::Error),

    #[error("falha no banco de dados SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("falha ao executar migration/estatuto: {0}: {1}")]
    Migration(String, #[source] rusqlite::Error),

    #[error("falha ao confirmar transação: {0}")]
    TransactionFailed(#[source] rusqlite::Error),

    #[error("falha ao executar VACUUM: {0}")]
    VacuumFailed(#[source] rusqlite::Error),

    #[error("entidade não encontrada: {0}")]
    NotFound(String),
}
