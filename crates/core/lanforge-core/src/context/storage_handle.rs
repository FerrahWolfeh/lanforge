use lanforge_types::storage::{StorageQuery, StorageQueryResult};
use tokio::sync::{mpsc, oneshot};

/// A decoupled handle for communicating with the database and log worker over MPSC channels.
#[derive(Clone)]
pub struct StorageHandle {
    tx: mpsc::Sender<(StorageQuery, oneshot::Sender<Result<StorageQueryResult, String>>)>,
}

impl StorageHandle {
    #[must_use]
    pub const fn new(
        tx: mpsc::Sender<(StorageQuery, oneshot::Sender<Result<StorageQueryResult, String>>)>,
    ) -> Self {
        Self { tx }
    }

    /// Sends a storage query/command and waits for the response.
    ///
    /// # Errors
    /// Returns an error if the database worker is unreachable, closed, or fails to respond.
    pub async fn send_query(&self, req: StorageQuery) -> Result<StorageQueryResult, String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send((req, resp_tx))
            .await
            .map_err(|_| "Database worker channel closed".to_string())?;
        resp_rx
            .await
            .map_err(|_| "Database worker failed to respond".to_string())?
    }
}
