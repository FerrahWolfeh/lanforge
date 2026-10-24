use std::any::Any;
use tokio::sync::{mpsc, oneshot};

/// A boxed closure command executed against the stores facade.
pub type StorageCallFn = Box<dyn FnOnce(&dyn Any) + Send>;

/// Commands sent to the storage worker.
pub enum StorageCommand {
    /// A boxed closure command executed against the stores facade.
    Call(StorageCallFn),
    /// Requests an immediate commit of pending batches and live config to disk.
    FlushNow(oneshot::Sender<Result<(), String>>),
}

/// A decoupled handle for communicating with the database and log worker over MPSC channels.
#[derive(Clone)]
pub struct StorageHandle {
    tx: mpsc::Sender<StorageCommand>,
}

impl StorageHandle {
    #[must_use]
    pub const fn new(tx: mpsc::Sender<StorageCommand>) -> Self {
        Self { tx }
    }

    /// Executes a closure against the storage worker and awaits the result.
    ///
    /// # Errors
    /// Returns an error if the database worker channel is closed, dropped the response,
    /// or if the store type downcast fails.
    pub async fn call<S: 'static, R: Send + 'static, E: From<String> + Send + 'static>(
        &self,
        f: impl FnOnce(&S) -> Result<R, E> + Send + 'static,
    ) -> Result<R, E> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = StorageCommand::Call(Box::new(move |any: &dyn Any| {
            if let Some(stores) = any.downcast_ref::<S>() {
                let res = f(stores);
                let _ = resp_tx.send(res);
            } else {
                let _ = resp_tx.send(Err(E::from(
                    "Storage handle downcast failure: store type mismatch".to_string(),
                )));
            }
        }));

        self.tx
            .send(cmd)
            .await
            .map_err(|_| E::from("Database worker channel closed".to_string()))?;

        resp_rx
            .await
            .map_err(|_| E::from("Database worker failed to respond".to_string()))?
    }

    /// Triggers an immediate commit of all pending batches and writes live config to disk.
    ///
    /// # Errors
    /// Returns an error if the worker channel is closed or if the worker failed to flush.
    pub async fn flush_now(&self) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(StorageCommand::FlushNow(resp_tx))
            .await
            .map_err(|_| "Database worker channel closed".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Database worker failed to respond".to_string())?
    }
}
