use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use tokio::sync::{mpsc, oneshot};

/// A decoupled handle for communicating with the DNS service over MPSC channels.
#[derive(Clone)]
pub struct DnsHandle {
    tx: mpsc::Sender<(DnsRequest, oneshot::Sender<DnsResponse>)>,
}

impl DnsHandle {
    #[must_use]
    pub const fn new(tx: mpsc::Sender<(DnsRequest, oneshot::Sender<DnsResponse>)>) -> Self {
        Self { tx }
    }

    /// Sends a DNS request and waits for the response.
    ///
    /// # Errors
    /// Returns an error if the DNS service is unreachable, closed, or fails to respond.
    pub async fn send_request(&self, req: DnsRequest) -> Result<DnsResponse, String> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send((req, resp_tx))
            .await
            .map_err(|_| "DNS service channel closed".to_string())?;
        resp_rx
            .await
            .map_err(|_| "DNS service failed to respond".to_string())
    }
}
