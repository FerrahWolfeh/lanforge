use std::time::Duration;

use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Requests queued for the DNS service, with the channel each answer goes back on.
pub type DnsRequestRx = mpsc::Receiver<(DnsRequest, oneshot::Sender<DnsResponse>)>;

/// How long a request waits for the DNS service. The queue outlives a DNS restart, so a request
/// sent mid-restart is answered by the next instance; this only bounds a DNS that stays down.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
        let exchange = async {
            self.tx
                .send((req, resp_tx))
                .await
                .map_err(|_| "DNS service channel closed".to_string())?;
            resp_rx
                .await
                .map_err(|_| "DNS service failed to respond".to_string())
        };
        timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| "DNS service unavailable".to_string())?
    }
}
