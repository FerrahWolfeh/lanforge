use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

type InertReceiver<A> = Arc<Mutex<mpsc::Receiver<(Vec<u8>, A)>>>;

/// Test handle for injecting synthetic network packets and receiving outgoing replies without raw sockets or root.
#[derive(Clone)]
pub struct InertHandle<A> {
    in_tx: mpsc::Sender<(Vec<u8>, A)>,
    out_rx: InertReceiver<A>,
}

impl<A: Clone + Send + 'static> InertHandle<A> {
    #[must_use]
    pub fn new(
        in_tx: mpsc::Sender<(Vec<u8>, A)>,
        out_rx: mpsc::Receiver<(Vec<u8>, A)>,
    ) -> Self {
        Self {
            in_tx,
            out_rx: Arc::new(Mutex::new(out_rx)),
        }
    }

    /// Injects a synthetic incoming packet into the transport as if received from the wire.
    pub async fn inject(&self, packet: Vec<u8>, src: A) {
        let _ = self.in_tx.send((packet, src)).await;
    }

    /// Awaits and receives the next outgoing reply sent through the transport.
    pub async fn recv_reply(&self) -> Option<(Vec<u8>, A)> {
        self.out_rx.lock().await.recv().await
    }

    /// Awaits and receives just the outgoing packet payload, ignoring the destination.
    pub async fn recv_payload(&self) -> Option<Vec<u8>> {
        self.recv_reply().await.map(|(p, _)| p)
    }

    /// Attempts to receive a reply immediately without waiting.
    pub fn try_recv_reply(&self) -> Option<(Vec<u8>, A)> {
        self.out_rx.try_lock().ok()?.try_recv().ok()
    }
}

/// Internal endpoints for the inert transport mode.
#[derive(Clone)]
pub struct InertPort<A> {
    pub(crate) in_rx: InertReceiver<A>,
    pub(crate) out_tx: mpsc::Sender<(Vec<u8>, A)>,
}

impl<A: Clone + Send + 'static> InertPort<A> {
    #[must_use]
    pub fn pair(capacity: usize) -> (InertHandle<A>, Self) {
        let (in_tx, in_rx) = mpsc::channel(capacity);
        let (out_tx, out_rx) = mpsc::channel(capacity);

        let handle = InertHandle::new(in_tx, out_rx);
        let port = Self {
            in_rx: Arc::new(Mutex::new(in_rx)),
            out_tx,
        };

        (handle, port)
    }
}
