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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_inject_and_receive_via_internal_port() {
        let (handle, port) = InertPort::pair(10);
        handle.inject(b"hello".to_vec(), "192.168.1.1").await;

        let mut rx = port.in_rx.lock().await;
        let (data, addr) = rx.recv().await.expect("Expected packet on port");
        assert_eq!(data, b"hello");
        assert_eq!(addr, "192.168.1.1");
    }

    #[tokio::test]
    async fn should_send_reply_via_port_and_receive_via_handle() {
        let (handle, port) = InertPort::pair(10);
        port.out_tx
            .send((b"pong".to_vec(), "10.0.0.1"))
            .await
            .expect("Send failed");

        let (data, addr) = handle.recv_reply().await.expect("Expected reply on handle");
        assert_eq!(data, b"pong");
        assert_eq!(addr, "10.0.0.1");
    }

    #[tokio::test]
    async fn should_receive_payload_only_ignoring_address() {
        let (handle, port) = InertPort::pair(10);
        port.out_tx
            .send((b"only payload".to_vec(), 42))
            .await
            .expect("Send failed");

        let data = handle.recv_payload().await.expect("Expected payload");
        assert_eq!(data, b"only payload");
    }

    #[tokio::test]
    async fn should_try_receive_reply_without_blocking() {
        let (handle, port) = InertPort::pair(10);
        assert_eq!(handle.try_recv_reply(), None);

        port.out_tx
            .send((b"quick".to_vec(), 1))
            .await
            .expect("Send failed");

        assert_eq!(handle.try_recv_reply(), Some((b"quick".to_vec(), 1)));
        assert_eq!(handle.try_recv_reply(), None);
    }

    #[tokio::test]
    async fn should_return_none_when_port_is_dropped() {
        let (handle, port) = InertPort::<String>::pair(10);
        drop(port);

        assert_eq!(handle.recv_reply().await, None);
        assert_eq!(handle.recv_payload().await, None);
        assert_eq!(handle.try_recv_reply(), None);
    }

    #[tokio::test]
    async fn should_preserve_fifo_ordering() {
        let (handle, port) = InertPort::pair(10);
        handle.inject(b"1".to_vec(), ()).await;
        handle.inject(b"2".to_vec(), ()).await;
        handle.inject(b"3".to_vec(), ()).await;

        let mut rx = port.in_rx.lock().await;
        assert_eq!(rx.recv().await.unwrap().0, b"1");
        assert_eq!(rx.recv().await.unwrap().0, b"2");
        assert_eq!(rx.recv().await.unwrap().0, b"3");
    }
}
