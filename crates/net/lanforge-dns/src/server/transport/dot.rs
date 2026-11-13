use lanforge_core::error::CoreError;
use lanforge_types::network::dns::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, trace};

use crate::server::DnsContext;
use crate::server::transport::net::bind_tcp;
use crate::server::worker::tcp::{MAX_TCP_CONNECTIONS, TCP_IDLE_TIMEOUT, serve_stream};
use lanforge_crypto::tls::load_tls_config;
use lanforge_transport::DualTcpListener;

/// Opens the `DoT` listener on `addr` with the certificate `cert`/`key` (PEM).
///
/// # Errors
/// The TLS configuration is unusable or the address cannot be bound ([`CoreError::Bind`]).
pub fn bind_dot(
    addr: SocketAddr,
    cert: &str,
    key: &str,
) -> Result<(DualTcpListener, TlsAcceptor), CoreError> {
    let tls_config =
        load_tls_config(cert, key).map_err(|e| CoreError::Generic(format!("TLS config: {e}")))?;
    Ok((bind_tcp(addr)?, TlsAcceptor::from(Arc::new(tls_config))))
}

/// Runs the `DoT` listener (RFC 7858) opened by [`bind_dot`].
///
/// Connections are owned by this future (no detached tasks): aborting it drops every open TLS
/// session with the listener. A silent client is closed after [`TCP_IDLE_TIMEOUT`], both during
/// the handshake and between queries.
pub async fn run_dot_worker(
    listener: DualTcpListener,
    acceptor: TlsAcceptor,
    addr: SocketAddr,
    ctx: Arc<DnsContext>,
) {
    info!("DoT listening on tls://{addr}");

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    if connections.len() >= MAX_TCP_CONNECTIONS {
                        trace!(%peer, "DoT connection limit reached, refusing");
                        continue;
                    }
                    connections.spawn(serve_tls(acceptor.clone(), stream, peer, Arc::clone(&ctx)));
                }
                // EMFILE and the like: pause, or the loop spins at 100 % CPU.
                Err(e) => {
                    error!("DoT accept error on {addr}: {e}");
                    sleep(Duration::from_millis(100)).await;
                }
            },
            // Reap finished connections so the set does not grow without bound.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_tls(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<DnsContext>,
) {
    match timeout(TCP_IDLE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => serve_stream(tls, peer.ip(), &ctx, TransportProtocol::Tls).await,
        Ok(Err(e)) => trace!(%peer, "DoT handshake failed: {e}"),
        Err(_) => trace!(%peer, "DoT handshake timed out"),
    }
}
