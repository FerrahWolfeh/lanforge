use lanforge_core::error::CoreError;
use lanforge_types::network::dns::TransportProtocol;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, Incoming, RecvStream, SendStream, ServerConfig, TransportConfig};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, trace};

use crate::server::DnsContext;
use crate::server::worker::tcp::{
    MAX_STREAM_QUERY, MAX_TCP_CONNECTIONS, Reply, TCP_IDLE_TIMEOUT, answer_message,
};
use lanforge_crypto::tls::load_tls_config;

/// Runs the `DoQ` endpoint (RFC 9250) on `addr`.
///
/// Connections and their streams are owned by this future (no detached tasks). It returns when
/// `stop` fires (or its sender is dropped) after closing every connection and waiting, up to
/// [`DRAIN_TIMEOUT`], for the endpoint to go idle: quinn's driver holds the UDP socket until
/// then, so aborting this future instead would leave the port bound past a restart.
pub async fn run_doq_worker(
    addr: SocketAddr,
    cert: &str,
    key: &str,
    ctx: Arc<DnsContext>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), CoreError> {
    let mut tls_config = load_tls_config(cert, key)
        .map_err(|e| CoreError::Generic(format!("Failed to load TLS config for DoQ: {e}")))?;

    tls_config.alpn_protocols = vec![b"doq".to_vec()];

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|e| CoreError::Generic(format!("QUIC idle timeout: {e}")))?,
    ));
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config)
            .map_err(|e| CoreError::Generic(format!("QUIC config error: {e}")))?,
    ));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::server(server_config, addr)
        .map_err(|e| CoreError::Generic(format!("DoQ bind error on {addr}: {e}")))?;

    info!("DoQ listening on quic://{addr}");

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if connections.len() >= MAX_TCP_CONNECTIONS {
                    trace!(peer = %incoming.remote_address(), "DoQ connection limit reached, refusing");
                    incoming.refuse();
                    continue;
                }
                connections.spawn(serve_connection(incoming, Arc::clone(&ctx)));
            }
            // Reap finished connections so the set does not grow without bound.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    endpoint.close(DOQ_NO_ERROR, b"shutdown");
    connections.shutdown().await;
    if timeout(DRAIN_TIMEOUT, endpoint.wait_idle()).await.is_err() {
        debug!("DoQ endpoint still draining after {DRAIN_TIMEOUT:?}; port may stay bound briefly");
    }
    Ok(())
}

/// How long a stop waits for closed connections to drain before giving up the endpoint.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Serves one QUIC connection: each bidirectional stream carries one query (RFC 9250 §4.2).
/// Concurrent streams are bounded by quinn's `max_concurrent_bidi_streams`.
async fn serve_connection(incoming: Incoming, ctx: Arc<DnsContext>) {
    let peer = incoming.remote_address();
    let conn = match timeout(TCP_IDLE_TIMEOUT, incoming).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return trace!(%peer, "DoQ handshake failed: {e}"),
        Err(_) => return trace!(%peer, "DoQ handshake timed out"),
    };

    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => match accepted {
                Ok((send, recv)) => {
                    streams.spawn(serve_query(send, recv, peer.ip(), Arc::clone(&ctx)));
                }
                Err(e) => return trace!(%peer, "DoQ connection closed: {e}"),
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
}

/// Answers the single query of one stream: a 2-byte length prefix and the message, then FIN;
/// the answer goes back the same way.
async fn serve_query(
    mut send: SendStream,
    mut recv: RecvStream,
    peer: IpAddr,
    ctx: Arc<DnsContext>,
) {
    let framed = match timeout(TCP_IDLE_TIMEOUT, recv.read_to_end(2 + MAX_STREAM_QUERY)).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => return trace!(%peer, "DoQ stream read error: {e}"),
        Err(_) => return trace!(%peer, "DoQ stream read timed out"),
    };
    let Some(query) = unframe(&framed) else {
        trace!(%peer, len = framed.len(), "DoQ stream without a valid length prefix");
        let _ = send.reset(DOQ_PROTOCOL_ERROR);
        return;
    };
    ctx.streams.record_rx(query.len());

    let mut resp = Vec::with_capacity(query.len() + 128);
    let reply = answer_message(&ctx, query, peer, TransportProtocol::Quic, &mut resp).await;
    if !matches!(reply, Reply::Send) || resp.is_empty() {
        // Nothing to answer: end the stream so the client does not wait for the idle timeout.
        let _ = send.reset(DOQ_NO_ERROR);
        return;
    }
    let Ok(prefix) = u16::try_from(resp.len()) else {
        let _ = send.reset(DOQ_INTERNAL_ERROR);
        return;
    };
    let written = async {
        send.write_all(&prefix.to_be_bytes()).await?;
        send.write_all(&resp).await
    };
    match written.await {
        Ok(()) => ctx.streams.record_tx(resp.len()),
        Err(e) => trace!(%peer, "DoQ stream write error: {e}"),
    }
    let _ = send.finish();
}

/// RFC 9250 §4.3 error codes used to reset a stream.
const DOQ_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0);
const DOQ_INTERNAL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x1);
const DOQ_PROTOCOL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x2);

/// The DNS message of a `DoQ` stream: its 2-byte length prefix must match the bytes that follow.
pub(crate) fn unframe(framed: &[u8]) -> Option<&[u8]> {
    let (prefix, message) = framed.split_first_chunk::<2>()?;
    (usize::from(u16::from_be_bytes(*prefix)) == message.len() && !message.is_empty())
        .then_some(message)
}
