use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use futures::future::join_all;
use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_transport::DualTcpListener;
use lanforge_types::network::dns::TransportProtocol;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, trace};

/// An open connection with no complete query for this long is closed (RFC 7766 §6.2.3); `DoT`
/// and `DoQ` use the same bound for their handshake and for each query.
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once per listener (TCP, `DoT`, `DoQ`); more are refused so clients
/// cannot exhaust the daemon's tasks and file descriptors.
pub(crate) const MAX_TCP_CONNECTIONS: usize = 128;
/// Largest query accepted on a stream transport; a longer length prefix closes the connection.
pub(crate) const MAX_STREAM_QUERY: usize = 4096;

/// Spawns the plain-TCP DNS listeners.
///
/// Listeners and their connections are owned by the returned task (no detached tasks), so
/// aborting it and awaiting the handle guarantees port 53/tcp is released before a rebind.
pub fn spawn_tcp_worker(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut listeners = Vec::new();
        for addr in ctx.cfg.listen.addrs() {
            match crate::server::transport::net::bind_tcp(addr) {
                Ok(listener) => {
                    tracing::info!(%addr, "TCP listening");
                    listeners.push(serve_listener(listener, addr, Arc::clone(&ctx)));
                }
                Err(e) => error!("Failed to bind TCP listener on {}: {}", addr, e),
            }
        }
        join_all(listeners).await;
    })
}

async fn serve_listener(listener: DualTcpListener, addr: SocketAddr, ctx: Arc<DnsContext>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, src)) => {
                    if connections.len() >= MAX_TCP_CONNECTIONS {
                        trace!(%src, "TCP connection limit reached, refusing");
                        drop(stream);
                        continue;
                    }
                    connections.spawn(handle_connection(stream, src, Arc::clone(&ctx)));
                }
                Err(e) => {
                    error!("TCP worker accept error on {}: {}", addr, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            // Reap finished connections so the set does not grow without bound.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn handle_connection(stream: TcpStream, src: SocketAddr, task_ctx: Arc<DnsContext>) {
    serve_stream(stream, src.ip(), &task_ctx, TransportProtocol::Tcp).await;
}

/// What a stream transport does after one message was handled.
pub(crate) enum Reply {
    /// Send the answer written into the buffer (nothing when it is empty).
    Send,
    /// A response, not a query: nothing is answered, the connection stays.
    Ignore,
    /// Unparsable: close the connection.
    Close,
}

/// Answers one DNS message received on a stream transport (TCP, `DoT`, `DoQ`) into `resp`.
pub(crate) async fn answer_message(
    ctx: &DnsContext,
    data: &[u8],
    src: IpAddr,
    protocol: TransportProtocol,
    resp: &mut Vec<u8>,
) -> Reply {
    let Some(header) = WireHeader::parse(data) else {
        return Reply::Close;
    };
    // A response is never answered; a query without exactly one question is malformed.
    if !header.is_query() {
        return Reply::Ignore;
    }
    if header.qdcount() != 1 {
        WireResponseWriter::write_header_formerr(data, resp);
        return Reply::Send;
    }
    let Some(question) = WireQuestion::parse(data) else {
        return Reply::Close;
    };

    let run_res = ctx
        .pipeline
        .run(
            ctx,
            DnsPipelineRequest::new(data, &header, &question, src, protocol),
            resp,
        )
        .await;

    if let Err(e) = run_res {
        trace!("Pipeline error (sending SERVFAIL): {:?}", e);
        resp.clear();
        WireResponseWriter::write_error_response(
            data,
            &question,
            2, // SERVFAIL
            WireOptScanner::scan(data, &header, &question),
            !ctx.recursive.is_empty(),
            resp,
        );
    }
    Reply::Send
}

/// Serves length-prefixed DNS messages (RFC 7766 / RFC 7858) on one connection until the
/// client closes it, stays idle past [`TCP_IDLE_TIMEOUT`] or sends garbage.
pub(crate) async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    src: IpAddr,
    ctx: &DnsContext,
    protocol: TransportProtocol,
) {
    let mut len_buf = [0u8; 2];
    while matches!(
        tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await,
        Ok(Ok(_))
    ) {
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > MAX_STREAM_QUERY {
            break;
        }

        let mut data = vec![0u8; len];
        if !matches!(
            tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut data)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        ctx.streams.record_rx(len);

        let mut resp_buf = Vec::with_capacity(len + 128);
        match answer_message(ctx, &data, src, protocol, &mut resp_buf).await {
            Reply::Send => {
                if !send_framed(&mut stream, &resp_buf, ctx).await {
                    break;
                }
            }
            Reply::Ignore => {}
            Reply::Close => break,
        }
    }
}

/// Writes one length-prefixed answer and counts it; `false` once the connection is gone. An
/// empty answer sends nothing.
async fn send_framed<S: AsyncWrite + Unpin>(stream: &mut S, resp: &[u8], ctx: &DnsContext) -> bool {
    if resp.is_empty() {
        return true;
    }
    let len = u16::try_from(resp.len()).unwrap_or(u16::MAX).to_be_bytes();
    if stream.write_all(&len).await.is_err() || stream.write_all(resp).await.is_err() {
        return false;
    }
    ctx.streams.record_tx(resp.len());
    true
}
