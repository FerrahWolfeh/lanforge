use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use futures::future::join_all;
use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_transport::DualTcpListener;
use lanforge_types::network::dns::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, trace};

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

async fn handle_connection(mut stream: TcpStream, src: SocketAddr, task_ctx: Arc<DnsContext>) {
    let mut len_buf = [0u8; 2];
    while stream.read_exact(&mut len_buf).await.is_ok() {
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > 4096 {
            break;
        }

        let mut data = vec![0u8; len];
        if stream.read_exact(&mut data).await.is_err() {
            break;
        }

        let header = match WireHeader::parse(&data) {
            Some(h) => h,
            None => break,
        };
        let question = match WireQuestion::parse(&data) {
            Some(q) => q,
            None => break,
        };

        // Noise filtering (e.g. malformed IoT queries like empty qname or ":0")
        let mut labels = question.labels();
        let is_noise = match labels.next() {
            None => true,                                             // Empty qname (.)
            Some(l) if l == b":0" && labels.next().is_none() => true, // Literally ":0"
            _ => false,
        };

        let edns = WireOptScanner::scan(&data, &header, &question);

        if is_noise {
            let mut resp_buf = Vec::with_capacity(64);
            WireResponseWriter::write_error_response(
                &data,
                &question,
                1, // FORMERR
                edns,
                false,
                &mut resp_buf,
            );

            if !resp_buf.is_empty() {
                let resp_len = u16::try_from(resp_buf.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes();
                if stream.write_all(&resp_len).await.is_err() {
                    break;
                }
                if stream.write_all(&resp_buf).await.is_err() {
                    break;
                }
            }
            continue;
        }

        let mut resp_buf = Vec::with_capacity(len + 128);
        let run_res = task_ctx
            .pipeline
            .run(
                &task_ctx,
                DnsPipelineRequest::new(
                    &data,
                    &header,
                    &question,
                    src.ip(),
                    TransportProtocol::Tcp,
                ),
                &mut resp_buf,
            )
            .await;

        if let Err(e) = run_res {
            trace!("Pipeline error (sending SERVFAIL): {:?}", e);
            resp_buf.clear();
            WireResponseWriter::write_error_response(
                &data,
                &question,
                2, // SERVFAIL
                edns,
                !task_ctx.recursive.is_empty(),
                &mut resp_buf,
            );
        }

        if !resp_buf.is_empty() {
            let resp_len = u16::try_from(resp_buf.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes();
            if stream.write_all(&resp_len).await.is_err() {
                break;
            }
            if stream.write_all(&resp_buf).await.is_err() {
                break;
            }
        }
    }
}
