use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_dns_wire::{WireHeader, WireQuestion};
use lanforge_types::network::dns::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use crate::server::transport::tls::load_tls_config;

/// Runs the internal DoT worker listener on the given socket address.
pub async fn run_dot_worker(
    addr: SocketAddr,
    cert: &str,
    key: &str,
    ctx: LanforgeContext,
) -> Result<(), CoreError> {
    let tls_config = load_tls_config(cert, key)
        .map_err(|e| CoreError::Generic(format!("Failed to load TLS config for DoT: {e}")))?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| CoreError::Generic(format!("DoT bind error on {addr}: {e}")))?;

    info!("DNS: DoT listening on tls://{addr}");

    while ctx.is_running() {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let acceptor = acceptor.clone();
                let ctx_conn = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_dot_connection(stream, acceptor, ctx_conn, peer).await {
                        debug!("DoT connection from {peer} closed with error: {e}");
                    }
                });
            }
            Err(e) => {
                if !ctx.is_running() {
                    break;
                }
                error!("DoT accept error: {e}");
            }
        }
    }
    Ok(())
}

async fn handle_dot_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    ctx: LanforgeContext,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tls_stream = acceptor.accept(stream).await?;
    let dns_ctx = ctx
        .get_shared::<DnsContext>()
        .ok_or("DNS engine not ready")?;

    loop {
        let mut len_buf = [0u8; 2];
        if tokio::time::timeout(Duration::from_secs(10), tls_stream.read_exact(&mut len_buf))
            .await
            .is_err()
        {
            break;
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len > 4096 || len == 0 {
            break;
        }

        let mut query_buf = vec![0u8; len];
        tls_stream.read_exact(&mut query_buf).await?;

        let header = match WireHeader::parse(&query_buf) {
            Some(h) => h,
            None => break,
        };
        let question = match WireQuestion::parse(&query_buf) {
            Some(q) => q,
            None => break,
        };

        let mut resp_buf = Vec::with_capacity(512);
        dns_ctx
            .pipeline
            .run(
                &dns_ctx,
                DnsPipelineRequest::new(
                    &query_buf,
                    &header,
                    &question,
                    peer.ip(),
                    TransportProtocol::Tls,
                ),
                &mut resp_buf,
            )
            .await?;

        if !resp_buf.is_empty() {
            let resp_len = u16::try_from(resp_buf.len())?.to_be_bytes();
            tls_stream.write_all(&resp_len).await?;
            tls_stream.write_all(&resp_buf).await?;
        }
    }

    Ok(())
}
