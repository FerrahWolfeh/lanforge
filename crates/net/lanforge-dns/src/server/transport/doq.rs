use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_dns_wire::{WireHeader, WireQuestion};
use lanforge_types::network::dns::TransportProtocol;
use quinn::{Connection, Endpoint, ServerConfig, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use crate::server::transport::tls::load_tls_config;

/// Runs the internal DoQ worker endpoint on the given socket address.
pub async fn run_doq_worker(
    addr: SocketAddr,
    cert: &str,
    key: &str,
    ctx: LanforgeContext,
) -> Result<(), CoreError> {
    let mut tls_config = load_tls_config(cert, key)
        .map_err(|e| CoreError::Generic(format!("Failed to load TLS config for DoQ: {e}")))?;

    tls_config.alpn_protocols = vec![b"doq".to_vec()];

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| CoreError::Generic(format!("QUIC config error: {e}")))?,
    ));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::server(server_config, addr)
        .map_err(|e| CoreError::Generic(format!("DoQ bind error on {addr}: {e}")))?;

    info!("DoQ listening on quic://{addr}");

    while ctx.is_running() {
        if let Some(incoming) = endpoint.accept().await {
            let ctx_conn = ctx.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_doq_connection(conn, ctx_conn).await {
                            debug!("DoQ connection closed: {e}");
                        }
                    }
                    Err(e) => {
                        debug!("DoQ handshake failed: {e}");
                    }
                }
            });
        } else {
            break;
        }
    }
    Ok(())
}

async fn handle_doq_connection(
    conn: Connection,
    ctx: LanforgeContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = conn.remote_address();
    let dns_ctx = ctx
        .get_shared::<DnsContext>()
        .ok_or("DNS engine not ready")?;

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let dns_ctx = Arc::clone(&dns_ctx);

                tokio::spawn(async move {
                    let query_buf = match recv.read_to_end(4096).await {
                        Ok(buf) => buf,
                        Err(e) => {
                            debug!("DoQ stream read error: {e}");
                            return;
                        }
                    };
                    if query_buf.is_empty() {
                        return;
                    }

                    let header = match WireHeader::parse(&query_buf) {
                        Some(h) => h,
                        None => return,
                    };
                    let question = match WireQuestion::parse(&query_buf) {
                        Some(q) => q,
                        None => return,
                    };

                    let mut resp_buf = Vec::with_capacity(512);
                    match dns_ctx
                        .pipeline
                        .run(
                            &dns_ctx,
                            DnsPipelineRequest::new(
                                &query_buf,
                                &header,
                                &question,
                                peer.ip(),
                                TransportProtocol::Quic,
                            ),
                            &mut resp_buf,
                        )
                        .await
                    {
                        Ok(()) => {
                            if !resp_buf.is_empty() {
                                if let Err(e) = send.write_all(&resp_buf).await {
                                    debug!("DoQ stream write error: {e}");
                                }
                                let _ = send.finish();
                            }
                        }
                        Err(e) => {
                            debug!("DoQ pipeline error: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
