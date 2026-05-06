use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};

use crate::config::DnsConfig;
use crate::server::{DnsContext, handle_query};
use crate::tls_utils::load_tls_config;

#[lanforge_macros::lanforge_service(
    id = "dot",
    name = "DNS over TLS",
    critical = false,
    describe = format!("DoT on {}", self.cfg.dot_listen.map_or_else(|| "853".to_string(), |a| a.to_string()))
)]
pub struct DotService {
    cfg: Arc<DnsConfig>,
    ctx: LanforgeContext,
}

impl DotService {
    #[must_use]
    pub const fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for DotService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let Some(addr_str) = &self.cfg.dot_listen else {
            return Ok(());
        };

        let cert = self.cfg.tls_cert.as_deref().ok_or_else(|| {
            CoreError::Generic("DoT requires tls_cert to be configured".to_string())
        })?;
        let key = self.cfg.tls_key.as_deref().ok_or_else(|| {
            CoreError::Generic("DoT requires tls_key to be configured".to_string())
        })?;

        let tls_config = load_tls_config(cert, key)
            .map_err(|e| CoreError::Generic(format!("Failed to load TLS config: {e}")))?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(addr_str)
            .await
            .map_err(|e| CoreError::Generic(format!("DoT bind error: {e}")))?;

        info!("🚀 DoT listening on tls://{}", addr_str);
        ctrl.signal_ready();

        let mut rx = self.ctx.bus().subscribe();
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let acceptor = acceptor.clone();
                            let ctx = self.ctx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_dot_connection(stream, acceptor, ctx, peer).await {
                                    debug!("DoT connection from {} closed with error: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("DoT accept error: {}", e);
                        }
                    }
                }
                _ = rx.recv() => {
                    if !self.ctx.is_running() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_dot_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    ctx: LanforgeContext,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tls_stream = acceptor.accept(stream).await?;

    // DNS over TCP/TLS uses a 2-byte length prefix
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

        let dns_ctx_any = ctx.get_dns_context().ok_or("DNS engine not ready")?;
        let dns_ctx = dns_ctx_any
            .downcast_ref::<DnsContext>()
            .ok_or("Invalid DNS context")?;

        let mut resp_buf = Vec::with_capacity(512);
        if let Ok(true) = handle_query(&query_buf, dns_ctx, peer.ip(), &mut resp_buf).await {
            let resp_len = u16::try_from(resp_buf.len())?.to_be_bytes();
            tls_stream.write_all(&resp_len).await?;
            tls_stream.write_all(&resp_buf).await?;
        }
    }

    Ok(())
}
