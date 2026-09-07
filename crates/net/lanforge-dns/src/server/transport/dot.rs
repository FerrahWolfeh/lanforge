use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::system::ServiceState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};

use crate::config::DnsConfig;
use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use crate::server::transport::tls::load_tls_config;
use lanforge_dns_wire::{WireHeader, WireQuestion};

#[lanforge_macros::lanforge_service(
    id = "dot",
    name = "DNS over TLS",
    critical = false,
    describe = format!("DoT on {}", self.cfg.dot_listen.map_or_else(|| "853".to_string(), |a| a.to_string()))
)]
#[derive(Clone)]
pub struct DotService {
    cfg: Arc<DnsConfig>,
    _ctx: LanforgeContext,
}

impl DotService {
    #[must_use]
    pub const fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, _ctx: ctx }
    }
}

impl AsyncService for DotService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[
            ServiceDependency::Database,
            ServiceDependency::Service("dns"),
        ]
    }

    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let port = self.cfg.dot_listen.map_or(853, |a| a.port());
        let listen = self.cfg.dot_listen.map_or("disabled".to_string(), |a| a.to_string());
        vec![
            (std::borrow::Cow::Borrowed("port"), port.to_string()),
            (std::borrow::Cow::Borrowed("listen"), listen),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let Some(addr_str) = &self.cfg.dot_listen else {
            info!("DoT is disabled in configuration.");
            ctx.set_service_state("dot", ServiceState::Inactive);
            std::future::pending::<()>().await;
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

        info!("DoT listening on tls://{}", addr_str);

        let mut rx = ctx.bus().subscribe();
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let acceptor = acceptor.clone();
                            let ctx_conn = ctx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_dot_connection(stream, acceptor, ctx_conn, peer).await {
                                    debug!("DoT connection from {} closed with error: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => { error!("DoT accept error: {}", e); }
                    }
                }
                res = rx.recv() => {
                    if let Ok(timed) = res {
                        if matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) || !ctx.is_running() {
                            break;
                        }
                    } else {
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
    let dns_ctx = ctx
        .get_service_state_ref::<DnsContext>("dns::context")
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
