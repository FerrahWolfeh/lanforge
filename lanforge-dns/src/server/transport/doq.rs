use lanforge_types::network::dns::TransportProtocol;
use quinn::{Endpoint, ServerConfig, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};

use crate::config::DnsConfig;
use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use crate::server::transport::tls::load_tls_config;
use lanforge_dns_wire::{WireHeader, WireQuestion};

#[lanforge_macros::lanforge_service(
    id = "doq",
    name = "DNS over QUIC",
    critical = false,
    describe = format!("DoQ on {}", self.cfg.doq_listen.map_or_else(|| "853".to_string(), |a| a.to_string()))
)]
pub struct DoqService {
    cfg: Arc<DnsConfig>,
    ctx: LanforgeContext,
}

impl DoqService {
    #[must_use]
    pub const fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for DoqService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let Some(addr) = self.cfg.doq_listen else {
            return Ok(());
        };

        let cert = self.cfg.tls_cert.as_deref().ok_or_else(|| {
            CoreError::Generic("DoQ requires tls_cert to be configured".to_string())
        })?;
        let key = self.cfg.tls_key.as_deref().ok_or_else(|| {
            CoreError::Generic("DoQ requires tls_key to be configured".to_string())
        })?;

        let mut tls_config = load_tls_config(cert, key)
            .map_err(|e| CoreError::Generic(format!("Failed to load TLS config: {e}")))?;

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
            .map_err(|e| CoreError::Generic(format!("DoQ bind error: {e}")))?;

        info!("🚀 DoQ listening on quic://{}", addr);
        ctrl.signal_ready();

        let mut rx = self.ctx.bus().subscribe();
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        let ctx = self.ctx.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => {
                                    if let Err(e) = handle_doq_connection(conn, ctx).await {
                                        debug!("DoQ connection closed: {}", e);
                                    }
                                }
                                Err(e) => { debug!("DoQ handshake failed: {}", e); }
                            }
                        });
                    }
                }
                _ = rx.recv() => {
                    if !self.ctx.is_running() { break; }
                }
            }
        }
        Ok(())
    }
}

async fn handle_doq_connection(
    connection: quinn::Connection,
    ctx: LanforgeContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = connection.remote_address();
    let dns_ctx_any = ctx.get_dns_context().ok_or("DNS engine not ready")?;
    let _ = dns_ctx_any
        .downcast_ref::<DnsContext>()
        .ok_or("Invalid DNS context")?;

    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // Actually dns_ctx is Arc-wrapped inside LanforgeContext anyway if we downcast properly.
                // Wait, get_dns_context() returns Arc<dyn Any + Send + Sync>.
                // So we can clone the Arc.
                let dns_ctx_arc = dns_ctx_any
                    .clone()
                    .downcast::<DnsContext>()
                    .map_err(|_| "Downcast failed")?;

                tokio::spawn(async move {
                    let query_buf = match recv.read_to_end(4096).await {
                        Ok(buf) => buf,
                        Err(e) => {
                            debug!("DoQ stream read error: {}", e);
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
                    match dns_ctx_arc
                        .pipeline
                        .run(
                            &dns_ctx_arc,
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
                                    debug!("DoQ stream write error: {}", e);
                                }
                                let _ = send.finish();
                            }
                        }
                        Err(e) => {
                            debug!("DoQ pipeline error: {}", e);
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
