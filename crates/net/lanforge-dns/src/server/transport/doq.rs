use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::system::{DormantReason, ServiceState};
use quinn::{Endpoint, ServerConfig, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceDependency, ServiceHandle};

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
#[derive(Clone)]
pub struct DoqService {
    cfg: Arc<DnsConfig>,
    _ctx: LanforgeContext,
}

impl DoqService {
    #[must_use]
    pub const fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, _ctx: ctx }
    }
}

impl AsyncService for DoqService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[
            ServiceDependency::Database,
            ServiceDependency::Service("dns"),
        ]
    }

    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let port = self.cfg.doq_listen.map_or(853, |a| a.port());
        let listen = self.cfg.doq_listen.map_or("disabled".to_string(), |a| a.to_string());
        vec![
            (std::borrow::Cow::Borrowed("port"), port.to_string()),
            (std::borrow::Cow::Borrowed("listen"), listen),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        let Some(addr) = self.cfg.doq_listen else {
            info!("DoQ is disabled in configuration.");
            h.dormant(DormantReason::disabled("dns.doq_listen"));
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

        info!("DoQ listening on quic://{}", addr);
        h.ready();

        let mut rx = ctx.bus().subscribe();
        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => break,
                        ServiceCommand::Restart => {
                            h.request_restart();
                            break;
                        }
                        _ => {}
                    }
                }
                incoming = endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        let ctx_conn = ctx.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => {
                                    if let Err(e) = handle_doq_connection(conn, ctx_conn).await {
                                        debug!("DoQ connection closed: {}", e);
                                    }
                                }
                                Err(e) => { debug!("DoQ handshake failed: {}", e); }
                            }
                        });
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

async fn handle_doq_connection(
    connection: quinn::Connection,
    ctx: LanforgeContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = connection.remote_address();
    let dns_ctx_arc = ctx
        .get_shared::<DnsContext>()
        .ok_or("DNS engine not ready")?;

    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let dns_ctx_arc = Arc::clone(&dns_ctx_arc);

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
