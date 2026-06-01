pub mod config;

use crate::config::TftpConfig;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl, StatusProvider};
use lanforge_types::system::ServiceBanner;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info};

#[derive(Error, Debug)]
pub enum TftpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

#[lanforge_macros::lanforge_service(
    id = "tftp",
    name = "TFTP Server",
    critical = false,
    describe = format!("TFTP Server on {}", self.cfg.listen_addr)
)]
#[derive(Clone)]
pub struct TftpService {
    ctx: LanforgeContext,
    cfg: TftpConfig,
}

impl TftpService {
    #[must_use]
    pub fn new(ctx: LanforgeContext, cfg: TftpConfig) -> Self {
        ctx.register_status_provider(Arc::new(Self {
            ctx: ctx.clone(),
            cfg: cfg.clone(),
        }));
        Self { ctx, cfg }
    }
}

impl StatusProvider for TftpService {
    fn banner(&self) -> ServiceBanner {
        let stats = vec![
            (
                std::borrow::Cow::Borrowed("listen"),
                self.cfg.listen_addr.clone(),
            ),
            (
                std::borrow::Cow::Borrowed("root_dir"),
                self.cfg.root_dir.to_string_lossy().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("block_size"),
                self.cfg.block_size.to_string(),
            ),
        ];
        ServiceBanner {
            id: "tftp".to_string(),
            name: "TFTP Server".to_string(),
            state: self.ctx.get_service_state("tftp"),
            uptime_secs: self.ctx.get_service_uptime("tftp"),
            stats,
        }
    }
}

impl AsyncService for TftpService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let socket = UdpSocket::bind(&self.cfg.listen_addr).await.map_err(|e| {
            CoreError::Generic(format!(
                "Failed to bind TFTP to {}: {}",
                self.cfg.listen_addr, e
            ))
        })?;

        let local_addr = socket.local_addr().map_err(CoreError::Io)?;
        self.cfg.listen_addr = local_addr.to_string();
        self.ctx.register_status_provider(Arc::new(self.clone()));

        info!("🚀 TFTP Server listening on {}", self.cfg.listen_addr);
        ctrl.signal_ready();

        let mut buf = [0u8; 1024];
        let socket = Arc::new(socket);
        let mut bus_rx = self.ctx.bus().subscribe();

        loop {
            tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((size, src)) => {
                            let data = buf[..size].to_vec();
                            let socket_clone = socket.clone();
                            let cfg_clone = self.cfg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_packet(socket_clone, src, data, cfg_clone).await {
                                    debug!("TFTP error handling request from {}: {}", src, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("TFTP socket recv error: {}", e);
                        }
                    }
                }
                event = bus_rx.recv() => {
                    if let Ok(timed) = event {
                        if matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                            info!("TFTP: shutdown signal received");
                            break;
                        }
                    } else {
                        break; // Bus closed
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_packet(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    data: Vec<u8>,
    cfg: TftpConfig,
) -> Result<(), TftpError> {
    if data.len() < 4 {
        return Ok(());
    }

    let opcode = u16::from_be_bytes([data[0], data[1]]);
    match opcode {
        1 => {
            // RRQ
            handle_rrq(socket, src, &data[2..], cfg).await
        }
        _ => {
            // We only support RRQ for now
            send_error(&socket, src, 4, "Illegal TFTP operation (RRQ only)").await
        }
    }
}

async fn handle_rrq(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    data: &[u8],
    cfg: TftpConfig,
) -> Result<(), TftpError> {
    let mut parts = data.split(|&b| b == 0);
    let filename_bytes = parts
        .next()
        .ok_or_else(|| TftpError::Protocol("Missing filename".into()))?;
    let filename = String::from_utf8_lossy(filename_bytes).to_string();

    // Security: prevent path traversal
    let rel_path = std::path::Path::new(&filename);
    if rel_path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return send_error(&socket, src, 2, "Access violation").await;
    }

    let path = cfg.root_dir.join(rel_path);
    if !path.starts_with(&cfg.root_dir) {
        return send_error(&socket, src, 2, "Access violation").await;
    }

    if !path.is_file() {
        return send_error(&socket, src, 1, "File not found").await;
    }

    info!("TFTP: Sending {} to {}", filename, src);

    let mut file = File::open(path).await?;
    let mut block_num: u16 = 1;
    let mut buffer = vec![0u8; cfg.block_size as usize];

    // TFTP uses a new port for the transfer (TID)
    let session_socket = UdpSocket::bind("0.0.0.0:0").await?;

    loop {
        let n = file.read(&mut buffer).await?;

        // Send DATA packet
        let mut packet = Vec::with_capacity(4 + n);
        packet.extend_from_slice(&3u16.to_be_bytes()); // Opcode 3
        packet.extend_from_slice(&block_num.to_be_bytes());
        packet.extend_from_slice(&buffer[..n]);

        let mut retries = 0;
        loop {
            session_socket.send_to(&packet, src).await?;

            // Wait for ACK
            let mut ack_buf = [0u8; 4];
            if let Ok(Ok((4, _))) = timeout(
                Duration::from_secs(cfg.timeout),
                session_socket.recv_from(&mut ack_buf),
            )
            .await
            {
                let ack_opcode = u16::from_be_bytes([ack_buf[0], ack_buf[1]]);
                let ack_block = u16::from_be_bytes([ack_buf[2], ack_buf[3]]);
                if ack_opcode == 4 && ack_block == block_num {
                    break; // Success
                }
            } else {
                retries += 1;
                if retries > cfg.max_retries {
                    return Err(TftpError::Protocol("Transfer timed out".into()));
                }
                debug!("TFTP: Retrying block {} to {}", block_num, src);
            }
        }

        if n < cfg.block_size as usize {
            break; // End of file
        }
        block_num = block_num.wrapping_add(1);
    }

    Ok(())
}

async fn send_error(
    socket: &UdpSocket,
    src: SocketAddr,
    code: u16,
    msg: &str,
) -> Result<(), TftpError> {
    let mut packet = Vec::with_capacity(4 + msg.len() + 1);
    packet.extend_from_slice(&5u16.to_be_bytes()); // Opcode 5
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend_from_slice(msg.as_bytes());
    packet.push(0);
    socket.send_to(&packet, src).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use lanforge_core::{bus::EventBus, context::state::State};

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_tftp_service_new() {
        let bus = Arc::new(EventBus::new());
        let ctx = LanforgeContext::new(bus, State::new(), None);
        let cfg = TftpConfig {
            listen_addr: "127.0.0.1:0".into(),
            root_dir: PathBuf::from("/tmp"),
            ..Default::default()
        };
        let service = TftpService::new(ctx, cfg);
        assert_eq!(service.cfg.listen_addr, "127.0.0.1:0");
        assert_eq!(service.cfg.root_dir, PathBuf::from("/tmp"));
    }
}
