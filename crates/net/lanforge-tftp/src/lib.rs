pub mod config;

use crate::config::TftpConfig;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::system::ServiceState;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use smallvec::SmallVec;
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
    describe = format!("TFTP Server on {}", self.cfg.listen)
)]
#[derive(Clone)]
pub struct TftpService {
    _ctx: LanforgeContext,
    cfg: TftpConfig,
    bound_addr: Arc<RwLock<Option<String>>>,
}

impl TftpService {
    #[must_use]
    pub fn new(ctx: LanforgeContext, cfg: TftpConfig) -> Self {
        Self {
            _ctx: ctx,
            cfg,
            bound_addr: Arc::new(RwLock::new(None)),
        }
    }
}

impl AsyncService for TftpService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }
    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let listen = self
            .bound_addr
            .read()
            .clone()
            .unwrap_or_else(|| self.cfg.listen.to_string());
        vec![
            (std::borrow::Cow::Borrowed("listen"), listen),
            (
                std::borrow::Cow::Borrowed("root_dir"),
                self.cfg.root_dir.to_string_lossy().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("block_size"),
                self.cfg.block_size.to_string(),
            ),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("TFTP service is disabled in configuration.");
            ctx.set_service_state("tftp", ServiceState::Inactive);
            return Ok(());
        }

        let addrs = self.cfg.listen.addrs();
        if addrs.is_empty() {
            return Err(CoreError::Generic(
                "No TFTP listen addresses configured".to_string(),
            ));
        }

        let mut actual_bound = Vec::new();
        let mut sockets = Vec::new();

        for addr in addrs {
            let socket = bind_udp_dual_stack(addr)?;
            let local_addr = socket.local_addr().map_err(CoreError::Io)?;
            actual_bound.push(local_addr.to_string());
            sockets.push(Arc::new(socket));
        }

        let bound_str = actual_bound.join(", ");
        *self.bound_addr.write() = Some(bound_str.clone());
        info!(addr = %bound_str, "TFTP: Server listening");

        let (shutdown_tx, _) = tokio::sync::watch::channel(());
        let shutdown_tx_clone = shutdown_tx.clone();
        let mut bus_rx = ctx.bus().subscribe_system();

        let cfg_shared = Arc::new(self.cfg.clone());
        let mut reader_handles = Vec::new();
        for socket in sockets {
            let cfg = Arc::clone(&cfg_shared);
            let mut shutdown_rx = shutdown_tx.subscribe();
            reader_handles.push(tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    tokio::select! {
                        res = socket.recv_from(&mut buf) => {
                            match res {
                                Ok((size, src)) => {
                                    let data = SmallVec::<[u8; 512]>::from_slice(&buf[..size]);
                                    let socket_clone = Arc::clone(&socket);
                                    let cfg_clone = Arc::clone(&cfg);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_packet(socket_clone, src, &data, &cfg_clone).await {
                                            debug!("TFTP error handling request from {src}: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("TFTP socket recv error: {e}");
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            break;
                        }
                    }
                }
            }));
        }

        loop {
            tokio::select! {
                event = bus_rx.recv() => {
                    if let Ok(timed) = event {
                        if matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                            info!("TFTP: shutdown signal received");
                            let _ = shutdown_tx_clone.send(());
                            break;
                        }
                    } else {
                        let _ = shutdown_tx_clone.send(());
                        break; // Bus closed
                    }
                }
            }
        }

        for h in reader_handles {
            let _ = h.await;
        }

        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        *self.bound_addr.write() = None;
        Ok(())
    }
}

async fn handle_packet(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    data: &[u8],
    cfg: &TftpConfig,
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
    cfg: &TftpConfig,
) -> Result<(), TftpError> {
    let mut parts = data.split(|&b| b == 0);
    let filename_bytes = parts
        .next()
        .ok_or_else(|| TftpError::Protocol("Missing filename".into()))?;
    let Ok(filename) = std::str::from_utf8(filename_bytes) else {
        return send_error(&socket, src, 0, "Invalid UTF-8 filename").await;
    };

    // Security: prevent path traversal
    let rel_path = std::path::Path::new(filename);
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

    info!("TFTP: Sending {filename} to {src}");

    let mut file = File::open(path).await?;
    let mut block_num: u16 = 1;
    let block_size = cfg.block_size as usize;
    let mut packet = vec![0u8; 4 + block_size];
    packet[0..2].copy_from_slice(&3u16.to_be_bytes()); // Opcode 3 (DATA)

    // TFTP uses a new port for the transfer (TID)
    let session_socket = match src {
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
    };

    loop {
        packet[2..4].copy_from_slice(&block_num.to_be_bytes());
        let n = file.read(&mut packet[4..4 + block_size]).await?;
        let packet_slice = &packet[..4 + n];

        let mut retries = 0;
        loop {
            session_socket.send_to(packet_slice, src).await?;

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
                debug!("TFTP: Retrying block {block_num} to {src}");
            }
        }

        if n < block_size {
            break; // End of file
        }
        block_num = block_num.wrapping_add(1);
    }

    Ok(())
}

fn bind_udp_dual_stack(addr: SocketAddr) -> Result<tokio::net::UdpSocket, CoreError> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            let socket_res = (|| -> std::io::Result<socket2::Socket> {
                let s = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                s.set_only_v6(false)?;
                s.set_nonblocking(true)?;
                s.bind(&socket2::SockAddr::from(addr))?;
                Ok(s)
            })();

            match socket_res {
                Ok(s) => {
                    let std_sock: std::net::UdpSocket = s.into();
                    tokio::net::UdpSocket::from_std(std_sock).map_err(CoreError::Io)
                }
                Err(e) => {
                    tracing::warn!(
                        "TFTP: IPv6 dual-stack UDP bind to {} failed ({}), falling back to 0.0.0.0:{}",
                        addr,
                        e,
                        v6.port()
                    );
                    let v4_addr = SocketAddr::from(([0, 0, 0, 0], v6.port()));
                    let s = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )
                    .map_err(CoreError::Io)?;
                    s.set_nonblocking(true).map_err(CoreError::Io)?;
                    s.bind(&socket2::SockAddr::from(v4_addr))
                        .map_err(CoreError::Io)?;
                    let std_sock: std::net::UdpSocket = s.into();
                    tokio::net::UdpSocket::from_std(std_sock).map_err(CoreError::Io)
                }
            }
        }
        SocketAddr::V6(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(CoreError::Io)?;
            s.set_only_v6(true).map_err(CoreError::Io)?;
            s.set_nonblocking(true).map_err(CoreError::Io)?;
            s.bind(&socket2::SockAddr::from(addr)).map_err(CoreError::Io)?;
            let std_sock: std::net::UdpSocket = s.into();
            tokio::net::UdpSocket::from_std(std_sock).map_err(CoreError::Io)
        }
        SocketAddr::V4(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(CoreError::Io)?;
            s.set_nonblocking(true).map_err(CoreError::Io)?;
            s.bind(&socket2::SockAddr::from(addr)).map_err(CoreError::Io)?;
            let std_sock: std::net::UdpSocket = s.into();
            tokio::net::UdpSocket::from_std(std_sock).map_err(CoreError::Io)
        }
    }
}

async fn send_error(
    socket: &UdpSocket,
    src: SocketAddr,
    code: u16,
    msg: &str,
) -> Result<(), TftpError> {
    let mut packet = [0u8; 128];
    packet[0..2].copy_from_slice(&5u16.to_be_bytes()); // Opcode 5
    packet[2..4].copy_from_slice(&code.to_be_bytes());
    let msg_bytes = msg.as_bytes();
    let msg_len = msg_bytes.len().min(128 - 5);
    packet[4..4 + msg_len].copy_from_slice(&msg_bytes[..msg_len]);
    packet[4 + msg_len] = 0;
    let total_len = 5 + msg_len;
    socket.send_to(&packet[..total_len], src).await?;
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
            listen: "127.0.0.1:0".parse().unwrap(),
            root_dir: PathBuf::from("/tmp"),
            ..Default::default()
        };
        let service = TftpService::new(ctx, cfg);
        assert_eq!(service.cfg.listen.to_string(), "127.0.0.1:0");
        assert_eq!(service.cfg.root_dir, PathBuf::from("/tmp"));
    }
}
