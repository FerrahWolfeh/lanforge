use std::net::SocketAddr;
use std::path::{PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt};
use tokio::net::UdpSocket;
use tracing::{error, info, debug};
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_core::context::LanforgeContext;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use thiserror::Error;

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
    describe = format!("TFTP Server on {}", self.listen_addr)
)]
pub struct TftpService {
    ctx: LanforgeContext,
    listen_addr: String,
    root_dir: PathBuf,
}

impl TftpService {
    pub fn new(ctx: LanforgeContext, listen_addr: String, root_dir: PathBuf) -> Self {
        Self {
            ctx,
            listen_addr,
            root_dir,
        }
    }
}

impl AsyncService for TftpService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let socket = UdpSocket::bind(&self.listen_addr).await.map_err(|e| {
            CoreError::Generic(format!("Failed to bind TFTP to {}: {}", self.listen_addr, e))
        })?;

        info!("🚀 TFTP Server listening on {}", self.listen_addr);
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
                            let root = self.root_dir.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_packet(socket_clone, src, data, root).await {
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
    root: PathBuf,
) -> Result<(), TftpError> {
    if data.len() < 4 {
        return Ok(());
    }

    let opcode = u16::from_be_bytes([data[0], data[1]]);
    match opcode {
        1 => { // RRQ
            handle_rrq(socket, src, &data[2..], root).await
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
    root: PathBuf,
) -> Result<(), TftpError> {
    let mut parts = data.split(|&b| b == 0);
    let filename_bytes = parts.next().ok_or_else(|| TftpError::Protocol("Missing filename".into()))?;
    let filename = String::from_utf8_lossy(filename_bytes).to_string();
    
    // Security: prevent path traversal
    let path = root.join(&filename);
    if !path.starts_with(&root) {
        return send_error(&socket, src, 2, "Access violation").await;
    }

    if !path.is_file() {
        return send_error(&socket, src, 1, "File not found").await;
    }

    info!("TFTP: Sending {} to {}", filename, src);
    
    let mut file = File::open(path).await?;
    let mut block_num: u16 = 1;
    let mut buffer = [0u8; 512];

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
            match tokio::time::timeout(tokio::time::Duration::from_secs(3), session_socket.recv_from(&mut ack_buf)).await {
                Ok(Ok((4, _))) => {
                    let ack_opcode = u16::from_be_bytes([ack_buf[0], ack_buf[1]]);
                    let ack_block = u16::from_be_bytes([ack_buf[2], ack_buf[3]]);
                    if ack_opcode == 4 && ack_block == block_num {
                        break; // Success
                    }
                }
                _ => {
                    retries += 1;
                    if retries > 3 {
                        return Err(TftpError::Protocol("Transfer timed out".into()));
                    }
                    debug!("TFTP: Retrying block {} to {}", block_num, src);
                }
            }
        }

        if n < 512 {
            break; // End of file
        }
        block_num = block_num.wrapping_add(1);
    }

    Ok(())
}

async fn send_error(socket: &UdpSocket, src: SocketAddr, code: u16, msg: &str) -> Result<(), TftpError> {
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
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_tftp_service_new() {
        let bus = Arc::new(lanforge_core::bus::EventBus::new());
        let ctx = LanforgeContext::new(bus, lanforge_core::context::state::State::new(), None);
        let service = TftpService::new(ctx, "127.0.0.1:0".into(), PathBuf::from("/tmp"));
        assert_eq!(service.listen_addr, "127.0.0.1:0");
        assert_eq!(service.root_dir, PathBuf::from("/tmp"));
    }
}
