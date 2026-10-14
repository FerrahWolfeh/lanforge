pub mod config;

use crate::config::TftpConfig;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_transport::UdpTransport;
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
        let mut transports = Vec::new();

        for addr in addrs {
            let transport = match addr {
                SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    UdpTransport::dual_stack(v6.port()).map_err(CoreError::Io)?
                }
                _ => UdpTransport::bind_single(addr).map_err(CoreError::Io)?,
            };
            for local_addr in transport.local_addrs().map_err(CoreError::Io)? {
                actual_bound.push(local_addr.to_string());
            }
            transports.push(transport);
        }

        let bound_str = actual_bound.join(", ");
        *self.bound_addr.write() = Some(bound_str.clone());
        info!(addr = %bound_str, "TFTP: Server listening");

        let (shutdown_tx, _) = tokio::sync::watch::channel(());
        let shutdown_tx_clone = shutdown_tx.clone();
        let mut bus_rx = ctx.bus().subscribe_system();

        let cfg_shared = Arc::new(self.cfg.clone());
        let mut reader_handles = Vec::new();
        for transport in transports {
            let cfg = Arc::clone(&cfg_shared);
            let mut shutdown_rx = shutdown_tx.subscribe();
            reader_handles.push(tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    tokio::select! {
                        res = transport.recv(&mut buf) => {
                            match res {
                                Ok((size, src)) => {
                                    let data = SmallVec::<[u8; 512]>::from_slice(&buf[..size]);
                                    let trans_clone = transport.clone();
                                    let cfg_clone = Arc::clone(&cfg);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_packet(&trans_clone, src, &data, &cfg_clone).await {
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
    transport: &UdpTransport,
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
            handle_rrq(transport, src, &data[2..], cfg).await
        }
        _ => {
            // We only support RRQ for now
            send_error(transport, src, 4, "Illegal TFTP operation (RRQ only)").await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RrqOptions {
    pub blksize: Option<u16>,
    pub tsize: bool,
}

#[must_use]
pub fn parse_rrq_options<'a>(mut parts: impl Iterator<Item = &'a [u8]>, cfg: &TftpConfig) -> RrqOptions {
    let mut blksize = None;
    let mut tsize = false;

    while let Some(opt_name_bytes) = parts.next() {
        let Some(opt_val_bytes) = parts.next() else { break; };
        if let (Ok(name), Ok(val)) = (
            std::str::from_utf8(opt_name_bytes),
            std::str::from_utf8(opt_val_bytes),
        ) {
            if name.eq_ignore_ascii_case("blksize") {
                if let Ok(bs) = val.parse::<u16>() {
                    let max_bs = cfg.block_size.clamp(512, 1468);
                    blksize = Some(bs.clamp(512, max_bs));
                }
            } else if name.eq_ignore_ascii_case("tsize") {
                tsize = true;
            }
        }
    }

    RrqOptions { blksize, tsize }
}

/// Validates that a requested filename is valid UTF-8 and stays strictly inside `root_dir`.
///
/// Prevents path traversal vulnerabilities (`..`, root directory escape, prefixes).
pub fn sanitize_rrq_path(
    filename_bytes: &[u8],
    root_dir: &std::path::Path,
) -> Result<(std::path::PathBuf, String), &'static str> {
    let Ok(filename) = std::str::from_utf8(filename_bytes) else {
        return Err("Invalid UTF-8 filename");
    };

    let rel_path = std::path::Path::new(filename);
    if rel_path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err("Access violation");
    }

    let path = root_dir.join(rel_path);
    if !path.starts_with(root_dir) {
        return Err("Access violation");
    }

    Ok((path, filename.to_string()))
}

async fn validate_rrq_path(
    transport: &UdpTransport,
    src: SocketAddr,
    filename_bytes: &[u8],
    root_dir: &std::path::Path,
) -> Result<Option<(std::path::PathBuf, u64, String)>, TftpError> {
    let (path, filename) = match sanitize_rrq_path(filename_bytes, root_dir) {
        Ok(res) => res,
        Err(err) => {
            let code = if err.contains("UTF-8") { 0 } else { 2 };
            send_error(transport, src, code, err).await?;
            return Ok(None);
        }
    };

    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) if m.is_file() => m,
        _ => {
            send_error(transport, src, 1, "File not found").await?;
            return Ok(None);
        }
    };

    Ok(Some((path, meta.len(), filename.to_string())))
}

async fn bind_session_socket(src: SocketAddr) -> Result<(UdpSocket, SocketAddr), TftpError> {
    match src {
        SocketAddr::V6(_) => Ok((UdpSocket::bind("[::]:0").await?, src)),
        SocketAddr::V4(_) => Ok((UdpSocket::bind("0.0.0.0:0").await?, src)),
    }
}

async fn send_block_with_retries(
    session_socket: &UdpSocket,
    packet_slice: &[u8],
    target_addr: SocketAddr,
    block_num: u16,
    cfg: &TftpConfig,
) -> Result<(), TftpError> {
    let mut retries = 0;
    loop {
        session_socket.send_to(packet_slice, target_addr).await?;

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
                return Ok(());
            }
        }

        retries += 1;
        if retries > cfg.max_retries {
            return Err(TftpError::Protocol("Transfer timed out".into()));
        }
        debug!("TFTP: Retrying block {block_num} to {target_addr}");
    }
}

async fn transfer_file(
    file_path: std::path::PathBuf,
    block_size: usize,
    session_socket: &UdpSocket,
    target_addr: SocketAddr,
    cfg: &TftpConfig,
) -> Result<(), TftpError> {
    let mut file = File::open(file_path).await?;
    let mut block_num: u16 = 1;
    let mut packet = vec![0u8; 4 + block_size];
    packet[0..2].copy_from_slice(&3u16.to_be_bytes()); // Opcode 3 (DATA)

    loop {
        packet[2..4].copy_from_slice(&block_num.to_be_bytes());
        let n = file.read(&mut packet[4..4 + block_size]).await?;
        let packet_slice = &packet[..4 + n];

        send_block_with_retries(session_socket, packet_slice, target_addr, block_num, cfg).await?;

        if n < block_size {
            break;
        }
        block_num = block_num.wrapping_add(1);
    }

    Ok(())
}

async fn handle_rrq(
    transport: &UdpTransport,
    src: SocketAddr,
    data: &[u8],
    cfg: &TftpConfig,
) -> Result<(), TftpError> {
    let mut parts = data.split(|&b| b == 0);
    let filename_bytes = parts
        .next()
        .ok_or_else(|| TftpError::Protocol("Missing filename".into()))?;

    let Some((path, file_len, filename)) =
        validate_rrq_path(transport, src, filename_bytes, &cfg.root_dir).await?
    else {
        return Ok(());
    };

    let _mode = parts.next();
    let opts = parse_rrq_options(parts, cfg);

    info!("TFTP: Sending {filename} ({file_len} bytes) to {src}");

    let (session_socket, target_addr) = bind_session_socket(src).await?;
    let block_size = opts.blksize.unwrap_or(cfg.block_size) as usize;

    if opts.blksize.is_some() || opts.tsize {
        handle_oack_handshake(
            &session_socket,
            target_addr,
            opts.blksize,
            opts.tsize,
            file_len,
            cfg,
        )
        .await?;
    }

    transfer_file(path, block_size, &session_socket, target_addr, cfg).await
}

async fn handle_oack_handshake(
    session_socket: &UdpSocket,
    target_addr: SocketAddr,
    requested_blksize: Option<u16>,
    requested_tsize: bool,
    file_len: u64,
    cfg: &TftpConfig,
) -> Result<(), TftpError> {
    use std::io::Write;
    let mut oack = Vec::with_capacity(64);
    oack.extend_from_slice(&6u16.to_be_bytes()); // Opcode 6 (OACK)
    if let Some(bs) = requested_blksize {
        oack.extend_from_slice(b"blksize\0");
        let _ = write!(&mut oack, "{bs}\0");
    }
    if requested_tsize {
        oack.extend_from_slice(b"tsize\0");
        let _ = write!(&mut oack, "{file_len}\0");
    }

    let mut oack_retries = 0;
    loop {
        session_socket.send_to(&oack, target_addr).await?;
        let mut ack_buf = [0u8; 4];
        if let Ok(Ok((4, _))) = timeout(
            Duration::from_secs(cfg.timeout),
            session_socket.recv_from(&mut ack_buf),
        )
        .await
        {
            let ack_opcode = u16::from_be_bytes([ack_buf[0], ack_buf[1]]);
            let ack_block = u16::from_be_bytes([ack_buf[2], ack_buf[3]]);
            if ack_opcode == 4 && ack_block == 0 {
                return Ok(()); // Client acknowledged OACK with block 0!
            }
        } else {
            oack_retries += 1;
            if oack_retries > cfg.max_retries {
                return Err(TftpError::Protocol("OACK transfer timed out".into()));
            }
            debug!("TFTP: Retrying OACK to {target_addr}");
        }
    }
}

async fn send_error(
    transport: &UdpTransport,
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
    transport.send(&packet[..total_len], &src).await?;
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
