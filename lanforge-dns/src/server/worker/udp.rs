use crate::server::DnsContext;
use crate::wire::{WireHeader, WireQuestion};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{error, trace};

pub fn spawn_udp_worker(ctx: Arc<DnsContext>, socket: Arc<UdpSocket>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500]; // Standard MTU-ish buffer
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let task_ctx = Arc::clone(&ctx);
                    let task_socket = Arc::clone(&socket);
                    let data = buf[..len].to_vec();

                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_query(task_ctx, task_socket, &data, src).await {
                            trace!("UDP query handling failed: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("UDP worker receive error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    })
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn handle_udp_query(
    ctx: Arc<DnsContext>,
    socket: Arc<UdpSocket>,
    data: &[u8],
    src: std::net::SocketAddr,
) -> Result<(), crate::error::DnsError> {
    let header = WireHeader::parse(data).ok_or(crate::error::DnsError::WireParseError)?;
    let question = WireQuestion::parse(data).ok_or(crate::error::DnsError::WireParseError)?;

    let mut resp_buf = Vec::with_capacity(512);
    ctx.pipeline
        .run(&ctx, data, &header, &question, src.ip(), &mut resp_buf)
        .await?;

    if !resp_buf.is_empty() {
        socket.send_to(&resp_buf, src).await?;
    }

    Ok(())
}
