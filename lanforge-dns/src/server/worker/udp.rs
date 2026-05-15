use crate::error::DnsError;
use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_types::network::dns::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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
                    tokio::time::sleep(Duration::from_millis(100)).await;
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
    src: SocketAddr,
) -> Result<(), DnsError> {
    let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
    let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;

    // Noise filtering (e.g. malformed IoT queries like empty qname or ":0")
    let mut labels = question.labels();
    let is_noise = match labels.next() {
        None => true,                                             // Empty qname (.)
        Some(l) if l == b":0" && labels.next().is_none() => true, // Literally ":0"
        _ => false,
    };

    let edns = WireOptScanner::scan(data, &header, &question);

    if is_noise {
        let mut resp_buf = Vec::with_capacity(64);
        WireResponseWriter::write_error_response(
            data,
            &question,
            1, // FORMERR
            edns,
            false,
            &mut resp_buf,
        );
        socket.send_to(&resp_buf, src).await?;
        return Ok(());
    }

    let mut resp_buf = Vec::with_capacity(512);
    let run_res = ctx
        .pipeline
        .run(
            &ctx,
            DnsPipelineRequest::new(data, &header, &question, src.ip(), TransportProtocol::Udp),
            &mut resp_buf,
        )
        .await;

    if let Err(e) = run_res {
        trace!("Pipeline error (sending SERVFAIL): {:?}", e);
        resp_buf.clear();
        WireResponseWriter::write_error_response(
            data,
            &question,
            2, // SERVFAIL
            edns,
            !ctx.recursive.is_empty(),
            &mut resp_buf,
        );
    }

    if !resp_buf.is_empty() {
        socket.send_to(&resp_buf, src).await?;
    }

    Ok(())
}
