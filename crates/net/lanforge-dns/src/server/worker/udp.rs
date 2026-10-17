use crate::error::DnsError;
use crate::pipeline::DnsPipelineRequest;
use crate::server::DnsContext;
use lanforge_dns_wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_transport::UdpTransport;
use lanforge_types::network::dns::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, trace};

pub fn spawn_udp_worker(ctx: Arc<DnsContext>, transport: UdpTransport) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500]; // Standard MTU-ish buffer
        loop {
            match transport.recv(&mut buf).await {
                Ok((len, src)) => {
                    let task_ctx = Arc::clone(&ctx);
                    let task_transport = transport.clone();
                    let data = buf[..len].to_vec();

                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_query(task_ctx, task_transport, &data, src).await {
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
    transport: UdpTransport,
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
        transport.send(&resp_buf, &src).await?;
        return Ok(());
    }

    let mut resp_buf = Vec::with_capacity(512);
    let filter_match = parking_lot::Mutex::new(None);
    let run_res = ctx
        .pipeline
        .run(
            &ctx,
            DnsPipelineRequest::new(
                data,
                &header,
                &question,
                src.ip(),
                TransportProtocol::Udp,
                &filter_match,
            ),
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
        transport.send(&resp_buf, &src).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        DnsPacketBuilder, create_test_dns_context, extract_a, init_test_context, mock_config,
        parse_response,
    };
    use lanforge_types::identifiers::MacAddr;
    use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode};
    use lanforge_types::update::DeviceUpdate;
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    #[tokio::test]
    async fn should_handle_query_and_send_response_via_inert_transport() {
        let ctx = init_test_context();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac,
            ip,
            expires: SystemTime::now() + Duration::from_secs(3600),
        });
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: "workstation".to_string(),
        });

        let dns_ctx = create_test_dns_context(ctx, mock_config());
        let (handle, transport) = UdpTransport::inert();

        let worker_handle = spawn_udp_worker(dns_ctx, transport);

        let client_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let query_bytes = DnsPacketBuilder::query("workstation.lan", DnsRecordType::A)
            .with_id(0xabcd)
            .build_bytes();

        handle.inject(query_bytes, client_addr).await;

        let (reply_bytes, dest) = handle.recv_reply().await.expect("Expected reply from worker");
        assert_eq!(dest, client_addr);

        let msg = parse_response(&reply_bytes).expect("Valid DNS response");
        assert_eq!(msg.header.id, 0xabcd);
        assert_eq!(msg.header.rcode, DnsResponseCode::NoError);
        assert_eq!(extract_a(&msg), vec![ip]);

        worker_handle.abort();
    }

    #[tokio::test]
    async fn should_return_nxdomain_for_unknown_local_query() {
        let ctx = init_test_context();
        let dns_ctx = create_test_dns_context(ctx, mock_config());
        let (handle, transport) = UdpTransport::inert();

        let worker_handle = spawn_udp_worker(dns_ctx, transport);

        let client_addr: SocketAddr = "192.168.1.100:54322".parse().unwrap();
        let query_bytes = DnsPacketBuilder::query("unknown-device.lan", DnsRecordType::A)
            .with_id(0x1122)
            .build_bytes();

        handle.inject(query_bytes, client_addr).await;

        let (reply_bytes, dest) = handle.recv_reply().await.expect("Expected reply from worker");
        assert_eq!(dest, client_addr);

        let msg = parse_response(&reply_bytes).expect("Valid DNS response");
        assert_eq!(msg.header.id, 0x1122);
        assert_eq!(msg.header.rcode, DnsResponseCode::NXDomain);

        worker_handle.abort();
    }
}

