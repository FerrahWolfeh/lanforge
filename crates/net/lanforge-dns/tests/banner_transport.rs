#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! The DNS banner counts the messages served over TCP, not only the UDP datagrams.

#[path = "common/mod.rs"]
mod common;

use common::{DnsPacketBuilder, init_test_context, mock_config, wait_for_service_online};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::DnsListenConfig;
use lanforge_types::network::ListenConfig;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::snapshot::TransportSnapshot;
use lanforge_types::system::ServiceId;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("ephemeral port")
}

fn dns_transport(ctx: &LanforgeContext) -> Option<TransportSnapshot> {
    ctx.service_banners()
        .into_iter()
        .find(|b| b.id == ServiceId::Dns)
        .and_then(|b| b.transport)
}

/// A query over TCP shows in the banner both ways (it used to count UDP sockets only).
#[tokio::test]
async fn banner_counts_tcp_queries() {
    let ctx = init_test_context();
    ctx.register_service(ServiceId::Dns, "DNS");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    let mut service = DnsService::new(
        DnsConfig {
            enabled: true,
            ..mock_config()
        },
        ctx.clone(),
    );
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
    let ctx_serve = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    sleep(Duration::from_millis(50)).await;

    let query = DnsPacketBuilder::query("router.lan", DnsRecordType::A).build_bytes();
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let len = u16::try_from(query.len()).unwrap().to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(&query).await.unwrap();
    let mut resp_len = [0u8; 2];
    timeout(Duration::from_secs(2), stream.read_exact(&mut resp_len))
        .await
        .expect("answered")
        .expect("read");
    let resp_len = usize::from(u16::from_be_bytes(resp_len));
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();

    let counters = dns_transport(&ctx).expect("DNS registered its counters");
    assert_eq!(counters.rx_packets, 1, "{counters:?}");
    assert_eq!(counters.rx_bytes, query.len() as u64, "{counters:?}");
    assert_eq!(counters.tx_packets, 1, "{counters:?}");
    assert_eq!(counters.tx_bytes, resp_len as u64, "{counters:?}");

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    let _ = timeout(Duration::from_secs(2), serve).await;
}
