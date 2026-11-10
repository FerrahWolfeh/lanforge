//! Regression: the lifetime DNS counters survive a service restart.
//!
//! The supervisor builds a new `DnsService` for every run. Each instance used to seed its
//! counters from the snapshot loaded at boot, so a restart (crash, admin restart, listen change,
//! disable/enable) dropped every query counted since boot, and the db worker then persisted the
//! smaller value over the stored one.

use crate::common::{DnsPacketBuilder, init_test_context, mock_config, wait_for_service_online};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::DnsListenConfig;
use lanforge_types::network::ListenConfig;
use lanforge_types::network::dns::{DnsRecordType, DnsRequest, DnsResponse};
use lanforge_types::system::ServiceId;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("ephemeral port")
}

/// One supervisor run: a fresh instance, as the runner's factory builds it.
fn start(
    ctx: &LanforgeContext,
) -> (
    mpsc::Sender<ServiceCommand>,
    JoinHandle<Result<(), CoreError>>,
) {
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };
    let mut service = DnsService::new(cfg, ctx.clone());
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
    let ctx = ctx.clone();
    let serve = tokio::spawn(async move { service.serve(&ctx, &h).await });
    (cmd_tx, serve)
}

async fn total_requests(ctx: &LanforgeContext) -> u64 {
    let handle = ctx.dns_handle().expect("DNS handle registered");
    match handle.send_request(DnsRequest::LifetimeStats).await {
        Ok(DnsResponse::LifetimeStats(s)) => s.total_requests,
        other => panic!("unexpected answer: {:?}", other.err()),
    }
}

#[tokio::test]
async fn lifetime_counters_survive_a_restart() {
    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });

    let (cmd_tx, serve) = start(&ctx);
    wait_for_service_online(&ctx, ServiceId::Dns).await;

    // A dotless name is answered locally (NXDOMAIN): no upstream needed.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = DnsPacketBuilder::query("nosuchhost", DnsRecordType::A).build_bytes();
    client.send_to(&query, addr).await.unwrap();
    let mut buf = [0u8; 512];
    timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("query answered")
        .unwrap();
    let before = total_requests(&ctx).await;
    assert!(before >= 1, "the query was counted");

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");

    let (cmd_tx, serve) = start(&ctx);
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    let after = total_requests(&ctx).await;
    assert!(
        after >= before,
        "lifetime total went back from {before} to {after} after a restart"
    );

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    let _ = timeout(Duration::from_secs(2), serve).await;
}

/// `DoH` reaches the engine through the context's shared `DnsContext`. It is published while a
/// run serves and withdrawn when the run ends: `DoH` used to keep answering through a stopped
/// (or disabled) DNS, and the stopped run's cache and adblock filter stayed in memory.
#[tokio::test]
async fn engine_is_withdrawn_when_the_run_ends() {
    use lanforge_dns::server::DnsContext;

    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });

    let (cmd_tx, serve) = start(&ctx);
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    assert!(
        ctx.get_shared::<DnsContext>().is_some(),
        "published while serving"
    );

    cmd_tx.send(ServiceCommand::Stop).await.expect("alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");
    assert!(
        ctx.get_shared::<DnsContext>().is_none(),
        "a stopped run's engine is still published"
    );
}
