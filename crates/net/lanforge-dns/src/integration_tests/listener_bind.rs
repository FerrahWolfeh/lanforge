//! A listener that cannot bind (TCP/53, `DoT`, `DoQ`) degrades the service with the typed bind
//! error, and the WAN coming up does not clear it. Only the UDP sockets are fatal. Regression:
//! the failure was only logged and the service reported `Online` while serving UDP alone.

use super::common::{init_test_context, mock_config};
use crate::config::DnsConfig;
use crate::server::service::DnsService;
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_types::DnsListenConfig;
use lanforge_types::network::ListenConfig;
use lanforge_types::network::snapshot::{WanSnapshot, WanState};
use lanforge_types::system::{ServiceId, ServiceState};
use smallvec::smallvec;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// A loopback port whose TCP side is held by `TcpListener` (kept alive by the caller) while
/// its UDP side is free.
fn tcp_taken_port() -> (TcpListener, u16) {
    loop {
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("ephemeral port");
        let port = held.local_addr().expect("bound").port();
        if UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return (held, port);
        }
    }
}

async fn wait_for_state(ctx: &LanforgeContext, state: ServiceState) {
    timeout(Duration::from_secs(2), async {
        while ctx.get_service_state(ServiceId::Dns) != state {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {state:?}, got {:?} / {:?}",
            ctx.get_service_state(ServiceId::Dns),
            ctx.get_service_detail(ServiceId::Dns)
        )
    });
}

fn detail(ctx: &LanforgeContext) -> String {
    ctx.get_service_detail(ServiceId::Dns)
        .map(|d| d.to_string())
        .unwrap_or_default()
}

async fn serve(ctx: &LanforgeContext) -> (mpsc::Sender<ServiceCommand>, JoinHandle<()>) {
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
    let task = tokio::spawn(async move {
        let _ = service.serve(&ctx_serve, &h).await;
    });
    (cmd_tx, task)
}

#[tokio::test]
async fn a_taken_tcp_port_degrades_the_service() {
    let ctx = init_test_context();
    let (_held, port) = tcp_taken_port();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    let (cmd_tx, task) = serve(&ctx).await;

    wait_for_state(&ctx, ServiceState::Degraded).await;
    assert!(
        detail(&ctx).contains(&format!("tcp listener: address in use: {addr}")),
        "{}",
        detail(&ctx)
    );

    // The WAN coming up clears an upstream problem, not a listener that never bound.
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(9),
        ifname: Some("ppp0".into()),
        v4: Some((Ipv4Addr::new(203, 0, 113, 2), 32)),
        v6_prefixes: smallvec![],
        generation: 7,
    });
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        ctx.get_service_state(ServiceId::Dns),
        ServiceState::Degraded
    );
    assert!(detail(&ctx).contains("tcp listener"), "{}", detail(&ctx));

    let _ = cmd_tx.send(ServiceCommand::Stop).await;
    let _ = timeout(Duration::from_secs(2), task).await;
}

#[cfg(feature = "dot")]
#[tokio::test]
async fn a_taken_dot_port_degrades_the_service() {
    use super::common::tls::{free_port, self_signed};

    let ctx = init_test_context();
    let cert = self_signed();
    let (_held, dot_port) = tcp_taken_port();
    let dot = SocketAddr::from((Ipv4Addr::LOCALHOST, dot_port));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))),
        dot_listen: Some(dot),
        dot_enabled: true,
        tls_cert: Some(cert.cert_pem.clone()),
        tls_key: Some(cert.key_pem.clone()),
        ..DnsListenConfig::default()
    });
    let (cmd_tx, task) = serve(&ctx).await;

    wait_for_state(&ctx, ServiceState::Degraded).await;
    assert!(
        detail(&ctx).contains(&format!("DoT listener: address in use: {dot}")),
        "{}",
        detail(&ctx)
    );

    let _ = cmd_tx.send(ServiceCommand::Stop).await;
    let _ = timeout(Duration::from_secs(2), task).await;
}
