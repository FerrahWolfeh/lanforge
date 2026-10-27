//! Regression: stopping the DNS service must release its TCP listener immediately, so a
//! restart can rebind the port (it used to leak detached accept tasks holding the socket).

#[path = "common/mod.rs"]
mod common;

use common::{init_test_context, mock_config, wait_for_service_online};
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::DnsListenConfig;
use lanforge_types::network::ListenConfig;
use lanforge_types::system::ServiceId;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Picks a free loopback port (UDP and TCP both bind it).
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("ephemeral port")
}

#[tokio::test]
async fn stop_releases_tcp_listener_for_immediate_rebind() {
    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };

    for round in 0..3 {
        let mut service = DnsService::new(cfg.clone(), ctx.clone());
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
        let ctx_serve = ctx.clone();
        let serve = tokio::spawn(async move { service.serve(&ctx_serve, &h).await });
        wait_for_service_online(&ctx, ServiceId::Dns).await;
        // Give the TCP worker time to bind before stopping it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        cmd_tx
            .send(ServiceCommand::Stop)
            .await
            .expect("service alive");
        timeout(Duration::from_secs(2), serve)
            .await
            .expect("serve must return on Stop")
            .expect("join")
            .expect("serve ok");

        // The port must be free right after serve returns.
        let rebind = TcpListener::bind(addr);
        assert!(
            rebind.is_ok(),
            "round {round}: TCP {addr} still held: {:?}",
            rebind.err()
        );
    }
}

/// A new listen port from the live config (WebUI) restarts the DNS service alone and binds the
/// new port; the old one is released. The static `[dns]` value is not what gets bound.
#[tokio::test]
async fn live_listen_change_restarts_dns_on_the_new_port() {
    let ctx = init_test_context();
    let old_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let new_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let static_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        listen: ListenConfig::Single(old_addr),
        ..DnsListenConfig::default()
    });
    let cfg = DnsConfig {
        enabled: true,
        listen: ListenConfig::Single(static_addr),
        ..mock_config()
    };

    let start = |cfg: DnsConfig| {
        let ctx = ctx.clone();
        let mut service = DnsService::new(cfg, ctx.clone());
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
        let serve = tokio::spawn(async move { service.serve(&ctx, &h).await });
        (cmd_tx, serve)
    };

    let (_cmd_tx, serve) = start(cfg.clone());
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpListener::bind(old_addr).is_err(), "live port is bound");
    assert!(TcpListener::bind(static_addr).is_ok(), "static port is not");

    ctx.update_dns_listen(DnsListenConfig {
        listen: ListenConfig::Single(new_addr),
        ..DnsListenConfig::default()
    });
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("a listener change must end this serve (restart)")
        .expect("join")
        .expect("serve ok");
    assert!(TcpListener::bind(old_addr).is_ok(), "old port released");

    // The supervisor starts a fresh instance: it binds the new port.
    let (cmd_tx, serve) = start(cfg);
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpListener::bind(new_addr).is_err(), "new port is bound");
    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let _ = timeout(Duration::from_secs(2), serve).await;
}

/// Internal callers (API, db worker) hold the same `DnsHandle` across a DNS restart: a request
/// sent while no instance is serving waits and is answered by the next one, instead of failing
/// on the closed channel of the instance that stopped.
#[tokio::test]
async fn dns_requests_wait_through_a_restart() {
    use lanforge_types::network::dns::{DnsRequest, DnsResponse};

    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };
    let start = || {
        let ctx = ctx.clone();
        let mut service = DnsService::new(cfg.clone(), ctx.clone());
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let h = ServiceHandle::with_command_channel(ServiceId::Dns, ctx.clone(), cmd_rx);
        let serve = tokio::spawn(async move { service.serve(&ctx, &h).await });
        (cmd_tx, serve)
    };

    let (cmd_tx, serve) = start();
    wait_for_service_online(&ctx, ServiceId::Dns).await;
    let handle = ctx.dns_handle().expect("DNS handle registered");
    assert!(matches!(
        handle.send_request(DnsRequest::Stats).await,
        Ok(DnsResponse::Stats(_))
    ));

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");

    // Restart window: the request is sent while nothing serves the queue.
    let pending = tokio::spawn(async move { handle.send_request(DnsRequest::Stats).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !pending.is_finished(),
        "the request waits instead of failing"
    );

    let (cmd_tx, serve) = start();
    let answer = timeout(Duration::from_secs(3), pending)
        .await
        .expect("answered by the next instance")
        .expect("join");
    assert!(
        matches!(answer, Ok(DnsResponse::Stats(_))),
        "{:?}",
        answer.err()
    );
    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let _ = timeout(Duration::from_secs(2), serve).await;
}
