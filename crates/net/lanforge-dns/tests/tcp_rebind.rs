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
        enabled: true,
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

/// A new listen port from the live config (`WebUI`) restarts the DNS service alone and binds the
/// new port; the old one is released. The static `[dns]` value is not what gets bound.
#[tokio::test]
async fn live_listen_change_restarts_dns_on_the_new_port() {
    let ctx = init_test_context();
    let old_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let new_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let static_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
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
        enabled: true,
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
        enabled: true,
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

/// A cache miss waits on the upstream in a child task that holds the UDP socket. Those children
/// were detached `tokio::spawn`s: aborting the UDP worker left them alive, so a restart on the
/// same port could not rebind :53 until every in-flight upstream query timed out.
#[tokio::test]
async fn stop_releases_udp_socket_with_upstream_queries_in_flight() {
    use common::DnsPacketBuilder;
    use lanforge_types::network::dns::DnsRecordType;
    use lanforge_types::network::dns::upstream::UpstreamTarget;

    // An upstream that never answers keeps the query in flight.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_target = format!("udp://{}", silent.local_addr().unwrap())
        .parse::<UpstreamTarget>()
        .unwrap();

    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    ctx.update_dns_upstreams(vec![silent_target]);
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

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for name in ["a.example.org", "b.example.org", "c.example.org"] {
        let query = DnsPacketBuilder::query(name, DnsRecordType::A).build_bytes();
        client.send_to(&query, addr).await.unwrap();
    }
    let mut probe = [0u8; 64];
    let _ = silent.recv_from(&mut probe).await; // the miss reached the upstream
    tokio::time::sleep(Duration::from_millis(50)).await;

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop")
        .expect("join")
        .expect("serve ok");

    let rebind = std::net::UdpSocket::bind(addr);
    assert!(rebind.is_ok(), "UDP {addr} still held: {:?}", rebind.err());
}

/// An idle DNS-over-TCP connection is closed by the server (RFC 7766 §6.2.3). It used to stay
/// open forever, one task and one fd each: a misbehaving client could exhaust the daemon's fds.
#[tokio::test]
async fn idle_tcp_connection_is_closed() {
    use tokio::io::AsyncReadExt;

    let ctx = init_test_context();
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
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut idle = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(15), idle.read(&mut byte))
        .await
        .expect("server must close an idle connection");
    assert_eq!(read.expect("clean close"), 0, "EOF from the server");

    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    let _ = timeout(Duration::from_secs(2), serve).await;
}

/// `DnsHandle` requests were served one at a time: a diagnostic query stuck on a silent
/// upstream held up every other request (stats, adblock toggles, cache) for its whole timeout,
/// freezing the `WebUI`'s DNS pages.
#[tokio::test]
async fn slow_handle_request_does_not_block_others() {
    use lanforge_types::network::dns::upstream::UpstreamTarget;
    use lanforge_types::network::dns::{DnsRecordType, DnsRequest, DnsResponse};

    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_target = format!("udp://{}", silent.local_addr().unwrap())
        .parse::<UpstreamTarget>()
        .unwrap();

    let ctx = init_test_context();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
        ..DnsListenConfig::default()
    });
    ctx.update_dns_upstreams(vec![silent_target]);
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
    let handle = ctx.dns_handle().expect("DNS handle registered");

    let slow_handle = handle.clone();
    let slow = tokio::spawn(async move {
        slow_handle
            .send_request(DnsRequest::Query {
                name: "stuck.example.org".into(),
                qtype: DnsRecordType::A,
            })
            .await
    });
    let mut probe = [0u8; 64];
    let _ = silent.recv_from(&mut probe).await; // the diagnostic query is in flight

    let stats = timeout(
        Duration::from_millis(500),
        handle.send_request(DnsRequest::Stats),
    )
    .await
    .expect("Stats must not wait behind a slow query");
    assert!(matches!(stats, Ok(DnsResponse::Stats(_))));

    slow.abort();
    cmd_tx
        .send(ServiceCommand::Stop)
        .await
        .expect("service alive");
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns on Stop with a request in flight")
        .expect("join")
        .expect("serve ok");
}
