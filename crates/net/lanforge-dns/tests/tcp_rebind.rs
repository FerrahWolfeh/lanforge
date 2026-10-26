//! Regression: stopping the DNS service must release its TCP listener immediately, so a
//! restart can rebind the port (it used to leak detached accept tasks holding the socket).

#[path = "common/mod.rs"]
mod common;

use common::{init_test_context, mock_config, wait_for_service_online};
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
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
    let cfg = DnsConfig {
        enabled: true,
        listen: ListenConfig::Single(addr),
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
