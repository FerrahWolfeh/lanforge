//! The DNS service reports its upstreams as reachable only while the WAN is up, from the start:
//! it used to report `Online` at start and only follow later WAN changes, so a DNS started
//! without internet looked healthy. Without a configured WAN there is nothing to judge.

use super::common::{init_test_context, mock_config};
use crate::config::DnsConfig;
use crate::server::service::DnsService;
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_types::DnsListenConfig;
use lanforge_types::network::ListenConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::snapshot::{WanSnapshot, WanState};
use lanforge_types::system::{DegradedReason, ServiceId, ServiceState, StateDetail};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

fn listen_on_a_free_port(ctx: &LanforgeContext) {
    let port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|s| s.local_addr())
        .expect("ephemeral port")
        .port();
    ctx.update_dns_listen(DnsListenConfig {
        enabled: true,
        listen: ListenConfig::Single(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        ..DnsListenConfig::default()
    });
}

fn configure_pppoe_wan(ctx: &LanforgeContext) {
    ctx.update_pppoe_config(PppoeConfig {
        enabled: true,
        wan_iface: "wan0".into(),
        ..Default::default()
    });
}

fn wan(state: WanState, generation: u64) -> WanSnapshot {
    WanSnapshot {
        state,
        ifname: (state == WanState::Up).then(|| "ppp0".into()),
        generation,
        ..Default::default()
    }
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

async fn wait_for(ctx: &LanforgeContext, state: ServiceState, detail: Option<StateDetail>) {
    timeout(Duration::from_secs(2), async {
        while ctx.get_service_state(ServiceId::Dns) != state
            || ctx.get_service_detail(ServiceId::Dns) != detail
        {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {state:?} / {detail:?}, got {:?} / {:?}",
            ctx.get_service_state(ServiceId::Dns),
            ctx.get_service_detail(ServiceId::Dns)
        )
    });
}

async fn stop(cmd_tx: mpsc::Sender<ServiceCommand>, task: JoinHandle<()>) {
    let _ = cmd_tx.send(ServiceCommand::Stop).await;
    let _ = timeout(Duration::from_secs(2), task).await;
}

const UNREACHABLE: Option<StateDetail> =
    Some(StateDetail::Degraded(DegradedReason::UpstreamUnreachable));

#[tokio::test]
async fn a_wan_down_at_start_degrades_until_it_comes_up() {
    let ctx = init_test_context();
    listen_on_a_free_port(&ctx);
    configure_pppoe_wan(&ctx);
    ctx.set_wan_snapshot(wan(WanState::Down, 1));
    let (cmd_tx, task) = serve(&ctx).await;

    wait_for(&ctx, ServiceState::Degraded, UNREACHABLE).await;
    ctx.set_wan_snapshot(wan(WanState::Up, 2));
    wait_for(&ctx, ServiceState::Online, None).await;

    stop(cmd_tx, task).await;
}

#[tokio::test]
async fn a_wan_up_at_start_is_online() {
    let ctx = init_test_context();
    listen_on_a_free_port(&ctx);
    configure_pppoe_wan(&ctx);
    ctx.set_wan_snapshot(wan(WanState::Up, 2));
    let (cmd_tx, task) = serve(&ctx).await;

    wait_for(&ctx, ServiceState::Online, None).await;

    stop(cmd_tx, task).await;
}

#[tokio::test]
async fn no_configured_wan_is_online() {
    let ctx = init_test_context();
    listen_on_a_free_port(&ctx);
    ctx.set_wan_snapshot(wan(WanState::Down, 1));
    let (cmd_tx, task) = serve(&ctx).await;

    wait_for(&ctx, ServiceState::Online, None).await;

    stop(cmd_tx, task).await;
}
