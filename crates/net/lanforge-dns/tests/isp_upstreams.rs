//! Without configured upstreams, DNS forwards to the resolvers the ISP announced over PPPoE.
//!
//! They used to be learned only from the `SessionUp` event, so a DNS restart with the session
//! already up, a lagged PPPoE topic, or removing the custom upstreams left the LAN with no
//! upstream at all until the next PPPoE reconnect.

#[path = "common/mod.rs"]
mod common;

use common::{init_test_context, mock_config, wait_for_service_online};
use lanforge_core::bus::{LanforgeEvent, PppoeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_types::events::pppoe::PppoeSessionUp;
use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use lanforge_types::system::{PppoeSessionState, PppoeStatusResponse, ServiceId};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

const ISP_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53));

fn connected_status() -> PppoeStatusResponse {
    PppoeStatusResponse {
        enabled: true,
        state: PppoeSessionState::Connected,
        interface: Some("ppp0".into()),
        dns_servers: vec![ISP_DNS],
        ..Default::default()
    }
}

async fn start_dns(ctx: &LanforgeContext) {
    let (_handle, mut service) = DnsService::inert(
        DnsConfig {
            enabled: true,
            ..mock_config()
        },
        ctx.clone(),
    );
    let ctx_service = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dns, ctx_service.clone());
        let _ = service.serve(&ctx_service, &h).await;
    });
    wait_for_service_online(ctx, ServiceId::Dns).await;
}

async fn upstream_addrs(ctx: &LanforgeContext) -> Vec<SocketAddr> {
    let dns = ctx.dns_handle().expect("DNS handle registered");
    match dns.send_request(DnsRequest::Upstreams).await.unwrap() {
        DnsResponse::Upstreams(snaps) => snaps.into_iter().map(|s| s.target).collect(),
        other => panic!("unexpected response {other:?}"),
    }
}

async fn wait_upstreams(ctx: &LanforgeContext, want: &[SocketAddr]) {
    timeout(Duration::from_millis(500), async {
        while upstream_addrs(ctx).await != want {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("DNS upstreams never became {want:?}"));
}

fn isp() -> SocketAddr {
    SocketAddr::new(ISP_DNS, 53)
}

/// `lanforge service restart dns` (or a crash restart) while PPPoE is up gets no SessionUp.
#[tokio::test]
async fn dns_started_with_pppoe_up_uses_the_isp_resolvers() {
    let ctx = init_test_context();
    ctx.set_pppoe_status(Some(connected_status()));
    start_dns(&ctx).await;
    wait_upstreams(&ctx, &[isp()]).await;
}

/// A SessionUp lost to a lagged PPPoE topic must not leave DNS without upstreams.
#[tokio::test]
async fn dns_resyncs_isp_resolvers_after_a_lagged_bus() {
    let ctx = init_test_context();
    start_dns(&ctx).await;
    assert!(upstream_addrs(&ctx).await.is_empty());

    ctx.set_pppoe_status(Some(connected_status()));
    let up = PppoeSessionUp {
        interface: "ppp0".into(),
        ac_mac: None,
        ac_name: None,
        session_id: 1,
        mru: 1492,
        ipv4: None,
        ipv4_peer: None,
        dns: vec![ISP_DNS],
        ipv6_link_local: false,
    };
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(up))));
    for attempt in 0..1000 {
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::Pppoe(PppoeEvent::Reconnecting {
                attempt,
                next_retry_secs: 0,
            }));
    }
    wait_upstreams(&ctx, &[isp()]).await;
}

/// Removing the last custom upstream falls back to the ISP resolvers instead of nothing.
#[tokio::test]
async fn removing_custom_upstreams_falls_back_to_the_isp_resolvers() {
    let ctx = init_test_context();
    let custom = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53);
    ctx.update_dns_upstreams(vec![UpstreamTarget {
        addr: custom,
        protocol: UpstreamProtocol::Udp,
        hostname: None,
        domain: None,
    }]);
    ctx.set_pppoe_status(Some(connected_status()));
    start_dns(&ctx).await;
    wait_upstreams(&ctx, &[custom]).await;

    ctx.update_dns_upstreams(Vec::new());
    wait_upstreams(&ctx, &[isp()]).await;
}
