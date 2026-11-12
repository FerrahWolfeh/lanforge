//! Upstreams given by host name (`udp://resolver.example:<port>`, `tls://dns.google`) are looked
//! up through the bootstrap resolvers (`[dns] bootstrap`), never through the system resolver.

use super::common::{
    init_test_context, mock_config, mock_dns_context, process_query_test, wait_for_service_online,
};
use crate::config::DnsConfig;
use crate::resolver::UpstreamManager;
use crate::server::service::DnsService;
use crate::test_utils::{DnsPacketBuilder, MockUpstreamServer};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_types::DnsListenConfig;
use lanforge_types::network::QueryResult;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsRecordType, DnsRequest, DnsResponse, UpstreamHealthSnapshot,
};
use lanforge_types::system::ServiceId;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const NAME: &str = "resolver.example";

/// A bootstrap resolver that knows `NAME` at 127.0.0.1.
async fn bootstrap_server() -> MockUpstreamServer {
    MockUpstreamServer::spawn(HashMap::from([(
        NAME.to_string(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )]))
    .await
}

fn set_bootstrap(ctx: &LanforgeContext, servers: Vec<SocketAddr>) {
    ctx.update_dns_listen(DnsListenConfig {
        bootstrap: servers,
        ..ctx.get_dns_listen()
    });
}

async fn start_dns(ctx: &LanforgeContext) -> JoinHandle<()> {
    let (_handle, mut service) = DnsService::inert(
        DnsConfig {
            enabled: true,
            ..mock_config()
        },
        ctx.clone(),
    );
    let ctx_service = ctx.clone();
    let task = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dns, ctx_service.clone());
        let _ = service.serve(&ctx_service, &h).await;
    });
    wait_for_service_online(ctx, ServiceId::Dns).await;
    task
}

async fn upstreams(ctx: &LanforgeContext) -> Vec<UpstreamHealthSnapshot> {
    let dns = ctx.dns_handle().expect("DNS handle registered");
    match dns.send_request(DnsRequest::Upstreams).await.unwrap() {
        DnsResponse::Upstreams(snaps) => snaps,
        other => panic!("unexpected response {other:?}"),
    }
}

/// Waits until the one upstream is `NAME` at `want`.
async fn wait_named_upstream(ctx: &LanforgeContext, want: SocketAddr) {
    timeout(Duration::from_secs(3), async {
        loop {
            let snaps = upstreams(ctx).await;
            if let [snap] = snaps.as_slice()
                && snap.target == want
                && snap.host_name.as_deref() == Some(NAME)
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("DNS never forwarded to {NAME} at {want}"));
}

#[tokio::test]
async fn a_named_upstream_is_looked_up_through_the_bootstrap_resolvers() {
    let ctx = init_test_context();
    let boot = bootstrap_server().await;
    let upstream = MockUpstreamServer::spawn(HashMap::new()).await;
    set_bootstrap(&ctx, vec![boot.addr]);
    let target: UpstreamTarget = format!("udp://{NAME}:{}", upstream.addr.port())
        .parse()
        .unwrap();
    ctx.update_dns_upstreams(vec![target]);

    let _dns = start_dns(&ctx).await;
    wait_named_upstream(&ctx, upstream.addr).await;
}

/// Bootstrap unreachable when DNS starts (before `PPPoE` is up, or a wrong `bootstrap`): the
/// name is left out, and fixing `bootstrap` brings it in place, without restarting DNS.
#[tokio::test]
async fn a_bootstrap_change_looks_the_names_up_again_in_place() {
    let ctx = init_test_context();
    let boot = bootstrap_server().await;
    let upstream = MockUpstreamServer::spawn(HashMap::new()).await;
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    set_bootstrap(&ctx, vec![silent.local_addr().unwrap()]);
    let target: UpstreamTarget = format!("udp://{NAME}:{}", upstream.addr.port())
        .parse()
        .unwrap();
    ctx.update_dns_upstreams(vec![target]);

    let dns = start_dns(&ctx).await;
    assert!(upstreams(&ctx).await.is_empty());

    set_bootstrap(&ctx, vec![boot.addr]);
    wait_named_upstream(&ctx, upstream.addr).await;
    assert!(!dns.is_finished(), "a bootstrap change restarted DNS");
}

/// The query log names the upstream that answered, as configured: by host name for a named
/// one, and none for an answer from the cache.
#[tokio::test]
async fn the_query_log_names_the_upstream_that_answered() {
    let upstream = MockUpstreamServer::spawn(HashMap::from([(
        "www.example.com".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))],
    )]))
    .await;
    let dns_ctx = mock_dns_context(init_test_context(), mock_config()).await;
    let target: UpstreamTarget = format!("udp://{NAME}:{}", upstream.addr.port())
        .parse()
        .unwrap();
    let mgr = UpstreamManager::new(&target, upstream.addr, Arc::clone(&dns_ctx.cache))
        .await
        .unwrap();
    dns_ctx.recursive.replace_upstreams(vec![mgr]);

    let query = DnsPacketBuilder::query("www.example.com", DnsRecordType::A).build_bytes();
    for _ in 0..2 {
        let mut resp = Vec::new();
        process_query_test(&query, &dns_ctx, "192.168.1.50".parse().unwrap(), &mut resp)
            .await
            .unwrap();
    }

    let logged: Vec<_> = dns_ctx
        .query_log
        .as_ref()
        .unwrap()
        .get_recent(2)
        .into_iter()
        .map(|e| (e.result, e.upstream.as_deref().map(str::to_string)))
        .collect();
    let named = format!("udp://{NAME}:{}", upstream.addr.port());
    assert!(
        logged.contains(&(QueryResult::Forwarded, Some(named))),
        "{logged:?}"
    );
    assert!(logged.contains(&(QueryResult::Cached, None)), "{logged:?}");
}
