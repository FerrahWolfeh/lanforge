//! Reverse (PTR) routing through the serving DNS: conditional domain routes on long reverse
//! names, per-subnet reverse resolvers (`[dns.reverse]`) and the private reverse zones of
//! RFC 6303 / RFC 7793.

use super::common::{
    DnsPacketBuilder, extract_ptr, init_test_context, mock_config, parse_response,
    register_test_device, wait_for_service_online,
};
use crate::config::DnsConfig;
use crate::server::service::DnsService;
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_transport::InertHandle;
use lanforge_types::device::TransientOrigin;
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
};
use lanforge_types::system::ServiceId;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

/// A UDP resolver that answers every PTR question with one fixed name and counts the queries;
/// an empty name makes it mute (a tailnet peer's resolver that never answers).
struct PtrUpstream {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl PtrUpstream {
    async fn spawn(name: &'static str) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind mock resolver");
        let addr = sock.local_addr().expect("mock resolver address");
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let Some(req) = WireDecoder::new(&buf[..n]).decode_message() else {
                    continue;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                if name.is_empty() {
                    continue;
                }
                let mut resp = DnsMessage::new();
                resp.header.id = req.header.id;
                resp.header.qr = true;
                resp.header.rd = req.header.rd;
                resp.header.ra = true;
                resp.header.qdcount = req.questions.len() as u16;
                resp.questions = req.questions.clone();
                match req.questions.first() {
                    Some(q) if q.qtype == DnsRecordType::PTR && !name.is_empty() => {
                        resp.answers.push(DnsRecord {
                            name: Arc::clone(&q.name),
                            rtype: DnsRecordType::PTR,
                            rclass: DnsClass::IN,
                            ttl: 5,
                            rdata: DnsRData::PTR(Arc::from(name)),
                        })
                    }
                    _ => resp.header.rcode = DnsResponseCode::NXDomain,
                }
                resp.header.ancount = resp.answers.len() as u16;
                let bytes = WireEncoder::new().encode_message(&resp);
                let _ = sock.send_to(&bytes, src).await;
            }
        });
        Self {
            addr,
            queries,
            task,
        }
    }

    fn target(&self) -> UpstreamTarget {
        format!("udp://{}", self.addr)
            .parse()
            .expect("mock resolver target")
    }

    fn target_for(&self, domain: &str) -> UpstreamTarget {
        format!("udp://{}#{domain}", self.addr)
            .parse()
            .expect("mock conditional target")
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }
}

impl Drop for PtrUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts the DNS service on an inert transport and waits until it serves.
async fn serve(ctx: &LanforgeContext) -> InertHandle<SocketAddr> {
    let cfg = DnsConfig {
        enabled: true,
        ..mock_config()
    };
    let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
    let served = ctx.clone();
    tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dns, served.clone());
        service
            .serve(&served, &h)
            .await
            .expect("DNS service failed");
    });
    wait_for_service_online(ctx, ServiceId::Dns).await;
    handle
}

/// Sends a PTR query for `ip` and returns the answer.
async fn query_ptr(handle: &InertHandle<SocketAddr>, ip: &str) -> DnsMessage {
    let ip: IpAddr = ip.parse().expect("test address");
    let client: SocketAddr = "192.168.1.100:54329".parse().expect("client address");
    handle
        .inject(
            DnsPacketBuilder::query_ptr(ip).with_id(4242).build_bytes(),
            client,
        )
        .await;
    let (reply, _) = handle.recv_reply().await.expect("a reply");
    parse_response(&reply).expect("a DNS response")
}

/// A conditional upstream for a reverse zone takes the PTR names under it. An `ip6.arpa`
/// name has 34 labels: the route lookup used to see only the first 16, so a v6 reverse zone
/// never matched and the query went to the global upstreams.
#[tokio::test]
async fn conditional_route_matches_a_full_ip6_arpa_name() {
    let ctx = init_test_context();
    let global = PtrUpstream::spawn("global.example.").await;
    let tailnet = PtrUpstream::spawn("archie.tailnet.ts.net.").await;
    ctx.update_dns_upstreams(vec![
        global.target(),
        tailnet.target_for("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"),
    ]);
    let handle = serve(&ctx).await;

    let resp = query_ptr(&handle, "fd7a:115c:a1e0::ca37:dd28").await;

    assert_eq!(extract_ptr(&resp), ["archie.tailnet.ts.net"]);
    assert_eq!(tailnet.queries(), 1);
    assert_eq!(global.queries(), 0);
    ctx.terminate();
}

fn reverse(subnet: &str, resolver: &PtrUpstream) -> DnsReverseResolver {
    DnsReverseResolver {
        subnet: subnet.parse().expect("test subnet"),
        resolver: resolver.target(),
    }
}

/// `[dns.reverse]` routes the PTR names of a subnet's addresses to its resolver, v4 and v6
/// (the Tailscale ranges here). They used to go to the global upstreams: the subnet's
/// resolver was only asked about the querying client's own address, in the background.
#[tokio::test]
async fn reverse_resolver_takes_the_ptr_queries_of_its_subnet() {
    let ctx = init_test_context();
    let global = PtrUpstream::spawn("global.example.").await;
    let tailnet = PtrUpstream::spawn("archie.tailnet.ts.net.").await;
    ctx.update_dns_upstreams(vec![global.target()]);
    ctx.set_reverse_resolvers(vec![
        reverse("100.64.0.0/10", &tailnet),
        reverse("fd7a:115c:a1e0::/48", &tailnet),
    ]);
    let handle = serve(&ctx).await;

    let v4 = query_ptr(&handle, "100.64.0.1").await;
    let v6 = query_ptr(&handle, "fd7a:115c:a1e0::ca37:dd28").await;
    let outside = query_ptr(&handle, "8.8.4.4").await;

    assert_eq!(extract_ptr(&v4), ["archie.tailnet.ts.net"]);
    assert_eq!(extract_ptr(&v6), ["archie.tailnet.ts.net"]);
    assert_eq!(extract_ptr(&outside), ["global.example"]);
    assert_eq!(tailnet.queries(), 2);
    assert_eq!(global.queries(), 1);
    ctx.terminate();
}

/// The most specific subnet wins, whatever the order in the file.
#[tokio::test]
async fn most_specific_reverse_subnet_wins() {
    let ctx = init_test_context();
    let wide = PtrUpstream::spawn("wide.example.").await;
    let narrow = PtrUpstream::spawn("narrow.example.").await;
    ctx.update_dns_upstreams(vec![]);
    ctx.set_reverse_resolvers(vec![
        reverse("10.0.0.0/8", &wide),
        reverse("10.1.0.0/16", &narrow),
    ]);
    let handle = serve(&ctx).await;

    assert_eq!(
        extract_ptr(&query_ptr(&handle, "10.1.2.3").await),
        ["narrow.example"]
    );
    assert_eq!(
        extract_ptr(&query_ptr(&handle, "10.2.2.3").await),
        ["wide.example"]
    );
    ctx.terminate();
}

/// A LAN device's address is answered locally even inside a reverse subnet.
#[tokio::test]
async fn lan_device_ptr_stays_local_inside_a_reverse_subnet() {
    let ctx = init_test_context();
    let resolver = PtrUpstream::spawn("remote.example.").await;
    register_test_device(
        &ctx,
        "printer",
        "aa:bb:cc:dd:ee:01".parse().expect("mac"),
        Ipv4Addr::new(192, 168, 1, 50),
    );
    ctx.set_reverse_resolvers(vec![reverse("192.168.0.0/16", &resolver)]);
    let handle = serve(&ctx).await;

    let resp = query_ptr(&handle, "192.168.1.50").await;

    assert_eq!(extract_ptr(&resp), ["printer.lan"]);
    assert_eq!(resolver.queries(), 0);
    ctx.terminate();
}

/// Removing a reverse resolver applies in place: its subnet goes back to the global upstreams.
#[tokio::test]
async fn reverse_resolver_change_applies_in_place() {
    let ctx = init_test_context();
    let global = PtrUpstream::spawn("global.example.").await;
    let tailnet = PtrUpstream::spawn("archie.tailnet.ts.net.").await;
    ctx.update_dns_upstreams(vec![global.target()]);
    ctx.set_reverse_resolvers(vec![reverse("100.64.0.0/10", &tailnet)]);
    let handle = serve(&ctx).await;
    assert_eq!(
        extract_ptr(&query_ptr(&handle, "100.64.0.1").await),
        ["archie.tailnet.ts.net"]
    );

    ctx.set_reverse_resolvers(vec![]);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // A different address each time: the first answer is cached.
        let resp = query_ptr(&handle, "100.64.0.2").await;
        if extract_ptr(&resp) == ["global.example"] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the removed resolver is still used"
        );
        sleep(Duration::from_millis(20)).await;
    }
    ctx.terminate();
}

/// A client in a reverse subnet is named from its resolver's PTR answer (a transient host),
/// by its raw host name: the first label.
#[tokio::test]
async fn client_in_a_reverse_subnet_gets_named() {
    let ctx = init_test_context();
    let tailnet = PtrUpstream::spawn("archie.tailnet.ts.net.").await;
    ctx.set_reverse_resolvers(vec![reverse("100.64.0.0/10", &tailnet)]);
    let handle = serve(&ctx).await;
    let client_ip: IpAddr = "100.64.0.5".parse().expect("client address");

    let query = DnsPacketBuilder::query("nonexistent.lan", DnsRecordType::A).build_bytes();
    handle
        .inject(query, SocketAddr::new(client_ip, 40000))
        .await;
    handle.recv_reply().await.expect("a reply");

    let deadline = Instant::now() + Duration::from_secs(2);
    let host = loop {
        if let Some(host) = ctx.get_transient_host(&client_ip) {
            break host;
        }
        assert!(Instant::now() < deadline, "the client was never named");
        sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(host.hostname.name, "archie");
    assert_eq!(host.origin, TransientOrigin::Tailscale);
    ctx.terminate();
}

/// A client its reverse resolver does not answer for is asked about once per retry window,
/// not on every query it sends: each query after a timeout used to start another PTR lookup
/// (and log another warning).
#[tokio::test]
async fn unanswered_client_is_not_looked_up_on_every_query() {
    let ctx = init_test_context();
    let tailnet = PtrUpstream::spawn("").await;
    ctx.set_reverse_resolvers(vec![reverse("100.64.0.0/10", &tailnet)]);
    let handle = serve(&ctx).await;
    let client = SocketAddr::new("100.64.0.5".parse().expect("client address"), 40000);
    let ask = |name: &str| DnsPacketBuilder::query(name, DnsRecordType::A).build_bytes();

    handle.inject(ask("one.lan"), client).await;
    handle.recv_reply().await.expect("a reply");
    // The upstream timeout is 3 s: the first lookup has failed by then.
    sleep(Duration::from_millis(3300)).await;
    handle.inject(ask("two.lan"), client).await;
    handle.recv_reply().await.expect("a reply");
    sleep(Duration::from_millis(100)).await;

    assert_eq!(tailnet.queries(), 1);
    ctx.terminate();
}
