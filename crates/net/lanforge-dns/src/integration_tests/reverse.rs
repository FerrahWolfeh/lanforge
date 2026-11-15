//! Reverse (PTR) routing through the serving DNS: conditional domain routes on long reverse
//! names, per-subnet reverse resolvers (`[dns.reverse]`) and the private reverse zones of
//! RFC 6303 / RFC 7793.

use super::common::{
    DnsPacketBuilder, extract_ptr, init_test_context, mock_config, parse_response,
    wait_for_service_online,
};
use crate::server::service::DnsService;
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_transport::InertHandle;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
};
use lanforge_types::system::ServiceId;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// A UDP resolver that answers every PTR question with one fixed name and counts the queries.
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
                let mut resp = DnsMessage::new();
                resp.header.id = req.header.id;
                resp.header.qr = true;
                resp.header.rd = req.header.rd;
                resp.header.ra = true;
                resp.header.qdcount = req.questions.len() as u16;
                resp.questions = req.questions.clone();
                match req.questions.first() {
                    Some(q) if q.qtype == DnsRecordType::PTR => resp.answers.push(DnsRecord {
                        name: Arc::clone(&q.name),
                        rtype: DnsRecordType::PTR,
                        rclass: DnsClass::IN,
                        ttl: 5,
                        rdata: DnsRData::PTR(Arc::from(name)),
                    }),
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
    let cfg = crate::config::DnsConfig {
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
