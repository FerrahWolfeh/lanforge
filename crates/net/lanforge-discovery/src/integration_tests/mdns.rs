use crate::mdns::{MdnsConfig, MdnsProber};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_transport::{InertHandle, UdpTransport};
use lanforge_types::device::DeviceClass;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::{DnsClass, DnsMessage, DnsRData, DnsRecord, DnsRecordType};
use lanforge_types::system::{ServiceId, ServiceState};
use lanforge_types::update::DeviceUpdate;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const WAIT: Duration = Duration::from_secs(2);

fn context() -> LanforgeContext {
    LanforgeContext::new(Arc::new(EventBus::new()), State::new(), None)
}

/// A running prober: its command channel and task.
struct Running {
    cmd: mpsc::Sender<ServiceCommand>,
    task: JoinHandle<Result<(), CoreError>>,
}

impl Running {
    async fn stop(self) {
        self.cmd.send(ServiceCommand::Stop).await.expect("command");
        timeout(WAIT, self.task)
            .await
            .expect("serve returns on Stop")
            .expect("task")
            .expect("serve");
    }
}

async fn start(ctx: &LanforgeContext, mut prober: MdnsProber) -> Running {
    let (cmd, rx) = mpsc::channel(4);
    let h = ServiceHandle::with_command_channel(ServiceId::Mdns, ctx.clone(), rx);
    let c = ctx.clone();
    let task = tokio::spawn(async move { prober.serve(&c, &h).await });
    for _ in 0..200 {
        if ctx.get_service_state(ServiceId::Mdns) == ServiceState::Online {
            return Running { cmd, task };
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("mDNS did not come online");
}

/// The questions of the next query the prober sends, with its destination.
async fn next_query(
    handle: &InertHandle<SocketAddr>,
) -> (Vec<(String, DnsRecordType)>, SocketAddr) {
    let (bytes, to) = timeout(WAIT, handle.recv_reply())
        .await
        .expect("a query is sent")
        .expect("channel open");
    let msg = WireDecoder::new(&bytes)
        .decode_message()
        .expect("valid DNS");
    assert!(!msg.header.qr, "a query");
    let questions = msg
        .questions
        .iter()
        .map(|q| (q.name.to_string(), q.qtype))
        .collect();
    (questions, to)
}

fn answer(records: Vec<DnsRecord>) -> Vec<u8> {
    let mut msg = DnsMessage::new();
    msg.header.qr = true;
    msg.header.aa = true;
    msg.header.ancount = u16::try_from(records.len()).expect("few records");
    msg.answers = records;
    WireEncoder::new().encode_message(&msg)
}

fn ptr(name: &str, target: &str) -> DnsRecord {
    DnsRecord {
        name: Arc::from(name),
        rtype: DnsRecordType::PTR,
        rclass: DnsClass::IN,
        ttl: 120,
        rdata: DnsRData::PTR(Arc::from(target)),
    }
}

/// On start the prober asks the DNS-SD meta-query (RFC 6763 §9) on both groups, and a
/// responder's list of service types classifies its device.
#[tokio::test]
async fn meta_query_answers_classify_the_device() {
    let ctx = context();
    let mac = MacAddr([0x02, 0, 0, 0, 0, 0x31]);
    let ip = Ipv4Addr::new(192, 168, 3, 31);
    let _ = ctx.apply(DeviceUpdate::ArpSeen {
        mac,
        ip,
        is_active: true,
    });

    let (handle, transport) = UdpTransport::inert();
    let running = start(
        &ctx,
        MdnsProber::with_transport(MdnsConfig::default(), transport),
    )
    .await;

    let meta = (
        "_services._dns-sd._udp.local".to_string(),
        DnsRecordType::PTR,
    );
    let (q4, to4) = next_query(&handle).await;
    let (q6, to6) = next_query(&handle).await;
    assert_eq!(
        (q4, to4),
        (vec![meta.clone()], SocketAddr::from((MDNS_V4, 5353)))
    );
    assert_eq!((q6, to6), (vec![meta], SocketAddr::from((MDNS_V6, 5353))));

    handle
        .inject(
            answer(vec![ptr("_services._dns-sd._udp.local", "_ipp._tcp.local")]),
            SocketAddr::from((ip, 5353)),
        )
        .await;
    for _ in 0..100 {
        if ctx
            .get_device(&mac)
            .is_some_and(|d| d.class == DeviceClass::Printer)
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let dev = ctx.get_device(&mac).expect("device");
    assert_eq!(dev.class, DeviceClass::Printer);
    assert!(
        dev.hostname.name.is_empty(),
        "a service type is not a hostname"
    );

    running.stop().await;
}

fn sh(cmd: &str) {
    let ok = Command::new("sh")
        .args(["-c", cmd])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "`{cmd}` failed");
}

/// UDP sockets bound to port 5353 (`/proc/net/udp{,6}`, local port `14E9`).
fn sockets_on_5353() -> usize {
    ["/proc/net/udp", "/proc/net/udp6"]
        .iter()
        .map(|p| {
            fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .filter(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .is_some_and(|local| local.ends_with(":14E9"))
                })
                .count()
        })
        .sum()
}

/// Stopping the prober closes its sockets: a service restart must not leave a listener on 5353
/// (with `SO_REUSEPORT` a leftover one could take the answers). The old prober's blocking
/// listener threads held their sockets until the whole daemon stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace: unshare -rn <test binary> --ignored mdns_stop"]
async fn mdns_stop_closes_its_sockets() {
    sh("sysctl -qw net.ipv6.conf.default.accept_dad=0");
    sh("ip link add lfl0 type veth peer name lfl1");
    sh("for l in lo lfl0 lfl1; do ip link set $l up; done");
    sh("ip addr add 10.1.0.1/24 dev lfl0 && ip addr add 10.1.0.2/24 dev lfl1");

    let ctx = context();
    ctx.set_target_interface_name("lfl0".to_string());
    assert_eq!(sockets_on_5353(), 0);

    for round in 0..3 {
        let running = start(&ctx, MdnsProber::new(MdnsConfig::default())).await;
        assert!(
            sockets_on_5353() > 0,
            "round {round}: the prober listens on 5353"
        );
        running.stop().await;
        assert_eq!(
            sockets_on_5353(),
            0,
            "round {round}: a stopped prober keeps no socket on 5353"
        );
    }
    assert!(ctx.is_running(), "only the service stopped, not the daemon");
}
