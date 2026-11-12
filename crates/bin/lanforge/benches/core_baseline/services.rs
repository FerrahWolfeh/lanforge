use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, ensure};
use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::{ConfigPatch, LanforgeContext};
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service, Dhcpv4Transport};
use lanforge_dns::config::DnsConfig;
use lanforge_dns::server::service::DnsService;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::{Dhcpv4Options, Dhcpv4Pool};
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType};
use lanforge_types::system::{ServiceId, ServiceState};
use serde_json::{Value, json};
use tokio::runtime::Builder;
use tokio::time::{sleep, timeout};

use super::{Args, Scenario, ip, mac, stats};

async fn ready(ctx: &LanforgeContext, id: ServiceId) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        while ctx.get_service_state(id) != ServiceState::Online {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .context("service did not become ready")
}

pub(super) fn run(ctx: &LanforgeContext, args: &Args) -> Result<Value> {
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut samples = Vec::with_capacity(args.iterations as usize);
        if matches!(args.scenario, Scenario::Dns | Scenario::DnsBusy) {
            let cfg = DnsConfig {
                enabled: true,
                search_domains: vec!["lan".to_string()],
                adblock_enabled: false,
                ..Default::default()
            };
            let (handle, mut service) = DnsService::inert(cfg, ctx.clone());
            let serving_ctx = ctx.clone();
            let task = tokio::spawn(async move {
                let h = ServiceHandle::new(ServiceId::Dns, serving_ctx.clone());
                service.serve(&serving_ctx, &h).await
            });
            ready(ctx, ServiceId::Dns).await?;
            let client = SocketAddr::new(IpAddr::V4(ip(0)), 53000);
            let packets: Vec<_> = (0..args.devices).map(|index| {
                dns_packet(index)
            }).collect();
            let mut profile = None;
            let mut writer = None;
            for sequence in 0..args.warmup + args.iterations {
                if sequence == args.warmup {
                    profile = super::start_profile();
                    if args.scenario == Scenario::DnsBusy { writer = Some(Writer::start(ctx.clone(), args.devices)); }
                }
                let index = sequence % args.devices;
                let started = Instant::now();
                handle.inject(packets[index as usize].clone(), client).await;
                let (reply, destination) = timeout(Duration::from_secs(2), handle.recv_reply()).await?.context("DNS reply missing")?;
                let elapsed = u64::try_from(started.elapsed().as_nanos())?;
                let message = WireDecoder::new(&reply).decode_message().context("invalid DNS reply")?;
                ensure!(destination == client && message.answers.iter().any(|answer| matches!(answer.rdata, DnsRData::A(address) if address == ip(index))), "incorrect local DNS answer");
                if sequence >= args.warmup { samples.push(elapsed); }
            }
            drop(writer);
            ctx.terminate();
            let _ = ctx.bus().publish(LanforgeEvent::System(SystemEvent::Shutdown));
            timeout(Duration::from_secs(5), task).await???;
            #[cfg(feature = "hotpath")]
            drop(profile);
            #[cfg(not(feature = "hotpath"))]
            let _ = profile;
        } else {
            let mut cfg = Dhcpv4Config { enabled: true, ..Default::default() };
            cfg.iface = "benchmark0".to_string();
            cfg.server_id = Ipv4Addr::new(10, 10, 0, 1);
            cfg.router = cfg.server_id;
            cfg.subnet_mask = Ipv4Addr::new(255, 255, 0, 0);
            cfg.pools = vec![Dhcpv4Pool {
                range_start: ip(0), range_end: ip(args.devices + 100),
                lease_time: Some(3600), router: Some(cfg.router), ..Default::default()
            }];
            ctx.apply_config(ConfigPatch::new().with_dhcp_v4_pools(cfg.pools.clone()).with_dhcp_v4_options(Dhcpv4Options { router: Some(cfg.router), subnet_mask: Some(cfg.subnet_mask), lease_time: cfg.lease_time, ..Default::default() }));
            let (handle, transport) = Dhcpv4Transport::inert();
            let mut service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
            let serving_ctx = ctx.clone();
            let task = tokio::spawn(async move {
                let h = ServiceHandle::new(ServiceId::Dhcp4, serving_ctx.clone());
                service.serve(&serving_ctx, &h).await
            });
            ready(ctx, ServiceId::Dhcp4).await?;
            let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);
            let mut profile = None;
            for sequence in 0..args.warmup + args.iterations {
                if sequence == args.warmup { profile = super::start_profile(); }
                let index = sequence % args.devices;
                let discover = dhcp_packet(mac(index), None)?;
                let started = Instant::now();
                handle.inject(discover, client).await;
                let offer = timeout(Duration::from_secs(2), handle.recv_reply()).await?.context("DHCP offer missing")?.message()?;
                ensure!(offer.opts().get(OptionCode::MessageType) == Some(&DhcpOption::MessageType(MessageType::Offer)), "expected OFFER");
                let offered = offer.yiaddr();
                let request = dhcp_packet(mac(index), Some((offered, cfg.server_id)))?;
                handle.inject(request, client).await;
                let ack = timeout(Duration::from_secs(2), handle.recv_reply()).await?.context("DHCP ACK missing")?.message()?;
                let elapsed = u64::try_from(started.elapsed().as_nanos())?;
                ensure!(ack.opts().get(OptionCode::MessageType) == Some(&DhcpOption::MessageType(MessageType::Ack)), "expected ACK");
                ensure!(ack.yiaddr() == offered && ctx.get_by_ip(&IpAddr::V4(offered)).is_some_and(|d| d.mac == mac(index)), "DHCP lease not committed");
                if sequence >= args.warmup { samples.push(elapsed); }
            }
            ctx.terminate();
            let _ = ctx.bus().publish(LanforgeEvent::System(SystemEvent::Shutdown));
            timeout(Duration::from_secs(5), task).await???;
            #[cfg(feature = "hotpath")]
            drop(profile);
            #[cfg(not(feature = "hotpath"))]
            let _ = profile;
        }
        Ok(json!({"round_trip": stats(samples), "transport": "inert", "runtime": "current_thread"}))
    })
}

fn dns_packet(index: u32) -> Vec<u8> {
    let mut message = DnsMessage::new();
    message.header.id = 1234;
    message.header.qdcount = 1;
    message.questions.push(DnsQuestion {
        name: format!("host-{index}.lan").into(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    WireEncoder::new().encode_message(&message)
}

fn dhcp_packet(mac: MacAddr, requested: Option<(Ipv4Addr, Ipv4Addr)>) -> Result<Vec<u8>> {
    let mut message = Message::new(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.0,
    );
    message.set_xid(42);
    message
        .opts_mut()
        .insert(DhcpOption::MessageType(if requested.is_some() {
            MessageType::Request
        } else {
            MessageType::Discover
        }));
    if let Some((ip, server)) = requested {
        message
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(ip));
        message
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(server));
    }
    let mut packet = Vec::new();
    message.encode(&mut Encoder::new(&mut packet))?;
    Ok(packet)
}

// Always stop and join the writer, including when a query assertion fails.
struct Writer {
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl Writer {
    fn start(ctx: LanforgeContext, devices: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let task = thread::spawn(move || {
            let mut sequence = 1;
            let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
            while !stopping.load(Ordering::Relaxed) {
                let _ = ctx.apply(super::lease(sequence % devices, epoch, sequence));
                sequence += 1;
            }
        });
        Self {
            stop,
            task: Some(task),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            task.join().expect("writer completed");
        }
    }
}
