use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use lanforge_types::identifiers::MacAddr;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::error::LabError;
use crate::report::{DhcpFloodReport, DhcpStormReport, DoraResult};

fn create_dhcp_socket(server_addr: SocketAddr, iface: Option<&str>) -> std::io::Result<UdpSocket> {
    let target_port = if server_addr.port() == 67 {
        Some(68)
    } else if server_addr.port() == 1067 {
        Some(1068)
    } else {
        None
    };

    if let Some(port) = target_port {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let _ = socket.set_reuse_address(true);
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        let _ = socket.set_reuse_port(true);
        let _ = socket.set_broadcast(true);

        if let Some(ifname) = iface {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            let _ = socket.bind_device(Some(ifname.as_bytes()));
        }

        let bind_addr: SocketAddr = ([0, 0, 0, 0], port).into();
        if socket.bind(&bind_addr.into()).is_ok() {
            let _ = socket.set_nonblocking(true);
            return UdpSocket::from_std(socket.into());
        }
    }

    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let _ = sock.set_broadcast(true);
    let _ = sock.set_nonblocking(true);
    UdpSocket::from_std(sock)
}

/// Engine for simulating `DHCPv4` clients and high-throughput stress tests.
pub struct DhcpEngine {
    server_addr: SocketAddr,
    timeout_duration: Duration,
    iface: Option<String>,
}

impl DhcpEngine {
    #[must_use]
    pub const fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout_duration: Duration::from_secs(3),
            iface: None,
        }
    }

    #[must_use]
    pub fn with_iface(mut self, iface: Option<String>) -> Self {
        self.iface = iface;
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout_duration = d;
        self
    }

    /// Simulates a single complete DHCP DORA flow for a client.
    pub async fn simulate_dora(
        &self,
        mac: MacAddr,
        hostname: Option<&str>,
    ) -> Result<DoraResult, LabError> {
        let start_total = Instant::now();
        let sock = create_dhcp_socket(self.server_addr, self.iface.as_deref())?;

        let mut xid_bytes = [0u8; 4];
        rand::rng().fill(&mut xid_bytes);
        let xid = u32::from_be_bytes(xid_bytes);

        // --- 1. DISCOVER ---
        let mut disc_msg = Message::new(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac.0,
        );
        disc_msg.set_xid(xid);
        disc_msg.set_flags(Flags::default().set_broadcast());
        disc_msg
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        if let Some(host) = hostname {
            disc_msg
                .opts_mut()
                .insert(DhcpOption::Hostname(host.to_string()));
        }

        let mut disc_buf = Vec::with_capacity(512);
        disc_msg
            .encode(&mut Encoder::new(&mut disc_buf))
            .map_err(|e| LabError::Protocol(format!("DHCP encode discover failed: {e}")))?;

        let t0 = Instant::now();
        sock.send_to(&disc_buf, self.server_addr).await?;

        // Await OFFER
        let mut recv_buf = [0u8; 1500];
        let offer_msg = match timeout(self.timeout_duration, async {
            loop {
                let (n, _) = sock.recv_from(&mut recv_buf).await?;
                if let Ok(msg) = Message::decode(&mut Decoder::new(&recv_buf[..n]))
                    && msg.xid() == xid
                    && msg.opts().get(OptionCode::MessageType)
                        == Some(&DhcpOption::MessageType(MessageType::Offer))
                {
                    return Ok::<Message, LabError>(msg);
                }
            }
        })
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                return Ok(DoraResult {
                    client_mac: mac.to_string(),
                    hostname: hostname.map(ToString::to_string),
                    offered_ip: None,
                    assigned_ip: None,
                    subnet_mask: None,
                    router: None,
                    dns_servers: Vec::new(),
                    lease_time_secs: None,
                    discover_to_offer_ms: t0.elapsed().as_secs_f64() * 1000.0,
                    request_to_ack_ms: 0.0,
                    total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
                    success: false,
                    error: Some("Timeout waiting for DHCP Offer".to_string()),
                });
            }
        };

        let disc_to_offer_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let offered_ip = offer_msg.yiaddr();
        let server_id =
            offer_msg
                .opts()
                .get(OptionCode::ServerIdentifier)
                .and_then(|opt| match opt {
                    DhcpOption::ServerIdentifier(ip) => Some(*ip),
                    _ => None,
                });

        // --- 2. REQUEST ---
        let mut req_msg = Message::new(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac.0,
        );
        req_msg.set_xid(xid);
        req_msg.set_flags(Flags::default().set_broadcast());
        req_msg
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        req_msg
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offered_ip));
        if let Some(srv) = server_id {
            req_msg.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
        }
        if let Some(host) = hostname {
            req_msg
                .opts_mut()
                .insert(DhcpOption::Hostname(host.to_string()));
        }

        let mut req_buf = Vec::with_capacity(512);
        req_msg
            .encode(&mut Encoder::new(&mut req_buf))
            .map_err(|e| LabError::Protocol(format!("DHCP encode request failed: {e}")))?;

        let t1 = Instant::now();
        sock.send_to(&req_buf, self.server_addr).await?;

        // Await ACK
        let ack_msg = match timeout(self.timeout_duration, async {
            loop {
                let (n, _) = sock.recv_from(&mut recv_buf).await?;
                if let Ok(msg) = Message::decode(&mut Decoder::new(&recv_buf[..n]))
                    && msg.xid() == xid
                    && msg.opts().get(OptionCode::MessageType)
                        == Some(&DhcpOption::MessageType(MessageType::Ack))
                {
                    return Ok::<Message, LabError>(msg);
                }
            }
        })
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                return Ok(DoraResult {
                    client_mac: mac.to_string(),
                    hostname: hostname.map(ToString::to_string),
                    offered_ip: Some(offered_ip),
                    assigned_ip: None,
                    subnet_mask: None,
                    router: None,
                    dns_servers: Vec::new(),
                    lease_time_secs: None,
                    discover_to_offer_ms: disc_to_offer_ms,
                    request_to_ack_ms: t1.elapsed().as_secs_f64() * 1000.0,
                    total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
                    success: false,
                    error: Some("Timeout waiting for DHCP Ack".to_string()),
                });
            }
        };

        let req_to_ack_ms = t1.elapsed().as_secs_f64() * 1000.0;
        let total_ms = start_total.elapsed().as_secs_f64() * 1000.0;

        let subnet_mask = ack_msg
            .opts()
            .get(OptionCode::SubnetMask)
            .and_then(|opt| match opt {
                DhcpOption::SubnetMask(ip) => Some(*ip),
                _ => None,
            });
        let router = ack_msg
            .opts()
            .get(OptionCode::Router)
            .and_then(|opt| match opt {
                DhcpOption::Router(ips) => ips.first().copied(),
                _ => None,
            });
        let dns_servers = ack_msg
            .opts()
            .get(OptionCode::DomainNameServer)
            .map_or_else(Vec::new, |opt| match opt {
                DhcpOption::DomainNameServer(ips) => ips.clone(),
                _ => Vec::new(),
            });
        let lease_time_secs = ack_msg
            .opts()
            .get(OptionCode::AddressLeaseTime)
            .and_then(|opt| match opt {
                DhcpOption::AddressLeaseTime(secs) => Some(*secs),
                _ => None,
            });

        Ok(DoraResult {
            client_mac: mac.to_string(),
            hostname: hostname.map(ToString::to_string),
            offered_ip: Some(offered_ip),
            assigned_ip: Some(ack_msg.yiaddr()),
            subnet_mask,
            router,
            dns_servers,
            lease_time_secs,
            discover_to_offer_ms: disc_to_offer_ms,
            request_to_ack_ms: req_to_ack_ms,
            total_time_ms: total_ms,
            success: true,
            error: None,
        })
    }

    /// Executes a concurrent DHCP storm benchmark.
    pub async fn storm_benchmark(
        &self,
        total_clients: usize,
        concurrency: usize,
    ) -> Result<DhcpStormReport, LabError> {
        let sock = Arc::new(create_dhcp_socket(self.server_addr, self.iface.as_deref())?);
        let pending = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<Message>>::new()));

        let listener_handle = {
            let sock = Arc::clone(&sock);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                while let Ok((n, _)) = sock.recv_from(&mut buf).await {
                    if let Ok(msg) = Message::decode(&mut Decoder::new(&buf[..n])) {
                        let xid = msg.xid();
                        let sender = {
                            let mut guard = pending.lock();
                            guard.remove(&xid)
                        };
                        if let Some(tx) = sender {
                            let _ = tx.send(msg);
                        }
                    }
                }
            })
        };

        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let start_time = Instant::now();
        let mut handles = Vec::with_capacity(total_clients);

        for i in 0..total_clients {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                LabError::Protocol(format!("Failed to acquire semaphore permit: {e}"))
            })?;
            let sock = Arc::clone(&sock);
            let pending = Arc::clone(&pending);
            let server_addr = self.server_addr;
            let timeout_duration = self.timeout_duration;

            let b0 = 0x02;
            let b1 = 0x00;
            let b2 = (i >> 24) as u8;
            let b3 = (i >> 16) as u8;
            let b4 = (i >> 8) as u8;
            let b5 = i as u8;
            let mac = MacAddr([b0, b1, b2, b3, b4, b5]);

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                simulate_dora_shared(&sock, &pending, server_addr, mac, None, timeout_duration)
                    .await
            }));
        }

        let mut successful = 0;
        let mut failed = 0;
        let mut latencies = Vec::with_capacity(total_clients);

        for handle in handles {
            match handle.await {
                Ok(dora) if dora.success => {
                    successful += 1;
                    latencies.push(dora.total_time_ms);
                }
                _ => {
                    failed += 1;
                }
            }
        }

        listener_handle.abort();

        let duration_secs = start_time.elapsed().as_secs_f64();
        let throughput = if duration_secs > 0.0 {
            successful as f64 / duration_secs
        } else {
            0.0
        };

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let (min, p50, p95, p99, max) = if latencies.is_empty() {
            (0.0, 0.0, 0.0, 0.0, 0.0)
        } else {
            let min = *latencies.first().unwrap_or(&0.0);
            let max = *latencies.last().unwrap_or(&0.0);
            let p50 = latencies[(latencies.len() * 50) / 100];
            let p95 = latencies[(latencies.len() * 95) / 100];
            let p99 = latencies[(latencies.len() * 99) / 100];
            (min, p50, p95, p99, max)
        };

        Ok(DhcpStormReport {
            total_clients,
            successful_leases: successful,
            failed_leases: failed,
            duration_secs,
            throughput_dora_per_sec: throughput,
            min_latency_ms: min,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            max_latency_ms: max,
        })
    }

    /// Executes a continuous high-rate DHCP Discover flood to stress-test the server CPU.
    pub async fn flood_benchmark(
        &self,
        target_pps: usize,
        duration: Duration,
    ) -> Result<DhcpFloodReport, LabError> {
        let start_time = Instant::now();
        let total_sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let concurrency = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        let mut handles = Vec::with_capacity(concurrency);

        let pps_per_worker = if target_pps > 0 {
            (target_pps / concurrency).max(1)
        } else {
            0
        };

        for worker_id in 0..concurrency {
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            let _ = sock.set_broadcast(true);
            let server_addr = self.server_addr;
            let total_sent = Arc::clone(&total_sent);
            let running = Arc::clone(&running);

            handles.push(tokio::spawn(async move {
                let mut buf = Vec::with_capacity(512);
                let mut counter: usize = 0;

                while running.load(std::sync::atomic::Ordering::Relaxed) {
                    let iter_start = Instant::now();
                    let batch_size = if pps_per_worker > 0 {
                        (pps_per_worker / 100).max(1)
                    } else {
                        100
                    };

                    for _ in 0..batch_size {
                        counter += 1;
                        let b2 = (worker_id >> 8) as u8;
                        let b3 = worker_id as u8;
                        let b4 = (counter >> 8) as u8;
                        let b5 = counter as u8;
                        let mac = [0x02, 0x00, b2, b3, b4, b5];
                        let xid = rand::rng().random_range(1..=u32::MAX);

                        let mut msg = Message::new(
                            Ipv4Addr::UNSPECIFIED,
                            Ipv4Addr::UNSPECIFIED,
                            Ipv4Addr::UNSPECIFIED,
                            Ipv4Addr::UNSPECIFIED,
                            &mac,
                        );
                        msg.set_xid(xid);
                        msg.set_flags(Flags::default().set_broadcast());
                        msg.opts_mut()
                            .insert(DhcpOption::MessageType(MessageType::Discover));
                        msg.opts_mut()
                            .insert(DhcpOption::Hostname(format!("flood-{worker_id}-{counter}")));

                        buf.clear();
                        if msg.encode(&mut Encoder::new(&mut buf)).is_ok() {
                            let _ = sock.send_to(&buf, server_addr).await;
                            total_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }

                    if pps_per_worker > 0 {
                        let expected_time = Duration::from_micros(
                            (batch_size as u64 * 1_000_000) / pps_per_worker as u64,
                        );
                        let elapsed = iter_start.elapsed();
                        if let Some(remaining) = expected_time.checked_sub(elapsed) {
                            tokio::time::sleep(remaining).await;
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(duration).await;
        running.store(false, std::sync::atomic::Ordering::Relaxed);

        for handle in handles {
            let _ = handle.await;
        }

        let elapsed_secs = start_time.elapsed().as_secs_f64();
        let sent = total_sent.load(std::sync::atomic::Ordering::Relaxed);
        let actual_pps = if elapsed_secs > 0.0 {
            sent as f64 / elapsed_secs
        } else {
            0.0
        };

        Ok(DhcpFloodReport {
            total_sent: sent,
            duration_secs: elapsed_secs,
            actual_pps,
        })
    }
}

async fn simulate_dora_shared(
    sock: &Arc<UdpSocket>,
    pending: &Arc<Mutex<HashMap<u32, oneshot::Sender<Message>>>>,
    server_addr: SocketAddr,
    mac: MacAddr,
    hostname: Option<&str>,
    timeout_duration: Duration,
) -> DoraResult {
    let start_total = Instant::now();
    let mut xid_bytes = [0u8; 4];
    rand::rng().fill(&mut xid_bytes);
    let xid = u32::from_be_bytes(xid_bytes);

    let mut disc_msg = Message::new(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.0,
    );
    disc_msg.set_xid(xid);
    disc_msg.set_flags(Flags::default().set_broadcast());
    disc_msg
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    if let Some(host) = hostname {
        disc_msg
            .opts_mut()
            .insert(DhcpOption::Hostname(host.to_string()));
    }

    let mut disc_buf = Vec::with_capacity(512);
    if let Err(e) = disc_msg.encode(&mut Encoder::new(&mut disc_buf)) {
        return DoraResult {
            client_mac: mac.to_string(),
            hostname: hostname.map(ToString::to_string),
            offered_ip: None,
            assigned_ip: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time_secs: None,
            discover_to_offer_ms: 0.0,
            request_to_ack_ms: 0.0,
            total_time_ms: 0.0,
            success: false,
            error: Some(format!("Encode discover failed: {e}")),
        };
    }

    let (offer_tx, offer_rx) = oneshot::channel();
    pending.lock().insert(xid, offer_tx);

    let t0 = Instant::now();
    if let Err(e) = sock.send_to(&disc_buf, server_addr).await {
        pending.lock().remove(&xid);
        return DoraResult {
            client_mac: mac.to_string(),
            hostname: hostname.map(ToString::to_string),
            offered_ip: None,
            assigned_ip: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time_secs: None,
            discover_to_offer_ms: 0.0,
            request_to_ack_ms: 0.0,
            total_time_ms: 0.0,
            success: false,
            error: Some(format!("Send discover failed: {e}")),
        };
    }

    let offer_msg = match timeout(timeout_duration, offer_rx).await {
        Ok(Ok(m))
            if m.opts().get(OptionCode::MessageType)
                == Some(&DhcpOption::MessageType(MessageType::Offer)) =>
        {
            m
        }
        _ => {
            pending.lock().remove(&xid);
            return DoraResult {
                client_mac: mac.to_string(),
                hostname: hostname.map(ToString::to_string),
                offered_ip: None,
                assigned_ip: None,
                subnet_mask: None,
                router: None,
                dns_servers: Vec::new(),
                lease_time_secs: None,
                discover_to_offer_ms: t0.elapsed().as_secs_f64() * 1000.0,
                request_to_ack_ms: 0.0,
                total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
                success: false,
                error: Some("Timeout waiting for DHCP Offer".to_string()),
            };
        }
    };

    let disc_to_offer_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let offered_ip = offer_msg.yiaddr();
    let server_id = offer_msg
        .opts()
        .get(OptionCode::ServerIdentifier)
        .and_then(|opt| match opt {
            DhcpOption::ServerIdentifier(ip) => Some(*ip),
            _ => None,
        });

    let mut req_msg = Message::new(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.0,
    );
    req_msg.set_xid(xid);
    req_msg.set_flags(Flags::default().set_broadcast());
    req_msg
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    req_msg
        .opts_mut()
        .insert(DhcpOption::RequestedIpAddress(offered_ip));
    if let Some(srv) = server_id {
        req_msg.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
    }
    if let Some(host) = hostname {
        req_msg
            .opts_mut()
            .insert(DhcpOption::Hostname(host.to_string()));
    }

    let mut req_buf = Vec::with_capacity(512);
    if let Err(e) = req_msg.encode(&mut Encoder::new(&mut req_buf)) {
        return DoraResult {
            client_mac: mac.to_string(),
            hostname: hostname.map(ToString::to_string),
            offered_ip: Some(offered_ip),
            assigned_ip: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time_secs: None,
            discover_to_offer_ms: disc_to_offer_ms,
            request_to_ack_ms: 0.0,
            total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
            success: false,
            error: Some(format!("Encode request failed: {e}")),
        };
    }

    let (ack_tx, ack_rx) = oneshot::channel();
    pending.lock().insert(xid, ack_tx);

    let t1 = Instant::now();
    if let Err(e) = sock.send_to(&req_buf, server_addr).await {
        pending.lock().remove(&xid);
        return DoraResult {
            client_mac: mac.to_string(),
            hostname: hostname.map(ToString::to_string),
            offered_ip: Some(offered_ip),
            assigned_ip: None,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            lease_time_secs: None,
            discover_to_offer_ms: disc_to_offer_ms,
            request_to_ack_ms: 0.0,
            total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
            success: false,
            error: Some(format!("Send request failed: {e}")),
        };
    }

    let ack_msg = match timeout(timeout_duration, ack_rx).await {
        Ok(Ok(m))
            if m.opts().get(OptionCode::MessageType)
                == Some(&DhcpOption::MessageType(MessageType::Ack)) =>
        {
            m
        }
        _ => {
            pending.lock().remove(&xid);
            return DoraResult {
                client_mac: mac.to_string(),
                hostname: hostname.map(ToString::to_string),
                offered_ip: Some(offered_ip),
                assigned_ip: None,
                subnet_mask: None,
                router: None,
                dns_servers: Vec::new(),
                lease_time_secs: None,
                discover_to_offer_ms: disc_to_offer_ms,
                request_to_ack_ms: t1.elapsed().as_secs_f64() * 1000.0,
                total_time_ms: start_total.elapsed().as_secs_f64() * 1000.0,
                success: false,
                error: Some("Timeout waiting for DHCP Ack".to_string()),
            };
        }
    };

    let req_to_ack_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let total_ms = start_total.elapsed().as_secs_f64() * 1000.0;

    let subnet_mask = ack_msg
        .opts()
        .get(OptionCode::SubnetMask)
        .and_then(|opt| match opt {
            DhcpOption::SubnetMask(ip) => Some(*ip),
            _ => None,
        });
    let router = ack_msg
        .opts()
        .get(OptionCode::Router)
        .and_then(|opt| match opt {
            DhcpOption::Router(ips) => ips.first().copied(),
            _ => None,
        });
    let dns_servers = ack_msg
        .opts()
        .get(OptionCode::DomainNameServer)
        .map_or_else(Vec::new, |opt| match opt {
            DhcpOption::DomainNameServer(ips) => ips.clone(),
            _ => Vec::new(),
        });
    let lease_time_secs =
        ack_msg
            .opts()
            .get(OptionCode::AddressLeaseTime)
            .and_then(|opt| match opt {
                DhcpOption::AddressLeaseTime(secs) => Some(*secs),
                _ => None,
            });

    DoraResult {
        client_mac: mac.to_string(),
        hostname: hostname.map(ToString::to_string),
        offered_ip: Some(offered_ip),
        assigned_ip: Some(ack_msg.yiaddr()),
        subnet_mask,
        router,
        dns_servers,
        lease_time_secs,
        discover_to_offer_ms: disc_to_offer_ms,
        request_to_ack_ms: req_to_ack_ms,
        total_time_ms: total_ms,
        success: true,
        error: None,
    }
}
