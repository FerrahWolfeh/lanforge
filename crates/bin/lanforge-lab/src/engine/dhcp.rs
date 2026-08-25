use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use lanforge_types::identifiers::MacAddr;
use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::LabError;
use crate::report::{DhcpStormReport, DoraResult};

/// Engine for simulating `DHCPv4` clients and high-throughput stress tests.
pub struct DhcpEngine {
    server_addr: SocketAddr,
    timeout_duration: Duration,
}

impl DhcpEngine {
    #[must_use]
    pub const fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout_duration: Duration::from_secs(3),
        }
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
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let _ = sock.set_broadcast(true);

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
        let server_id = offer_msg
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
        req_msg
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        req_msg
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offered_ip));
        if let Some(srv) = server_id {
            req_msg
                .opts_mut()
                .insert(DhcpOption::ServerIdentifier(srv));
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

        let subnet_mask =
            ack_msg
                .opts()
                .get(OptionCode::SubnetMask)
                .and_then(|opt| match opt {
                    DhcpOption::SubnetMask(ip) => Some(*ip),
                    _ => None,
                });
        let router = ack_msg.opts().get(OptionCode::Router).and_then(|opt| match opt {
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
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let start_time = Instant::now();

        let mut handles = Vec::with_capacity(total_clients);

        for i in 0..total_clients {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                LabError::Protocol(format!("Failed to acquire semaphore permit: {e}"))
            })?;
            let server_addr = self.server_addr;
            let engine = Self::new(server_addr).with_timeout(Duration::from_secs(2));

            // Generate deterministic unique test MAC address (e.g. 02:00:xx:xx:xx:xx)
            let b0 = 0x02;
            let b1 = 0x00;
            let b2 = (i >> 24) as u8;
            let b3 = (i >> 16) as u8;
            let b4 = (i >> 8) as u8;
            let b5 = i as u8;
            let mac = MacAddr([b0, b1, b2, b3, b4, b5]);

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                engine.simulate_dora(mac, None).await
            }));
        }

        let mut successful = 0;
        let mut failed = 0;
        let mut latencies = Vec::with_capacity(total_clients);

        for handle in handles {
            match handle.await {
                Ok(Ok(dora)) if dora.success => {
                    successful += 1;
                    latencies.push(dora.total_time_ms);
                }
                _ => {
                    failed += 1;
                }
            }
        }

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
}
