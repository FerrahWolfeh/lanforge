use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::LabError;
use crate::report::{DnsFloodReport, DnsQueryResult};

/// Engine for simulating DNS client queries and high-QPS benchmarks.
pub struct DnsEngine {
    server_addr: SocketAddr,
    timeout_duration: Duration,
}

impl DnsEngine {
    #[must_use]
    pub const fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            timeout_duration: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub const fn with_timeout(mut self, d: Duration) -> Self {
        self.timeout_duration = d;
        self
    }

    /// Performs a single DNS query against the target server.
    pub async fn query(
        &self,
        domain: &str,
        qtype: DnsRecordType,
    ) -> Result<DnsQueryResult, LabError> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(self.server_addr).await?;

        let id = rand::rng().random_range(1000..=65535);

        let mut query = DnsMessage::new();
        query.header.id = id;
        query.header.rd = true;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from(domain),
            qtype,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&query);

        let start = Instant::now();
        sock.send(&query_bytes).await?;

        let mut buf = [0u8; 2048];
        let n = timeout(self.timeout_duration, sock.recv(&mut buf))
            .await
            .map_err(|_| LabError::Timeout(format!("DNS query for '{domain}'")))?
            .map_err(LabError::Io)?;

        let latency_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

        let mut decoder = WireDecoder::new(&buf[..n]);
        let response = decoder
            .decode_message()
            .ok_or_else(|| LabError::Protocol("Failed to decode DNS wire response".to_string()))?;

        let rcode_str = format!("{:?}", response.header.rcode);
        let mut answers = Vec::new();
        let mut resolved_ip = None;
        let mut is_blocked = false;

        for ans in &response.answers {
            match &ans.rdata {
                DnsRData::A(v4) => {
                    answers.push(v4.to_string());
                    if resolved_ip.is_none() {
                        resolved_ip = Some(IpAddr::V4(*v4));
                    }
                    if v4.is_unspecified() {
                        is_blocked = true;
                    }
                }
                DnsRData::AAAA(v6) => {
                    answers.push(v6.to_string());
                    if resolved_ip.is_none() {
                        resolved_ip = Some(IpAddr::V6(*v6));
                    }
                    if v6.is_unspecified() {
                        is_blocked = true;
                    }
                }
                DnsRData::PTR(name) => {
                    answers.push(name.to_string());
                }
                DnsRData::CNAME(name) => {
                    answers.push(format!("CNAME {name}"));
                }
                _ => {
                    answers.push("OTHER".to_string());
                }
            }
        }

        if response.header.rcode == DnsResponseCode::NXDomain && is_blocked {
            is_blocked = true;
        }

        Ok(DnsQueryResult {
            query_domain: domain.to_string(),
            query_type: format!("{qtype:?}"),
            rcode: rcode_str,
            answers,
            latency_us,
            is_blocked,
            resolved_ip,
        })
    }

    /// Executes a high-QPS DNS flood benchmark.
    pub async fn flood_benchmark(
        &self,
        target_qps: usize,
        duration: Duration,
        domains: &[String],
    ) -> Result<DnsFloodReport, LabError> {
        let domain_list: Vec<String> = if domains.is_empty() {
            vec![
                "google.com".to_string(),
                "lanforge.lan".to_string(),
                "doubleclick.net".to_string(),
                "github.com".to_string(),
                "adservice.google.com".to_string(),
            ]
        } else {
            domains.to_vec()
        };

        let start_time = Instant::now();
        let total_queries = (target_qps as f64 * duration.as_secs_f64()) as usize;
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(100));

        let mut handles = Vec::with_capacity(total_queries);

        for i in 0..total_queries {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                LabError::Protocol(format!("Failed to acquire semaphore permit: {e}"))
            })?;
            let domain = domain_list[i % domain_list.len()].clone();
            let server_addr = self.server_addr;
            let engine = Self::new(server_addr).with_timeout(Duration::from_millis(500));

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                engine.query(&domain, DnsRecordType::A).await
            }));

            // Pace requests if needed
            if i % (target_qps.max(1) / 10).max(1) == 0 {
                tokio::task::yield_now().await;
            }
        }

        let mut successful = 0;
        let mut failed = 0;
        let mut blocked_count = 0;
        let mut latencies = Vec::with_capacity(total_queries);

        for handle in handles {
            match handle.await {
                Ok(Ok(res)) => {
                    successful += 1;
                    latencies.push(res.latency_us);
                    if res.is_blocked {
                        blocked_count += 1;
                    }
                }
                _ => {
                    failed += 1;
                }
            }
        }

        let duration_secs = start_time.elapsed().as_secs_f64();
        let actual_qps = if duration_secs > 0.0 {
            successful as f64 / duration_secs
        } else {
            0.0
        };

        latencies.sort_unstable();

        let (min, p50, p95, p99, max) = if latencies.is_empty() {
            (0, 0, 0, 0, 0)
        } else {
            let min = *latencies.first().unwrap_or(&0);
            let max = *latencies.last().unwrap_or(&0);
            let p50 = latencies[(latencies.len() * 50) / 100];
            let p95 = latencies[(latencies.len() * 95) / 100];
            let p99 = latencies[(latencies.len() * 99) / 100];
            (min, p50, p95, p99, max)
        };

        Ok(DnsFloodReport {
            total_queries,
            successful_queries: successful,
            failed_queries: failed,
            duration_secs,
            actual_qps,
            min_latency_us: min,
            p50_latency_us: p50,
            p95_latency_us: p95,
            p99_latency_us: p99,
            max_latency_us: max,
            blocked_count,
        })
    }
}
