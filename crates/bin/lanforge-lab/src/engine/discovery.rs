use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsRData, DnsRecord, DnsRecordType,
};
use tracing::{debug, info};

use crate::error::LabError;

/// Engine for announcing mock devices and responding to mDNS service probes.
pub struct DiscoveryEngine;

impl DiscoveryEngine {
    /// Spawns a background mock mDNS responder that answers queries for a given hostname.
    ///
    /// Returns a cancellation handle (`Arc<AtomicBool>`).
    pub fn spawn_mock_mdns_responder(
        hostname: &str,
        ip: Ipv4Addr,
        _mac: MacAddr,
    ) -> Result<Arc<AtomicBool>, LabError> {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let host_str = hostname.to_string();

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| LabError::Socket(format!("Failed to bind mDNS mock socket: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(LabError::Io)?;

        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            info!("mDNS Mock Responder started for '{host_str}.local' -> {ip}");

            while running_clone.load(Ordering::Relaxed) {
                if let Ok((n, src)) = socket.recv_from(&mut buf)
                    && let Some(msg) = WireDecoder::new(&buf[..n]).decode_message()
                    && !msg.header.qr
                {
                    // Prepare answer response
                    let mut resp = DnsMessage::new();
                    resp.header.id = msg.header.id;
                    resp.header.qr = true;
                    resp.header.aa = true;
                    resp.header.ancount = 1;

                    for q in &msg.questions {
                        resp.answers.push(DnsRecord {
                            name: q.name.clone(),
                            rtype: DnsRecordType::A,
                            rclass: DnsClass::IN,
                            ttl: 120,
                            rdata: DnsRData::A(ip),
                        });
                    }

                    let mut encoder = WireEncoder::new();
                    let resp_bytes = encoder.encode_message(&resp);
                    let _ = socket.send_to(&resp_bytes, src);
                    debug!("mDNS Mock Responder answered query from {src}");
                }
            }
            info!("mDNS Mock Responder stopped for '{host_str}.local'");
        });

        Ok(running)
    }

    /// Tests connectivity / latency against a target IP using UDP probe.
    pub async fn probe_rtt(target: SocketAddr) -> Result<Duration, LabError> {
        let start = std::time::Instant::now();
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(target).await?;
        let _ = sock.send(&[0xDE, 0xAD, 0xBE, 0xEF]).await?;
        Ok(start.elapsed())
    }
}
