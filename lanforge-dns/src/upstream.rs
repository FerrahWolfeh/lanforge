//! Upstream DNS forwarding with caching.
//!
//! Forwards non-local queries to an upstream resolver (e.g., Unbound)
//! via UDP with automatic TCP fallback on truncation (RFC 1035).
//! Responses are cached using [`DnsCache`](crate::cache::DnsCache).

use crate::cache::DnsCache;
use crate::error::DnsError;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot::{self, Sender};
use tokio::time::timeout;
use tracing::trace;

const DNS_CACHE_SIZE: u64 = 5000;

/// Manager for upstream DNS forwarding.
///
/// Maintains a single UDP socket shared by all forwarding requests,
/// a pending response map for routing replies to callers, and a local
/// response cache to reduce upstream traffic.
pub struct UpstreamManager {
    /// Shared UDP socket for sending queries and receiving responses.
    pub(crate) socket: Arc<UdpSocket>,
    /// Map from internal query ID to oneshot sender for response routing.
    pub(crate) pending: Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>,
    /// Monotonically increasing ID generator to avoid collisions.
    pub(crate) next_id: AtomicU16,
    /// Cache of upstream responses with TTL-based expiry.
    pub(crate) cache: Arc<DnsCache>,
}

impl UpstreamManager {
    /// Creates a new upstream manager and spawns the UDP listener task.
    ///
    /// The listener continuously reads from the shared socket and routes
    /// responses to pending queries based on DNS message ID.
    pub async fn new(upstream: SocketAddr) -> Result<Arc<Self>, DnsError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pending = Arc::new(Mutex::new(HashMap::<u16, Sender<Vec<u8>>>::new()));
        let cache = Arc::new(DnsCache::new(DNS_CACHE_SIZE));

        let s = Arc::clone(&socket);
        let p = Arc::clone(&pending);

        // Centralized listening task for upstream UDP responses.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((len, src)) = s.recv_from(&mut buf).await {
                    if src != upstream {
                        continue;
                    }
                    if len >= 2 {
                        let id = u16::from_be_bytes([buf[0], buf[1]]);
                        let tx = {
                            let mut map = p.lock().unwrap();
                            map.remove(&id)
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(buf[..len].to_vec());
                        }
                    }
                }
            }
        });

        Ok(Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU16::new(1),
            cache,
        }))
    }

    /// Forwards a DNS query to the upstream resolver via UDP with TCP fallback.
    ///
    /// # Flow
    ///
    /// 1. Check the local cache — return cached response if found
    /// 2. Assign a unique internal ID to avoid collisions between clients
    /// 3. Send via UDP and wait for response (3s timeout)
    /// 4. If response is truncated (TC flag), fall back to TCP
    /// 5. Restore the original query ID before returning and caching
    pub async fn forward(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let query = Message::from_bytes(data)?;

        // 1. Try the cache first
        if let Some(cached_resp) = self.cache.get(&query) {
            return Ok(cached_resp);
        }

        // 2. Try UDP
        let orig_id = query.id();
        let mut forward_query = query.clone();

        // Maps to a unique internal ID to avoid collisions between multiple LAN clients
        let internal_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        forward_query.set_id(internal_id);

        let data_to_send = forward_query.to_bytes()?;
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending.lock().unwrap();
            map.insert(internal_id, tx);
        }

        self.socket.send_to(&data_to_send, upstream).await?;

        let udp_result = match timeout(Duration::from_secs(3), rx).await {
            Ok(Ok(resp_bytes)) => {
                if let Ok(resp) = Message::from_bytes(&resp_bytes) {
                    // RFC 1035: If TC (truncated) flag is set, fall back to TCP
                    if resp.truncated() {
                        trace!("UDP response truncated, attempting TCP fallback");
                        self.forward_tcp(data, upstream).await
                    } else {
                        Ok(resp_bytes)
                    }
                } else {
                    return Err(DnsError::UdpDecode("Corrupt UDP response".to_string()));
                }
            }
            Ok(Err(_)) => return Err(DnsError::ChannelClosed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&internal_id);
                return Err(DnsError::UpstreamTimeout);
            }
        };

        match udp_result {
            Ok(resp_bytes) => {
                // Restore original query ID before returning and caching
                if let Ok(mut resp) = Message::from_bytes(&resp_bytes) {
                    resp.set_id(orig_id);
                    let final_bytes = resp.to_bytes()?;
                    self.cache.insert(&query, &resp, final_bytes.clone());
                    Ok(final_bytes)
                } else {
                    let mut raw = resp_bytes;
                    if raw.len() >= 2 {
                        let id_bytes = orig_id.to_be_bytes();
                        raw[0] = id_bytes[0];
                        raw[1] = id_bytes[1];
                    }
                    Ok(raw)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// TCP fallback for large DNS responses (e.g., DNSSEC or many records).
    ///
    /// Per RFC 1035, TCP DNS messages are prefixed with a 2-byte length field
    /// in big-endian order.
    async fn forward_tcp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        timeout(Duration::from_secs(5), async {
            // RFC 1035: TCP DNS data is prefixed with 2-byte length (Big Endian)
            let len = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(data).await?;

            // Read response length prefix
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await?;

            Ok::<Vec<u8>, Error>(resp_buf)
        })
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(DnsError::Io)
    }
}

/// Convenience function to forward a query to the upstream resolver.
pub async fn forward_to_upstream(
    data: &[u8],
    upstream: SocketAddr,
    manager: &UpstreamManager,
) -> Result<Vec<u8>, DnsError> {
    manager.forward(data, upstream).await
}
