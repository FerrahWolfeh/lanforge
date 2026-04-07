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

use crate::cache::DnsCache;
const DNS_CACHE_SIZE: u64 = 5000;

pub struct UpstreamManager {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) pending: Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>,
    pub(crate) next_id: AtomicU16,
    pub(crate) cache: Arc<DnsCache>,
}

impl UpstreamManager {
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

    pub async fn forward(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let query = Message::from_bytes(data)?;

        // 1. Try the Cache first.
        if let Some(cached_resp) = self.cache.get(&query) {
            return Ok(cached_resp);
        }

        // 2. Try UDP.
        let orig_id = query.id();
        let mut forward_query = query.clone();

        // Maps to a unique internal ID to avoid collisions between multiple LAN clients.
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
                    // RFC 1035: If the TC (truncated) flag is set, we must fallback to TCP.
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
                // Restore the original query ID before returning to the client and caching the response.
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

    /// TCP fallback implementation for large DNS resolutions (e.g., DNSSEC or many records).
    async fn forward_tcp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        timeout(Duration::from_secs(5), async {
            // RFC 1035: In TCP, DNS data is prefixed by its 2-byte length (Big Endian).
            let len = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(data).await?;

            // Reading response...
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

pub async fn forward_to_upstream(
    data: &[u8],
    upstream: SocketAddr,
    manager: &UpstreamManager,
) -> Result<Vec<u8>, DnsError> {
    manager.forward(data, upstream).await
}
