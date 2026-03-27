use crate::error::DnsError;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashMap;
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

        // Task de escuta centralizada para o upstream (UDP)
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((len, src)) = s.recv_from(&mut buf).await {
                    if src != upstream {
                        continue;
                    }
                    if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                        let id = msg.id();
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

        // 1. Tentar o Cache primeiro
        if let Some(cached_resp) = self.cache.get(&query) {
            return Ok(cached_resp);
        }

        // 2. Tentar UDP
        let orig_id = query.id();
        let mut forward_query = query.clone();

        // Mapeia para um ID interno único para evitar colisões entre clientes LAN
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
                    // RFC 1035: Se a flag TC está ativa, devemos fazer fallback para TCP
                    if resp.truncated() {
                        trace!("UDP resposta truncada, tentando TCP fallback");
                        self.forward_tcp(data, upstream).await
                    } else {
                        Ok(resp_bytes)
                    }
                } else {
                    return Err(DnsError::UdpDecode("Resposta UDP corrompida".to_string()));
                }
            }
            Ok(Err(_)) => return Err(DnsError::ChannelClosed),
            Err(_) => {
                let mut map = self.pending.lock().unwrap();
                map.remove(&internal_id);
                return Err(DnsError::UpstreamTimeout);
            }
        };

        match udp_result {
            Ok(resp_bytes) => {
                // Restaura o ID original antes de devolver ao cliente e salvar no cache
                if let Ok(mut resp) = Message::from_bytes(&resp_bytes) {
                    resp.set_id(orig_id);
                    let final_bytes = resp.to_bytes()?;
                    self.cache.insert(&query, &resp, final_bytes.clone());
                    Ok(final_bytes)
                } else {
                    // If Message::from_bytes failed, we still return the raw bytes if they were Ok from UDP
                    // This case should ideally not happen if the previous `if let Ok(resp) = Message::from_bytes(&resp_bytes)` passed.
                    // But if it failed *after* the TC check, we return the original bytes.
                    // However, the logic implies that if `Message::from_bytes` fails, it's an error.
                    // Let's assume if we reach here, `resp_bytes` is valid and we just need to restore ID.
                    // The `else` branch here means `Message::from_bytes(&resp_bytes)` failed *again*.
                    // This is a bit redundant, but keeping it as per user's snippet.
                    Ok(resp_bytes)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Implementação de Fallback TCP para resoluções grandes (ex: DNSSEC ou muitos records)
    async fn forward_tcp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        // RFC 1035: No TCP, os dados são prefixados por 2 bytes de comprimento (Big Endian)
        let len = (data.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(data).await?;

        // Lendo resposta
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        Ok(resp_buf)
    }
}

pub async fn forward_to_upstream(
    data: &[u8],
    upstream: SocketAddr,
    manager: &UpstreamManager,
) -> Result<Vec<u8>, DnsError> {
    manager.forward(data, upstream).await
}
