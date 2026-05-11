//! Upstream DNS forwarding with caching.
//!
//! Forwards non-local queries to an upstream resolver (e.g., Unbound)
//! via UDP with automatic TCP fallback on truncation (RFC 1035).
//! Responses are cached using [`DnsCache`](crate::cache::DnsCache).

use crate::cache::DnsCache;
use crate::config::{UpstreamProtocol, UpstreamTarget};
use crate::error::DnsError;
use crate::health::UpstreamHealth;
use crate::wire::{WireHeader, WireQuestion};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    pub cache: Arc<DnsCache>,
    /// The specific upstream target this manager handles.
    pub target: UpstreamTarget,
    /// Performance and health tracking for this upstream.
    pub health: Arc<UpstreamHealth>,
    /// Shared DoH client if this upstream uses HTTPS.
    #[cfg(feature = "doh-upstream")]
    pub doh_client: Option<crate::doh::DohClient>,
}

impl UpstreamManager {
    /// Creates a new upstream manager and spawns the UDP listener task.
    ///
    /// The listener continuously reads from the shared socket and routes
    /// responses to pending queries based on DNS message ID.
    pub async fn new(target: &UpstreamTarget) -> Result<Arc<Self>, DnsError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pending = Arc::new(Mutex::new(HashMap::<u16, Sender<Vec<u8>>>::new()));
        let cache = Arc::new(DnsCache::new(DNS_CACHE_SIZE));

        let s = Arc::clone(&socket);
        let p = Arc::clone(&pending);
        let upstream_addr = target.addr;

        // Centralized listening task for upstream UDP responses.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((len, src)) = s.recv_from(&mut buf).await {
                    if src != upstream_addr {
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
            target: target.clone(),
            health: Arc::new(UpstreamHealth::new()),
            #[cfg(feature = "doh-upstream")]
            doh_client: if target.protocol == UpstreamProtocol::Https {
                Some(crate::doh::DohClient::new())
            } else {
                None
            },
        }))
    }

    /// Forwards a DNS query to the upstream resolver.
    ///
    /// # Flow
    ///
    /// 1. Check the local cache — return cached response if found
    /// 2. If protocol is UDP, use UDP with TCP fallback
    /// 3. If protocol is TLS, use DNS-over-TLS
    /// 4. Restore the original query ID before returning and caching
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn forward(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
        let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;

        // 1. Try the cache first
        if let Some(cached_resp) = self.cache.get_wire(data, &question) {
            return Ok((cached_resp, true));
        }

        let orig_id = header.id();
        let start = Instant::now();

        let resp_result = match self.target.protocol {
            UpstreamProtocol::Udp => self.forward_udp(data, self.target.addr).await,
            UpstreamProtocol::Tls => self.forward_dot(data, &self.target).await,
            UpstreamProtocol::Quic => {
                #[cfg(feature = "doq")]
                {
                    self.forward_doq(data, &self.target).await
                }
                #[cfg(not(feature = "doq"))]
                {
                    Err(DnsError::Tls("DoQ feature not enabled".to_string()))
                }
            }
            UpstreamProtocol::Https => {
                #[cfg(feature = "doh-upstream")]
                {
                    if let Some(client) = &self.doh_client {
                        client.resolve(&self.target, data).await
                    } else {
                        Err(DnsError::Generic("DoH client not initialized".to_string()))
                    }
                }
                #[cfg(not(feature = "doh-upstream"))]
                {
                    Err(DnsError::Generic("DoH feature not enabled".to_string()))
                }
            }
        };

        let resp_bytes = match resp_result {
            Ok(resp) => {
                let rtt = start.elapsed().as_micros().try_into().unwrap_or(u32::MAX);
                self.health.record_success(rtt);
                resp
            }
            Err(e) => {
                self.health.record_failure();
                return Err(e);
            }
        };

        // Restore original query ID before returning and caching
        if let Ok(resp) = Message::from_bytes(&resp_bytes) {
            let mut final_bytes = resp_bytes;
            if final_bytes.len() >= 2 {
                let id_bytes = orig_id.to_be_bytes();
                final_bytes[0] = id_bytes[0];
                final_bytes[1] = id_bytes[1];
            }

            let key = crate::cache::CacheKey {
                qname: question.qname_raw().to_vec(),
                qtype: question.qtype(),
                qclass: question.qclass(),
            };
            self.cache.insert(key, &resp, final_bytes.clone());
            Ok((final_bytes, false))
        } else {
            let mut raw = resp_bytes;
            if raw.len() >= 2 {
                let id_bytes = orig_id.to_be_bytes();
                raw[0] = id_bytes[0];
                raw[1] = id_bytes[1];
            }
            Ok((raw, false))
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn forward_udp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        // Maps to a unique internal ID to avoid collisions between multiple LAN clients
        let internal_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let mut data_to_send = data.to_vec();
        WireHeader::patch_id(&mut data_to_send, internal_id);

        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending.lock().unwrap();
            map.insert(internal_id, tx);
        }

        self.socket.send_to(&data_to_send, upstream).await?;

        let udp_result: Result<Vec<u8>, DnsError> = match timeout(Duration::from_secs(3), rx).await
        {
            Ok(Ok(resp_bytes)) => {
                let header = WireHeader::parse(&resp_bytes).ok_or(DnsError::WireParseError)?;
                // RFC 1035: If TC (truncated) flag is set, fall back to TCP
                if header.tc() {
                    trace!("UDP response truncated, attempting TCP fallback");
                    self.forward_tcp(data, upstream).await
                } else {
                    Ok(resp_bytes)
                }
            }
            Ok(Err(_)) => Err(DnsError::ChannelClosed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&internal_id);
                Err(DnsError::UpstreamTimeout)
            }
        };

        udp_result
    }

    #[cfg(not(feature = "dot"))]
    #[allow(clippy::unused_async)]
    async fn forward_dot(
        &self,
        _data: &[u8],
        _target: &UpstreamTarget,
    ) -> Result<Vec<u8>, DnsError> {
        Err(DnsError::Tls("DoT feature not enabled".to_string()))
    }

    #[cfg(feature = "dot")]
    async fn forward_dot(&self, data: &[u8], target: &UpstreamTarget) -> Result<Vec<u8>, DnsError> {
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
        let server_name = ServerName::try_from(hostname)
            .map_err(|e| DnsError::Tls(format!("Invalid upstream hostname: {e}")))?
            .to_owned();

        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let tcp_stream = timeout(Duration::from_secs(5), TcpStream::connect(target.addr))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        timeout(Duration::from_secs(5), async {
            let len = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
            tls_stream.write_all(&len).await?;
            tls_stream.write_all(data).await?;

            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            tls_stream.read_exact(&mut resp_buf).await?;

            Ok::<Vec<u8>, Error>(resp_buf)
        })
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(DnsError::Io)
    }

    /// DNS-over-QUIC (`DoQ`) forwarding.
    #[cfg(feature = "doq")]
    async fn forward_doq(&self, data: &[u8], target: &UpstreamTarget) -> Result<Vec<u8>, DnsError> {
        use quinn::{ClientConfig, Endpoint, TransportConfig};
        use rustls::RootCertStore;
        use rustls_pki_types::ServerName;

        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
        let _server_name = ServerName::try_from(hostname)
            .map_err(|e| DnsError::Tls(format!("Invalid upstream hostname: {e}")))?
            .to_owned();

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"doq".to_vec()];

        let mut transport_config = TransportConfig::default();
        transport_config.max_idle_timeout(Some(Duration::from_secs(5).try_into().unwrap()));

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| DnsError::Tls(format!("QUIC config error: {e}")))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        let client_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = Endpoint::client(client_addr).map_err(DnsError::Io)?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(target.addr, hostname)
            .map_err(|e| DnsError::Tls(e.to_string()))?;
        let conn = timeout(Duration::from_secs(5), conn)
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        send.write_all(data)
            .await
            .map_err(|e| DnsError::Io(std::io::Error::other(e)))?;
        send.finish()
            .map_err(|e| DnsError::Io(std::io::Error::other(e)))?;

        let resp = recv
            .read_to_end(4096)
            .await
            .map_err(|e| DnsError::Io(std::io::Error::other(e)))?;
        Ok(resp)
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
    _target: &UpstreamTarget,
    manager: &UpstreamManager,
) -> Result<(Vec<u8>, bool), DnsError> {
    manager.forward(data).await
}
