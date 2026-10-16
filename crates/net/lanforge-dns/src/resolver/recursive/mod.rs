pub mod cache;
pub mod strategy;

pub use cache::DnsCache;

use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
pub use strategy::{Resolved, UpstreamMode, UpstreamStrategy};
use tokio::task::{JoinHandle, yield_now};
#[cfg(feature = "dot")]
use tokio_rustls::TlsConnector;
#[cfg(feature = "dot")]
use tokio_rustls::client::TlsStream;

use crate::error::DnsError;
use crate::resolver::recursive::cache::CacheKey;
use crate::utils::health::{UpstreamHealth, UpstreamStatus};
use lanforge_dns_wire::{WireHeader, WireQuestion, WireResponseScanner};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot::{self, Sender};
use tokio::time::timeout;
use tracing::trace;

const DOT_POOL_MAX: usize = 8;

pub(crate) struct PendingQuery {
    pub sent_at: Instant,
    pub tx: Option<Sender<Vec<u8>>>,
}

pub struct UpstreamManager {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) pending: Arc<Mutex<HashMap<u16, PendingQuery>>>,
    pub(crate) next_id: AtomicU16,
    pub cache: Arc<DnsCache>,
    pub target: UpstreamTarget,
    pub health: Arc<UpstreamHealth>,
    #[cfg(feature = "doh-upstream")]
    pub doh_client: Option<crate::server::transport::doh::DohClient>,
    #[cfg(feature = "dot")]
    pub(crate) tls_connector: Option<TlsConnector>,
    #[cfg(feature = "dot")]
    pub(crate) dot_pool: tokio::sync::Mutex<Vec<TlsStream<TcpStream>>>,
    #[cfg(feature = "doq")]
    pub(crate) quic_endpoint: Option<quinn::Endpoint>,
    #[cfg(feature = "doq")]
    pub(crate) quic_conn: tokio::sync::Mutex<Option<quinn::Connection>>,
    pub(crate) rx_handle: Mutex<Option<JoinHandle<()>>>,
    pub(crate) probe_handle: Mutex<Option<JoinHandle<()>>>,
}

impl UpstreamManager {
    pub async fn new(target: &UpstreamTarget, cache: Arc<DnsCache>) -> Result<Arc<Self>, DnsError> {
        let socket = if target.addr.is_ipv4() {
            Arc::new(UdpSocket::bind("0.0.0.0:0").await?)
        } else {
            Arc::new(UdpSocket::bind("[::]:0").await?)
        };
        let pending = Arc::new(Mutex::new(HashMap::<u16, PendingQuery>::new()));

        #[cfg(any(feature = "dot", feature = "doq"))]
        let mut root_cert_store = rustls::RootCertStore::empty();
        #[cfg(any(feature = "dot", feature = "doq"))]
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(any(feature = "dot", feature = "doq"))]
        let shared_roots = Arc::new(root_cert_store);

        #[cfg(feature = "doq")]
        let quic_endpoint = if target.protocol == UpstreamProtocol::Quic {
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(Arc::clone(&shared_roots))
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"doq".to_vec()];

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            transport_config.keep_alive_interval(Some(Duration::from_secs(10)));

            let mut config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                    .map_err(|e| DnsError::Tls(format!("QUIC config error: {e}")))?,
            ));
            config.transport_config(Arc::new(transport_config));

            let bind_addr = if target.addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(DnsError::Io)?;
            endpoint.set_default_client_config(config);
            Some(endpoint)
        } else {
            None
        };

        let mgr = Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU16::new(1),
            cache,
            target: target.clone(),
            health: Arc::new(UpstreamHealth::new()),
            #[cfg(feature = "doh-upstream")]
            doh_client: if target.protocol == UpstreamProtocol::Https {
                Some(crate::server::transport::doh::DohClient::new())
            } else {
                None
            },
            #[cfg(feature = "dot")]
            tls_connector: if target.protocol == UpstreamProtocol::Tls {
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::clone(&shared_roots))
                    .with_no_client_auth();
                Some(TlsConnector::from(Arc::new(config)))
            } else {
                None
            },
            #[cfg(feature = "dot")]
            dot_pool: tokio::sync::Mutex::new(Vec::new()),
            #[cfg(feature = "doq")]
            quic_endpoint,
            #[cfg(feature = "doq")]
            quic_conn: tokio::sync::Mutex::new(None),
            rx_handle: Mutex::new(None),
            probe_handle: Mutex::new(None),
        });

        let s = Arc::clone(&mgr.socket);
        let p = Arc::clone(&mgr.pending);
        let health_rx = Arc::clone(&mgr.health);
        let upstream_addr = mgr.target.addr;

        let rx_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match s.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if src != upstream_addr {
                            continue;
                        }
                        if len >= 2 {
                            let id = u16::from_be_bytes([buf[0], buf[1]]);
                            let entry = {
                                let mut map = p.lock();
                                map.remove(&id)
                            };
                            if let Some(entry) = entry {
                                if let Some(tx) = entry.tx {
                                    let _ = tx.send(buf[..len].to_vec());
                                } else if len >= 12 {
                                    let rtt = entry
                                        .sent_at
                                        .elapsed()
                                        .as_micros()
                                        .try_into()
                                        .unwrap_or(u32::MAX);
                                    health_rx.record_success(rtt);
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        yield_now().await;
                    }
                    Err(e) => {
                        match e.kind() {
                            ErrorKind::Interrupted
                            | ErrorKind::ConnectionRefused
                            | ErrorKind::ConnectionReset
                            | ErrorKind::NetworkUnreachable
                            | ErrorKind::HostUnreachable => {
                                // Ignore transient UDP network errors
                            }
                            _ => {
                                tracing::warn!(
                                    "Fatal DNS UDP upstream receiver error for {}: {}",
                                    upstream_addr,
                                    e
                                );
                                break;
                            }
                        }
                    }
                }
            }
        });
        *mgr.rx_handle.lock() = Some(rx_task);

        let weak_mgr = Arc::downgrade(&mgr);
        let probe_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if let Some(mgr_clone) = weak_mgr.upgrade() {
                    if mgr_clone.health.status() == UpstreamStatus::Degraded
                        && mgr_clone.health.is_eligible_for_probing()
                    {
                        let _ = mgr_clone.probe().await;
                    }
                } else {
                    break;
                }
            }
        });
        *mgr.probe_handle.lock() = Some(probe_task);

        Ok(mgr)
    }

    async fn send_query_wire(&self, data: &[u8]) -> Result<Vec<u8>, DnsError> {
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

        match resp_result {
            Ok(resp) => {
                let rtt = start.elapsed().as_micros().try_into().unwrap_or(u32::MAX);
                self.health.record_success(rtt);
                Ok(resp)
            }
            Err(e) => {
                self.health.record_failure();
                Err(e)
            }
        }
    }

    /// Sends a direct network probe bypassing the DNS cache to verify upstream recovery.
    pub async fn probe(&self) -> Result<(), DnsError> {
        const PROBE_QUERY: &[u8] = &[
            0x00, 0x01, // ID: 1
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x00, // QNAME: .
            0x00, 0x01, // QTYPE: A (1)
            0x00, 0x01, // QCLASS: IN (1)
        ];
        self.send_query_wire(PROBE_QUERY).await.map(|_| ())
    }

    /// Forwards a pre-parsed query to the upstream without repeating a cache lookup.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn forward_with_parsed(
        &self,
        data: &[u8],
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let orig_id = header.id();
        let mut final_bytes = self.send_query_wire(data).await?;

        if final_bytes.len() >= 2 {
            let id_bytes = orig_id.to_be_bytes();
            final_bytes[0] = id_bytes[0];
            final_bytes[1] = id_bytes[1];
        }

        let scanner = WireResponseScanner::new(&final_bytes);
        let (offsets, min_ttl) = scanner.scan_ttls();

        let key = CacheKey::from_question(question);

        // Only cache NOERROR (0) and NXDOMAIN (3)
        if let Some(resp_header) = WireHeader::parse(&final_bytes) {
            let rcode = resp_header.rcode();
            if rcode == 0 || rcode == 3 {
                self.cache
                    .insert(key, final_bytes.clone(), offsets, min_ttl, false);
            }
        }
        Ok((final_bytes, false, false))
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn forward(&self, data: &[u8]) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
        let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;

        if let Some((cached_resp, is_block)) = self.cache.get_wire(data, &question) {
            return Ok((cached_resp, true, is_block));
        }

        self.forward_with_parsed(data, &header, &question).await
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn forward_udp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let internal_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut data_to_send = smallvec::SmallVec::<[u8; 512]>::from_slice(data);
        WireHeader::patch_id(&mut data_to_send, internal_id);

        let (tx, rx) = oneshot::channel();
        let now = Instant::now();
        {
            let mut map = self.pending.lock();
            if map.len() > 64 {
                map.retain(|_, v| now.duration_since(v.sent_at) < Duration::from_secs(5));
            }
            map.insert(
                internal_id,
                PendingQuery {
                    sent_at: now,
                    tx: Some(tx),
                },
            );
        }

        struct PendingGuard<'a> {
            pending: &'a Mutex<HashMap<u16, PendingQuery>>,
            id: u16,
            completed_or_timed_out: bool,
        }
        impl<'a> Drop for PendingGuard<'a> {
            fn drop(&mut self) {
                let mut map = self.pending.lock();
                if self.completed_or_timed_out {
                    map.remove(&self.id);
                } else if let Some(entry) = map.get_mut(&self.id) {
                    entry.tx = None;
                }
            }
        }
        let mut guard = PendingGuard {
            pending: &self.pending,
            id: internal_id,
            completed_or_timed_out: false,
        };

        if let Err(e) = self.socket.send_to(&data_to_send, upstream).await {
            guard.completed_or_timed_out = true;
            return Err(DnsError::Io(e));
        }

        let timeout_dur = if self.health.consecutive_failures.load(Ordering::Relaxed) >= 5 {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(3)
        };

        let res = timeout(timeout_dur, rx).await;
        guard.completed_or_timed_out = true;

        match res {
            Ok(Ok(resp_bytes)) => {
                let header = WireHeader::parse(&resp_bytes).ok_or(DnsError::WireParseError)?;
                if header.tc() {
                    trace!("UDP response truncated, attempting TCP fallback");
                    self.forward_tcp(data, upstream).await
                } else {
                    Ok(resp_bytes)
                }
            }
            Ok(Err(_)) => Err(DnsError::ChannelClosed),
            Err(_) => Err(DnsError::UpstreamTimeout),
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[cfg(feature = "dot")]
    async fn forward_dot(&self, data: &[u8], target: &UpstreamTarget) -> Result<Vec<u8>, DnsError> {
        // 1. Try to grab a connection from the pool
        let conn = {
            let mut pool = self.dot_pool.lock().await;
            pool.pop()
        };

        if let Some(mut stream) = conn {
            match Self::dot_exchange(&mut stream, data).await {
                Ok(resp) => {
                    // Success, return to pool
                    let mut pool = self.dot_pool.lock().await;
                    if pool.len() < DOT_POOL_MAX {
                        pool.push(stream);
                    }
                    return Ok(resp);
                }
                Err(_) => {
                    // Connection dead, fall through to reconnect
                    trace!("Cached DoT connection dead, reconnecting...");
                }
            }
        }

        // 2. Reconnect/Initial connect
        let mut stream = self.dot_connect(target).await?;
        let resp = Self::dot_exchange(&mut stream, data).await?;

        // 3. Return to pool
        let mut pool = self.dot_pool.lock().await;
        if pool.len() < DOT_POOL_MAX {
            pool.push(stream);
        }

        Ok(resp)
    }

    #[cfg(feature = "dot")]
    async fn dot_connect(&self, target: &UpstreamTarget) -> Result<TlsStream<TcpStream>, DnsError> {
        use rustls_pki_types::ServerName;

        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
        let server_name = ServerName::try_from(hostname)
            .map_err(|e| DnsError::Tls(format!("Invalid upstream hostname: {e}")))?
            .to_owned();

        let connector = self
            .tls_connector
            .as_ref()
            .ok_or_else(|| DnsError::Generic("TLS connector not initialized".to_string()))?;

        let tcp_stream = timeout(Duration::from_secs(5), TcpStream::connect(target.addr))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        let tls_stream = connector.connect(server_name, tcp_stream).await?;
        Ok(tls_stream)
    }

    #[cfg(feature = "dot")]
    async fn dot_exchange(
        stream: &mut TlsStream<TcpStream>,
        data: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        timeout(Duration::from_secs(5), async {
            let len = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(data).await?;

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

    #[cfg(not(feature = "dot"))]
    async fn forward_dot(
        &self,
        _data: &[u8],
        _target: &UpstreamTarget,
    ) -> Result<Vec<u8>, DnsError> {
        Err(DnsError::Tls("DoT feature not enabled".to_string()))
    }

    #[cfg(feature = "doq")]
    async fn forward_doq(&self, data: &[u8], target: &UpstreamTarget) -> Result<Vec<u8>, DnsError> {
        let mut guard = self.quic_conn.lock().await;

        // 1. Try existing connection
        if let Some(conn) = guard.as_ref() {
            if conn.close_reason().is_none() {
                match Self::doq_exchange(conn, data).await {
                    Ok(resp) => return Ok(resp),
                    Err(_) => {
                        trace!("Cached DoQ connection dead, reconnecting...");
                        *guard = None;
                    }
                }
            } else {
                *guard = None;
            }
        }

        // 2. Reconnect
        let conn = self.doq_connect(target).await?;
        let resp = Self::doq_exchange(&conn, data).await?;

        // 3. Store for reuse
        *guard = Some(conn);
        Ok(resp)
    }

    #[cfg(feature = "doq")]
    async fn doq_connect(&self, target: &UpstreamTarget) -> Result<quinn::Connection, DnsError> {
        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
        let endpoint = self
            .quic_endpoint
            .as_ref()
            .ok_or_else(|| DnsError::Generic("QUIC endpoint not initialized".to_string()))?;

        let conn = endpoint
            .connect(target.addr, hostname)
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        let conn = timeout(Duration::from_secs(5), conn)
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        Ok(conn)
    }

    #[cfg(feature = "doq")]
    async fn doq_exchange(conn: &quinn::Connection, data: &[u8]) -> Result<Vec<u8>, DnsError> {
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

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn forward_tcp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(upstream))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;

        timeout(Duration::from_secs(5), async {
            let len = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(data).await?;

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

impl Drop for UpstreamManager {
    fn drop(&mut self) {
        if let Some(h) = self.rx_handle.lock().take() {
            h.abort();
        }
        if let Some(h) = self.probe_handle.lock().take() {
            h.abort();
        }
    }
}
