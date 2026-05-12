pub mod cache;
pub mod strategy;

pub use cache::DnsCache;
pub use strategy::{UpstreamMode, UpstreamStrategy};

use crate::config::{UpstreamProtocol, UpstreamTarget};
use crate::error::DnsError;
use crate::utils::health::UpstreamHealth;
use crate::wire::{WireHeader, WireQuestion};
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

pub struct UpstreamManager {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) pending: Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>,
    pub(crate) next_id: AtomicU16,
    pub cache: Arc<DnsCache>,
    pub target: UpstreamTarget,
    pub health: Arc<UpstreamHealth>,
    #[cfg(feature = "doh-upstream")]
    pub doh_client: Option<crate::server::transport::doh::DohClient>,
}

impl UpstreamManager {
    pub async fn new(target: &UpstreamTarget) -> Result<Arc<Self>, DnsError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pending = Arc::new(Mutex::new(HashMap::<u16, Sender<Vec<u8>>>::new()));
        let cache = Arc::new(DnsCache::new(DNS_CACHE_SIZE));

        let s = Arc::clone(&socket);
        let p = Arc::clone(&pending);
        let upstream_addr = target.addr;

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
                Some(crate::server::transport::doh::DohClient::new())
            } else {
                None
            },
        }))
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn forward(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
        let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;

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

        let mut final_bytes = resp_bytes;
        if final_bytes.len() >= 2 {
            let id_bytes = orig_id.to_be_bytes();
            final_bytes[0] = id_bytes[0];
            final_bytes[1] = id_bytes[1];
        }

        let scanner = crate::wire::WireResponseScanner::new(&final_bytes);
        let (offsets, min_ttl) = scanner.scan_ttls();

        let key = cache::CacheKey {
            qname: question.qname_raw().to_vec(),
            qtype: question.qtype(),
            qclass: question.qclass(),
        };
        self.cache
            .insert(key, final_bytes.clone(), offsets, min_ttl);
        Ok((final_bytes, false))
    }

    async fn forward_udp(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
        let internal_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut data_to_send = data.to_vec();
        WireHeader::patch_id(&mut data_to_send, internal_id);

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(internal_id, tx);
        }

        self.socket.send_to(&data_to_send, upstream).await?;

        match timeout(Duration::from_secs(3), rx).await {
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
            Err(_) => {
                self.pending.lock().unwrap().remove(&internal_id);
                Err(DnsError::UpstreamTimeout)
            }
        }
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
        use quinn::{ClientConfig, Endpoint, TransportConfig};
        use rustls::RootCertStore;

        let hostname = target.hostname.as_deref().unwrap_or("dns.google");
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
