use crate::error::DnsError;
use crate::resolver::recursive::UpstreamManager;
use crate::resolver::recursive::cache::CacheKey;
use crate::utils::health::UpstreamStatus;
use dashmap::DashMap;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireQuestion};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordType, UpstreamHealthSnapshot,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::broadcast::Sender;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Sequential,
    Parallel,
    Fastest,
    RoundRobin,
}

type InFlightTx = Sender<Result<(Vec<u8>, bool, bool), String>>;

pub struct UpstreamStrategy {
    pub mode: UpstreamMode,
    /// Upstreams grouped by protocol tier. Index 0 = tier 0 (TLS/QUIC), etc.
    tiers: parking_lot::RwLock<Vec<Vec<Arc<UpstreamManager>>>>,
    fallback_upstreams: parking_lot::RwLock<Vec<Arc<UpstreamManager>>>,
    pub rr_index: AtomicUsize,
    in_flight: DashMap<CacheKey, InFlightTx>,
}

impl UpstreamStrategy {
    #[must_use]
    pub fn new(mode: UpstreamMode, upstreams: Vec<Arc<UpstreamManager>>) -> Self {
        let max_tier = upstreams
            .iter()
            .map(|m| m.target.protocol.tier() as usize)
            .max()
            .unwrap_or(0);

        let mut tiers = vec![Vec::new(); max_tier + 1];
        for mgr in upstreams {
            tiers[mgr.target.protocol.tier() as usize].push(mgr);
        }

        Self {
            mode,
            tiers: parking_lot::RwLock::new(tiers),
            fallback_upstreams: parking_lot::RwLock::new(Vec::new()),
            rr_index: AtomicUsize::new(0),
            in_flight: DashMap::new(),
        }
    }

    pub fn replace_upstreams(&self, upstreams: Vec<Arc<UpstreamManager>>) {
        let max_tier = upstreams
            .iter()
            .map(|m| m.target.protocol.tier() as usize)
            .max()
            .unwrap_or(0);

        let mut tiers = vec![Vec::new(); max_tier + 1];
        for mgr in upstreams {
            tiers[mgr.target.protocol.tier() as usize].push(mgr);
        }
        *self.tiers.write() = tiers;
    }

    pub fn replace_fallback_upstreams(&self, fallbacks: Vec<Arc<UpstreamManager>>) {
        *self.fallback_upstreams.write() = fallbacks;
    }


    /// Flat iterator of all upstreams.
    pub fn all_upstreams(&self) -> impl Iterator<Item = Arc<UpstreamManager>> {
        let tiers = self.tiers.read().clone();
        tiers.into_iter().flat_map(|t| t.into_iter())
    }

    /// Returns true if no upstreams are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tiers.read().iter().all(|t| t.is_empty())
    }

    pub fn snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        let mut snaps: Vec<_> = self
            .all_upstreams()
            .map(|m| {
                #[allow(unused_mut)]
                let mut snap = m.health.snapshot(m.target.addr, m.target.protocol);

                #[cfg(not(feature = "dot"))]
                if m.target.protocol == UpstreamProtocol::Tls {
                    snap.status = "Disabled (Feature)".to_string();
                }

                #[cfg(not(feature = "doq"))]
                if m.target.protocol == UpstreamProtocol::Quic {
                    snap.status = "Disabled (Feature)".to_string();
                }

                #[cfg(not(feature = "doh-upstream"))]
                if m.target.protocol == UpstreamProtocol::Https {
                    snap.status = "Disabled (Feature)".to_string();
                }

                snap
            })
            .collect();

        // Sort by tier, then by status (Healthy first)
        snaps.sort_by(|a, b| {
            a.protocol.tier().cmp(&b.protocol.tier()).then_with(|| {
                // Keep Healthy at top if possible
                let status_rank = |s: &str| match s {
                    "Healthy" => 0,
                    "Degraded" => 1,
                    _ => 2,
                };
                status_rank(&a.status).cmp(&status_rank(&b.status))
            })
        });

        snaps
    }

    pub async fn resolve(&self, data: &[u8]) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;
        let mut qname = question.qname_raw().to_vec();
        qname.make_ascii_lowercase();
        let key = CacheKey {
            qname,
            qtype: question.qtype(),
            qclass: question.qclass(),
        };

        let rx = { self.in_flight.get(&key).map(|tx| tx.subscribe()) };

        if let Some(mut rx) = rx {
            match rx.recv().await {
                Ok(Ok(res)) => return Ok(res),
                Ok(Err(e)) => return Err(DnsError::Generic(e)),
                Err(_) => {
                    // Leader task dropped/panicked, fall through to resolve_internal
                }
            }
        }

        let (tx, _) = tokio::sync::broadcast::channel(1);
        self.in_flight.insert(key.clone(), tx.clone());

        let res = self.resolve_internal(data).await;

        self.in_flight.remove(&key);
        let _ = tx.send(
            res.as_ref()
                .map(|(v, c, b)| (v.clone(), *c, *b))
                .map_err(|e| e.to_string()),
        );

        res
    }

    async fn resolve_internal(&self, data: &[u8]) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut last_err = DnsError::Refused;
        if self.is_empty() {
            let fallbacks = self.fallback_upstreams.read().clone();
            if !fallbacks.is_empty() {
                return self.resolve_sequential(&fallbacks, data).await;
            }
        }
        let tiers = self.tiers.read().clone();
        for tier in &tiers {
            if tier.is_empty() {
                continue;
            }

            match self.resolve_tier(tier, data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }


    async fn resolve_tier(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        match self.mode {
            UpstreamMode::Sequential => self.resolve_sequential(tier, data).await,
            UpstreamMode::Parallel => self.resolve_parallel(tier, data).await,
            UpstreamMode::Fastest => self.resolve_fastest(tier, data).await,
            UpstreamMode::RoundRobin => self.resolve_round_robin(tier, data).await,
        }
    }

    async fn resolve_sequential(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut last_err = DnsError::UpstreamTimeout;
        let mut available: Vec<_> = tier
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .collect();
        if available.is_empty() {
            available = tier.iter().collect();
        }

        for mgr in available {
            match mgr.forward(data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn resolve_parallel(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut set = JoinSet::new();

        let mut available: Vec<_> = tier
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .collect();
        if available.is_empty() {
            available = tier.iter().collect();
        }

        for mgr in available {
            let mgr = Arc::clone(mgr);
            let data = data.to_vec();
            set.spawn(async move { mgr.forward(&data).await });
        }

        let mut last_err = DnsError::UpstreamTimeout;
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(resp)) => {
                    set.abort_all();
                    return Ok(resp);
                }
                Ok(Err(e)) => last_err = e,
                Err(e) => {
                    last_err = DnsError::Generic(format!("Task panic: {e}"));
                }
            }
        }
        Err(last_err)
    }

    async fn resolve_fastest(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut available: Vec<_> = tier
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .cloned()
            .collect();
        if available.is_empty() {
            available = tier.to_vec();
        }
        available.sort_by_key(|m| m.health.rtt_ewma_us.load(Ordering::Relaxed));

        let mut last_err = DnsError::UpstreamTimeout;
        for mgr in available {
            match mgr.forward(data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    pub async fn resolve_round_robin(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut available: Vec<_> = tier
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .collect();
        if available.is_empty() {
            available = tier.iter().collect();
        }

        let len = available.len();
        let start = self.rr_index.fetch_add(1, Ordering::Relaxed) % len;

        let mut last_err = DnsError::UpstreamTimeout;
        for i in 0..len {
            let idx = (start + i) % len;
            let mgr = available[idx];
            match mgr.forward(data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Resolves a higher-level query message.
    pub async fn resolve_recursive(
        &self,
        name: &str,
        qtype: DnsRecordType,
    ) -> Result<DnsMessage, DnsError> {
        let mut query = DnsMessage::new();
        query.header.rd = true;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from(name),
            qtype,
            qclass: DnsClass::IN,
        });

        let mut encoder = WireEncoder::new();
        let wire_query = encoder.encode_message(&query);

        let (wire_resp, _, _) = self.resolve(&wire_query).await?;
        let mut decoder = WireDecoder::new(&wire_resp);
        decoder.decode_message().ok_or(DnsError::WireParseError)
    }
}
