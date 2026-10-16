use crate::error::DnsError;
use crate::resolver::recursive::UpstreamManager;
use crate::resolver::recursive::cache::CacheKey;
use crate::utils::health::UpstreamStatus;
use dashmap::DashMap;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordType, UpstreamHealthSnapshot,
};
use std::collections::HashMap;
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

#[derive(Clone)]
pub struct ConditionalRoute {
    pub domain: String,
    pub labels: Vec<Vec<u8>>,
    pub tiers: Arc<[Vec<Arc<UpstreamManager>>]>,
}

fn group_by_tier(upstreams: Vec<Arc<UpstreamManager>>) -> Arc<[Vec<Arc<UpstreamManager>>]> {
    let max_tier = upstreams
        .iter()
        .map(|m| m.target.protocol.tier() as usize)
        .max()
        .unwrap_or(0);

    let mut tiers = vec![Vec::new(); max_tier + 1];
    for mgr in upstreams {
        tiers[mgr.target.protocol.tier() as usize].push(mgr);
    }
    Arc::from(tiers)
}

fn normalize_domain(d: &str) -> String {
    d.trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn domain_to_labels(d: &str) -> Vec<Vec<u8>> {
    d.split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_ascii_lowercase())
        .collect()
}

pub struct UpstreamStrategy {
    pub mode: UpstreamMode,
    /// Upstreams grouped by protocol tier. Index 0 = tier 0 (TLS/QUIC), etc.
    tiers: parking_lot::RwLock<Arc<[Vec<Arc<UpstreamManager>>]>>,
    /// Conditional split-DNS domain routes sorted descending by label length.
    conditional_routes: parking_lot::RwLock<Arc<[Arc<ConditionalRoute>]>>,
    fallback_upstreams: parking_lot::RwLock<Arc<[Arc<UpstreamManager>]>>,
    pub rr_index: AtomicUsize,
    in_flight: DashMap<CacheKey, InFlightTx>,
}

impl UpstreamStrategy {
    #[must_use]
    pub fn new(mode: UpstreamMode, upstreams: Vec<Arc<UpstreamManager>>) -> Self {
        let strategy = Self {
            mode,
            tiers: parking_lot::RwLock::new(Arc::from(Vec::<Vec<Arc<UpstreamManager>>>::new())),
            conditional_routes: parking_lot::RwLock::new(Arc::from(Vec::<Arc<ConditionalRoute>>::new())),
            fallback_upstreams: parking_lot::RwLock::new(Arc::from(Vec::<Arc<UpstreamManager>>::new())),
            rr_index: AtomicUsize::new(0),
            in_flight: DashMap::new(),
        };
        strategy.replace_upstreams(upstreams);
        strategy
    }

    pub fn replace_upstreams(&self, upstreams: Vec<Arc<UpstreamManager>>) {
        let mut global = Vec::new();
        let mut by_domain: HashMap<String, Vec<Arc<UpstreamManager>>> = HashMap::new();

        for mgr in upstreams {
            let domain_opt = mgr.target.domain.as_deref().map(normalize_domain);
            if let Some(domain) = domain_opt && !domain.is_empty() {
                by_domain.entry(domain).or_default().push(mgr);
            } else {
                global.push(mgr);
            }
        }

        *self.tiers.write() = group_by_tier(global);

        let mut routes = Vec::new();
        for (domain, mgrs) in by_domain {
            let labels = domain_to_labels(&domain);
            let tiers = group_by_tier(mgrs);
            routes.push(Arc::new(ConditionalRoute {
                domain,
                labels,
                tiers,
            }));
        }

        // Sort descending by number of labels (longest suffix match wins)
        routes.sort_by_key(|a| std::cmp::Reverse(a.labels.len()));
        *self.conditional_routes.write() = Arc::from(routes);
    }

    pub fn replace_fallback_upstreams(&self, fallbacks: Vec<Arc<UpstreamManager>>) {
        *self.fallback_upstreams.write() = Arc::from(fallbacks);
    }

    /// Flat iterator of all upstreams (both global and domain-specific).
    pub fn all_upstreams(&self) -> impl Iterator<Item = Arc<UpstreamManager>> {
        let mut list = Vec::new();
        let tiers = Arc::clone(&*self.tiers.read());
        for tier in tiers.iter() {
            list.extend(tier.iter().cloned());
        }
        let conditionals = Arc::clone(&*self.conditional_routes.read());
        for route in conditionals.iter() {
            for tier in route.tiers.iter() {
                list.extend(tier.iter().cloned());
            }
        }
        list.into_iter()
    }

    /// Returns true if no upstreams are configured anywhere.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tiers.read().iter().all(|t| t.is_empty())
            && self.conditional_routes.read().is_empty()
    }

    /// Returns true if default global upstreams are configured.
    #[must_use]
    pub fn has_global_upstreams(&self) -> bool {
        self.tiers.read().iter().any(|t| !t.is_empty())
    }

    pub fn snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        let mut snaps: Vec<_> = self
            .all_upstreams()
            .map(|m| {
                #[allow(unused_mut)]
                let mut snap = m.health.snapshot(m.target.addr, m.target.protocol, m.target.domain.clone());

                #[cfg(not(feature = "dot"))]
                if m.target.protocol == UpstreamProtocol::Tls {
                    snap.status = UpstreamStatus::Disabled;
                }

                #[cfg(not(feature = "doq"))]
                if m.target.protocol == UpstreamProtocol::Quic {
                    snap.status = UpstreamStatus::Disabled;
                }

                #[cfg(not(feature = "doh-upstream"))]
                if m.target.protocol == UpstreamProtocol::Https {
                    snap.status = UpstreamStatus::Disabled;
                }

                snap
            })
            .collect();

        // Sort by tier, then by status (Healthy first)
        snaps.sort_by(|a, b| {
            a.protocol.tier().cmp(&b.protocol.tier()).then_with(|| {
                // Keep Healthy at top if possible
                let status_rank = |s: UpstreamStatus| match s {
                    UpstreamStatus::Healthy => 0,
                    UpstreamStatus::Degraded => 1,
                    UpstreamStatus::Disabled => 2,
                };
                status_rank(a.status).cmp(&status_rank(b.status))
            })
        });

        snaps
    }

    /// Finds the most specific matching conditional route for a query using zero allocations.
    fn find_conditional_route(&self, question: &WireQuestion<'_>) -> Option<Arc<ConditionalRoute>> {
        let routes = self.conditional_routes.read();
        if routes.is_empty() {
            return None;
        }

        let mut qlabels: [&[u8]; 16] = [b""; 16];
        let mut qcount = 0;
        for l in question.labels() {
            if qcount < 16 {
                qlabels[qcount] = l;
                qcount += 1;
            }
        }

        for route in routes.iter() {
            let rlen = route.labels.len();
            if qcount < rlen {
                continue;
            }
            let offset = qcount - rlen;
            let mut matched = true;
            for (i, expected) in route.labels.iter().enumerate() {
                if !qlabels[offset + i].eq_ignore_ascii_case(expected) {
                    matched = false;
                    break;
                }
            }
            if matched {
                return Some(Arc::clone(route));
            }
        }

        None
    }

    pub async fn resolve(&self, data: &[u8]) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
        let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;
        self.resolve_with_parsed(data, &header, &question).await
    }

    pub async fn resolve_with_parsed(
        &self,
        data: &[u8],
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let key = CacheKey::from_question(question);

        let (mut rx, is_leader) = match self.in_flight.entry(key.clone()) {
            dashmap::Entry::Occupied(occ) => (Some(occ.get().subscribe()), false),
            dashmap::Entry::Vacant(vac) => {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                vac.insert(tx);
                (None, true)
            }
        };

        if let Some(ref mut rx) = rx {
            match rx.recv().await {
                Ok(Ok(res)) => return Ok(res),
                Ok(Err(e)) => return Err(DnsError::Generic(e)),
                Err(_) => {
                    // Leader task dropped/panicked, fall through to resolve_internal
                }
            }
        }

        struct InFlightGuard<'a> {
            in_flight: &'a DashMap<CacheKey, InFlightTx>,
            key: Option<CacheKey>,
        }
        impl<'a> Drop for InFlightGuard<'a> {
            fn drop(&mut self) {
                if let Some(k) = self.key.take() {
                    self.in_flight.remove(&k);
                }
            }
        }

        let mut guard = InFlightGuard {
            in_flight: &self.in_flight,
            key: if is_leader { Some(key.clone()) } else { None },
        };

        let res = self.resolve_internal(data, header, question).await;

        guard.key = None;
        if let Some((_, tx)) = self.in_flight.remove(&key) {
            let _ = tx.send(
                res.as_ref()
                    .map(|(v, c, b)| (v.clone(), *c, *b))
                    .map_err(|e| e.to_string()),
            );
        }

        res
    }

    async fn resolve_internal(
        &self,
        data: &[u8],
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        // 1. Check for matching conditional domain route (Split DNS)
        if let Some(route) = self.find_conditional_route(question) {
            let mut last_err = DnsError::Refused;
            for tier in route.tiers.iter() {
                if tier.is_empty() {
                    continue;
                }
                match self.resolve_tier(tier, data, header, question).await {
                    Ok(resp) => return Ok(resp),
                    Err(e) => last_err = e,
                }
            }
            return Err(last_err);
        }

        // 2. Fall back to global upstreams
        let mut last_err = DnsError::Refused;
        if !self.has_global_upstreams() {
            let fallbacks = Arc::clone(&*self.fallback_upstreams.read());
            if !fallbacks.is_empty() {
                return self.resolve_sequential(&fallbacks, data, header, question).await;
            }
        }
        let tiers = Arc::clone(&*self.tiers.read());
        for tier in tiers.iter() {
            if tier.is_empty() {
                continue;
            }

            match self.resolve_tier(tier, data, header, question).await {
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
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        match self.mode {
            UpstreamMode::Sequential => self.resolve_sequential(tier, data, header, question).await,
            UpstreamMode::Parallel => self.resolve_parallel(tier, data, header, question).await,
            UpstreamMode::Fastest => self.resolve_fastest(tier, data, header, question).await,
            UpstreamMode::RoundRobin => self.resolve_round_robin(tier, data, header, question).await,
        }
    }

    async fn resolve_sequential(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
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
            match mgr.forward_with_parsed(data, header, question).await {
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
        _header: &WireHeader<'_>,
        _question: &WireQuestion<'_>,
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let mut set = JoinSet::new();

        let mut available: Vec<_> = tier
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .collect();
        if available.is_empty() {
            available = tier.iter().collect();
        }

        let shared_data = bytes::Bytes::copy_from_slice(data);
        for mgr in available {
            let mgr = Arc::clone(mgr);
            let shared_data = shared_data.clone();
            set.spawn(async move {
                let header = WireHeader::parse(&shared_data).ok_or(DnsError::WireParseError)?;
                let question = WireQuestion::parse(&shared_data).ok_or(DnsError::WireParseError)?;
                mgr.forward_with_parsed(&shared_data, &header, &question).await
            });
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
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
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
            match mgr.forward_with_parsed(data, header, question).await {
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
        header: &WireHeader<'_>,
        question: &WireQuestion<'_>,
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
            match mgr.forward_with_parsed(data, header, question).await {
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
