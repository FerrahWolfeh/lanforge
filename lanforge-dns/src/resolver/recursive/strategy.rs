use crate::error::DnsError;
use crate::resolver::recursive::UpstreamManager;
use crate::utils::health::UpstreamStatus;
use lanforge_core::types::network::dns::UpstreamHealthSnapshot;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Sequential,
    Parallel,
    Fastest,
    RoundRobin,
}

pub struct UpstreamStrategy {
    pub mode: UpstreamMode,
    /// Upstreams grouped by protocol tier. Index 0 = tier 0 (TLS/QUIC), etc.
    tiers: Vec<Vec<Arc<UpstreamManager>>>,
    pub rr_index: AtomicUsize,
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
            tiers,
            rr_index: AtomicUsize::new(0),
        }
    }

    /// Flat iterator over all upstreams.
    pub fn all_upstreams(&self) -> impl Iterator<Item = &Arc<UpstreamManager>> {
        self.tiers.iter().flat_map(|t| t.iter())
    }

    /// Returns true if no upstreams are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tiers.iter().all(|t| t.is_empty())
    }

    pub fn snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        let mut snaps: Vec<_> = self
            .all_upstreams()
            .map(|m| {
                let mut snap = m.health.snapshot(
                    format!("{}", m.target.addr),
                    format!("{:?}", m.target.protocol),
                );

                #[cfg(not(feature = "dot"))]
                if m.target.protocol == crate::config::UpstreamProtocol::Tls {
                    snap.status = "Disabled (Feature)".to_string();
                }

                #[cfg(not(feature = "doq"))]
                if m.target.protocol == crate::config::UpstreamProtocol::Quic {
                    snap.status = "Disabled (Feature)".to_string();
                }

                #[cfg(not(feature = "doh-upstream"))]
                if m.target.protocol == crate::config::UpstreamProtocol::Https {
                    snap.status = "Disabled (Feature)".to_string();
                }

                snap
            })
            .collect();

        // Sort by tier, then by status (Healthy first)
        snaps.sort_by(|a, b| {
            let tier = |p: &str| match p {
                "Tls" | "Quic" => 0,
                "Https" => 1,
                "Udp" => 2,
                _ => 3,
            };
            tier(&a.protocol).cmp(&tier(&b.protocol)).then_with(|| {
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
        let mut last_err = DnsError::Refused;
        for tier in &self.tiers {
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
        for mgr in tier {
            if mgr.health.status() == UpstreamStatus::Degraded {
                continue;
            }
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
        use tokio::task::JoinSet;
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
        let mut sorted = tier.to_vec();
        sorted.sort_by_key(|m| m.health.rtt_ewma_us.load(Ordering::Relaxed));

        let mut last_err = DnsError::UpstreamTimeout;
        for mgr in sorted {
            if mgr.health.status() == UpstreamStatus::Degraded {
                continue;
            }
            match mgr.forward(data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn resolve_round_robin(
        &self,
        tier: &[Arc<UpstreamManager>],
        data: &[u8],
    ) -> Result<(Vec<u8>, bool, bool), DnsError> {
        let len = tier.len();
        let start = self.rr_index.fetch_add(1, Ordering::Relaxed) % len;

        let mut last_err = DnsError::UpstreamTimeout;
        for i in 0..len {
            let idx = (start + i) % len;
            let mgr = &tier[idx];
            if mgr.health.status() == UpstreamStatus::Degraded {
                continue;
            }
            match mgr.forward(data).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}
