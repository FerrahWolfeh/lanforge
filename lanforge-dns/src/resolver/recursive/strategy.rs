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
    pub upstreams: Vec<Arc<UpstreamManager>>,
    pub rr_index: AtomicUsize,
}

impl UpstreamStrategy {
    #[must_use]
    pub const fn new(mode: UpstreamMode, upstreams: Vec<Arc<UpstreamManager>>) -> Self {
        Self {
            mode,
            upstreams,
            rr_index: AtomicUsize::new(0),
        }
    }

    pub fn snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        self.upstreams
            .iter()
            .map(|m| {
                m.health.snapshot(
                    format!("{}", m.target.addr),
                    format!("{:?}", m.target.protocol),
                )
            })
            .collect()
    }

    pub async fn resolve(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        if self.upstreams.is_empty() {
            return Err(DnsError::Refused);
        }

        match self.mode {
            UpstreamMode::Sequential => self.resolve_sequential(data).await,
            UpstreamMode::Parallel => self.resolve_parallel(data).await,
            UpstreamMode::Fastest => self.resolve_fastest(data).await,
            UpstreamMode::RoundRobin => self.resolve_round_robin(data).await,
        }
    }

    async fn resolve_sequential(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        let mut last_err = DnsError::UpstreamTimeout;
        for mgr in &self.upstreams {
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

    async fn resolve_parallel(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        use tokio::task::JoinSet;
        let mut set = JoinSet::new();

        let mut available: Vec<_> = self
            .upstreams
            .iter()
            .filter(|m| m.health.status() != UpstreamStatus::Degraded)
            .collect();
        if available.is_empty() {
            available = self.upstreams.iter().collect();
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

    async fn resolve_fastest(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        let mut sorted = self.upstreams.clone();
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

    async fn resolve_round_robin(&self, data: &[u8]) -> Result<(Vec<u8>, bool), DnsError> {
        let len = self.upstreams.len();
        let start = self.rr_index.fetch_add(1, Ordering::Relaxed) % len;

        let mut last_err = DnsError::UpstreamTimeout;
        for i in 0..len {
            let idx = (start + i) % len;
            let mgr = &self.upstreams[idx];
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
