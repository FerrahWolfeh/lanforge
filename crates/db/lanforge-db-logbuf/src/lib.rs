//! `LogDb` implementation using JSONL files in tmpfs and in-memory caches.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lanforge_core::bus::TimedEvent;
use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::network::{QueryLogEntry, QueryResult};

/// Error type mapping for log buffer.
#[derive(Debug, thiserror::Error)]
pub enum LogBufError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal database error: {0}")]
    Internal(String),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockedQueryEntry {
    pub timestamp: u64,
    pub src_ip: String,
    pub src_mac: Option<String>,
    pub domain: String,
}

pub struct LogDb {
    events_path: Option<PathBuf>,
    dns_path: Option<PathBuf>,
    blocked_path: Option<PathBuf>,

    system_logs: Mutex<Vec<TimedEvent>>,
    dns_queries: Mutex<Vec<QueryLogEntry>>,
    dns_blocked: Mutex<Vec<BlockedQueryEntry>>,

    last_prune: Mutex<Instant>,
}

impl LogDb {
    /// Opens the log buffer database.
    pub async fn open(url: &str) -> Result<Self, LogBufError> {
        let is_memory = url.contains(":memory:") || url.is_empty();

        let mut events_path = None;
        let mut dns_path = None;
        let mut blocked_path = None;

        let mut system_logs = Vec::new();
        let mut dns_queries = Vec::new();
        let mut dns_blocked = Vec::new();

        if !is_memory {
            let path_str = url
                .strip_prefix("sqlite://")
                .or_else(|| url.strip_prefix("sqlite:"))
                .unwrap_or(url);

            let path_str = path_str.split('?').next().unwrap_or(path_str);
            let path = Path::new(path_str);

            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
                events_path = Some(parent.join("events.jsonl"));
                dns_path = Some(parent.join("dns.jsonl"));
                blocked_path = Some(parent.join("dns_blocked.jsonl"));
            }
        }

        // Load existing logs from files if present
        if let Some(ref p) = events_path
            && p.exists()
        {
            let file = File::open(p)?;
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(event) = serde_json::from_str::<TimedEvent>(&line) {
                    system_logs.push(event);
                }
            }
            // Limit to 10k capacity
            if system_logs.len() > 10000 {
                system_logs.drain(0..system_logs.len() - 10000);
            }
        }

        if let Some(ref p) = dns_path
            && p.exists()
        {
            let file = File::open(p)?;
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<QueryLogEntry>(&line) {
                    dns_queries.push(entry);
                }
            }
            // Limit to 100k capacity
            if dns_queries.len() > 100000 {
                dns_queries.drain(0..dns_queries.len() - 100000);
            }
        }

        if let Some(ref p) = blocked_path
            && p.exists()
        {
            let file = File::open(p)?;
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<BlockedQueryEntry>(&line) {
                    dns_blocked.push(entry);
                }
            }
            // Limit to 50k capacity
            if dns_blocked.len() > 50000 {
                dns_blocked.drain(0..dns_blocked.len() - 50000);
            }
        }

        Ok(Self {
            events_path,
            dns_path,
            blocked_path,
            system_logs: Mutex::new(system_logs),
            dns_queries: Mutex::new(dns_queries),
            dns_blocked: Mutex::new(dns_blocked),
            last_prune: Mutex::new(Instant::now()),
        })
    }

    /// Appends single event.
    pub async fn record_log(&self, timed_event: &TimedEvent) -> Result<(), LogBufError> {
        let mut buf = String::new();
        self.record_logs_batch(std::slice::from_ref(timed_event), &mut buf)
            .await
    }

    /// Appends a batch of events.
    pub async fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        _json_buf: &mut String,
    ) -> Result<(), LogBufError> {
        if events.is_empty() {
            return Ok(());
        }

        {
            let mut logs = self.system_logs.lock();
            logs.extend(events.iter().cloned());

            // Cap in-memory count to 10000
            let len = logs.len();
            if len > 10000 {
                logs.drain(0..len - 10000);
            }
        }

        if let Some(ref p) = self.events_path {
            let mut file = OpenOptions::new().create(true).append(true).open(p)?;
            for event in events {
                let line = serde_json::to_string(event)?;
                writeln!(file, "{line}")?;
            }
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.maybe_prune(now_secs).await?;

        Ok(())
    }

    /// Records blocked query.
    pub async fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), LogBufError> {
        let entry = BlockedQueryEntry {
            timestamp: timed_event
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            src_ip: src_ip.to_string(),
            src_mac,
            domain: domain.to_string(),
        };

        {
            let mut blocked = self.dns_blocked.lock();
            blocked.push(entry.clone());
            let len = blocked.len();
            if len > 50000 {
                blocked.drain(0..len - 50000);
            }
        }

        if let Some(ref p) = self.blocked_path {
            let mut file = OpenOptions::new().create(true).append(true).open(p)?;
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{line}")?;
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.maybe_prune(now_secs).await?;

        Ok(())
    }

    /// Records batch of resolved DNS queries.
    pub async fn record_dns_queries_batch(
        &self,
        entries: &[QueryLogEntry],
    ) -> Result<(), LogBufError> {
        if entries.is_empty() {
            return Ok(());
        }

        {
            let mut queries = self.dns_queries.lock();
            queries.extend(entries.iter().cloned());
            let len = queries.len();
            if len > 100000 {
                queries.drain(0..len - 100000);
            }
        }

        if let Some(ref p) = self.dns_path {
            let mut file = OpenOptions::new().create(true).append(true).open(p)?;
            for entry in entries {
                let line = serde_json::to_string(entry)?;
                writeln!(file, "{line}")?;
            }
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.maybe_prune(now_secs).await?;

        Ok(())
    }

    /// Records single resolved DNS query.
    pub async fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), LogBufError> {
        self.record_dns_queries_batch(std::slice::from_ref(entry))
            .await
    }

    /// Auto-prunes older events and caps log file sizes to avoid infinite disk growth in tmpfs.
    async fn maybe_prune(&self, now_secs: i64) -> Result<(), LogBufError> {
        let should_prune = {
            let last_prune = self.last_prune.lock();
            last_prune.elapsed() >= Duration::from_secs(60)
        };
        if should_prune {
            let cutoff = now_secs - (7 * 24 * 3600);
            self.prune_logs(cutoff).await?;
            *self.last_prune.lock() = Instant::now();
        }
        Ok(())
    }

    /// Wipes all logged system events from the database cache and truncates file.
    pub async fn clear_logs(&self) -> Result<(), LogBufError> {
        self.system_logs.lock().clear();
        if let Some(ref p) = self.events_path {
            File::create(p)?; // Truncate
        }
        Ok(())
    }

    /// Wipes/prunes log entries older than the cutoff timestamp.
    pub async fn prune_logs(&self, before: i64) -> Result<(), LogBufError> {
        let cutoff_time = before as u64;

        // 1. Prune System Logs
        {
            let mut logs = self.system_logs.lock();
            logs.retain(|e| {
                e.timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    >= cutoff_time
            });
            if let Some(ref p) = self.events_path {
                let mut file = File::create(p)?;
                for event in logs.iter() {
                    let line = serde_json::to_string(event)?;
                    writeln!(file, "{line}")?;
                }
            }
        }

        // 2. Prune DNS Queries
        {
            let mut queries = self.dns_queries.lock();
            queries.retain(|q| q.timestamp >= cutoff_time);
            if let Some(ref p) = self.dns_path {
                let mut file = File::create(p)?;
                for entry in queries.iter() {
                    let line = serde_json::to_string(entry)?;
                    writeln!(file, "{line}")?;
                }
            }
        }

        // 3. Prune Blocked Logs
        {
            let mut blocked = self.dns_blocked.lock();
            blocked.retain(|b| b.timestamp >= cutoff_time);
            if let Some(ref p) = self.blocked_path {
                let mut file = File::create(p)?;
                for entry in blocked.iter() {
                    let line = serde_json::to_string(entry)?;
                    writeln!(file, "{line}")?;
                }
            }
        }

        Ok(())
    }

    /// Retrieves the most recent log events, oldest first.
    pub async fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, LogBufError> {
        let logs = self.system_logs.lock();
        let count = logs.len();
        let take = limit.min(count);
        let mut result = logs[count - take..].to_vec();
        result.reverse(); // Standard is newest first in stream, but let's reverse to match oldest first for the caller
        result.reverse(); // Wait, the sqlite implementation did: `entries.reverse(); Ok(entries);` so it returned oldest first!
        Ok(result)
    }

    /// Stream helper matching sqlite signature.
    pub fn stream_history(
        &self,
        limit: usize,
    ) -> impl futures::Stream<Item = Result<TimedEvent, LogBufError>> + '_ {
        let logs = self.system_logs.lock();
        let count = logs.len();
        let take = limit.min(count);
        let mut list = logs[count - take..].to_vec();
        list.reverse(); // newest first
        futures::stream::iter(list.into_iter().map(Ok))
    }

    /// Retrieves the most recent DNS queries.
    pub async fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
    ) -> Result<(Vec<QueryLogEntry>, usize), LogBufError> {
        let queries = self.dns_queries.lock();
        let total = queries.len();
        let offset = offset.unwrap_or(0);
        if offset >= total {
            return Ok((Vec::new(), total));
        }

        // Return latest first
        let mut reversed: Vec<QueryLogEntry> = queries.iter().cloned().rev().collect();
        let end = (offset + limit).min(total);
        let slice = reversed.drain(offset..end).collect();

        Ok((slice, total))
    }

    /// Retrieves top domains by query count.
    pub async fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            *counts.entry(q.domain.to_string()).or_insert(0u64) += 1;
        }
        let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        vec.truncate(limit);
        Ok(vec)
    }

    /// Retrieves top DNS domains filtered for a specific client (by IP or MAC).
    pub async fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            if q.src_ip.to_string() == client
                || q.src_mac.as_ref().map(|m| m.to_string()).as_deref() == Some(client)
            {
                *counts.entry(q.domain.to_string()).or_insert(0u64) += 1;
            }
        }
        let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        vec.truncate(limit);
        Ok(vec)
    }

    /// Retrieves query counts by type.
    pub async fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            *counts.entry(u16::from(q.qtype)).or_insert(0u64) += 1;
        }
        let mut vec: Vec<(u16, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        Ok(vec)
    }

    /// Retrieves query rate timeline.
    pub async fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut buckets = HashMap::new();
        for q in queries.iter() {
            if q.timestamp >= since_secs {
                let bucket = (q.timestamp / 30) * 30;
                *buckets.entry(bucket).or_insert(0u64) += 1;
            }
        }
        let mut vec: Vec<(u64, u64)> = buckets.into_iter().collect();
        vec.sort_by_key(|a| a.0);
        Ok(vec)
    }

    /// Retrieves detailed query rate timeline with disposition breakdown (timestamp, total, cached, forwarded, blocked).
    pub async fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<(u64, u64, u64, u64, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let bsize = if bucket_secs == 0 { 30 } else { bucket_secs };
        let mut buckets: HashMap<u64, (u64, u64, u64, u64)> = HashMap::new();
        for q in queries.iter() {
            if q.timestamp >= since_secs {
                let bucket = (q.timestamp / bsize) * bsize;
                let entry = buckets.entry(bucket).or_insert((0, 0, 0, 0));
                entry.0 += 1;
                match q.result {
                    QueryResult::Blocked | QueryResult::CachedBlock => {
                        entry.3 += 1;
                    }
                    QueryResult::Cached => {
                        entry.1 += 1;
                    }
                    _ => {
                        entry.2 += 1;
                    }
                }
            }
        }
        let mut vec: Vec<(u64, u64, u64, u64, u64)> = buckets
            .into_iter()
            .map(|(ts, (total, cached, fwd, blk))| (ts, total, cached, fwd, blk))
            .collect();
        vec.sort_by_key(|a| a.0);
        Ok(vec)
    }

    /// Retrieves top clients by query count.
    pub async fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            *counts.entry(q.src_ip.to_string()).or_insert(0u64) += 1;
        }
        let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        vec.truncate(limit);
        Ok(vec)
    }

    /// Retrieves query counts by protocol.
    pub async fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            let proto_str = match q.protocol {
                TransportProtocol::Udp => "udp",
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Tls => "dot",
                TransportProtocol::Quic => "doq",
                TransportProtocol::Https => "doh",
            };
            *counts.entry(proto_str.to_string()).or_insert(0u64) += 1;
        }
        let vec: Vec<(String, u64)> = counts.into_iter().collect();
        Ok(vec)
    }

    /// Retrieves top blocked domains by query count.
    pub async fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            if matches!(q.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                *counts.entry(q.domain.to_string()).or_insert(0u64) += 1;
            }
        }
        let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        vec.truncate(limit);
        Ok(vec)
    }

    /// Retrieves top blocked clients by query count.
    pub async fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut counts = HashMap::new();
        for q in queries.iter() {
            if matches!(q.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                *counts.entry(q.src_ip.to_string()).or_insert(0u64) += 1;
            }
        }
        let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
        vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        vec.truncate(limit);
        Ok(vec)
    }

    /// Retrieves blocked query rate timeline.
    pub async fn get_dns_blocked_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, LogBufError> {
        let queries = self.dns_queries.lock();
        let mut buckets = HashMap::new();
        for q in queries.iter() {
            if q.timestamp >= since_secs
                && matches!(q.result, QueryResult::Blocked | QueryResult::CachedBlock)
            {
                let bucket = (q.timestamp / 30) * 30;
                *buckets.entry(bucket).or_insert(0u64) += 1;
            }
        }
        let mut vec: Vec<(u64, u64)> = buckets.into_iter().collect();
        vec.sort_by_key(|a| a.0);
        Ok(vec)
    }

    /// Retrieves the most recent blocked DNS queries.
    pub async fn get_dns_block_history(
        &self,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, LogBufError> {
        let blocked = self.dns_blocked.lock();
        let count = blocked.len();
        let take = limit.min(count);
        let slice = &blocked[count - take..];
        let mut result = Vec::new();
        for entry in slice.iter().rev() {
            result.push(serde_json::json!({
                "timestamp": entry.timestamp,
                "src_ip": entry.src_ip,
                "src_mac": entry.src_mac,
                "domain": entry.domain,
            }));
        }
        Ok(result)
    }
}
