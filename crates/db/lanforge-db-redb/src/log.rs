//! LogStore implementation for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::{TABLE_DNS_BLOCKED, TABLE_DNS_QUERIES, TABLE_LOG_EVENTS};
use lanforge_core::bus::TimedEvent;
use lanforge_db_core::{BoxFuture, DbError, LogStore};
use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::network::{QueryLogEntry, QueryResult};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockedQueryEntry {
    pub timestamp: u64,
    pub src_ip: String,
    pub src_mac: Option<String>,
    pub domain: String,
}

impl RedbDatabase {
    /// Auto-prunes older events and caps table sizes to prevent unbounded disk growth.
    pub async fn maybe_prune(&self, now_secs: i64) -> Result<(), DbError> {
        let last = self.last_prune.load(Ordering::Relaxed);
        if now_secs - last >= 60
            && self
                .last_prune
                .compare_exchange(last, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            let cutoff = now_secs - (7 * 24 * 3600);
            self.prune_logs(cutoff).await?;
        }
        Ok(())
    }

    /// Retrieves the most recent blocked DNS queries.
    pub fn get_dns_block_history(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<serde_json::Value>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_BLOCKED) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut result = Vec::new();
            for item in table
                .iter()
                .map_err(|e| DbError::Backend(e.to_string()))?
                .rev()
                .take(limit)
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: BlockedQueryEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                result.push(serde_json::json!({
                    "timestamp": entry.timestamp,
                    "src_ip": entry.src_ip,
                    "src_mac": entry.src_mac,
                    "domain": entry.domain,
                }));
            }
            Ok(result)
        })
    }
}

impl LogStore for RedbDatabase {
    fn record_log<'a>(&'a self, timed_event: &'a TimedEvent) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut buf = String::new();
            self.record_logs_batch(std::slice::from_ref(timed_event), &mut buf)
                .await
        })
    }

    fn record_logs_batch<'a>(
        &'a self,
        events: &'a [TimedEvent],
        _json_buf: &'a mut String,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(());
            }

            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_LOG_EVENTS)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                for event in events {
                    let ts = event
                        .timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let seq = self.log_seq.fetch_add(1, Ordering::Relaxed);
                    let bytes = serde_json::to_vec(event)
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                    table
                        .insert((ts, seq), bytes.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.maybe_prune(now_secs).await?;

            Ok(())
        })
    }

    fn record_dns_block<'a>(
        &'a self,
        timed_event: &'a TimedEvent,
        src_ip: IpAddr,
        domain: &'a str,
        src_mac: Option<String>,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let ts = timed_event
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let entry = BlockedQueryEntry {
                timestamp: ts,
                src_ip: src_ip.to_string(),
                src_mac,
                domain: domain.to_string(),
            };
            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DNS_BLOCKED)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                let seq = self.log_seq.fetch_add(1, Ordering::Relaxed);
                table
                    .insert((ts, seq), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.maybe_prune(now_secs).await?;

            Ok(())
        })
    }

    fn record_dns_queries_batch<'a>(
        &'a self,
        entries: &'a [QueryLogEntry],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            if entries.is_empty() {
                return Ok(());
            }

            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DNS_QUERIES)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                for entry in entries {
                    let ts = entry.timestamp;
                    let seq = self.log_seq.fetch_add(1, Ordering::Relaxed);
                    let bytes = serde_json::to_vec(entry)
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                    table
                        .insert((ts, seq), bytes.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.maybe_prune(now_secs).await?;

            Ok(())
        })
    }

    fn record_dns_query<'a>(
        &'a self,
        entry: &'a QueryLogEntry,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.record_dns_queries_batch(std::slice::from_ref(entry))
    }

    fn clear_logs(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let _ = write_txn.delete_table(TABLE_LOG_EVENTS);
                let _ = write_txn.delete_table(TABLE_DNS_QUERIES);
                let _ = write_txn.delete_table(TABLE_DNS_BLOCKED);
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn prune_logs(&self, before: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let cutoff = before.max(0) as u64;
            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                // 1. Prune TABLE_LOG_EVENTS
                if let Ok(mut table) = write_txn.open_table(TABLE_LOG_EVENTS) {
                    let mut to_delete = Vec::new();
                    for item in table
                        .range(..(cutoff, 0))
                        .map_err(|e| DbError::Backend(e.to_string()))?
                    {
                        let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                        to_delete.push(k.value());
                    }
                    for k in to_delete {
                        let _ = table.remove(k);
                    }

                    // Capacity cap (10,000)
                    let len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    if len > 10_000 {
                        let excess = len - 10_000;
                        let mut excess_keys = Vec::with_capacity(excess);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(excess)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            excess_keys.push(k.value());
                        }
                        for k in excess_keys {
                            let _ = table.remove(k);
                        }
                    }
                }

                // 2. Prune TABLE_DNS_QUERIES
                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_QUERIES) {
                    let mut to_delete = Vec::new();
                    for item in table
                        .range(..(cutoff, 0))
                        .map_err(|e| DbError::Backend(e.to_string()))?
                    {
                        let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                        to_delete.push(k.value());
                    }
                    for k in to_delete {
                        let _ = table.remove(k);
                    }

                    // Capacity cap (100,000)
                    let len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    if len > 100_000 {
                        let excess = len - 100_000;
                        let mut excess_keys = Vec::with_capacity(excess);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(excess)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            excess_keys.push(k.value());
                        }
                        for k in excess_keys {
                            let _ = table.remove(k);
                        }
                    }
                }

                // 3. Prune TABLE_DNS_BLOCKED
                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_BLOCKED) {
                    let mut to_delete = Vec::new();
                    for item in table
                        .range(..(cutoff, 0))
                        .map_err(|e| DbError::Backend(e.to_string()))?
                    {
                        let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                        to_delete.push(k.value());
                    }
                    for k in to_delete {
                        let _ = table.remove(k);
                    }

                    // Capacity cap (50,000)
                    let len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    if len > 50_000 {
                        let excess = len - 50_000;
                        let mut excess_keys = Vec::with_capacity(excess);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(excess)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            excess_keys.push(k.value());
                        }
                        for k in excess_keys {
                            let _ = table.remove(k);
                        }
                    }
                }
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn get_history(&self, limit: usize) -> BoxFuture<'_, Result<Vec<TimedEvent>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_LOG_EVENTS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut entries = Vec::with_capacity(limit);
            for item in table
                .iter()
                .map_err(|e| DbError::Backend(e.to_string()))?
                .rev()
                .take(limit)
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let event: TimedEvent = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entries.push(event);
            }
            entries.reverse();
            Ok(entries)
        })
    }

    fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
    ) -> BoxFuture<'_, Result<(Vec<QueryLogEntry>, usize), DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), 0)),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let total = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
            let offset = offset.unwrap_or(0);
            if offset >= total {
                return Ok((Vec::new(), total));
            }

            let mut entries = Vec::with_capacity(limit);
            for item in table
                .iter()
                .map_err(|e| DbError::Backend(e.to_string()))?
                .rev()
                .skip(offset)
                .take(limit)
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entries.push(entry);
            }

            Ok((entries, total))
        })
    }

    fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                *counts.entry(entry.domain.to_string()).or_insert(0) += 1;
            }

            let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            Ok(vec)
        })
    }

    fn get_dns_top_domains_for_client<'a>(
        &'a self,
        client: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if entry.src_ip.to_string() == client
                    || entry.src_mac.as_ref().map(|m| m.to_string()).as_deref() == Some(client)
                {
                    *counts.entry(entry.domain.to_string()).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            Ok(vec)
        })
    }

    fn get_dns_query_types(&self) -> BoxFuture<'_, Result<Vec<(u16, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                *counts.entry(u16::from(entry.qtype)).or_insert(0) += 1;
            }

            let mut vec: Vec<(u16, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            Ok(vec)
        })
    }

    fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut buckets: std::collections::HashMap<u64, u64> =
                std::collections::HashMap::new();
            for item in table
                .range((since_secs, 0)..)
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                let bucket = (entry.timestamp / 30) * 30;
                *buckets.entry(bucket).or_insert(0) += 1;
            }

            let mut vec: Vec<(u64, u64)> = buckets.into_iter().collect();
            vec.sort_by_key(|a| a.0);
            Ok(vec)
        })
    }

    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64, u64, u64, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let bsize = if bucket_secs == 0 { 30 } else { bucket_secs };
            let mut buckets: std::collections::HashMap<u64, (u64, u64, u64, u64)> =
                std::collections::HashMap::new();
            for item in table
                .range((since_secs, 0)..)
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                let bucket = (entry.timestamp / bsize) * bsize;
                let counts = buckets.entry(bucket).or_insert((0, 0, 0, 0));
                counts.0 += 1;
                match entry.result {
                    QueryResult::Blocked | QueryResult::CachedBlock => counts.3 += 1,
                    QueryResult::Cached => counts.1 += 1,
                    _ => counts.2 += 1,
                }
            }

            let mut vec: Vec<(u64, u64, u64, u64, u64)> = buckets
                .into_iter()
                .map(|(ts, (total, cached, fwd, blk))| (ts, total, cached, fwd, blk))
                .collect();
            vec.sort_by_key(|a| a.0);
            Ok(vec)
        })
    }

    fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                *counts.entry(entry.src_ip.to_string()).or_insert(0) += 1;
            }

            let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            Ok(vec)
        })
    }

    fn get_dns_protocol_stats(&self) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                let proto_str = match entry.protocol {
                    TransportProtocol::Udp => "udp",
                    TransportProtocol::Tcp => "tcp",
                    TransportProtocol::Tls => "dot",
                    TransportProtocol::Quic => "doq",
                    TransportProtocol::Https => "doh",
                };
                *counts.entry(proto_str.to_string()).or_insert(0) += 1;
            }

            let vec: Vec<(String, u64)> = counts.into_iter().collect();
            Ok(vec)
        })
    }

    fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    *counts.entry(entry.domain.to_string()).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            Ok(vec)
        })
    }

    fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    *counts.entry(entry.src_ip.to_string()).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(String, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            Ok(vec)
        })
    }

    fn get_dns_blocked_query_rate(
        &self,
        since_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut buckets: std::collections::HashMap<u64, u64> =
                std::collections::HashMap::new();
            for item in table
                .range((since_secs, 0)..)
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: QueryLogEntry = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    let bucket = (entry.timestamp / 30) * 30;
                    *buckets.entry(bucket).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(u64, u64)> = buckets.into_iter().collect();
            vec.sort_by_key(|a| a.0);
            Ok(vec)
        })
    }
}
