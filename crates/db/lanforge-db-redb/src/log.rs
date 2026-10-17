//! LogStore implementation for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::{
    TABLE_CONFIG, TABLE_DNS_BLOCKED, TABLE_DNS_QUERIES, TABLE_DNS_TELEMETRY, TABLE_LOG_EVENTS,
};
use lanforge_core::bus::TimedEvent;
use lanforge_db_core::{BoxFuture, DbError, DnsQueryRateBucket, LogStore};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType, TransportProtocol};
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

#[derive(serde::Deserialize)]
struct QueryFilterRow<'a> {
    src_ip: IpAddr,
    #[serde(borrow)]
    domain: std::borrow::Cow<'a, str>,
    #[serde(default)]
    src_mac: Option<MacAddr>,
    #[serde(default)]
    qtype: Option<DnsRecordType>,
    #[serde(default)]
    result: Option<QueryResult>,
}

impl QueryFilterRow<'_> {
    fn matches(
        &self,
        client_filter_lower: Option<&str>,
        domain_filter_lower: Option<&str>,
        qtype_filter: Option<DnsRecordType>,
        result_filter: Option<QueryResult>,
    ) -> bool {
        if let Some(cf) = client_filter_lower {
            let ip_str = self.src_ip.to_string();
            let mut matched = ip_str.contains(cf);
            if !matched && let Some(mac) = self.src_mac {
                let mac_str = mac.to_string().to_lowercase();
                matched = mac_str.contains(cf);
            }
            if !matched {
                return false;
            }
        }

        if let Some(df) = domain_filter_lower
            && !self.domain.to_lowercase().contains(df)
        {
            return false;
        }

        if let Some(qt) = qtype_filter
            && self.qtype != Some(qt)
        {
            return false;
        }

        if let Some(res) = result_filter
            && self.result != Some(res)
        {
            return false;
        }

        true
    }
}

#[derive(serde::Deserialize)]
struct DomainResultRow<'a> {
    #[serde(borrow)]
    domain: std::borrow::Cow<'a, str>,
    result: QueryResult,
}

#[derive(serde::Deserialize)]
struct ClientDomainResultRow<'a> {
    #[serde(borrow)]
    domain: std::borrow::Cow<'a, str>,
    result: QueryResult,
    src_ip: IpAddr,
    #[serde(default)]
    src_mac: Option<MacAddr>,
}

#[derive(serde::Deserialize)]
struct QTypeResultRow {
    qtype: DnsRecordType,
}

#[derive(serde::Deserialize)]
struct QueryRateDetailedRow {
    result: QueryResult,
    qtype: DnsRecordType,
}

#[derive(serde::Deserialize)]
struct BlockedRateResultRow {
    result: QueryResult,
}

#[derive(serde::Deserialize)]
struct ClientResultRow {
    src_ip: IpAddr,
    result: QueryResult,
}

#[derive(serde::Deserialize)]
struct ProtocolResultRow {
    protocol: TransportProtocol,
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
            let mut buf = Vec::with_capacity(256);
            self.record_logs_batch(std::slice::from_ref(timed_event), &mut buf)
                .await
        })
    }

    fn record_logs_batch<'a>(
        &'a self,
        events: &'a [TimedEvent],
        bytes_buf: &'a mut Vec<u8>,
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
                    bytes_buf.clear();
                    serde_json::to_writer(&mut *bytes_buf, event)
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                    table
                        .insert((ts, seq), bytes_buf.as_slice())
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
            let mut bytes_buf = Vec::with_capacity(256);
            serde_json::to_writer(&mut bytes_buf, &entry)
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
                    .insert((ts, seq), bytes_buf.as_slice())
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

                let mut bytes_buf = Vec::with_capacity(512);
                for entry in entries {
                    let ts = entry.timestamp;
                    let seq = self.log_seq.fetch_add(1, Ordering::Relaxed);
                    bytes_buf.clear();
                    serde_json::to_writer(&mut bytes_buf, entry)
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                    table
                        .insert((ts, seq), bytes_buf.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                }

                // Pre-aggregate telemetry buckets (15-minute / 900s buckets)
                if let Ok(mut table_telemetry) = write_txn.open_table(TABLE_DNS_TELEMETRY) {
                    let mut cached_buckets: std::collections::HashMap<u64, DnsQueryRateBucket> =
                        std::collections::HashMap::with_capacity(2);

                    for entry in entries {
                        let bucket_ts = (entry.timestamp / 900) * 900;
                        let bucket = match cached_buckets.get_mut(&bucket_ts) {
                            Some(b) => b,
                            None => {
                                let loaded = match table_telemetry
                                    .get(bucket_ts)
                                    .map_err(|e| DbError::Backend(e.to_string()))?
                                {
                                    Some(val) => serde_json::from_slice(val.value()).unwrap_or_else(|_| {
                                        DnsQueryRateBucket {
                                            timestamp: bucket_ts,
                                            ..Default::default()
                                        }
                                    }),
                                    None => DnsQueryRateBucket {
                                        timestamp: bucket_ts,
                                        ..Default::default()
                                    },
                                };
                                cached_buckets.entry(bucket_ts).or_insert(loaded)
                            }
                        };

                        bucket.total += 1;
                        let outcome_key = match entry.result {
                            QueryResult::Blocked | QueryResult::CachedBlock => {
                                bucket.blocked += 1;
                                "blocked"
                            }
                            QueryResult::Cached | QueryResult::Coalesced => {
                                bucket.cached += 1;
                                "cached"
                            }
                            QueryResult::Local => {
                                bucket.local += 1;
                                "local"
                            }
                            QueryResult::Rewritten => {
                                bucket.rewritten += 1;
                                "rewritten"
                            }
                            _ => {
                                bucket.forwarded += 1;
                                "forwarded"
                            }
                        };

                        let static_qtype = entry.qtype.as_static_str();
                        let qtype_str: std::borrow::Cow<'_, str> = match static_qtype {
                            Some(s) => std::borrow::Cow::Borrowed(s),
                            None => std::borrow::Cow::Owned(entry.qtype.to_string()),
                        };

                        if let Some(count) = bucket.record_types.get_mut(qtype_str.as_ref()) {
                            *count += 1;
                        } else {
                            bucket.record_types.insert(qtype_str.clone().into_owned(), 1);
                        }

                        let submap = if let Some(m) = bucket.outcome_types.get_mut(outcome_key) {
                            m
                        } else {
                            bucket.outcome_types.entry(outcome_key.to_string()).or_default()
                        };
                        if let Some(count) = submap.get_mut(qtype_str.as_ref()) {
                            *count += 1;
                        } else {
                            submap.insert(qtype_str.into_owned(), 1);
                        }
                    }

                    for (bucket_ts, bucket) in cached_buckets {
                        let val_bytes = serde_json::to_vec(&bucket)
                            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                        table_telemetry
                            .insert(bucket_ts, val_bytes.as_slice())
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                    }
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
                let _ = write_txn.delete_table(TABLE_DNS_TELEMETRY);
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
                    loop {
                        let mut chunk = Vec::with_capacity(512);
                        for item in table
                            .range(..(cutoff, 0))
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(512)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }

                    // Capacity cap (10,000)
                    let mut len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    while len > 10_000 {
                        let to_take = (len - 10_000).min(512);
                        let mut chunk = Vec::with_capacity(to_take);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(to_take)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        len -= chunk.len();
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }
                }

                // 2. Prune TABLE_DNS_QUERIES
                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_QUERIES) {
                    loop {
                        let mut chunk = Vec::with_capacity(512);
                        for item in table
                            .range(..(cutoff, 0))
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(512)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }

                    // Capacity cap (100,000)
                    let mut len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    while len > 100_000 {
                        let to_take = (len - 100_000).min(512);
                        let mut chunk = Vec::with_capacity(to_take);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(to_take)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        len -= chunk.len();
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }
                }

                // 3. Prune TABLE_DNS_BLOCKED
                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_BLOCKED) {
                    loop {
                        let mut chunk = Vec::with_capacity(512);
                        for item in table
                            .range(..(cutoff, 0))
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(512)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }

                    // Capacity cap (50,000)
                    let mut len = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
                    while len > 50_000 {
                        let to_take = (len - 50_000).min(512);
                        let mut chunk = Vec::with_capacity(to_take);
                        for item in table
                            .iter()
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(to_take)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        len -= chunk.len();
                        for k in chunk {
                            let _ = table.remove(k);
                        }
                    }
                }

                // 4. Prune TABLE_DNS_TELEMETRY (keep up to 30 days of 15-minute buckets)
                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_TELEMETRY) {
                    let telemetry_cutoff = cutoff.saturating_sub(23 * 86400); // 30 days total retention
                    loop {
                        let mut chunk = Vec::with_capacity(512);
                        for item in table
                            .range(..telemetry_cutoff)
                            .map_err(|e| DbError::Backend(e.to_string()))?
                            .take(512)
                        {
                            let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                            chunk.push(k.value());
                        }
                        if chunk.is_empty() {
                            break;
                        }
                        for k in chunk {
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
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
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

            let offset = offset.unwrap_or(0);
            let client_filter = client.as_deref().map(|c| c.trim()).filter(|c| !c.is_empty());
            let domain_filter = domain.as_deref().map(|d| d.trim()).filter(|d| !d.is_empty());
            let has_filters =
                client_filter.is_some() || domain_filter.is_some() || qtype.is_some() || result.is_some();

            if has_filters {
                let cf_lower = client_filter.map(|c| c.to_lowercase());
                let df_lower = domain_filter.map(|d| d.to_lowercase());
                let mut matched_total = 0;
                let mut entries = Vec::with_capacity(limit);

                for item in table
                    .iter()
                    .map_err(|e| DbError::Backend(e.to_string()))?
                    .rev()
                {
                    let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    let bytes = val.value();
                    let filter_row: QueryFilterRow = serde_json::from_slice(bytes)
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    if filter_row.matches(
                        cf_lower.as_deref(),
                        df_lower.as_deref(),
                        qtype,
                        result,
                    ) {
                        if matched_total >= offset && entries.len() < limit {
                            let entry: QueryLogEntry = serde_json::from_slice(bytes)
                                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                            entries.push(entry);
                        }
                        matched_total += 1;
                    }
                }
                Ok((entries, matched_total))
            } else {
                let total = table.len().map_err(|e| DbError::Backend(e.to_string()))? as usize;
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
            }
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
                let entry: DomainResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    continue;
                }
                if let Some(count) = counts.get_mut(entry.domain.as_ref()) {
                    *count += 1;
                } else {
                    counts.insert(entry.domain.to_string(), 1);
                }
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

            let client_ip: Option<IpAddr> = client.parse().ok();
            let client_mac: Option<MacAddr> = client.parse().ok();

            let mut counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ClientDomainResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    continue;
                }
                let matches = (client_ip.is_some() && client_ip == Some(entry.src_ip))
                    || (client_mac.is_some() && client_mac == entry.src_mac);
                if matches {
                    if let Some(count) = counts.get_mut(entry.domain.as_ref()) {
                        *count += 1;
                    } else {
                        counts.insert(entry.domain.to_string(), 1);
                    }
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
                let entry: QTypeResultRow = serde_json::from_slice(val.value())
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
                let (k, _) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let (timestamp, _) = k.value();
                let bucket = (timestamp / 30) * 30;
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
    ) -> BoxFuture<'_, Result<Vec<DnsQueryRateBucket>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let bsize = if bucket_secs == 0 { 900 } else { bucket_secs };

            // 1. Try reading from pre-aggregated TABLE_DNS_TELEMETRY first
            if let Ok(table_telemetry) = read_txn.open_table(TABLE_DNS_TELEMETRY) {
                let rounded_since = (since_secs / 900) * 900;
                let mut buckets: Vec<DnsQueryRateBucket> = Vec::new();

                for item in table_telemetry
                    .range(rounded_since..)
                    .map_err(|e| DbError::Backend(e.to_string()))?
                {
                    let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    if let Ok(b) = serde_json::from_slice::<DnsQueryRateBucket>(val.value()) {
                        buckets.push(b);
                    }
                }

                if !buckets.is_empty() {
                    buckets.sort_by_key(|b| b.timestamp);
                    if bsize == 900 {
                        return Ok(buckets);
                    }
                    let mut reaggregated: std::collections::BTreeMap<u64, DnsQueryRateBucket> =
                        std::collections::BTreeMap::new();
                    for b in buckets {
                        let target_ts = (b.timestamp / bsize) * bsize;
                        let target = reaggregated.entry(target_ts).or_insert_with(|| DnsQueryRateBucket {
                            timestamp: target_ts,
                            ..Default::default()
                        });
                        target.total += b.total;
                        target.cached += b.cached;
                        target.forwarded += b.forwarded;
                        target.blocked += b.blocked;
                        target.local += b.local;
                        target.rewritten += b.rewritten;
                        for (k, v) in b.record_types {
                            *target.record_types.entry(k).or_insert(0) += v;
                        }
                        for (outcome, map) in b.outcome_types {
                            let out_map = target.outcome_types.entry(outcome).or_default();
                            for (rtype, cnt) in map {
                                *out_map.entry(rtype).or_insert(0) += cnt;
                            }
                        }
                    }
                    return Ok(reaggregated.into_values().collect());
                }
            }

            // 2. Fallback to scanning raw TABLE_DNS_QUERIES
            let table = match read_txn.open_table(TABLE_DNS_QUERIES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let bsize = if bucket_secs == 0 { 30 } else { bucket_secs };
            let mut buckets: std::collections::HashMap<u64, DnsQueryRateBucket> =
                std::collections::HashMap::new();
            for item in table
                .range((since_secs, 0)..)
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let (ts, _) = k.value();
                let entry: QueryRateDetailedRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                let bucket_ts = (ts / bsize) * bsize;
                let bucket = buckets.entry(bucket_ts).or_insert_with(|| DnsQueryRateBucket {
                    timestamp: bucket_ts,
                    ..Default::default()
                });
                bucket.total += 1;

                let outcome_key = match entry.result {
                    QueryResult::Blocked | QueryResult::CachedBlock => {
                        bucket.blocked += 1;
                        "blocked"
                    }
                    QueryResult::Cached | QueryResult::Coalesced => {
                        bucket.cached += 1;
                        "cached"
                    }
                    QueryResult::Local => {
                        bucket.local += 1;
                        "local"
                    }
                    QueryResult::Rewritten => {
                        bucket.rewritten += 1;
                        "rewritten"
                    }
                    _ => {
                        bucket.forwarded += 1;
                        "forwarded"
                    }
                };

                if let Some(s) = entry.qtype.as_static_str() {
                    if let Some(cnt) = bucket.record_types.get_mut(s) {
                        *cnt += 1;
                    } else {
                        bucket.record_types.insert(s.to_string(), 1);
                    }
                    let out_map = bucket.outcome_types.entry(outcome_key.to_string()).or_default();
                    if let Some(cnt) = out_map.get_mut(s) {
                        *cnt += 1;
                    } else {
                        out_map.insert(s.to_string(), 1);
                    }
                } else {
                    let qtype_str = entry.qtype.to_string();
                    *bucket.record_types.entry(qtype_str.clone()).or_insert(0) += 1;
                    *bucket
                        .outcome_types
                        .entry(outcome_key.to_string())
                        .or_default()
                        .entry(qtype_str)
                        .or_insert(0) += 1;
                }
            }

            let mut vec: Vec<DnsQueryRateBucket> = buckets.into_values().collect();
            vec.sort_by_key(|a| a.timestamp);
            Ok(vec)
        })
    }

    fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64, u64)>, DbError>> {
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

            let mut counts: std::collections::HashMap<IpAddr, (u64, u64)> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ClientResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                let c = counts.entry(entry.src_ip).or_insert((0, 0));
                c.0 += 1;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    c.1 += 1;
                }
            }

            let mut vec: Vec<(IpAddr, (u64, u64))> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse((b.1).0));
            vec.truncate(limit);
            let result = vec
                .into_iter()
                .map(|(ip, (total, blocked))| (ip.to_string(), total, blocked))
                .collect();
            Ok(result)
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

            let mut udp = 0u64;
            let mut tcp = 0u64;
            let mut dot = 0u64;
            let mut doq = 0u64;
            let mut doh = 0u64;
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ProtocolResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                match entry.protocol {
                    TransportProtocol::Udp => udp += 1,
                    TransportProtocol::Tcp => tcp += 1,
                    TransportProtocol::Tls => dot += 1,
                    TransportProtocol::Quic => doq += 1,
                    TransportProtocol::Https => doh += 1,
                }
            }

            let vec = vec![
                ("udp".to_string(), udp),
                ("tcp".to_string(), tcp),
                ("dot".to_string(), dot),
                ("doq".to_string(), doq),
                ("doh".to_string(), doh),
            ];
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
                let entry: DomainResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    if let Some(count) = counts.get_mut(entry.domain.as_ref()) {
                        *count += 1;
                    } else {
                        counts.insert(entry.domain.to_string(), 1);
                    }
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

            let mut counts: std::collections::HashMap<IpAddr, u64> =
                std::collections::HashMap::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: ClientResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    *counts.entry(entry.src_ip).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(IpAddr, u64)> = counts.into_iter().collect();
            vec.sort_by_key(|b| std::cmp::Reverse(b.1));
            vec.truncate(limit);
            let result = vec
                .into_iter()
                .map(|(ip, count)| (ip.to_string(), count))
                .collect();
            Ok(result)
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
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let entry: BlockedRateResultRow = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock) {
                    let (timestamp, _) = k.value();
                    let bucket = (timestamp / 30) * 30;
                    *buckets.entry(bucket).or_insert(0) += 1;
                }
            }

            let mut vec: Vec<(u64, u64)> = buckets.into_iter().collect();
            vec.sort_by_key(|a| a.0);
            Ok(vec)
        })
    }

    fn load_dns_lifetime_stats(&self) -> BoxFuture<'_, Result<DnsLifetimeStats, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
                .begin_read()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_CONFIG) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(DnsLifetimeStats::default()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            match table
                .get("dns_lifetime_stats")
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                Some(val) => {
                    let stats: DnsLifetimeStats = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Ok(stats)
                }
                None => Ok(DnsLifetimeStats::default()),
            }
        })
    }

    fn save_dns_lifetime_stats<'a>(
        &'a self,
        stats: &'a DnsLifetimeStats,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let bytes = serde_json::to_vec(stats)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
            let write_txn = self
                .db
                .read()
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_CONFIG)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                table
                    .insert("dns_lifetime_stats", bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }
}
