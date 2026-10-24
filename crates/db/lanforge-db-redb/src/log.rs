//! LogStore implementation for `RedbDatabase`.

use crate::{RedbDatabase, decode, encode, encode_into};
use crate::tables::{
    TABLE_CONFIG, TABLE_DNS_BLOCKED, TABLE_DNS_QUERIES, TABLE_DNS_TELEMETRY,
    TABLE_DNS_STATS_HOURLY, TABLE_LOG_EVENTS,
    TABLE_RUNTIME_DEVICES,
};
use lanforge_core::bus::TimedEvent;
use lanforge_db_core::{DbError, DnsQueryRateBucket, LogStore};
use lanforge_types::device::{Device, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType};
use lanforge_types::network::{QueryLogEntry, QueryResult, TrafficHistorySample};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::net::IpAddr;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockedQueryEntry {
    pub timestamp: u64,
    pub src_ip: String,
    pub src_mac: Option<String>,
    pub domain: String,
}

const MAX_HOURLY_CARDINALITY: usize = 2_000;

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct HourlyDnsStats {
    total: u64,
    blocked: u64,
    domains: BTreeMap<String, u64>,
    clients: BTreeMap<String, u64>,
    qtypes: BTreeMap<u16, u64>,
    protocols: BTreeMap<String, u64>,
    blocked_domains: BTreeMap<String, u64>,
    blocked_clients: BTreeMap<String, u64>,
    other_domains: u64,
    other_clients: u64,
    other_qtypes: u64,
    other_protocols: u64,
    other_blocked_domains: u64,
    other_blocked_clients: u64,
    client_domains: BTreeMap<String, u64>,
    other_client_domains: u64,
}

fn bump_capped(map: &mut BTreeMap<String, u64>, key: String, other: &mut u64) {
    if let Some(count) = map.get_mut(&key) {
        *count += 1;
    } else if map.len() < MAX_HOURLY_CARDINALITY {
        map.insert(key, 1);
    } else {
        *other += 1;
    }
}

fn bump_capped_qtype(map: &mut BTreeMap<u16, u64>, key: u16, other: &mut u64) {
    if let Some(count) = map.get_mut(&key) {
        *count += 1;
    } else if map.len() < MAX_HOURLY_CARDINALITY {
        map.insert(key, 1);
    } else {
        *other += 1;
    }
}

fn load_recent_hourly_stats(db: &RedbDatabase) -> Result<Vec<HourlyDnsStats>, DbError> {
    let txn = db.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
    let table = match txn.open_table(TABLE_DNS_STATS_HOURLY) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(DbError::Backend(error.to_string())),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let start = (now / 3600).saturating_sub(167) * 3600;
    table.range(start..).map_err(|e| DbError::Backend(e.to_string()))?.take(168)
        .map(|row| {
            let (_, value) = row.map_err(|e| DbError::Backend(e.to_string()))?;
            decode(value.value())
        })
        .collect()
}

fn query_matches(
    entry: &QueryLogEntry,
    client_filter_lower: Option<&str>,
    domain_filter_lower: Option<&str>,
    qtype_filter: Option<DnsRecordType>,
    result_filter: Option<QueryResult>,
) -> bool {
    if let Some(client) = client_filter_lower {
        let ip_matches = entry.src_ip.to_string().contains(client);
        let mac_matches = entry.src_mac.is_some_and(|mac| mac.to_string().to_lowercase().contains(client));
        if !ip_matches && !mac_matches { return false; }
    }
    if domain_filter_lower.is_some_and(|domain| !entry.domain.to_lowercase().contains(domain)) {
        return false;
    }
    if qtype_filter.is_some_and(|qtype| entry.qtype != qtype) { return false; }
    if result_filter.is_some_and(|result| entry.result != result) { return false; }
    true
}

impl RedbDatabase {
    pub fn load_runtime_devices(&self) -> Result<Vec<Device>, DbError> {
        let txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match txn.open_table(TABLE_RUNTIME_DEVICES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(DbError::Backend(error.to_string())),
        };
        table.iter().map_err(|e| DbError::Backend(e.to_string()))?.map(|row| {
            let (_, value) = row.map_err(|e| DbError::Backend(e.to_string()))?;
            decode(value.value())
        }).collect()
    }

    pub fn sync_runtime_devices(
        &self,
        upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        if upserts.is_empty() && deletes.is_empty() { return Ok(()); }
        let txn = self.begin_write()?;
        let mut table = txn.open_table(TABLE_RUNTIME_DEVICES)
            .map_err(|e| DbError::Backend(e.to_string()))?;
        for mac in deletes {
            table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        }
        let mut bytes = Vec::with_capacity(512);
        for device in upserts {
            if device.origin == Origin::Dynamic {
                encode_into(device.as_ref(), &mut bytes)?;
                table.insert(device.mac.0.as_slice(), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            } else {
                table.remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        drop(table);
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }

    pub fn replace_runtime_devices(&self, upserts: &[std::sync::Arc<Device>]) -> Result<(), DbError> {
        let txn = self.begin_write()?;
        let mut table = txn.open_table(TABLE_RUNTIME_DEVICES)
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let keys: Vec<Vec<u8>> = table.iter().map_err(|e| DbError::Backend(e.to_string()))?
            .map(|row| row.map(|(key, _)| key.value().to_vec()).map_err(|e| DbError::Backend(e.to_string())))
            .collect::<Result<_, _>>()?;
        for key in keys {
            table.remove(key.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        }
        let mut bytes = Vec::with_capacity(512);
        for device in upserts.iter().filter(|device| device.origin == Origin::Dynamic) {
            encode_into(device.as_ref(), &mut bytes)?;
            table.insert(device.mac.0.as_slice(), bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        drop(table);
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }

    /// Auto-prunes older events and caps table sizes to prevent unbounded disk growth.
    pub fn maybe_prune(&self, now_secs: i64) -> Result<(), DbError> {
        let last = self.last_prune.load(Ordering::Relaxed);
        if now_secs - last >= 60
            && self
                .last_prune
                .compare_exchange(last, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            let cutoff = now_secs - (7 * 24 * 3600);
            self.prune_logs(cutoff)?;
        }
        Ok(())
    }

    /// Retrieves the most recent blocked DNS queries.
    pub fn get_dns_block_history(
        &self,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, DbError> {
            let read_txn = self.db
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
                let entry: BlockedQueryEntry = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
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

impl LogStore for RedbDatabase {
    fn load_runtime_devices(&self) -> Result<Vec<Device>, DbError> {
        RedbDatabase::load_runtime_devices(self)
    }

    fn sync_runtime_devices(
        &self,
        upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        RedbDatabase::sync_runtime_devices(self, upserts, deletes)
    }

    fn replace_runtime_devices(&self, upserts: &[std::sync::Arc<Device>]) -> Result<(), DbError> {
        RedbDatabase::replace_runtime_devices(self, upserts)
    }

    fn record_log(&self, timed_event: &TimedEvent) -> Result<(), DbError> {
        let mut buf = Vec::with_capacity(256);
        self.record_logs_batch(std::slice::from_ref(timed_event), &mut buf)
    }

    fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        bytes_buf: &mut Vec<u8>,
    ) -> Result<(), DbError> {
            if events.is_empty() {
                return Ok(());
            }

            let write_txn = self.db
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
                    encode_into(event, bytes_buf)?;
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
            self.maybe_prune(now_secs)?;

            Ok(())
    }

    fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError> {
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
            encode_into(&entry, &mut bytes_buf)?;

            let write_txn = self.db
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
            self.maybe_prune(now_secs)?;

            Ok(())
    }

    fn record_dns_queries_batch(
        &self,
        entries: &[QueryLogEntry],
    ) -> Result<(), DbError> {
            if entries.is_empty() {
                return Ok(());
            }

            let write_txn = self.db
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
                    encode_into(entry, &mut bytes_buf)?;
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
                                    Some(val) => decode(val.value()).unwrap_or_else(|_| {
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
                        let val_bytes = encode(&bucket)
                            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                        table_telemetry
                            .insert(bucket_ts, val_bytes.as_slice())
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                    }
                }

                let mut hourly = write_txn.open_table(TABLE_DNS_STATS_HOURLY)
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                let mut buckets: std::collections::HashMap<u64, HourlyDnsStats> =
                    std::collections::HashMap::with_capacity(2);
                for entry in entries {
                    let hour_ts = (entry.timestamp / 3600) * 3600;
                    let stats = match buckets.entry(hour_ts) {
                        std::collections::hash_map::Entry::Occupied(row) => row.into_mut(),
                        std::collections::hash_map::Entry::Vacant(row) => {
                            let existing = hourly.get(hour_ts)
                                .map_err(|e| DbError::Backend(e.to_string()))?
                                .map(|value| decode(value.value()))
                                .transpose()?
                                .unwrap_or_default();
                            row.insert(existing)
                        }
                    };
                    stats.total += 1;
                    let client = entry.src_ip.to_string();
                    bump_capped(&mut stats.clients, client.clone(), &mut stats.other_clients);
                    bump_capped_qtype(&mut stats.qtypes, u16::from(entry.qtype), &mut stats.other_qtypes);
                    let protocol = entry.protocol.to_string().to_ascii_lowercase();
                    bump_capped(&mut stats.protocols, protocol, &mut stats.other_protocols);
                    let is_blocked = matches!(entry.result, QueryResult::Blocked | QueryResult::CachedBlock);
                    if is_blocked {
                        stats.blocked += 1;
                        bump_capped(&mut stats.blocked_domains, entry.domain.to_string(), &mut stats.other_blocked_domains);
                        bump_capped(&mut stats.blocked_clients, client, &mut stats.other_blocked_clients);
                    } else {
                        bump_capped(&mut stats.domains, entry.domain.to_string(), &mut stats.other_domains);
                        bump_capped(
                            &mut stats.client_domains,
                            format!("{}|{}", entry.src_ip, entry.domain),
                            &mut stats.other_client_domains,
                        );
                    }
                }
                for (hour_ts, stats) in buckets {
                    let bytes = encode(&stats)?;
                    hourly.insert(hour_ts, bytes.as_slice())
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
            self.maybe_prune(now_secs)?;

            Ok(())
    }

    fn record_dns_query(
        &self,
        entry: &QueryLogEntry,
    ) -> Result<(), DbError> {
        self.record_dns_queries_batch(std::slice::from_ref(entry))
    }

    fn clear_logs(&self) -> Result<(), DbError> {
            let write_txn = self.db
                .begin_write()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let _ = write_txn.delete_table(TABLE_LOG_EVENTS);
                let _ = write_txn.delete_table(TABLE_DNS_QUERIES);
                let _ = write_txn.delete_table(TABLE_DNS_BLOCKED);
                let _ = write_txn.delete_table(TABLE_DNS_TELEMETRY);
                let _ = write_txn.delete_table(TABLE_DNS_STATS_HOURLY);
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
    }

    fn prune_logs(&self, before: i64) -> Result<(), DbError> {
            let cutoff = before.max(0) as u64;
            let write_txn = self.db
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

                if let Ok(mut table) = write_txn.open_table(TABLE_DNS_STATS_HOURLY) {
                    let hourly_cutoff = cutoff.saturating_sub(167 * 3600);
                    let old: Vec<u64> = table.range(..hourly_cutoff)
                        .map_err(|e| DbError::Backend(e.to_string()))?
                        .map(|row| row.map(|(key, _)| key.value()).map_err(|e| DbError::Backend(e.to_string())))
                        .collect::<Result<_, _>>()?;
                    for hour in old {
                        table.remove(hour).map_err(|e| DbError::Backend(e.to_string()))?;
                    }
                }
            }
            write_txn
                .commit()
                .map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
    }

    fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, DbError> {
            let read_txn = self.db
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
                let event: TimedEvent = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                entries.push(event);
            }
            entries.reverse();
            Ok(entries)
    }

    fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
    ) -> Result<(Vec<QueryLogEntry>, usize), DbError> {
            let read_txn = self.db
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
                    let entry: QueryLogEntry = match decode(bytes) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!("Skipping unreadable DNS query log entry during filtering: {e}");
                            continue;
                        }
                    };
                    if query_matches(
                        &entry,
                        cf_lower.as_deref(),
                        df_lower.as_deref(),
                        qtype,
                        result,
                    ) {
                        if matched_total >= offset && entries.len() < limit {
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
                {
                    if entries.len() >= limit {
                        break;
                    }
                    let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    match decode(val.value()) {
                        Ok(entry) => entries.push(entry),
                        Err(e) => {
                            tracing::warn!("Skipping unreadable DNS query log entry: {e}");
                        }
                    }
                }

                Ok((entries, total))
            }
    }

    fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DNS_STATS_HOURLY) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(DbError::Backend(error.to_string())),
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let start = (now / 3600).saturating_sub(167) * 3600;
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for row in table.range(start..).map_err(|e| DbError::Backend(e.to_string()))?.take(168) {
            let (_, value) = row.map_err(|e| DbError::Backend(e.to_string()))?;
            let stats: HourlyDnsStats = decode(value.value())?;
            for (domain, count) in stats.domains {
                *counts.entry(domain).or_default() += count;
            }
        }
        let mut rows: Vec<_> = counts.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        Ok(rows)
    }

    fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
            if let Ok(ip) = client.parse::<IpAddr>() {
                let prefix = format!("{ip}|");
                let mut counts = BTreeMap::<String, u64>::new();
                for bucket in load_recent_hourly_stats(self)? {
                    for (key, count) in bucket.client_domains {
                        if let Some(domain) = key.strip_prefix(&prefix) {
                            *counts.entry(domain.to_string()).or_default() += count;
                        }
                    }
                }
                let mut rows: Vec<_> = counts.into_iter().collect();
                rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                rows.truncate(limit);
                return Ok(rows);
            }
            let read_txn = self.db
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
                let entry: QueryLogEntry = decode(val.value())
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
    }

    fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError> {
        let mut counts = BTreeMap::<u16, u64>::new();
        for bucket in load_recent_hourly_stats(self)? {
            for (qtype, count) in bucket.qtypes { *counts.entry(qtype).or_default() += count; }
        }
        Ok(counts.into_iter().collect())
    }

    fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, DbError> {
            let read_txn = self.db
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
    }

    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<DnsQueryRateBucket>, DbError> {
            let read_txn = self.db
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
                    if let Ok(b) = decode::<DnsQueryRateBucket>(val.value()) {
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
                let entry: QueryLogEntry = decode(val.value())
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
    }

    fn get_dns_top_clients(&self, limit: usize) -> Result<Vec<(String, u64, u64)>, DbError> {
        let mut counts = BTreeMap::<String, (u64, u64)>::new();
        for bucket in load_recent_hourly_stats(self)? {
            for (client, count) in bucket.clients { counts.entry(client).or_default().0 += count; }
            for (client, count) in bucket.blocked_clients { counts.entry(client).or_default().1 += count; }
        }
        let mut rows: Vec<_> = counts.into_iter().map(|(client, (total, blocked))| (client, total, blocked)).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        Ok(rows)
    }

    fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError> {
        let mut counts = BTreeMap::<String, u64>::new();
        for bucket in load_recent_hourly_stats(self)? {
            for (protocol, count) in bucket.protocols { *counts.entry(protocol).or_default() += count; }
        }
        Ok(counts.into_iter().collect())
    }

    fn get_dns_top_blocked_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        let mut counts = BTreeMap::<String, u64>::new();
        for bucket in load_recent_hourly_stats(self)? {
            for (domain, count) in bucket.blocked_domains { *counts.entry(domain).or_default() += count; }
        }
        let mut rows: Vec<_> = counts.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        Ok(rows)
    }

    fn get_dns_top_blocked_clients(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        let mut counts = BTreeMap::<String, u64>::new();
        for bucket in load_recent_hourly_stats(self)? {
            for (client, count) in bucket.blocked_clients { *counts.entry(client).or_default() += count; }
        }
        let mut rows: Vec<_> = counts.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        Ok(rows)
    }

    fn get_dns_blocked_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError> {
        let cutoff = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
            .as_secs().saturating_sub(since_secs);
        let txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match txn.open_table(TABLE_DNS_STATS_HOURLY) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(DbError::Backend(error.to_string())),
        };
        table.range((cutoff / 3600) * 3600..)
            .map_err(|e| DbError::Backend(e.to_string()))?
            .take(168)
            .map(|row| {
                let (key, value) = row.map_err(|e| DbError::Backend(e.to_string()))?;
                let stats: HourlyDnsStats = decode(value.value())?;
                Ok((key.value(), stats.blocked))
            })
            .collect()
    }

    fn load_dns_lifetime_stats(&self) -> Result<DnsLifetimeStats, DbError> {
            let read_txn = self.db
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
                    let stats: DnsLifetimeStats = decode(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Ok(stats)
                }
                None => Ok(DnsLifetimeStats::default()),
            }
    }

    fn save_dns_lifetime_stats(
        &self,
        stats: &DnsLifetimeStats,
    ) -> Result<(), DbError> {
            let bytes = encode(stats)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
            let write_txn = self.db
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
    }

    fn load_traffic_history(&self) -> Result<Vec<TrafficHistorySample>, DbError> {
        let read_txn = self.db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table
            .get("traffic_history_snapshot")
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
            Some(val) => {
                let samples: Vec<TrafficHistorySample> = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(samples)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_traffic_history(&self, samples: &[TrafficHistorySample]) -> Result<(), DbError> {
        let bytes = encode(samples)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
        let write_txn = self.db
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            table
                .insert("traffic_history_snapshot", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}
