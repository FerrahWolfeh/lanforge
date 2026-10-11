//! Log engine backed by embedded `redb` (`runtime.redb`).

use lanforge_core::bus::TimedEvent;
use lanforge_db_core::{BoxFuture, DbError, DnsQueryRateBucket, LogStore};
use lanforge_db_redb::RedbDatabase;
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType};
use lanforge_types::network::{QueryLogEntry, QueryResult};
use std::net::IpAddr;
use std::path::Path;

/// Compatibility alias for log database error.
pub type LogBufError = DbError;

/// Runtime log database facade.
#[derive(Clone)]
pub struct LogDb {
    inner: RedbDatabase,
}

impl LogDb {
    /// Opens the runtime log database at the given path or URL.
    /// If path is empty or contains ":memory:", opens in-memory.
    pub async fn open(url_or_path: &str) -> Result<Self, DbError> {
        let is_memory = url_or_path.contains(":memory:") || url_or_path.is_empty();
        if is_memory {
            return Ok(Self::open_in_memory());
        }

        let path_str = url_or_path
            .strip_prefix("sqlite://")
            .or_else(|| url_or_path.strip_prefix("sqlite:"))
            .or_else(|| url_or_path.strip_prefix("redb://"))
            .unwrap_or(url_or_path);
        let path_str = path_str.split('?').next().unwrap_or(path_str);

        match RedbDatabase::open(path_str) {
            Ok(db) => Ok(Self { inner: db }),
            Err(DbError::Validation(e)) => Err(DbError::Validation(e)),
            Err(e) => {
                tracing::warn!(
                    "Failed to open runtime redb at {path_str}: {e}. Falling back to in-memory mode."
                );
                Ok(Self::open_in_memory())
            }
        }
    }

    /// Opens an isolated in-memory runtime log database without file persistence.
    #[must_use]
    pub fn open_in_memory() -> Self {
        Self {
            inner: RedbDatabase::open_in_memory(),
        }
    }

    /// Returns true if running without file persistence.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        self.inner.is_in_memory()
    }

    /// Returns the current schema version of the runtime database.
    pub fn schema_version(&self) -> Result<u32, DbError> {
        self.inner.schema_version()
    }

    /// Returns the path to the runtime database file, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.inner.path()
    }

    /// Direct access to inner RedbDatabase.
    #[must_use]
    pub fn inner(&self) -> &RedbDatabase {
        &self.inner
    }

    pub async fn record_log(&self, timed_event: &TimedEvent) -> Result<(), DbError> {
        self.inner.record_log(timed_event).await
    }

    pub async fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        bytes_buf: &mut Vec<u8>,
    ) -> Result<(), DbError> {
        self.inner.record_logs_batch(events, bytes_buf).await
    }

    pub async fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError> {
        self.inner
            .record_dns_block(timed_event, src_ip, domain, src_mac)
            .await
    }

    pub async fn record_dns_queries_batch(
        &self,
        entries: &[QueryLogEntry],
    ) -> Result<(), DbError> {
        self.inner.record_dns_queries_batch(entries).await
    }

    pub async fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), DbError> {
        self.inner.record_dns_query(entry).await
    }

    pub async fn clear_logs(&self) -> Result<(), DbError> {
        self.inner.clear_logs().await
    }

    pub async fn prune_logs(&self, before: i64) -> Result<(), DbError> {
        self.inner.prune_logs(before).await
    }

    pub async fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, DbError> {
        self.inner.get_history(limit).await
    }

    pub async fn get_dns_query_history(
        &self,
        limit: usize,
        offset: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
    ) -> Result<(Vec<QueryLogEntry>, usize), DbError> {
        self.inner
            .get_dns_query_history(limit, offset, client, domain, qtype, result)
            .await
    }

    pub async fn get_dns_top_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_domains(limit).await
    }

    pub async fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
        self.inner
            .get_dns_top_domains_for_client(client, limit)
            .await
    }

    pub async fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError> {
        self.inner.get_dns_query_types().await
    }

    pub async fn get_dns_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError> {
        self.inner.get_dns_query_rate(since_secs).await
    }

    pub async fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<DnsQueryRateBucket>, DbError> {
        self.inner
            .get_dns_query_rate_detailed(since_secs, bucket_secs)
            .await
    }

    pub async fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64, u64)>, DbError> {
        self.inner.get_dns_top_clients(limit).await
    }

    pub async fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_protocol_stats().await
    }

    pub async fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_blocked_domains(limit).await
    }

    pub async fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_blocked_clients(limit).await
    }

    pub async fn get_dns_blocked_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, DbError> {
        self.inner.get_dns_blocked_query_rate(since_secs).await
    }

    pub async fn load_dns_lifetime_stats(&self) -> Result<DnsLifetimeStats, DbError> {
        self.inner.load_dns_lifetime_stats().await
    }

    pub async fn save_dns_lifetime_stats(&self, stats: &DnsLifetimeStats) -> Result<(), DbError> {
        self.inner.save_dns_lifetime_stats(stats).await
    }
}

impl LogStore for LogDb {
    fn record_log<'a>(&'a self, timed_event: &'a TimedEvent) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_log(timed_event)
    }

    fn record_logs_batch<'a>(
        &'a self,
        events: &'a [TimedEvent],
        bytes_buf: &'a mut Vec<u8>,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_logs_batch(events, bytes_buf)
    }

    fn record_dns_block<'a>(
        &'a self,
        timed_event: &'a TimedEvent,
        src_ip: IpAddr,
        domain: &'a str,
        src_mac: Option<String>,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_dns_block(timed_event, src_ip, domain, src_mac)
    }

    fn record_dns_queries_batch<'a>(
        &'a self,
        entries: &'a [QueryLogEntry],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_dns_queries_batch(entries)
    }

    fn record_dns_query<'a>(
        &'a self,
        entry: &'a QueryLogEntry,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.record_dns_query(entry)
    }

    fn clear_logs(&self) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.clear_logs()
    }

    fn prune_logs(&self, before: i64) -> BoxFuture<'_, Result<(), DbError>> {
        self.inner.prune_logs(before)
    }

    fn get_history(&self, limit: usize) -> BoxFuture<'_, Result<Vec<TimedEvent>, DbError>> {
        self.inner.get_history(limit)
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
        self.inner
            .get_dns_query_history(limit, offset, client, domain, qtype, result)
    }

    fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        self.inner.get_dns_top_domains(limit)
    }

    fn get_dns_top_domains_for_client<'a>(
        &'a self,
        client: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Result<Vec<(String, u64)>, DbError>> {
        self.inner.get_dns_top_domains_for_client(client, limit)
    }

    fn get_dns_query_types(&self) -> BoxFuture<'_, Result<Vec<(u16, u64)>, DbError>> {
        self.inner.get_dns_query_types()
    }

    fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>> {
        self.inner.get_dns_query_rate(since_secs)
    }

    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<DnsQueryRateBucket>, DbError>> {
        self.inner.get_dns_query_rate_detailed(since_secs, bucket_secs)
    }

    fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64, u64)>, DbError>> {
        self.inner.get_dns_top_clients(limit)
    }

    fn get_dns_protocol_stats(&self) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        self.inner.get_dns_protocol_stats()
    }

    fn get_dns_top_blocked_domains(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        self.inner.get_dns_top_blocked_domains(limit)
    }

    fn get_dns_top_blocked_clients(
        &self,
        limit: usize,
    ) -> BoxFuture<'_, Result<Vec<(String, u64)>, DbError>> {
        self.inner.get_dns_top_blocked_clients(limit)
    }

    fn get_dns_blocked_query_rate(
        &self,
        since_secs: u64,
    ) -> BoxFuture<'_, Result<Vec<(u64, u64)>, DbError>> {
        self.inner.get_dns_blocked_query_rate(since_secs)
    }

    fn load_dns_lifetime_stats(&self) -> BoxFuture<'_, Result<DnsLifetimeStats, DbError>> {
        self.inner.load_dns_lifetime_stats()
    }

    fn save_dns_lifetime_stats<'a>(
        &'a self,
        stats: &'a DnsLifetimeStats,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        self.inner.save_dns_lifetime_stats(stats)
    }
}
