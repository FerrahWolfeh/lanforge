//! Log engine backed by embedded `redb` (`runtime.redb`).

use lanforge_core::bus::TimedEvent;
use lanforge_db_core::{DbError, DnsQueryRateBucket, LogStore};
use lanforge_db_redb::RedbDatabase;
use lanforge_types::device::Device;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::{DnsLifetimeStats, DnsRecordType};
use lanforge_types::network::{QueryLogEntry, QueryResult, TrafficHistorySample};
use std::net::IpAddr;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;

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
    pub fn open(url_or_path: &str) -> Result<Self, DbError> {
        let normalized = url_or_path.trim().to_ascii_lowercase();
        let is_memory = normalized.is_empty()
            || normalized == "memory"
            || normalized == "none"
            || normalized == "mock"
            || normalized.contains(":memory:");
        if is_memory {
            return Ok(Self::open_in_memory());
        }

        let path_str = url_or_path
            .strip_prefix("sqlite://")
            .or_else(|| url_or_path.strip_prefix("sqlite:"))
            .or_else(|| url_or_path.strip_prefix("redb://"))
            .unwrap_or(url_or_path);
        let path_str = path_str.split('?').next().unwrap_or(path_str);

        let requested = PathBuf::from(path_str);
        let mut candidates = vec![
            requested.clone(),
            PathBuf::from("/run/lanforge/runtime.redb"),
        ];
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            candidates.push(PathBuf::from(xdg).join("lanforge/runtime.redb"));
        }
        candidates.push(PathBuf::from("/tmp/lanforge/runtime.redb"));
        candidates.dedup();

        let mut last_error = None;
        for candidate in candidates {
            match RedbDatabase::open_volatile(&candidate) {
                Ok(db) => {
                    warn_if_runtime_filesystem_is_persistent(
                        candidate.parent().unwrap_or(Path::new("/")),
                    );
                    return Ok(Self { inner: db });
                }
                Err(error) => {
                    tracing::warn!(path = %candidate.display(), %error, "Runtime database path unavailable; trying fallback");
                    last_error = Some(error);
                }
            }
        }
        tracing::warn!(error = ?last_error, "All runtime database paths failed; using in-memory mode");
        Ok(Self::open_in_memory())
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
}

fn warn_if_runtime_filesystem_is_persistent(directory: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(directory.as_os_str().as_bytes()) else {
        return;
    };
    // Linux TMPFS_MAGIC and RAMFS_MAGIC values from linux/magic.h.
    const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
    const RAMFS_MAGIC: libc::c_long = 0x8584_58f6u32 as libc::c_long;
    // SAFETY: `path` is a NUL-terminated pathname and `stats` points to writable storage.
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let result = unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        tracing::warn!(path = %directory.display(), error = %std::io::Error::last_os_error(), "Could not inspect runtime database filesystem; flash wear is possible");
        return;
    }
    // SAFETY: statfs initialized stats after returning success.
    let fs = unsafe { stats.assume_init() };
    if fs.f_type != TMPFS_MAGIC && fs.f_type != RAMFS_MAGIC {
        tracing::warn!(path = %directory.display(), filesystem_magic = fs.f_type, "Runtime database is not on tmpfs/ramfs; writes may increase flash wear");
    }
}

impl Deref for LogDb {
    type Target = RedbDatabase;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl LogStore for LogDb {
    fn load_runtime_devices(&self) -> Result<Vec<Device>, DbError> {
        self.inner.load_runtime_devices()
    }

    fn sync_runtime_devices(
        &self,
        upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        self.inner.sync_runtime_devices(upserts, deletes)
    }

    fn replace_runtime_devices(&self, upserts: &[std::sync::Arc<Device>]) -> Result<(), DbError> {
        self.inner.replace_runtime_devices(upserts)
    }

    fn record_log(&self, timed_event: &TimedEvent) -> Result<(), DbError> {
        self.inner.record_log(timed_event)
    }

    fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        bytes_buf: &mut Vec<u8>,
    ) -> Result<(), DbError> {
        self.inner.record_logs_batch(events, bytes_buf)
    }

    fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), DbError> {
        self.inner
            .record_dns_block(timed_event, src_ip, domain, src_mac)
    }

    fn record_dns_queries_batch(
        &self,
        entries: &[std::sync::Arc<QueryLogEntry>],
    ) -> Result<(), DbError> {
        self.inner.record_dns_queries_batch(entries)
    }

    fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), DbError> {
        self.inner.record_dns_query(entry)
    }

    fn clear_logs(&self) -> Result<(), DbError> {
        self.inner.clear_logs()
    }

    fn prune_logs(&self, before: i64) -> Result<(), DbError> {
        self.inner.prune_logs(before)
    }

    fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, DbError> {
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
    ) -> Result<(Vec<QueryLogEntry>, usize), DbError> {
        self.inner
            .get_dns_query_history(limit, offset, client, domain, qtype, result)
    }

    fn get_dns_top_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_domains(limit)
    }

    fn get_dns_top_domains_for_client(
        &self,
        client: &str,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_domains_for_client(client, limit)
    }

    fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, DbError> {
        self.inner.get_dns_query_types()
    }

    fn get_dns_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError> {
        self.inner.get_dns_query_rate(since_secs)
    }

    fn get_dns_query_rate_detailed(
        &self,
        since_secs: u64,
        bucket_secs: u64,
    ) -> Result<Vec<DnsQueryRateBucket>, DbError> {
        self.inner
            .get_dns_query_rate_detailed(since_secs, bucket_secs)
    }

    fn get_dns_top_clients(&self, limit: usize) -> Result<Vec<(String, u64, u64)>, DbError> {
        self.inner.get_dns_top_clients(limit)
    }

    fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_protocol_stats()
    }

    fn get_dns_top_blocked_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_blocked_domains(limit)
    }

    fn get_dns_top_blocked_clients(&self, limit: usize) -> Result<Vec<(String, u64)>, DbError> {
        self.inner.get_dns_top_blocked_clients(limit)
    }

    fn get_dns_blocked_query_rate(&self, since_secs: u64) -> Result<Vec<(u64, u64)>, DbError> {
        self.inner.get_dns_blocked_query_rate(since_secs)
    }

    fn load_dns_lifetime_stats(&self) -> Result<DnsLifetimeStats, DbError> {
        self.inner.load_dns_lifetime_stats()
    }

    fn save_dns_lifetime_stats(&self, stats: &DnsLifetimeStats) -> Result<(), DbError> {
        self.inner.save_dns_lifetime_stats(stats)
    }

    fn load_traffic_history(&self) -> Result<Vec<TrafficHistorySample>, DbError> {
        self.inner.load_traffic_history()
    }

    fn save_traffic_history(&self, samples: &[TrafficHistorySample]) -> Result<(), DbError> {
        self.inner.save_traffic_history(samples)
    }
}
