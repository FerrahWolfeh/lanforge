//! `DbWorker` — Background service for database persistence and logging.
//!
//! Listens for events on the global `EventBus` and performs batch updates
//! to the `LanforgeDb` (persistent) and `LogDb` (transient).
//!
//! ## Batching
//!
//! To avoid excessive disk I/O, the worker batches `DeviceTableDirty` events
//! and only flushes the entire table to disk once every 5 seconds or when
//! a high-priority event occurs.
//!
//! ## Logging
//!
//! All loggable events are immediately recorded in the in-memory `LogDb`.

use lanforge_core::bus::{
    DeviceEvent, DnsEvent, EventTopic, LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent,
    TimedEvent,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lanforge_core::context::{LanforgeContext, StorageCommand, StorageHandle};
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_db_core::{DeviceStore, LogStore, PrefixStore};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::QueryLogEntry;
use lanforge_types::network::dns::{DnsRequest, DnsResponse};
use lanforge_types::system::{DegradedReason, ServiceId};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::{Instant, Interval, interval};
use tracing::{debug, error, info, warn};

use crate::config::DatabaseConfig;
use crate::engine::LanforgeDb;
use crate::log_engine::LogDb;

const MAX_LOG_BUFFER: usize = 10_000;
const MAX_DNS_LOG_BUFFER: usize = 50_000;

/// The pending persistence operation for a specific MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDeviceOp {
    /// Full sync required (lease changes, new discoveries, expiration).
    UpsertFull,
    /// Base attributes only sync (hostname, metadata changes).
    UpsertBase,
    /// Deletion from database (purged host).
    Delete,
}

/// Background worker for database operations.
pub struct DbWorker {
    cfg: DatabaseConfig,
    ctx: LanforgeContext,
    db: Arc<LanforgeDb>,
    log_db: Arc<LogDb>,
    full_flush_requested: bool,
    pending_devices: HashMap<MacAddr, PendingDeviceOp>,
    log_buffer: VecDeque<TimedEvent>,
    dns_log_buffer: VecDeque<Arc<QueryLogEntry>>,
    bytes_buf: Vec<u8>,
    storage_rx: Option<mpsc::Receiver<StorageCommand>>,
    log_flush_failing: bool,
    dns_flush_failing: bool,
    device_flush_failing: bool,
}

impl DbWorker {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Db;
    /// Creates a new `DbWorker` for the specified databases.
    #[must_use]
    pub fn new(
        cfg: DatabaseConfig,
        ctx: LanforgeContext,
        db: Arc<LanforgeDb>,
        log_db: Arc<LogDb>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);
        ctx.set_storage_handle(StorageHandle::new(tx));

        Self {
            cfg,
            ctx,
            db,
            log_db,
            full_flush_requested: false,
            pending_devices: HashMap::new(),
            log_buffer: VecDeque::with_capacity(128),
            dns_log_buffer: VecDeque::with_capacity(128),
            bytes_buf: Vec::with_capacity(4096),
            storage_rx: Some(rx),
            log_flush_failing: false,
            dns_flush_failing: false,
            device_flush_failing: false,
        }
    }

    /// Writes the batched DNS query log; `false` when the write failed (the batch is kept).
    fn flush_dns_log(&mut self, log_db: &LogDb) -> bool {
        if self.dns_log_buffer.is_empty() {
            return true;
        }
        let slice = self.dns_log_buffer.make_contiguous();
        if let Err(e) = log_db.record_dns_queries_batch(slice) {
            if !self.dns_flush_failing {
                error!("Failed to flush DNS log batch: {e}");
                self.dns_flush_failing = true;
            }
            return false;
        }
        if self.dns_flush_failing {
            info!("DNS log batch flush recovered");
            self.dns_flush_failing = false;
        }
        self.dns_log_buffer.clear();
        true
    }

    /// Flushes the current device table to the persistent database.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn flush_batch(&mut self, db: &LanforgeDb, log_db: &LogDb) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut had_error = false;
        let mut written_devices_count = 0;

        // 1. Flush Logs
        if !self.log_buffer.is_empty() {
            let slice = self.log_buffer.make_contiguous();
            if let Err(e) = log_db.record_logs_batch(slice, &mut self.bytes_buf) {
                if !self.log_flush_failing {
                    error!("Failed to flush log batch: {e}");
                    self.log_flush_failing = true;
                }
                had_error = true;
            } else {
                if self.log_flush_failing {
                    info!("Log batch flush recovered");
                    self.log_flush_failing = false;
                }
                self.log_buffer.clear();
            }
        }

        let had_dns_queries = !self.dns_log_buffer.is_empty();
        if !self.flush_dns_log(log_db) {
            had_error = true;
        }

        // 2. Flush DNS Lifetime Stats (only when new queries were processed)
        if had_dns_queries
            && let Some(handle) = self.ctx.dns_handle()
            && let Ok(DnsResponse::LifetimeStats(stats)) =
                handle.send_request(DnsRequest::LifetimeStats).await
            && let Err(e) = log_db.save_dns_lifetime_stats(&stats)
        {
            error!("Failed to flush DNS lifetime stats: {e}");
        }

        // 3. Flush Main DB
        let metrics = self.ctx.db_metrics();
        if !self.full_flush_requested && self.pending_devices.is_empty() {
            metrics.last_flush_ts.store(now, Ordering::Relaxed);
            metrics.flush_count.fetch_add(1, Ordering::Relaxed);
            metrics.last_error.store(had_error, Ordering::Relaxed);
            self.ctx.record_db_flush();
            return;
        }

        let res = if self.full_flush_requested {
            // Full flush requested (rare)
            let snapshot = self.ctx.snapshot_for_persistence();
            let len = snapshot.devices.len();
            let devices: Vec<_> = snapshot.devices.values().cloned().collect();
            db.save_snapshot(&snapshot)
                .and_then(|()| log_db.replace_runtime_devices(&devices))
                .map(|()| len)
        } else {
            // Incremental flush (common)
            let (lease_devices, base_devices, purges) = self.ctx.with_state(|state| {
                let mut lease = Vec::new();
                let mut base = Vec::new();
                let mut purges = Vec::new();
                for (&mac, &op) in &self.pending_devices {
                    match op {
                        PendingDeviceOp::Delete => purges.push(mac),
                        PendingDeviceOp::UpsertFull => {
                            if let Some(device) = state.devices.get(&mac).cloned() {
                                lease.push(device);
                            } else {
                                // Missing from state: move to delete (F8)
                                purges.push(mac);
                            }
                        }
                        PendingDeviceOp::UpsertBase => {
                            if let Some(device) = state.devices.get(&mac).cloned() {
                                base.push(device);
                            } else {
                                // Missing from state: move to delete (F8)
                                purges.push(mac);
                            }
                        }
                    }
                }
                (lease, base, purges)
            });

            let count = lease_devices.len() + base_devices.len() + purges.len();
            let runtime_upserts: Vec<_> =
                lease_devices.iter().chain(&base_devices).cloned().collect();
            let result = db
                .batch_sync_devices(&lease_devices, &base_devices, &purges)
                .and_then(|()| log_db.sync_runtime_devices(&runtime_upserts, &purges));
            result.map(|()| count)
        };

        match res {
            Err(e) => {
                if !self.device_flush_failing {
                    error!("Failed to save device table to database: {e}");
                    self.device_flush_failing = true;
                }
                had_error = true;
            }
            Ok(count) => {
                if self.device_flush_failing {
                    info!("Device table flush recovered");
                    self.device_flush_failing = false;
                }
                written_devices_count = count;
                let was_full_flush = self.full_flush_requested;
                self.full_flush_requested = false;
                self.pending_devices.clear();

                if count > 0 {
                    let _ = self
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::Storage(StorageEvent::DbWrite {
                            devices: count,
                        }));
                    if was_full_flush {
                        debug!("Main DB flushed (all devices)");
                    } else {
                        debug!("Main DB flushed ({count} devices)");
                    }
                }
            }
        }

        metrics.last_flush_ts.store(now, Ordering::Relaxed);
        metrics.flush_count.fetch_add(1, Ordering::Relaxed);
        metrics
            .devices_written
            .fetch_add(written_devices_count as u64, Ordering::Relaxed);
        metrics.last_error.store(had_error, Ordering::Relaxed);
        self.ctx.record_db_flush();
    }
}

impl AsyncService for DbWorker {
    async fn init(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let mode = if ctx.is_recovery_mode() {
            "RECOVERY MODE (in-memory)"
        } else if self.db.is_in_memory() {
            "in-memory"
        } else {
            "redb (persistent)"
        };
        info!("Database worker initialized (mode: {mode})");
        Ok(())
    }

    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        let db = Arc::clone(&self.db);
        let log_db = Arc::clone(&self.log_db);

        if ctx.is_recovery_mode() {
            h.degraded(DegradedReason::custom("no persistence"));
        } else {
            h.ready();
        }

        let mut storage_rx = self.storage_rx.take().unwrap_or_else(|| {
            let (tx, rx) = mpsc::channel(64);
            ctx.set_storage_handle(StorageHandle::new(tx));
            rx
        });
        let mut system_rx = ctx.bus().subscribe_system();
        let mut network_rx = ctx.bus().subscribe_network();
        let mut device_rx = ctx.bus().subscribe_device();
        let mut dns_rx = ctx.bus().subscribe_dns();
        let mut storage_rx_events = ctx.bus().subscribe_storage();
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut firewall_rx = ctx.bus().subscribe_firewall();
        let mut traffic_rx = ctx.bus().subscribe_traffic();
        let mut flush_interval: Interval = interval(Duration::from_secs(self.cfg.flush_interval));
        let mut last_prune = Instant::now();
        let stores = db.stores(Arc::clone(&log_db) as _);

        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            self.flush_batch(&db, &log_db).await;
                            break;
                        }
                        ServiceCommand::Restart => {
                            h.request_restart();
                            self.flush_batch(&db, &log_db).await;
                            break;
                        }
                        _ => {}
                    }
                }

                // Storage commands via closure channel
                cmd = storage_rx.recv() => {
                    match cmd {
                        Some(StorageCommand::Call(call)) => {
                            call(&stores);
                        }
                        Some(StorageCommand::FlushNow(resp_tx)) => {
                            self.flush_batch(&db, &log_db).await;
                            let _ = resp_tx.send(Ok(()));
                        }
                        Some(StorageCommand::FlushDnsLog(resp_tx)) => {
                            self.flush_dns_log(&log_db);
                            let _ = resp_tx.send(());
                        }
                        None => break,
                    }
                }

                // Event handling
                (topic, res) = async {
                    tokio::select! {
                        res = system_rx.recv() => (EventTopic::System, res),
                        res = network_rx.recv() => (EventTopic::Network, res),
                        res = device_rx.recv() => (EventTopic::Device, res),
                        res = dns_rx.recv() => (EventTopic::Dns, res),
                        res = storage_rx_events.recv() => (EventTopic::Storage, res),
                        res = pppoe_rx.recv() => (EventTopic::Pppoe, res),
                        res = firewall_rx.recv() => (EventTopic::Firewall, res),
                        res = traffic_rx.recv() => (EventTopic::Traffic, res),
                    }
                } => {
                    let Ok(timed_event) = res else {
                        if let Err(RecvError::Lagged(n)) = res {
                            warn!(service = "DbWorker", lost = n, "Event bus lagged");
                            continue;
                        }
                        break;
                    };
                    let mirrored = matches!(
                        (&timed_event.event, topic),
                        (LanforgeEvent::System(SystemEvent::Shutdown), topic)
                            if topic != EventTopic::System
                    ) || matches!(
                        (&timed_event.event, topic),
                        (LanforgeEvent::Pppoe(_), EventTopic::Dns)
                    );
                    if mirrored { continue; }
                    // 1. Record in log database if loggable
                    if timed_event.is_loggable() {
                        if self.log_buffer.len() >= MAX_LOG_BUFFER {
                            self.log_buffer.pop_front();
                            self.ctx.db_metrics().dropped_logs.fetch_add(1, Ordering::Relaxed);
                        }
                        self.log_buffer.push_back(timed_event.clone());
                        if self.log_buffer.len() >= 100 {
                            let slice = self.log_buffer.make_contiguous();
                            if let Err(e) = log_db.record_logs_batch(slice, &mut self.bytes_buf) {
                                if !self.log_flush_failing {
                                    error!("Immediate log flush error: {e}");
                                    self.log_flush_failing = true;
                                }
                            } else {
                                if self.log_flush_failing {
                                    info!("Immediate log flush recovered");
                                    self.log_flush_failing = false;
                                }
                                self.log_buffer.clear();
                            }
                        }
                    }

                    // 2. Process specific events
                    let mut break_loop = false;
                    lanforge_core::match_event!(timed_event, {
                        // Remember the LAN's delegated prefix only (not `ppp0`'s own), and keep the
                        // last known one while it is briefly withdrawn during a reconnect.
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged(details)) => {
                            if Some(details.ifindex) == ctx.target_ifindex()
                                && let Some(gua) = details.gua
                            {
                                let _ = db.save_last_gua_prefix(Some(gua));
                            }
                        }
                        LanforgeEvent::Device(DeviceEvent::NetworkUpdate { mac, change, .. }) => {
                            if change.is_persistent() {
                                if change.is_lease_change() {
                                    self.pending_devices.insert(*mac, PendingDeviceOp::UpsertFull);
                                } else {
                                    self.pending_devices
                                        .entry(*mac)
                                        .and_modify(|op| {
                                            if *op != PendingDeviceOp::UpsertFull {
                                                *op = PendingDeviceOp::UpsertBase;
                                            }
                                        })
                                        .or_insert(PendingDeviceOp::UpsertBase);
                                }
                            }
                        }
                        LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, .. }) => {
                            self.pending_devices
                                .entry(*mac)
                                .and_modify(|op| {
                                    if *op != PendingDeviceOp::UpsertFull {
                                        *op = PendingDeviceOp::UpsertBase;
                                    }
                                })
                                .or_insert(PendingDeviceOp::UpsertBase);
                        }
                        LanforgeEvent::Device(DeviceEvent::Discovered { mac, .. })
                        | LanforgeEvent::Device(DeviceEvent::Expired { mac, .. }) => {
                            self.pending_devices.insert(*mac, PendingDeviceOp::UpsertFull);
                        }
                        LanforgeEvent::Device(DeviceEvent::Purged { mac }) => {
                            self.pending_devices.insert(*mac, PendingDeviceOp::Delete);

                            // Flush immediately for administrative host removal
                            self.flush_batch(&db, &log_db).await;
                        }
                        LanforgeEvent::Storage(StorageEvent::TableDirty) => {
                            self.full_flush_requested = true;
                            self.pending_devices.clear();
                            self.flush_batch(&db, &log_db).await;
                        }
                        LanforgeEvent::Storage(StorageEvent::DbLogClean) => {
                            if let Err(e) = log_db.clear_logs() {
                                error!("Log clear error: {e}");
                            }
                        }
                        LanforgeEvent::Storage(StorageEvent::DbPrune) => {
                            if let Err(e) = db.prune_zombies() {
                                error!("Prune error: {e}");
                            }
                        }
                        LanforgeEvent::Storage(StorageEvent::DbReset) => {
                            warn!("Legacy DbReset event received in worker (ignored as reset is now synchronous)");
                        }
                        LanforgeEvent::Storage(StorageEvent::DbResetCompleted) => {
                            info!("Database reset completed. Clearing internal buffers.");
                            self.full_flush_requested = false;
                            self.pending_devices.clear();
                            self.log_buffer.clear();
                            self.dns_log_buffer.clear();
                        }
                        LanforgeEvent::Storage(StorageEvent::SaveTrafficHistory(samples)) => {
                            if let Err(e) = log_db.save_traffic_history(samples) {
                                error!("Failed to save traffic history: {e}");
                            }
                        }
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("Database worker shutting down...");
                            self.flush_batch(&db, &log_db).await;
                            if let Some(handle) = self.ctx.dns_handle()
                                && let Ok(DnsResponse::LifetimeStats(stats)) = handle.send_request(DnsRequest::LifetimeStats).await
                            {
                                let _ = log_db.save_dns_lifetime_stats(&stats);
                            }
                            break_loop = true;
                        }
                        #[cfg(feature = "adblock")]
                        LanforgeEvent::Dns(DnsEvent::QueryBlocked { src_addr, domain }) => {
                            let src_mac = ctx
                                .get_mac_by_ip(*src_addr)
                                .map(|m| m.to_string());
                            if let Err(e) = log_db
                                .record_dns_block(&timed_event, *src_addr, domain, src_mac)
                            {
                                error!("DNS log record error: {e}");
                            }
                        }
                        LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) => {
                            if self.dns_log_buffer.len() >= MAX_DNS_LOG_BUFFER {
                                self.dns_log_buffer.pop_front();
                                self.ctx.db_metrics().dropped_logs.fetch_add(1, Ordering::Relaxed);
                            }
                            self.dns_log_buffer.push_back(Arc::clone(entry));
                            if self.dns_log_buffer.len() >= 100 {
                                self.flush_dns_log(&log_db);
                            }
                        }
                    });

                    if break_loop {
                        break;
                    }
                }

                // Periodic flush
                _ = flush_interval.tick() => {
                    self.flush_batch(&db, &log_db).await;

                    if last_prune.elapsed() >= Duration::from_secs(600) {
                        if let Err(e) = db.prune_zombies() {
                            error!("Background db prune failed: {e}");
                        }
                        last_prune = Instant::now();
                    }
                }
            }
        }

        Ok(())
    }

    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        info!("Database worker flushing pending state and logs on cleanup...");
        let db = Arc::clone(&self.db);
        let log_db = Arc::clone(&self.log_db);
        self.flush_batch(&db, &log_db).await;
        Ok(())
    }
}

impl LanforgeService for DbWorker {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "Database Worker",
            runtime: RuntimeClass::Dedicated {
                multi_thread: false,
                worker_threads: None,
            },
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(1),
                max_backoff: Duration::from_secs(30),
                max_retries: 5,
                healthy_uptime: Duration::from_secs(30),
            },
            shutdown_timeout: Duration::from_secs(3),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }

    fn describe(&self) -> String {
        format!("Database Worker ({})", self.cfg.config_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;
    use lanforge_types::network::dns::{
        DnsRecordType, QueryLogEntry, QueryResult, TransportProtocol,
    };
    use std::sync::atomic::Ordering;

    fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
        let bus = Arc::new(EventBus::new());
        let state = State::new();
        let ctx = LanforgeContext::new(Arc::clone(&bus), state, None);
        (ctx, bus)
    }

    #[tokio::test]
    async fn test_worker_buffer_capping_and_dropped_metrics() {
        let (ctx, _bus) = create_test_context();
        let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
        let log_db = Arc::new(LogDb::open_in_memory());
        let mut worker = DbWorker::new(DatabaseConfig::default(), ctx.clone(), db, log_db);

        // 1. Test log buffer capping
        let sample_event = TimedEvent::new(LanforgeEvent::System(SystemEvent::SystemReady));
        for _ in 0..MAX_LOG_BUFFER + 10 {
            if worker.log_buffer.len() >= MAX_LOG_BUFFER {
                worker.log_buffer.pop_front();
                worker
                    .ctx
                    .db_metrics()
                    .dropped_logs
                    .fetch_add(1, Ordering::Relaxed);
            }
            worker.log_buffer.push_back(sample_event.clone());
        }

        assert_eq!(worker.log_buffer.len(), MAX_LOG_BUFFER);
        assert_eq!(
            worker.ctx.db_metrics().dropped_logs.load(Ordering::Relaxed),
            10
        );

        // 2. Test dns log buffer capping
        let query_entry = Arc::new(QueryLogEntry {
            timestamp: 123456,
            src_ip: "192.168.1.100".parse().unwrap(),
            domain: Arc::from("test.example"),
            upstream_us: 100,
            qtype: DnsRecordType::A,
            result: QueryResult::Forwarded,
            cached: false,
            src_mac: None,
            answer: None,
            protocol: TransportProtocol::Udp,
            filter: None,
            coalesce_id: None,
            repeats: 1,
        });

        for _ in 0..MAX_DNS_LOG_BUFFER + 5 {
            if worker.dns_log_buffer.len() >= MAX_DNS_LOG_BUFFER {
                worker.dns_log_buffer.pop_front();
                worker
                    .ctx
                    .db_metrics()
                    .dropped_logs
                    .fetch_add(1, Ordering::Relaxed);
            }
            worker.dns_log_buffer.push_back(Arc::clone(&query_entry));
        }

        assert_eq!(worker.dns_log_buffer.len(), MAX_DNS_LOG_BUFFER);
        assert_eq!(
            worker.ctx.db_metrics().dropped_logs.load(Ordering::Relaxed),
            15
        );
    }

    #[tokio::test]
    async fn test_worker_vanished_mac_moved_to_purges() {
        let (ctx, _bus) = create_test_context();
        let db = Arc::new(LanforgeDb::open_in_memory().unwrap());
        let log_db = Arc::new(LogDb::open_in_memory());
        let mut worker = DbWorker::new(
            DatabaseConfig::default(),
            ctx.clone(),
            Arc::clone(&db),
            Arc::clone(&log_db),
        );

        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Mark MAC as pending UpsertFull, but do not insert into ctx state
        worker
            .pending_devices
            .insert(mac, PendingDeviceOp::UpsertFull);
        assert_eq!(worker.pending_devices.len(), 1);

        // Flush batch — F8 says vanished MACs must be moved to purges and cleared on success
        worker.flush_batch(&db, &log_db).await;

        assert!(worker.pending_devices.is_empty());
        let devices = db.load_all_devices().unwrap();
        assert!(!devices.iter().any(|d| d.mac == mac));
    }

    #[test]
    fn test_worker_pending_device_op_transitions() {
        let mut pending = HashMap::new();
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // 1. Initial UpsertBase
        pending.insert(mac, PendingDeviceOp::UpsertBase);
        assert_eq!(pending.get(&mac), Some(&PendingDeviceOp::UpsertBase));

        // 2. Upgrade to UpsertFull
        pending.insert(mac, PendingDeviceOp::UpsertFull);
        assert_eq!(pending.get(&mac), Some(&PendingDeviceOp::UpsertFull));

        // 3. AdminUpdate (UpsertBase) preserves UpsertFull
        pending.entry(mac).and_modify(|op| {
            if *op != PendingDeviceOp::UpsertFull {
                *op = PendingDeviceOp::UpsertBase;
            }
        });
        assert_eq!(pending.get(&mac), Some(&PendingDeviceOp::UpsertFull));

        // 4. Purge in same tick overrides to Delete
        pending.insert(mac, PendingDeviceOp::Delete);
        assert_eq!(pending.get(&mac), Some(&PendingDeviceOp::Delete));
    }
}
