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

use lanforge_api::api::{
    AllowlistEntry, DnsUpstreamConfig, ExportedApiToken, HostConfigEntry, SystemConfigExport,
};
use lanforge_api::config_file::{
    ConfigFile, Section, SectionSet, patch_sections, section_hashes, toml_edit::DocumentMut,
    write_toml_atomically,
};
use lanforge_core::bus::{
    DeviceEvent, DnsEvent, FirewallEvent, LanforgeEvent, StorageEvent, SystemEvent, TimedEvent,
    TrafficEvent,
};
use lanforge_db_core::{
    AdblockStore, ApiTokenStore, DeviceStore, DhcpConfigStore, DnsStore, DnsUpstreamStore,
    FirewallConfigStore, LogStore, PppoeConfigStore, RaConfigStore, TrafficConfigStore, UserStore,
};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::adblock::AdblockRuleEntry;
use lanforge_types::network::dns::{AdblockUrlEntry, DnsRequest, DnsResponse};
use lanforge_types::network::{DnsReverseResolver, QueryLogEntry};
use lanforge_types::storage::{DnsAnalyticsData, StorageQuery, StorageQueryResult};
use lanforge_types::system::ServiceAction;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, interval};
use tracing::{debug, error, info, warn};

use lanforge_core::context::{LanforgeContext, StorageHandle};
use lanforge_core::error::CoreError;
use lanforge_core::service::AsyncService;

use crate::config::DatabaseConfig;
use crate::engine::LanforgeDb;
use crate::log_engine::LogDb;

type StorageQueryItem = (
    StorageQuery,
    oneshot::Sender<Result<StorageQueryResult, String>>,
);

/// Background worker for database operations.
#[lanforge_macros::lanforge_service(
    id = "db",
    name = "Database Worker",
    critical = true,
    retries = 5,
    base_backoff = 1,
    max_backoff = 30,
    describe = format!("Database Worker ({})", self.cfg.config_path)
)]
pub struct DbWorker {
    cfg: DatabaseConfig,
    ctx: LanforgeContext,
    db: Arc<LanforgeDb>,
    log_db: Arc<LogDb>,
    dirty: bool,
    dirty_macs: HashSet<MacAddr>,
    dirty_lease_macs: HashSet<MacAddr>,
    purged_macs: HashSet<MacAddr>,
    log_buffer: Vec<TimedEvent>,
    dns_log_buffer: Vec<QueryLogEntry>,
    bytes_buf: Vec<u8>,
    storage_rx: Option<mpsc::Receiver<StorageQueryItem>>,
    dirty_sections: lanforge_api::config_file::SectionSet,
}

impl DbWorker {
    /// Creates a new `DbWorker` for the specified databases.
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
            dirty: false,
            dirty_macs: HashSet::new(),
            dirty_lease_macs: HashSet::new(),
            purged_macs: HashSet::new(),
            log_buffer: Vec::with_capacity(128),
            dns_log_buffer: Vec::with_capacity(128),
            bytes_buf: Vec::with_capacity(4096),
            storage_rx: Some(rx),
            dirty_sections: lanforge_api::config_file::SectionSet::empty(),
        }
    }

    /// Flushes the current device table to the persistent database.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn flush_batch(&mut self, db: &LanforgeDb, log_db: &LogDb) {
        let metrics = self.ctx.db_metrics();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut had_error = false;
        let mut written_devices_count = 0;

        // 1. Flush Logs
        if !self.log_buffer.is_empty() {
            if let Err(e) = log_db.record_logs_batch(&self.log_buffer, &mut self.bytes_buf) {
                error!("Failed to flush log batch: {e}");
                had_error = true;
            } else {
                self.log_buffer.clear();
            }
        }

        let had_dns_queries = !self.dns_log_buffer.is_empty();
        if had_dns_queries {
            if let Err(e) = log_db.record_dns_queries_batch(&self.dns_log_buffer) {
                error!("Failed to flush DNS log batch: {e}");
                had_error = true;
            } else {
                self.dns_log_buffer.clear();
            }
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
        if !self.dirty && self.dirty_macs.is_empty() && self.purged_macs.is_empty() {
            metrics.last_flush_ts.store(now, Ordering::Relaxed);
            metrics.flush_count.fetch_add(1, Ordering::Relaxed);
            metrics.last_error.store(had_error, Ordering::Relaxed);
            return;
        }

        let res = if self.dirty {
            // Full flush requested (rare)
            let snapshot = self.ctx.snapshot_for_persistence();
            let len = snapshot.devices.len();
            db.save_snapshot(&snapshot).map(|()| len)
        } else {
            // Incremental flush (common)
            let (lease_devices, base_devices) = self.ctx.with_state(|state| {
                let mut lease = Vec::new();
                let mut base = Vec::new();
                for mac in &self.dirty_macs {
                    if let Some(device) = state.devices.get(mac).cloned() {
                        if self.dirty_lease_macs.contains(mac) {
                            lease.push(device);
                        } else {
                            base.push(device);
                        }
                    }
                }
                (lease, base)
            });

            let purges: Vec<MacAddr> = self.purged_macs.iter().copied().collect();
            let count = lease_devices.len() + base_devices.len() + purges.len();

            let result = db.batch_sync_devices(&lease_devices, &base_devices, &purges);
            result.map(|()| count)
        };

        match res {
            Err(e) => {
                error!("Failed to save device table to database: {e}");
                had_error = true;
            }
            Ok(count) => {
                written_devices_count = count;
                let was_full_flush = self.dirty;
                self.dirty = false;
                self.dirty_macs.clear();
                self.dirty_lease_macs.clear();
                self.purged_macs.clear();

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
    }

    fn build_current_export(&self, db: &LanforgeDb) -> SystemConfigExport {
        let hosts = self.ctx.with_state(|state| {
            state
                .devices
                .values()
                .filter(|dev| dev.origin != lanforge_types::device::Origin::Dynamic)
                .map(|dev| HostConfigEntry {
                    mac: dev.mac,
                    hostname: dev.hostname.name.clone(),
                    v4_fixed: match &dev.v4 {
                        lanforge_types::device::IPv4State::Static(ip) => Some(*ip),
                        _ => None,
                    },
                    v6_suffix: dev.v6.iter().find_map(|s| match s {
                        lanforge_types::device::IPv6State::Static(suf, _) => Some(*suf),
                        _ => None,
                    }),
                    origin: dev.origin,
                    ignore_dns_log: dev.ignore_dns_log,
                    ignored_log_domains: dev.ignored_log_domains.clone(),
                })
                .collect()
        });

        let dns_rewrites = self.ctx.get_dns_rewrites();

        let dns_upstreams = self
            .ctx
            .get_dns_upstreams()
            .into_iter()
            .map(|row| DnsUpstreamConfig {
                addr: row.addr,
                protocol: row.protocol,
                domain: row.domain,
            })
            .collect();

        let dns_adblock_config = self.ctx.get_dns_adblock();
        let dns_adblock_urls = self.ctx.get_dns_adblock_urls();
        let dns_allowlist = self
            .ctx
            .get_dns_allowlist()
            .into_iter()
            .enumerate()
            .map(|(id, domain)| AllowlistEntry {
                id: id as i64 + 1,
                domain,
            })
            .collect();

        let dns_adblock_rules = Some(self.ctx.get_dns_adblock_rules());

        let api_tokens = db.load_api_tokens().ok().map(|tokens| {
            tokens
                .into_iter()
                .map(|t| ExportedApiToken {
                    token: t.token,
                    name: t.name,
                    created_at: t.created_at,
                    last_used: t.last_used,
                    scopes: t.scopes,
                    expires_at: t.expires_at,
                })
                .collect()
        });

        let dhcp_v4_pools = Some(self.ctx.get_dhcp_v4_pools());
        let dhcp_v6_pools = Some(self.ctx.get_dhcp_v6_pools());
        let ra_prefixes = Some(self.ctx.get_ra_prefixes());
        let ra_rdnss = Some(self.ctx.get_ra_rdnss());
        let ra_dnssl = Some(self.ctx.get_ra_dnssl());
        let pppoe_config = self.ctx.get_pppoe_config().map(Box::new);
        let dhcp_options = Some(Box::new(self.ctx.get_dhcp_options()));
        let dns_reverse_resolvers = Some(self.ctx.with_state(|s| s.reverse_resolvers.clone()));
        let firewall_config = self.ctx.get_firewall_config().map(Box::new);
        let traffic_config = self.ctx.get_traffic_config().map(Box::new);

        SystemConfigExport {
            hosts,
            dns_rewrites,
            dns_upstreams,
            dns_adblock_config,
            dns_adblock_urls,
            dns_allowlist,
            dns_adblock_rules,
            api_tokens,
            dhcp_v4_pools,
            dhcp_v6_pools,
            ra_prefixes,
            ra_rdnss,
            ra_dnssl,
            pppoe_config,
            dhcp_options,
            dns_reverse_resolvers,
            firewall_config,
            traffic_config,
            overwrite: false,
        }
    }

    async fn flush_live_config_to_file(&mut self, db: &LanforgeDb) {
        if self.dirty_sections.is_empty() {
            return;
        }

        if !self.ctx.is_config_writable() {
            debug!("Config directory/file is read-only; skipping live write-back");
            self.dirty_sections = SectionSet::empty();
            return;
        }

        let Some(path) = self.ctx.config_path() else {
            return;
        };

        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let mut doc = existing.parse::<DocumentMut>().unwrap_or_default();

        let export = self.build_current_export(db);
        let config_file = ConfigFile::from(&export);

        if let Err(e) = patch_sections(&mut doc, &config_file, self.dirty_sections) {
            error!("Failed to patch TOML document: {e}");
            return;
        }

        let rendered = doc.to_string();
        if let Err(e) = write_toml_atomically(&path, &rendered) {
            error!(
                "Failed to write live config back to {}: {e}",
                path.display()
            );
            return;
        }

        // Update hashes only after the file is safely replaced. If writing fails,
        // the next boot must still see the old hash and reconcile the mismatch.
        let hashes = section_hashes(&config_file);
        for sec in Section::ALL {
            if self.dirty_sections.contains(sec.as_bitflag())
                && let Some(&hash) = hashes.get(&sec)
                && let Err(e) = db.set_config_section_hash(sec.name(), hash)
            {
                warn!(
                    "Failed to update config section hash for {}: {e}",
                    sec.name()
                );
            }
        }

        debug!(
            "Live config successfully written back to {} for dirty sections: {:?}",
            path.display(),
            self.dirty_sections
        );
        self.dirty_sections = SectionSet::empty();
    }

    fn handle_storage_query(
        db: &LanforgeDb,
        log_db: &LogDb,
        ctx: &LanforgeContext,
        query: StorageQuery,
    ) -> Result<StorageQueryResult, String> {
        match query {
            StorageQuery::StoreApiToken {
                token,
                name,
                scopes,
                expires_at,
                now,
            } => {
                let id = db
                    .store_api_token(&token, &name, &scopes, expires_at, now)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Id(id))
            }
            StorageQuery::LoadApiTokens => {
                let tokens = db.load_api_tokens().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::ApiTokens(tokens))
            }
            StorageQuery::DeleteApiToken(token) => {
                db.delete_api_token(&token).map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::DeleteApiTokenByIdOrName(id_or_name) => {
                db.delete_api_token_by_id_or_name(&id_or_name)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::GetApiTokenInfo(id_or_name) => {
                let info = db
                    .get_api_token_info(&id_or_name)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::ApiTokenInfo(info))
            }
            StorageQuery::CreateUser {
                username,
                password_hash,
                role,
                now,
            } => {
                let user = db
                    .create_user(&username, &password_hash, role, now)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::User(Some(user)))
            }
            StorageQuery::GetUserByUsername(username) => {
                let user = db
                    .get_user_by_username(&username)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::User(user))
            }
            StorageQuery::ListUsers => {
                let users = db.list_users().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Users(users))
            }
            StorageQuery::UpdateUserPassword {
                username,
                new_hash,
                now,
            } => {
                db.update_user_password(&username, &new_hash, now)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::UpdateUserRole {
                username,
                new_role,
                now,
            } => {
                db.update_user_role(&username, new_role, now)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::DeleteUser(username) => {
                db.delete_user(&username).map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::CountUsers => {
                let count = db.count_users().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Count(count as usize))
            }
            StorageQuery::IsProvisioned => {
                let p = db.is_provisioned().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Boolean(p))
            }
            StorageQuery::SetProvisioned(p) => {
                db.set_provisioned(p).map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::Vacuum => {
                db.vacuum().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::PruneZombies => {
                let count = db.prune_zombies().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Count(count))
            }
            StorageQuery::PruneLogs { before } => {
                log_db.prune_logs(before).map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearLogs => {
                log_db.clear_logs().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ResetDb => {
                db.reset().map_err(|e| e.to_string())?;
                log_db.clear_logs().map_err(|e| e.to_string())?;
                ctx.reset();
                let _ = ctx
                    .bus()
                    .publish(LanforgeEvent::Storage(StorageEvent::DbResetCompleted));
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::GetLogHistory(limit) => {
                let history = log_db.get_history(limit).map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::LogHistory(history))
            }
            StorageQuery::GetDnsQueryHistory {
                limit,
                offset,
                client,
                domain,
                qtype,
                result,
            } => {
                let (queries, total) = log_db
                    .get_dns_query_history(limit, offset, client, domain, qtype, result)
                    .map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::DnsQueryHistory { queries, total })
            }
            StorageQuery::GetDnsAnalytics { limit, client } => {
                let top_domains = if let Some(ref c) = client {
                    log_db
                        .get_dns_top_domains_for_client(c, limit)
                        .unwrap_or_default()
                } else {
                    log_db.get_dns_top_domains(limit).unwrap_or_default()
                };
                let query_types = log_db.get_dns_query_types().unwrap_or_default();
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let since_secs = now_secs.saturating_sub(86400);
                let detailed_rates = log_db
                    .get_dns_query_rate_detailed(since_secs, 900)
                    .unwrap_or_default();
                let top_clients = log_db.get_dns_top_clients(limit).unwrap_or_default();
                let protocol_stats = log_db.get_dns_protocol_stats().unwrap_or_default();
                let top_blocked_domains = log_db
                    .get_dns_top_blocked_domains(limit)
                    .unwrap_or_default();
                let top_blocked_clients = log_db
                    .get_dns_top_blocked_clients(limit)
                    .unwrap_or_default();
                let blocked_query_rate = log_db
                    .get_dns_blocked_query_rate(since_secs)
                    .unwrap_or_default();

                Ok(StorageQueryResult::DnsAnalytics(DnsAnalyticsData {
                    top_domains,
                    query_types,
                    detailed_rates,
                    top_clients,
                    protocol_stats,
                    top_blocked_domains,
                    top_blocked_clients,
                    blocked_query_rate,
                }))
            }
            StorageQuery::UpsertDnsRewrite {
                domain,
                rtype,
                answer,
            } => {
                db.upsert_dns_rewrite(&domain, rtype, &answer)
                    .map_err(|e| e.to_string())?;
                if let Ok(rewrites) = db.load_dns_rewrites() {
                    ctx.update_dns_rewrites(rewrites);
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::DeleteDnsRewrite(id) => {
                db.delete_dns_rewrite_by_id(id).map_err(|e| e.to_string())?;
                if let Ok(rewrites) = db.load_dns_rewrites() {
                    ctx.update_dns_rewrites(rewrites);
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearDnsRewrites => {
                db.clear_dns_rewrites().map_err(|e| e.to_string())?;
                ctx.update_dns_rewrites(Vec::new());
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::AddDnsAllowlist(domain) => {
                db.add_dns_allowlist(&domain).map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_dns_allowlist() {
                    ctx.update_dns_allowlist(rows.into_iter().map(|(_, d)| d).collect());
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::RemoveDnsAllowlist(domain) => {
                db.remove_dns_allowlist(&domain)
                    .map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_dns_allowlist() {
                    ctx.update_dns_allowlist(rows.into_iter().map(|(_, d)| d).collect());
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearDnsAllowlist => {
                db.clear_dns_allowlist().map_err(|e| e.to_string())?;
                ctx.update_dns_allowlist(Vec::new());
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::SetAdblockConfigValue { key, value } => {
                db.set_adblock_config_value(&key, &value)
                    .map_err(|e| e.to_string())?;
                if let Ok(cfg) = db.load_adblock_config() {
                    ctx.update_dns_adblock(cfg);
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::AddAdblockUrl { url, kind, format } => {
                db.add_adblock_url(&url, kind, format)
                    .map_err(|e| e.to_string())?;
                if let Ok(urls) = db.load_adblock_urls() {
                    ctx.update_dns_adblock_urls(
                        urls.into_iter()
                            .map(|(id, url, kind, format)| AdblockUrlEntry {
                                id: Some(id),
                                url,
                                kind,
                                format,
                            })
                            .collect(),
                    );
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::RemoveAdblockUrl(url) => {
                db.remove_adblock_url(&url).map_err(|e| e.to_string())?;
                if let Ok(urls) = db.load_adblock_urls() {
                    ctx.update_dns_adblock_urls(
                        urls.into_iter()
                            .map(|(id, url, kind, format)| AdblockUrlEntry {
                                id: Some(id),
                                url,
                                kind,
                                format,
                            })
                            .collect(),
                    );
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearAdblockUrls => {
                db.clear_adblock_urls().map_err(|e| e.to_string())?;
                ctx.update_dns_adblock_urls(Vec::new());
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::AddAdblockRule { domain, action } => {
                let id = db
                    .add_adblock_rule(&domain, action)
                    .map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_adblock_rules() {
                    ctx.update_dns_adblock_rules(
                        rows.into_iter()
                            .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                                id: Some(id),
                                domain,
                                action,
                                enabled,
                            })
                            .collect(),
                    );
                }
                Ok(StorageQueryResult::Id(id))
            }
            StorageQuery::RemoveAdblockRule(id) => {
                db.remove_adblock_rule(id).map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_adblock_rules() {
                    ctx.update_dns_adblock_rules(
                        rows.into_iter()
                            .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                                id: Some(id),
                                domain,
                                action,
                                enabled,
                            })
                            .collect(),
                    );
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::UpdateAdblockRuleStatus { id, enabled } => {
                db.update_adblock_rule_status(id, enabled)
                    .map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_adblock_rules() {
                    ctx.update_dns_adblock_rules(
                        rows.into_iter()
                            .map(|(id, domain, action, enabled)| AdblockRuleEntry {
                                id: Some(id),
                                domain,
                                action,
                                enabled,
                            })
                            .collect(),
                    );
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearAdblockRules => {
                db.clear_adblock_rules().map_err(|e| e.to_string())?;
                ctx.update_dns_adblock_rules(Vec::new());
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::AddDnsUpstream {
                addr,
                protocol,
                domain,
            } => {
                let id = db
                    .add_dns_upstream(addr, protocol, domain.as_deref())
                    .map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_dns_upstreams() {
                    ctx.update_dns_upstreams(rows.into_iter().map(|r| r.to_target()).collect());
                }
                Ok(StorageQueryResult::Id(id))
            }
            StorageQuery::RemoveDnsUpstream {
                addr,
                protocol,
                domain,
            } => {
                db.remove_dns_upstream(addr, protocol, domain.as_deref())
                    .map_err(|e| e.to_string())?;
                if let Ok(rows) = db.load_dns_upstreams() {
                    ctx.update_dns_upstreams(rows.into_iter().map(|r| r.to_target()).collect());
                }
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearDnsUpstreams => {
                db.clear_dns_upstreams().map_err(|e| e.to_string())?;
                ctx.update_dns_upstreams(Vec::new());
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::GetDnsUpstreamMode => {
                let mode = db.load_dns_upstream_mode().map_err(|e| e.to_string())?;
                Ok(StorageQueryResult::DnsUpstreamMode(mode))
            }
            StorageQuery::SetDnsUpstreamMode(mode) => {
                db.save_dns_upstream_mode(mode).map_err(|e| e.to_string())?;
                ctx.update_dns_upstream_mode(mode);
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::AddReverseResolver { subnet, resolver } => {
                db.add_dns_reverse_resolver(&subnet, &resolver)
                    .map_err(|e| e.to_string())?;
                ctx.add_reverse_resolver(DnsReverseResolver { subnet, resolver });
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::RemoveReverseResolver(subnet) => {
                db.remove_dns_reverse_resolver(&subnet)
                    .map_err(|e| e.to_string())?;
                ctx.remove_reverse_resolver(subnet);
                Ok(StorageQueryResult::Success)
            }
            StorageQuery::ClearReverseResolvers => {
                db.clear_dns_reverse_resolvers()
                    .map_err(|e| e.to_string())?;
                ctx.set_reverse_resolvers(Vec::new());
                Ok(StorageQueryResult::Success)
            }
        }
    }
}

impl AsyncService for DbWorker {
    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let metrics = ctx.db_metrics();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_flush_ts = metrics.last_flush_ts.load(Ordering::Relaxed);
        let last_flush_ago = if last_flush_ts > 0 && now >= last_flush_ts {
            format!("{}s ago", now - last_flush_ts)
        } else {
            "—".to_string()
        };
        let error_str = if metrics.last_error.load(Ordering::Relaxed) {
            "error".to_string()
        } else {
            "ok".to_string()
        };

        vec![
            (
                std::borrow::Cow::Borrowed("flush_count"),
                metrics.flush_count.load(Ordering::Relaxed).to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("devices_written"),
                metrics.devices_written.load(Ordering::Relaxed).to_string(),
            ),
            (std::borrow::Cow::Borrowed("last_flush"), last_flush_ago),
            (
                std::borrow::Cow::Borrowed("log_buffer"),
                self.log_buffer.len().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("dns_log_buffer"),
                self.dns_log_buffer.len().to_string(),
            ),
            (std::borrow::Cow::Borrowed("status"), error_str),
        ]
    }

    async fn init(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let mode = if ctx.is_recovery_mode() {
            "RECOVERY MODE (in-memory)"
        } else if self.db.is_in_memory() {
            "in-memory"
        } else {
            "redb (persistent)"
        };
        info!("Database worker initialized (mode: {mode})");
        ctx.set_db_ready(true);
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::DbReady));
        Ok(())
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let db = self.db.clone();
        let log_db = self.log_db.clone();

        let mut storage_rx = self.storage_rx.take().unwrap_or_else(|| {
            let (tx, rx) = mpsc::channel(64);
            ctx.set_storage_handle(StorageHandle::new(tx));
            rx
        });
        let mut bus_rx = ctx.bus().subscribe();
        let mut flush_interval: Interval = interval(Duration::from_secs(self.cfg.flush_interval));
        let mut last_prune = tokio::time::Instant::now();

        loop {
            tokio::select! {
                // Storage queries from API dispatch / handles
                res = storage_rx.recv() => {
                    if let Some((query, resp_tx)) = res {
                        match &query {
                            StorageQuery::UpsertDnsRewrite { .. }
                            | StorageQuery::DeleteDnsRewrite(_)
                            | StorageQuery::ClearDnsRewrites
                            | StorageQuery::AddDnsAllowlist(_)
                            | StorageQuery::RemoveDnsAllowlist(_)
                            | StorageQuery::ClearDnsAllowlist
                            | StorageQuery::AddDnsUpstream { .. }
                            | StorageQuery::RemoveDnsUpstream { .. }
                            | StorageQuery::ClearDnsUpstreams
                            | StorageQuery::SetDnsUpstreamMode(_)
                            | StorageQuery::AddReverseResolver { .. }
                            | StorageQuery::RemoveReverseResolver(_)
                            | StorageQuery::ClearReverseResolvers => {
                                self.dirty_sections |= SectionSet::DNS;
                            }
                            StorageQuery::SetAdblockConfigValue { .. }
                            | StorageQuery::AddAdblockUrl { .. }
                            | StorageQuery::RemoveAdblockUrl(_)
                            | StorageQuery::ClearAdblockUrls
                            | StorageQuery::AddAdblockRule { .. }
                            | StorageQuery::RemoveAdblockRule(_)
                            | StorageQuery::UpdateAdblockRuleStatus { .. }
                            | StorageQuery::ClearAdblockRules => {
                                self.dirty_sections |= SectionSet::ADBLOCK;
                            }
                            StorageQuery::StoreApiToken { .. }
                            | StorageQuery::DeleteApiToken(_)
                            | StorageQuery::DeleteApiTokenByIdOrName(_) => {
                                self.dirty_sections |= SectionSet::API;
                            }
                            _ => {}
                        }
                        let result = Self::handle_storage_query(&db, &log_db, ctx, query);
                        let _ = resp_tx.send(result);
                    }
                }

                // Event handling
                res = bus_rx.recv() => {
                    let Ok(timed_event) = res else {
                        if let Err(RecvError::Lagged(n)) = res {
                            warn!(service = "DbWorker", lost = n, "Event bus lagged");
                            continue;
                        }
                        break;
                    };
                    // 1. Record in log database if loggable
                    if timed_event.is_loggable() {
                        self.log_buffer.push(timed_event.clone());
                        if self.log_buffer.len() >= 100 {
                            if let Err(e) = log_db.record_logs_batch(&self.log_buffer, &mut self.bytes_buf) {
                                error!("Immediate log flush error: {e}");
                            } else {
                                self.log_buffer.clear();
                            }
                        }
                    }

                    // 2. Process specific events
                    let mut break_loop = false;
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Network(lanforge_core::bus::NetworkEvent::PrefixChanged(details)) => {
                            let _ = db.save_last_gua_prefix(details.gua);
                        }
                        LanforgeEvent::Device(DeviceEvent::NetworkUpdate { mac, change, .. }) => {
                            if change.is_persistent() {
                                self.dirty_macs.insert(*mac);
                                if change.is_lease_change() {
                                    self.dirty_lease_macs.insert(*mac);
                                }
                                // If it was previously purged, it's now alive again
                                self.purged_macs.remove(mac);
                            }
                        }
                        LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, .. }) => {
                            self.dirty_macs.insert(*mac);
                            self.purged_macs.remove(mac);
                            self.dirty_sections |= SectionSet::HOSTS;
                        }
                        LanforgeEvent::Device(DeviceEvent::Discovered { mac, .. })
                        | LanforgeEvent::Device(DeviceEvent::Expired { mac, .. }) => {
                            self.dirty_macs.insert(*mac);
                            self.dirty_lease_macs.insert(*mac);
                            self.purged_macs.remove(mac);
                        }
                        LanforgeEvent::Device(DeviceEvent::Purged { mac }) => {
                            self.purged_macs.insert(*mac);
                            self.dirty_macs.remove(mac);
                            self.dirty_lease_macs.remove(mac);
                            self.dirty_sections |= SectionSet::HOSTS;

                            // Flush immediately for administrative host removal
                            self.flush_batch(&db, &log_db).await;
                        }
                        LanforgeEvent::Storage(StorageEvent::TableDirty) => {
                            self.dirty = true;
                        }
                        LanforgeEvent::Storage(StorageEvent::DbVacuum) => {
                            if let Err(e) = db.vacuum() {
                                error!("Vacuum error: {e}");
                            }
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
                            self.dirty = false;
                            self.dirty_macs.clear();
                            self.dirty_lease_macs.clear();
                            self.purged_macs.clear();
                            self.log_buffer.clear();
                            self.dns_log_buffer.clear();
                        }
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("Database worker shutting down...");
                            self.flush_batch(&db, &log_db).await;
                            self.flush_live_config_to_file(&db).await;
                            if let Some(handle) = self.ctx.dns_handle()
                                && let Ok(DnsResponse::LifetimeStats(stats)) = handle.send_request(DnsRequest::LifetimeStats).await
                            {
                                let _ = log_db.save_dns_lifetime_stats(&stats);
                            }
                            break_loop = true;
                        }
                        LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) => {
                            if id == "db" && matches!(action, ServiceAction::Stop | ServiceAction::Restart) {
                                info!(action = ?action, "Database worker received service control, flushing and exiting loop");
                                self.flush_batch(&db, &log_db).await;
                                self.flush_live_config_to_file(&db).await;
                                break_loop = true;
                            }
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
                            self.dns_log_buffer.push((**entry).clone());
                            if self.dns_log_buffer.len() >= 100 {
                                if let Err(e) = log_db.record_dns_queries_batch(&self.dns_log_buffer) {
                                    error!("Immediate DNS query log flush error: {e}");
                                } else {
                                    self.dns_log_buffer.clear();
                                }
                            }
                        }
                        LanforgeEvent::System(SystemEvent::ConfigDhcpV4Changed) => {
                            self.dirty_sections |= SectionSet::DHCP;
                            let pools = ctx.get_dhcp_v4_pools();
                            if let Err(e) = db.save_dhcp_v4_pools(&pools) {
                                error!("Failed to persist DHCPv4 pools: {e}");
                            }
                        }
                        LanforgeEvent::System(SystemEvent::ConfigDhcpV6Changed) => {
                            self.dirty_sections |= SectionSet::DHCP;
                            let pools = ctx.get_dhcp_v6_pools();
                            if let Err(e) = db.save_dhcp_v6_pools(&pools) {
                                error!("Failed to persist DHCPv6 pools: {e}");
                            }
                        }
                        LanforgeEvent::System(SystemEvent::ConfigDhcpOptionsChanged) => {
                            self.dirty_sections |= SectionSet::DHCP;
                            let opts = ctx.get_dhcp_options();
                            if let Err(e) = db.save_dhcp_options(&opts) {
                                error!("Failed to persist DHCP options: {e}");
                            }
                        }
                        LanforgeEvent::System(SystemEvent::ConfigRaChanged) => {
                            self.dirty_sections |= SectionSet::RA;
                            let prefixes = ctx.get_ra_prefixes();
                            let rdnss = ctx.get_ra_rdnss();
                            let dnssl = ctx.get_ra_dnssl();
                            let _ = db.save_ra_prefixes(&prefixes);
                            let _ = db.save_ra_rdnss(&rdnss);
                            let _ = db.save_ra_dnssl(&dnssl);
                        }
                        LanforgeEvent::Firewall(FirewallEvent::RulesetChanged) => {
                            self.dirty_sections |= SectionSet::FIREWALL;
                            if let Some(cfg) = ctx.get_firewall_config()
                                && let Err(e) = db.save_firewall_config(&cfg)
                            {
                                error!("Failed to persist Firewall config: {e}");
                            }
                        }
                        LanforgeEvent::Traffic(event) => {
                            if matches!(**event, TrafficEvent::RulesetChanged) {
                                self.dirty_sections |= SectionSet::TRAFFIC;
                                if let Some(cfg) = ctx.get_traffic_config()
                                    && let Err(e) = db.save_traffic_config(&cfg)
                                {
                                    error!("Failed to persist Traffic config: {e}");
                                }
                            }
                        }
                        LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                            self.dirty_sections |= SectionSet::PPPOE;
                            if let Some(cfg) = ctx.get_pppoe_config()
                                && let Err(e) = db.save_pppoe_config(&cfg)
                            {
                                error!("Failed to persist PPPoE config: {e}");
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
                    self.flush_live_config_to_file(&db).await;

                    if last_prune.elapsed() >= Duration::from_secs(600) {
                        if let Err(e) = db.prune_zombies() {
                            error!("Background db prune failed: {e}");
                        }
                        last_prune = tokio::time::Instant::now();
                    }
                }
            }
        }

        Ok(())
    }

    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        info!("Database worker flushing pending state and logs on cleanup...");
        let db = self.db.clone();
        let log_db = self.log_db.clone();
        self.flush_batch(&db, &log_db).await;
        self.flush_live_config_to_file(&db).await;
        Ok(())
    }
}
