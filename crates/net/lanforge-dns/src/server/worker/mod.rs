pub mod tcp;
pub mod udp;

#[cfg(feature = "adblock")]
use std::path::Path;
#[cfg(feature = "adblock")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[cfg(feature = "adblock")]
use crate::resolver::AdBlocker;
#[cfg(feature = "adblock")]
use crate::resolver::filter::DiskBlocklist;
#[cfg(feature = "adblock")]
use crate::resolver::filter::manifest::{AdblockManifest, SourceManifestEntry};
#[cfg(feature = "adblock")]
use crate::resolver::filter::source::{
    SourceFetchResult, build_adblock_http_client, compile_source_artifacts,
    fetch_source_conditional,
};
use crate::server::DnsContext;

#[cfg(feature = "adblock")]
use chrono::Datelike;
#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::AdblockUrlEntry;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::syntax::ParseStats;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::{
    AdblockDbConfig, AdblockSourceFormat, AdblockUrlKind, TimeOfDay,
};
#[cfg(feature = "adblock")]
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
#[cfg(feature = "adblock")]
use tracing::{debug, error, info, warn};

/// Configured lists that have compiled artifacts, in configuration order (= bit order).
#[cfg(feature = "adblock")]
fn compiled_lists(
    sources_dir: &Path,
    configured: &[AdblockUrlEntry],
) -> Vec<(i64, AdblockUrlKind)> {
    configured
        .iter()
        .filter(|e| {
            sources_dir
                .join(format!("{}.block.fst", e.source_id()))
                .exists()
        })
        .map(|e| (e.source_id(), e.kind))
        .collect()
}

/// Opens the compiled lists; the artifacts of an unreadable one are removed so it is fetched again.
#[cfg(feature = "adblock")]
async fn load_lists(
    sources_dir: &Path,
    lists: Vec<(i64, AdblockUrlKind)>,
) -> Option<DiskBlocklist> {
    let dir = sources_dir.to_path_buf();
    let res = tokio::task::spawn_blocking(move || {
        let (bl, failed) = DiskBlocklist::load(&dir, &lists);
        for id in failed {
            for ext in ["block.fst", "allow.fst", "bad"] {
                let _ = std::fs::remove_file(dir.join(format!("{id}.{ext}")));
            }
        }
        bl
    })
    .await;
    match res {
        Ok(bl) => Some(bl),
        Err(e) => {
            error!(error = %e, "Adblock: task failed loading compiled lists");
            None
        }
    }
}

/// Spawns the adblock list refresh manager.
#[cfg(feature = "adblock")]
pub fn spawn_adblock_manager(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(filter) = &ctx.filter {
            let cache_dir = ctx
                .cfg
                .adblock_cache_dir
                .as_deref()
                .unwrap_or("/var/lib/lanforge");
            let adblock_dir = Path::new(cache_dir).join("adblock");
            let sources_dir = adblock_dir.join("sources");
            let manifest_path = adblock_dir.join("manifest.json");

            let _ = std::fs::create_dir_all(&sources_dir);
            // Merged indexes of older versions: never read (other value encoding), only removed.
            for old in [
                adblock_dir.join("block.fst"),
                adblock_dir.join("allow.fst"),
                Path::new(cache_dir).join("blocklist.fst"),
                Path::new(cache_dir).join("blocklist.hash"),
            ] {
                let _ = std::fs::remove_file(old);
            }

            let mut manifest = AdblockManifest::load_or_default(&manifest_path);
            let mut rx = ctx.bus.subscribe_dns();
            // Allowlist/custom rules are resynced by the DNS service loop; this worker only
            // owns list downloads, so it watches the adblock settings and source URLs.
            let mut adblock_sub = ctx.ctx.config_subscription::<AdblockDbConfig>();
            let mut urls_sub = ctx.ctx.config_subscription::<Vec<AdblockUrlEntry>>();
            let mut cache_loaded = false;
            let mut force_refresh = false;
            // When the last download pass ran: re-enabling within a day reuses the loaded lists.
            let mut last_refresh: Option<Instant> = None;
            // List downloads resolve through the system resolver, usually this DNS server: a
            // pass that fails before it has upstreams (boot, PPPoE down) retries once they appear.
            let mut upstreams_rx = ctx.recursive.watch_upstreams();

            loop {
                let db_cfg = ctx.ctx.get_dns_adblock();

                // Wait if disabled. A temporary pause is not a disable: the filter re-enables
                // itself lazily when it ends (no event), so the lists keep refreshing meanwhile.
                let mut resumed_fresh = false;
                let enabled = filter.is_enabled();
                let paused = filter.timer.disabled_until.load(Ordering::Relaxed) != 0;
                if !enabled && !paused {
                    debug!("Adblock: currently disabled, waiting for toggle or reload");
                    loop {
                        tokio::select! {
                            evt = rx.recv() => match evt {
                                Ok(evt) => match evt.event {
                                    LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                        force_refresh = true;
                                        break;
                                    }
                                    LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                                        enabled: true,
                                        ..
                                    }) => break,
                                    _ => {}
                                },
                                // A missed enable: the filter state is the truth.
                                Err(RecvError::Lagged(_)) => {
                                    if filter.is_enabled() {
                                        break;
                                    }
                                }
                                Err(RecvError::Closed) => return,
                            },
                            // Enabling adblock in the config must start the list download too.
                            Some(delta) = adblock_sub.next() => {
                                if delta.new.enabled {
                                    filter.set_enabled(true);
                                    break;
                                }
                            }
                        }
                    }
                    resumed_fresh = !force_refresh
                        && filter.blocklist_size() > 0
                        && last_refresh
                            .is_some_and(|t| t.elapsed() < Duration::from_secs(20 * 3600));
                }

                // 1. Try to load from disk if not yet loaded
                let mut skip_download_pass = resumed_fresh;
                if resumed_fresh {
                    info!("Adblock: re-enabled with recent lists, skipping download pass");
                }
                if !cache_loaded {
                    let compiled = compiled_lists(&sources_dir, &ctx.ctx.get_dns_adblock_urls());
                    if !compiled.is_empty() {
                        info!("Adblock: loading compiled lists from disk");
                        if let Some(bl) = load_lists(&sources_dir, compiled).await
                            && !bl.is_empty()
                        {
                            info!(domains = bl.len(), "Adblock: loaded domains from cache");
                            filter.replace_blocklist(bl);
                            ctx.cache.invalidate_all();

                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let elapsed = now.saturating_sub(manifest.last_merge);
                            if elapsed < 20 * 3600 {
                                skip_download_pass = true;
                                info!(
                                    fingerprint = format_args!("{:016x}", manifest.fingerprint),
                                    "Adblock: cached lists are fresh, skipping startup download"
                                );
                            } else {
                                info!(
                                    "Adblock: cached lists are stale, scheduling background update"
                                );
                            }
                        }
                    }
                    cache_loaded = true;
                }

                let start = Instant::now();
                // Upstream changes during this pass still wake the failure retry below.
                upstreams_rx.borrow_and_update();
                let configured_sources = ctx.ctx.get_dns_adblock_urls();

                if skip_download_pass {
                    info!("Adblock: skipping blocklist download pass (cached FST is fresh)");
                } else if configured_sources.is_empty() {
                    warn!("Adblock: no blocklist sources configured, clearing blocklist");
                    filter.clear_blocklist();
                    ctx.cache.invalidate_all();
                    manifest.fingerprint = 0;
                    manifest.merged_blocks = 0;
                    manifest.merged_exceptions = 0;
                    let _ = manifest.save_atomic(&manifest_path);
                } else {
                    debug!(
                        sources = configured_sources.len(),
                        "Adblock: starting source refresh"
                    );

                    let client = build_adblock_http_client();

                    let mut source_pairs = Vec::new();
                    let mut active_source_ids = Vec::new();
                    let mut active_lists = Vec::new();
                    let mut updated_sources = 0usize;
                    let mut unchanged_sources = 0usize;
                    let mut failed_sources = 0usize;

                    for (idx, entry) in configured_sources.iter().enumerate() {
                        let source_id = entry.source_id();
                        let source_idx = (idx as u16).min(u16::MAX - 1);

                        let block_path = sources_dir.join(format!("{source_id}.block.fst"));
                        let has_artifact = block_path.exists();
                        let prev_entry = manifest.sources.get(&source_id);
                        let (etag, last_mod) = if has_artifact && !force_refresh {
                            (
                                prev_entry.and_then(|p| p.etag.as_deref()),
                                prev_entry.and_then(|p| p.last_modified.as_deref()),
                            )
                        } else {
                            (None, None)
                        };

                        debug!(url = %entry.url, "Adblock: fetching source");
                        match fetch_source_conditional(&client, entry.url.clone(), etag, last_mod)
                            .await
                        {
                            Ok(SourceFetchResult::NotModified) => {
                                unchanged_sources += 1;
                                debug!(url = %entry.url, "Adblock source is unchanged");
                                if let Some(m_entry) = manifest.sources.get_mut(&source_id) {
                                    m_entry.last_attempt = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    m_entry.consecutive_failures = 0;
                                    m_entry.last_error = None;
                                }
                            }
                            Ok(SourceFetchResult::Fetched {
                                body,
                                etag,
                                last_modified,
                            }) => {
                                let url = entry.url.clone();
                                let s_dir = sources_dir.clone();
                                let format = entry.format;

                                let comp_res = tokio::task::spawn_blocking(move || {
                                    let text = String::from_utf8_lossy(&body);
                                    compile_source_artifacts(
                                        source_id,
                                        source_idx,
                                        &url,
                                        format,
                                        &text,
                                        etag,
                                        last_modified,
                                        &s_dir,
                                    )
                                })
                                .await;

                                match comp_res {
                                    Ok(Ok(s_entry)) => {
                                        updated_sources += 1;
                                        debug!(
                                            url = %entry.url,
                                            blocks = s_entry.stats.blocks,
                                            exceptions = s_entry.stats.exceptions,
                                            "Adblock: compiled source artifacts"
                                        );
                                        manifest.sources.insert(source_id, s_entry);
                                    }
                                    Ok(Err(e)) => {
                                        failed_sources += 1;
                                        error!(url = %entry.url, error = %e, "Adblock: compilation error");
                                        let m_entry = manifest
                                            .sources
                                            .entry(source_id)
                                            .or_insert_with(|| {
                                                let now = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();
                                                SourceManifestEntry {
                                                    id: source_id,
                                                    url: entry.url.clone(),
                                                    format_configured: entry.format,
                                                    format_detected: AdblockSourceFormat::Auto,
                                                    etag: None,
                                                    last_modified: None,
                                                    last_attempt: now,
                                                    last_success: 0,
                                                    consecutive_failures: 0,
                                                    last_error: None,
                                                    stats: ParseStats::default(),
                                                    unsupported_samples: Vec::new(),
                                                    content_hash: 0,
                                                }
                                            });
                                        m_entry.last_attempt = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        m_entry.last_error = Some(e.to_string());
                                        m_entry.consecutive_failures += 1;
                                    }
                                    Err(e) => {
                                        failed_sources += 1;
                                        error!(url = %entry.url, error = %e, "Adblock: compilation task panic");
                                    }
                                }
                            }
                            Err(e) => {
                                failed_sources += 1;
                                error!(
                                    url = %entry.url,
                                    error = %e,
                                    "Adblock: failed to fetch source, using cached version if available"
                                );
                                let m_entry =
                                    manifest.sources.entry(source_id).or_insert_with(|| {
                                        let now = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        SourceManifestEntry {
                                            id: source_id,
                                            url: entry.url.clone(),
                                            format_configured: entry.format,
                                            format_detected: AdblockSourceFormat::Auto,
                                            etag: None,
                                            last_modified: None,
                                            last_attempt: now,
                                            last_success: 0,
                                            consecutive_failures: 0,
                                            last_error: None,
                                            stats: ParseStats::default(),
                                            unsupported_samples: Vec::new(),
                                            content_hash: 0,
                                        }
                                    });
                                m_entry.last_attempt = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                m_entry.last_error = Some(e.to_string());
                                m_entry.consecutive_failures += 1;
                            }
                        }

                        if block_path.exists() {
                            let hash = manifest
                                .sources
                                .get(&source_id)
                                .map_or(0, |m| m.content_hash);
                            source_pairs.push((source_id, hash));
                            active_source_ids.push(source_id);
                            active_lists.push((source_id, entry.kind));
                        }
                    }

                    info!(
                        sources = configured_sources.len(),
                        updated = updated_sources,
                        unchanged = unchanged_sources,
                        failed = failed_sources,
                        "Adblock source refresh completed"
                    );

                    force_refresh = false;
                    let new_fingerprint = AdblockManifest::compute_fingerprint(&source_pairs);

                    if active_source_ids.is_empty() && !configured_sources.is_empty() {
                        warn!(
                            "Adblock: all configured sources failed to download and no cached artifacts exist; preserving existing blocklist"
                        );
                        let _ = manifest.save_atomic(&manifest_path);
                    } else if let Some(bl) = load_lists(&sources_dir, active_lists).await {
                        // Lists are queried in place: loading the refreshed set is a few mmaps.
                        manifest.fingerprint = new_fingerprint;
                        manifest.merged_blocks = bl.len();
                        manifest.merged_exceptions = bl.exceptions_len();
                        manifest.pruned_rules = 0;
                        manifest.last_merge = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        manifest.source_index = active_source_ids;
                        let _ = manifest.save_atomic(&manifest_path);
                        info!(
                            blocks = manifest.merged_blocks,
                            exceptions = manifest.merged_exceptions,
                            elapsed = ?start.elapsed(),
                            "Adblock: lists loaded"
                        );
                        filter.replace_blocklist(bl);
                        ctx.cache.invalidate_all();
                    }
                }

                // The manual rules are the DNS service's (`FilterSubscriptions`), not the lists'.

                // Re-read the config: `db_cfg` dates from the top of this pass, and adblock may
                // have been disabled while the lists were loading.
                if should_auto_enable(filter, ctx.ctx.get_dns_adblock().enabled) {
                    filter.set_enabled(true);
                    info!(
                        blocked_domains = filter.blocklist_size(),
                        "Adblock: enabled with active rules"
                    );
                }

                // Wait for valid NTP time if un-synced SBC boot (e.g. 1970)
                while chrono::Local::now().year() < 2024 {
                    warn!("Adblock: system clock appears un-synchronized; waiting 15s for NTP...");
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }

                // Refresh scheduling: if any configured source failed, retry with backoff
                let max_failures = configured_sources
                    .iter()
                    .map(|entry| {
                        let source_id = entry.source_id();
                        manifest
                            .sources
                            .get(&source_id)
                            .map_or(0, |s| s.consecutive_failures)
                    })
                    .max()
                    .unwrap_or(0);

                last_refresh = Some(Instant::now());
                let now_local = chrono::Local::now();
                let mut target_time = compute_next_refresh_target(now_local, db_cfg.refresh_time);
                let scheduled_dur = (target_time - now_local)
                    .to_std()
                    .unwrap_or(Duration::from_secs(60));

                let sleep_dur = if max_failures > 0 {
                    let backoff = compute_retry_backoff(max_failures);
                    let retry_dur = backoff.min(scheduled_dur);
                    warn!(
                        failures = max_failures,
                        retry_in_mins = retry_dur.as_secs() / 60,
                        "Adblock: some sources failed to refresh; retrying with backoff"
                    );
                    retry_dur
                } else {
                    info!(
                        target = %target_time.format("%Y-%m-%d %H:%M:%S"),
                        hours = format_args!("{:.1}", scheduled_dur.as_secs_f64() / 3600.0),
                        "Adblock: next scheduled daily update check"
                    );
                    scheduled_dur
                };

                let alarm = tokio::time::sleep(sleep_dur);
                tokio::pin!(alarm);
                // Created once per wait: a `sleep` built inside the select would restart on every
                // wake-up (one per client query on this topic) and never fire under traffic.
                let mut clock_check = tokio::time::interval_at(
                    tokio::time::Instant::now() + Duration::from_secs(1800),
                    Duration::from_secs(1800),
                );

                // Wait for next refresh or reload signal
                loop {
                    tokio::select! {
                        () = &mut alarm => {
                            info!("Adblock: daily scheduled refresh triggered");
                            break;
                        }
                        _ = clock_check.tick() => {
                            // Periodic 30m sanity check: detect NTP clock adjustments
                            let current = chrono::Local::now();
                            if current >= target_time {
                                info!("Adblock: wall-clock target reached during periodic check");
                                break;
                            }
                        }
                        // Toggles and blocking settings are applied by the DNS service; only the
                        // schedule and a first enable with nothing loaded concern this worker.
                        Some(delta) = adblock_sub.next() => {
                            if delta.new.refresh_time != delta.old.refresh_time {
                                let now_local = chrono::Local::now();
                                target_time =
                                    compute_next_refresh_target(now_local, delta.new.refresh_time);
                                let wait = (target_time - now_local)
                                    .to_std()
                                    .unwrap_or(Duration::from_secs(60));
                                // A pending failure retry that comes sooner is kept.
                                let deadline = alarm
                                    .deadline()
                                    .min(tokio::time::Instant::now() + wait);
                                alarm.as_mut().reset(deadline);
                                info!(
                                    target = %target_time.format("%Y-%m-%d %H:%M:%S"),
                                    "Adblock: refresh time changed, rescheduled"
                                );
                            }
                            if delta.new.enabled && filter.blocklist_size() == 0 {
                                info!("Adblock: enabled with no list loaded, refreshing");
                                break;
                            }
                        }
                        Some(_) = urls_sub.next() => {
                            info!("Adblock: source list changed, reloading");
                            break;
                        }
                        Ok(()) = upstreams_rx.changed(), if max_failures > 0 => {
                            if !ctx.recursive.is_empty() {
                                info!("Adblock: DNS upstreams available, retrying failed sources");
                                break;
                            }
                        }
                        evt_res = rx.recv() => {
                            let evt = match evt_res {
                                Ok(evt) => evt,
                                Err(RecvError::Lagged(_)) => continue,
                                // Never `break` here: the reload would loop on a closed bus.
                                Err(RecvError::Closed) => return,
                            };
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                    info!("Adblock: manual reload triggered via event bus");
                                    force_refresh = true;
                                    break;
                                }
                                // The DNS service flips the filter on a toggle; a disable is picked
                                // up at the next pass (the worker idles while disabled).
                                _ => continue,
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Whether the worker should switch the filter on after a successful list load.
///
/// Only when the config wants adblock on, rules are loaded, and the filter is off for no
/// other reason. A temporary pause (`disabled_until` armed) keeps the config `enabled`, so
/// it must never be overridden here.
#[cfg(feature = "adblock")]
fn should_auto_enable(filter: &AdBlocker, config_enabled: bool) -> bool {
    let paused = filter.timer.disabled_until.load(Ordering::Relaxed) != 0;
    config_enabled && !paused && !filter.is_enabled() && filter.blocklist_size() > 0
}

/// Computes the next local `DateTime` when the daily blocklist check should trigger.
#[cfg(feature = "adblock")]
#[must_use]
pub fn compute_next_refresh_target(
    now: chrono::DateTime<chrono::Local>,
    refresh_time: TimeOfDay,
) -> chrono::DateTime<chrono::Local> {
    let today_target = now
        .date_naive()
        .and_hms_opt(refresh_time.hour as u32, refresh_time.minute as u32, 0)
        .unwrap_or_else(|| {
            now.date_naive()
                .and_hms_opt(3, 0, 0)
                .expect("03:00 is a valid time")
        })
        .and_local_timezone(chrono::Local)
        .latest()
        .unwrap_or(now);

    if now < today_target {
        today_target
    } else {
        today_target + chrono::Duration::days(1)
    }
}

/// Computes backoff duration based on consecutive failure count.
#[cfg(feature = "adblock")]
fn compute_retry_backoff(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 => Duration::ZERO,
        1 => Duration::from_secs(300),  // 5 min
        2 => Duration::from_secs(900),  // 15 min
        3 => Duration::from_secs(1800), // 30 min
        _ => Duration::from_secs(3600), // 60 min
    }
}

#[cfg(all(test, feature = "adblock"))]
mod tests {
    use super::*;

    #[test]
    fn auto_enable_never_overrides_a_temporary_pause() {
        let filter = AdBlocker::new(true);
        filter.replace_rules("||ads.example.com^\n");

        // Paused for 30 s by the toggle: config still says enabled.
        let until = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 30;
        filter.timer.disabled_until.store(until, Ordering::Relaxed);
        filter.set_enabled(false);
        assert!(
            !should_auto_enable(&filter, true),
            "a pause must survive a list reload"
        );

        // Disabled in the config: stays off.
        filter.timer.disabled_until.store(0, Ordering::Relaxed);
        assert!(!should_auto_enable(&filter, false));

        // Off with no pause and config enabled (first load): switched on.
        assert!(should_auto_enable(&filter, true));

        // Already on: nothing to do.
        filter.set_enabled(true);
        assert!(!should_auto_enable(&filter, true));
    }

    #[test]
    fn test_retry_backoff_schedule() {
        assert_eq!(compute_retry_backoff(0), Duration::ZERO);
        assert_eq!(compute_retry_backoff(1), Duration::from_secs(300));
        assert_eq!(compute_retry_backoff(2), Duration::from_secs(900));
        assert_eq!(compute_retry_backoff(3), Duration::from_secs(1800));
        assert_eq!(compute_retry_backoff(4), Duration::from_secs(3600));
        assert_eq!(compute_retry_backoff(10), Duration::from_secs(3600));
    }

    #[test]
    fn test_compute_next_refresh_target() {
        use chrono::TimeZone;
        let local_now = chrono::Local
            .with_ymd_and_hms(2026, 10, 10, 2, 0, 0)
            .unwrap();
        let target = compute_next_refresh_target(local_now, TimeOfDay { hour: 3, minute: 0 });
        assert_eq!(
            target,
            chrono::Local
                .with_ymd_and_hms(2026, 10, 10, 3, 0, 0)
                .unwrap()
        );

        let local_later = chrono::Local
            .with_ymd_and_hms(2026, 10, 10, 4, 0, 0)
            .unwrap();
        let target_tomorrow =
            compute_next_refresh_target(local_later, TimeOfDay { hour: 3, minute: 0 });
        assert_eq!(
            target_tomorrow,
            chrono::Local
                .with_ymd_and_hms(2026, 10, 11, 3, 0, 0)
                .unwrap()
        );
    }
}

/// Spawns the cache maintenance handler.
pub fn spawn_cache_handler(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            for mgr in ctx.recursive.all_upstreams() {
                mgr.cache.cleanup();
            }
            if let Some(mgr) = ctx.recursive.all_upstreams().next() {
                ctx.stats
                    .cache_entries
                    .store(mgr.cache.cache.len() as u64, Ordering::Relaxed);
            }
        }
    })
}
