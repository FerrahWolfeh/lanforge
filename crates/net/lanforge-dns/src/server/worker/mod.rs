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

use crate::server::DnsContext;
#[cfg(feature = "adblock")]
use crate::resolver::filter::manifest::{AdblockManifest, SourceManifestEntry};
#[cfg(feature = "adblock")]
use crate::resolver::filter::source::{
    build_adblock_http_client, compile_source_artifacts, fetch_source_conditional,
    merge_all_sources, SourceFetchResult,
};
#[cfg(feature = "adblock")]
use crate::resolver::filter::DiskBlocklist;

#[cfg(feature = "adblock")]
use chrono::Datelike;
#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::{AdblockSourceFormat, TimeOfDay};
use tokio::task::JoinHandle;
#[cfg(feature = "adblock")]
use tracing::{debug, error, info, warn};

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
            let target_block_path = adblock_dir.join("block.fst");
            let target_allow_path = adblock_dir.join("allow.fst");
            let legacy_path = Path::new(cache_dir).join("blocklist.fst");
            let legacy_hash_path = Path::new(cache_dir).join("blocklist.hash");

            let _ = std::fs::create_dir_all(&sources_dir);

            let mut manifest = AdblockManifest::load_or_default(&manifest_path);
            let mut rx = ctx.bus.subscribe_dns();
            let mut cache_loaded = false;
            let mut force_refresh = false;

            loop {
                let db_cfg = ctx.ctx.get_dns_adblock();

                // Wait if disabled
                if !filter.is_enabled() {
                    debug!("Adblock: currently disabled, waiting for toggle or reload");
                    loop {
                        if let Ok(evt) = rx.recv().await {
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                    force_refresh = true;
                                    break;
                                }
                                LanforgeEvent::Dns(DnsEvent::AdblockToggle {
                                    enabled: true,
                                    ..
                                }) => break,
                                _ => continue,
                            }
                        }
                    }
                }


                // 1. Try to load from disk if not yet loaded
                let mut skip_download_pass = false;
                if !cache_loaded {
                    if target_block_path.exists() {
                        info!("Adblock: loading compiled blocklist from disk");
                        let tb = target_block_path.clone();
                        let load_res = tokio::task::spawn_blocking(move || DiskBlocklist::load(&tb, 50000)).await;
                        match load_res {
                            Ok(Ok(bl)) => {
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
                                        "Adblock: cached blocklist is fresh, skipping startup download"
                                    );
                                } else {
                                    info!("Adblock: cached blocklist is stale, scheduling background update");
                                }
                            }
                            Ok(Err(e)) => {
                                error!(error = %e, "Adblock: cached FST file corrupted, forcing rebuild");
                                let _ = std::fs::remove_file(&target_block_path);
                                let _ = std::fs::remove_file(&target_allow_path);
                            }
                            Err(e) => {
                                error!(error = %e, "Adblock: task failed loading cached FST");
                            }
                        }
                    } else if legacy_path.exists() {
                        info!("Adblock: loading legacy blocklist from disk");
                        let lp = legacy_path.clone();
                        if let Ok(Ok(bl)) = tokio::task::spawn_blocking(move || DiskBlocklist::load(&lp, 50000)).await {
                            filter.replace_blocklist(bl);
                            ctx.cache.invalidate_all();
                            let _ = std::fs::copy(&legacy_path, &target_block_path);
                        }
                        let _ = std::fs::remove_file(&legacy_path);
                        let _ = std::fs::remove_file(&legacy_hash_path);
                    }
                    cache_loaded = true;
                }

                let start = Instant::now();
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
                    let _ = std::fs::remove_file(&target_block_path);
                    let _ = std::fs::remove_file(&target_allow_path);
                } else {
                    let _ = ctx.ctx.wait_for_pppoe().await;
                    info!(sources = configured_sources.len(), "Adblock: updating blocklist sources");

                    let client = build_adblock_http_client();

                    let mut source_pairs = Vec::new();
                    let mut active_source_ids = Vec::new();

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
                        match fetch_source_conditional(&client, entry.url.clone(), etag, last_mod).await {
                            Ok(SourceFetchResult::NotModified) => {
                                info!(url = %entry.url, "Adblock: source not modified (304)");
                                if let Some(m_entry) = manifest.sources.get_mut(&source_id) {
                                    m_entry.last_attempt = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    m_entry.consecutive_failures = 0;
                                    m_entry.last_error = None;
                                }
                            }
                            Ok(SourceFetchResult::Fetched { body, etag, last_modified }) => {
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
                                }).await;

                                match comp_res {
                                    Ok(Ok(s_entry)) => {
                                        info!(
                                            url = %entry.url,
                                            blocks = s_entry.stats.blocks,
                                            exceptions = s_entry.stats.exceptions,
                                            "Adblock: compiled source artifacts"
                                        );
                                        manifest.sources.insert(source_id, s_entry);
                                    }
                                    Ok(Err(e)) => {
                                        error!(url = %entry.url, error = %e, "Adblock: compilation error");
                                        let m_entry = manifest.sources.entry(source_id).or_insert_with(|| {
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
                                                stats: crate::resolver::filter::parse::ParseStats::default(),
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
                                        error!(url = %entry.url, error = %e, "Adblock: compilation task panic");
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    url = %entry.url,
                                    error = %e,
                                    "Adblock: failed to fetch source, using cached version if available"
                                );
                                let m_entry = manifest.sources.entry(source_id).or_insert_with(|| {
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
                                        stats: crate::resolver::filter::parse::ParseStats::default(),
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
                            let hash = manifest.sources.get(&source_id).map_or(0, |m| m.content_hash);
                            source_pairs.push((source_id, hash));
                            active_source_ids.push(source_id);
                        }
                    }

                    let was_forced = force_refresh;
                    force_refresh = false;

                    // Check if fingerprint changed or target files missing
                    let new_fingerprint = AdblockManifest::compute_fingerprint(&source_pairs);

                    if active_source_ids.is_empty() && !configured_sources.is_empty() {
                        warn!("Adblock: all configured sources failed to download and no cached artifacts exist; preserving existing blocklist");
                        let _ = manifest.save_atomic(&manifest_path);
                    } else if was_forced || new_fingerprint != manifest.fingerprint || !target_block_path.exists() {

                        info!(
                            sources = active_source_ids.len(),
                            "Adblock: merging source FSTs"
                        );
                        let s_dir = sources_dir.clone();
                        let a_ids = active_source_ids.clone();
                        let tb_path = target_block_path.clone();
                        let ta_path = target_allow_path.clone();

                        let merge_res = tokio::task::spawn_blocking(move || {
                            merge_all_sources(&s_dir, &a_ids, &tb_path, &ta_path)
                        }).await;

                        match merge_res {
                            Ok(Ok((merged_blocks, merged_allows, pruned))) => {
                                manifest.fingerprint = new_fingerprint;
                                manifest.merged_blocks = merged_blocks;
                                manifest.merged_exceptions = merged_allows;
                                manifest.pruned_rules = pruned;
                                manifest.last_merge = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                manifest.source_index = active_source_ids;
                                let _ = manifest.save_atomic(&manifest_path);

                                let tb = target_block_path.clone();
                                match DiskBlocklist::load(&tb, 50000) {
                                    Ok(bl) => {
                                        filter.replace_blocklist(bl);
                                        ctx.cache.invalidate_all();

                                        info!(
                                            blocks = merged_blocks,
                                            exceptions = merged_allows,
                                            pruned = pruned,
                                            elapsed = ?start.elapsed(),
                                            "Adblock: merged blocklist successfully updated"
                                        );
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Adblock: failed to load newly merged FST");
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                error!(error = %e, "Adblock: merge failed");
                            }
                            Err(e) => {
                                error!(error = %e, "Adblock: merge task panicked");
                            }
                        }
                    } else {
                        info!("Adblock: fingerprint unchanged, skipping merge");
                        if filter.blocklist_size() == 0 && target_block_path.exists() {
                            info!("Adblock: in-memory blocklist empty, loading compiled FST from disk");
                            let tb = target_block_path.clone();
                            if let Ok(Ok(bl)) = tokio::task::spawn_blocking(move || DiskBlocklist::load(&tb, 50000)).await {
                                filter.replace_blocklist(bl);
                                ctx.cache.invalidate_all();
                            }
                        }
                        let _ = manifest.save_atomic(&manifest_path);
                    }
                }

                // Compile allowlist and custom manual blocklist
                filter.sync_from_context(&ctx.ctx);
                ctx.cache.invalidate_all();

                // Ensure enabled after first successful load (if it was intended to be enabled)
                if !filter.is_enabled() && filter.blocklist_size() > 0 && db_cfg.enabled {
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
                        manifest.sources.get(&source_id).map_or(0, |s| s.consecutive_failures)
                    })
                    .max()
                    .unwrap_or(0);

                let now_local = chrono::Local::now();
                let target_time = compute_next_refresh_target(now_local, db_cfg.refresh_time);
                let scheduled_dur = (target_time - now_local).to_std().unwrap_or(Duration::from_secs(60));

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

                // Wait for next refresh or reload signal
                loop {
                    tokio::select! {
                        () = &mut alarm => {
                            info!("Adblock: daily scheduled refresh triggered");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1800)) => {
                            // Periodic 30m sanity check: detect NTP clock adjustments
                            let current = chrono::Local::now();
                            if current >= target_time {
                                info!("Adblock: wall-clock target reached during periodic check");
                                break;
                            }
                        }
                        Ok(evt) = rx.recv() => {
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                    info!("Adblock: manual reload triggered via event bus");
                                    force_refresh = true;
                                    break;
                                }

                                LanforgeEvent::Dns(DnsEvent::AdblockToggle { .. }) => {
                                    info!("Adblock: toggle event received, checking status");
                                    break;
                                }
                                LanforgeEvent::Dns(DnsEvent::ConfigAdblockChanged) => {
                                    info!("Adblock: config changed, reloading");
                                    break;
                                }
                                LanforgeEvent::Dns(DnsEvent::ConfigAllowlistChanged | DnsEvent::ConfigAdblockRulesChanged) => {
                                    info!("Adblock: custom rules/allowlist changed, updating in-memory filter");
                                    filter.sync_from_context(&ctx.ctx);
                                    ctx.cache.invalidate_all();
                                }
                                LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain)) => {
                                    filter.add_block(&domain);
                                    ctx.cache.invalidate_all();
                                }
                                LanforgeEvent::Dns(DnsEvent::AdblockAllow(domain)) => {
                                    filter.add_allow(&domain);
                                    ctx.cache.invalidate_all();
                                }
                                _ => continue, // Ignore other events
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Computes the next local DateTime when the daily blocklist check should trigger.
#[cfg(feature = "adblock")]
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
        1 => Duration::from_secs(300),   // 5 min
        2 => Duration::from_secs(900),   // 15 min
        3 => Duration::from_secs(1800),  // 30 min
        _ => Duration::from_secs(3600),  // 60 min
    }
}

#[cfg(all(test, feature = "adblock"))]
mod tests {
    use super::*;

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
            chrono::Local.with_ymd_and_hms(2026, 10, 10, 3, 0, 0).unwrap()
        );

        let local_later = chrono::Local
            .with_ymd_and_hms(2026, 10, 10, 4, 0, 0)
            .unwrap();
        let target_tomorrow = compute_next_refresh_target(local_later, TimeOfDay { hour: 3, minute: 0 });
        assert_eq!(
            target_tomorrow,
            chrono::Local.with_ymd_and_hms(2026, 10, 11, 3, 0, 0).unwrap()
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
