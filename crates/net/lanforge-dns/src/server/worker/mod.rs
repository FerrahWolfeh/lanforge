pub mod tcp;
pub mod udp;

#[cfg(feature = "adblock")]
use std::collections::HashSet;
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
use crate::resolver::filter::manifest::AdblockManifest;
#[cfg(feature = "adblock")]
use crate::resolver::filter::source::{
    compile_source_artifacts, fetch_source_conditional, merge_all_sources, SourceFetchResult,
};
#[cfg(feature = "adblock")]
use crate::resolver::filter::DiskBlocklist;
#[cfg(feature = "adblock")]
use hyper_rustls::HttpsConnectorBuilder;
#[cfg(feature = "adblock")]
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "adblock")]
use hyper_util::client::legacy::Client;
#[cfg(feature = "adblock")]
use hyper_util::rt::TokioExecutor;
#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockSourceFormat;
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

            loop {
                let db_cfg = ctx.ctx.get_dns_adblock();

                // Wait if disabled
                if !filter.is_enabled() {
                    debug!("Adblock: currently disabled, waiting for toggle or reload");
                    loop {
                        if let Ok(evt) = rx.recv().await {
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload)
                                | LanforgeEvent::Dns(DnsEvent::AdblockToggle {
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
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let elapsed = now.saturating_sub(manifest.last_merge);
                        if elapsed < u64::from(db_cfg.refresh_hours) * 3600 {
                            info!("Adblock: loading compiled blocklist from disk");
                            let tb = target_block_path.clone();
                            let load_res = tokio::task::spawn_blocking(move || DiskBlocklist::load(&tb, 50000)).await;
                            match load_res {
                                Ok(Ok(bl)) => {
                                    info!(domains = bl.len(), "Adblock: loaded domains from cache");
                                    filter.replace_blocklist(bl);
                                    ctx.cache.invalidate_all();
                                    skip_download_pass = true;
                                    info!(
                                        fingerprint = format_args!("{:016x}", manifest.fingerprint),
                                        "Adblock: cached blocklist is fresh, skipping startup download"
                                    );
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

                    let mut http = HttpConnector::new();
                    http.set_connect_timeout(Some(Duration::from_secs(10)));
                    let https = HttpsConnectorBuilder::new()
                        .with_webpki_roots()
                        .https_or_http()
                        .enable_http1()
                        .enable_http2()
                        .wrap_connector(http);
                    let client = Client::builder(TokioExecutor::new())
                        .pool_idle_timeout(Duration::from_secs(30))
                        .build(https);

                    let mut source_pairs = Vec::new();
                    let mut active_source_ids = Vec::new();

                    for (idx, entry) in configured_sources.iter().enumerate() {
                        let source_id = entry.id.unwrap_or_else(|| {
                            let mut h = 0xcbf29ce484222325u64;
                            for &b in entry.url.as_bytes() {
                                h ^= b as u64;
                                h = h.wrapping_mul(0x100000001b3);
                            }
                            (h & 0x7FFF_FFFF_FFFF_FFFF) as i64
                        });
                        let source_idx = (idx as u16).min(u16::MAX - 1);

                        let prev_entry = manifest.sources.get(&source_id);
                        let etag = prev_entry.and_then(|p| p.etag.as_deref());
                        let last_mod = prev_entry.and_then(|p| p.last_modified.as_deref());

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
                                let format = AdblockSourceFormat::Auto;
                                let text = String::from_utf8_lossy(&body).into_owned();

                                let comp_res = tokio::task::spawn_blocking(move || {
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
                                        if let Some(m_entry) = manifest.sources.get_mut(&source_id) {
                                            m_entry.last_error = Some(e.to_string());
                                            m_entry.consecutive_failures += 1;
                                        }
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
                                if let Some(m_entry) = manifest.sources.get_mut(&source_id) {
                                    m_entry.last_error = Some(e.to_string());
                                    m_entry.consecutive_failures += 1;
                                }
                            }
                        }

                        let block_path = sources_dir.join(format!("{source_id}.block.fst"));
                        if block_path.exists() {
                            let hash = manifest.sources.get(&source_id).map_or(0, |m| m.content_hash);
                            source_pairs.push((source_id, hash));
                            active_source_ids.push(source_id);
                        }
                    }

                    // Check if fingerprint changed or target files missing
                    let new_fingerprint = AdblockManifest::compute_fingerprint(&source_pairs);

                    if active_source_ids.is_empty() && !configured_sources.is_empty() {
                        warn!("Adblock: all configured sources failed to download and no cached artifacts exist; preserving existing blocklist");
                    } else if new_fingerprint != manifest.fingerprint || !target_block_path.exists() {
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
                                let tb = target_block_path.clone();
                                match DiskBlocklist::load(&tb, 50000) {
                                    Ok(bl) => {
                                        filter.replace_blocklist(bl);
                                        ctx.cache.invalidate_all();
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
                    }
                }

                // Compile allowlist: manual allowlist + allow rules
                let mut full_allowlist = HashSet::new();
                for domain in ctx.ctx.get_dns_allowlist() {
                    full_allowlist.insert(domain.to_lowercase());
                }
                for rule in ctx.ctx.get_dns_adblock_rules() {
                    if rule.enabled && rule.is_allow() {
                        full_allowlist.insert(rule.domain.to_lowercase());
                    }
                }
                filter.replace_allowlist(full_allowlist);

                // Compile custom manual blocklist
                let mut custom_blocks = HashSet::new();
                for rule in ctx.ctx.get_dns_adblock_rules() {
                    if rule.enabled && rule.is_block() {
                        custom_blocks.insert(rule.domain.to_lowercase());
                    }
                }
                filter.replace_custom_blocks(custom_blocks);
                ctx.cache.invalidate_all();

                // Ensure enabled after first successful load (if it was intended to be enabled)
                if !filter.is_enabled() && filter.blocklist_size() > 0 && db_cfg.enabled {
                    filter.set_enabled(true);
                    info!(
                        blocked_domains = filter.blocklist_size(),
                        "Adblock: enabled with active rules"
                    );
                }

                // Refresh scheduling: if any configured source failed, retry with backoff
                let max_failures = configured_sources
                    .iter()
                    .map(|entry| {
                        let source_id = entry.id.unwrap_or_else(|| {
                            let mut h = 0xcbf29ce484222325u64;
                            for &b in entry.url.as_bytes() {
                                h ^= b as u64;
                                h = h.wrapping_mul(0x100000001b3);
                            }
                            (h & 0x7FFF_FFFF_FFFF_FFFF) as i64
                        });
                        manifest.sources.get(&source_id).map_or(0, |s| s.consecutive_failures)
                    })
                    .max()
                    .unwrap_or(0);

                let scheduled_refresh = compute_next_refresh(db_cfg.refresh_hours, db_cfg.refresh_at_night);
                let sleep_dur = if max_failures > 0 {
                    let backoff = compute_retry_backoff(max_failures);
                    let retry_dur = backoff.min(scheduled_refresh);
                    warn!(
                        failures = max_failures,
                        retry_in_mins = retry_dur.as_secs() / 60,
                        "Adblock: some sources failed to refresh; retrying with backoff"
                    );
                    retry_dur
                } else {
                    info!(
                        hours = format_args!("{:.1}", scheduled_refresh.as_secs_f64() / 3600.0),
                        "Adblock: next scheduled refresh"
                    );
                    scheduled_refresh
                };

                // Wait for next refresh or reload signal
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(sleep_dur) => {
                            info!("Adblock: scheduled refresh starting");
                            break;
                        }
                        Ok(evt) = rx.recv() => {
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                    info!("Adblock: manual reload triggered via event bus");
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
                                    let mut allow_set = HashSet::new();
                                    for domain in ctx.ctx.get_dns_allowlist() {
                                        allow_set.insert(domain.to_lowercase());
                                    }
                                    let mut block_set = HashSet::new();
                                    for rule in ctx.ctx.get_dns_adblock_rules() {
                                        if rule.enabled {
                                            if rule.is_allow() {
                                                allow_set.insert(rule.domain.to_lowercase());
                                            } else if rule.is_block() {
                                                block_set.insert(rule.domain.to_lowercase());
                                            }
                                        }
                                    }
                                    filter.replace_allowlist(allow_set);
                                    filter.replace_custom_blocks(block_set);
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

/// Computes how long to sleep before the next blocklist refresh.
/// If `prefer_night` is true, targets the next occurrence of 03:00 local time
/// that is at least `min_hours` in the future.
#[cfg(feature = "adblock")]
fn compute_next_refresh(min_hours: u32, prefer_night: bool) -> Duration {
    let min_hours = if min_hours == 0 { 12 } else { min_hours };
    let base = Duration::from_secs(u64::from(min_hours) * 3600);
    if !prefer_night {
        return base;
    }

    let now = chrono::Local::now();
    let mut next = now
        .date_naive()
        .and_hms_opt(3, 0, 0)
        .unwrap()
        .and_local_timezone(chrono::Local)
        .unwrap();

    // If 03:00 today has already passed, or it's too soon, target tomorrow
    if next <= now || (next - now).to_std().unwrap_or(Duration::ZERO) < base {
        next += chrono::Duration::days(1);
    }

    // Ensure it's at least min_hours away
    let mut diff = (next - now).to_std().unwrap_or(base);
    if diff < base {
        diff = base;
    }

    diff
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
    fn test_compute_next_refresh() {
        let dur = compute_next_refresh(12, false);
        assert_eq!(dur, Duration::from_secs(12 * 3600));
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
