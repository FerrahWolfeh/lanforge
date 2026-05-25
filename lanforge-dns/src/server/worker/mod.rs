pub mod tcp;
pub mod udp;

#[cfg(feature = "adblock")]
use crate::resolver::filter::{DiskBlocklist, hash_set_unordered};
use crate::server::DnsContext;
#[cfg(feature = "adblock")]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockUrlKind;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
#[cfg(feature = "adblock")]
use std::{
    path::Path,
    time::Instant,
};
use tokio::task::JoinHandle;
#[cfg(feature = "adblock")]
use tracing::{error, info, warn};

/// Spawns the adblock list refresh manager.
#[cfg(feature = "adblock")]
pub fn spawn_adblock_manager(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(filter) = &ctx.filter {
            let cache_path = Path::new("/var/lib/lanforge/blocklist.fst");
            let hash_path = Path::new("/var/lib/lanforge/blocklist.hash");
            let mut rx = ctx.bus.subscribe();
            let mut last_blocklist_hash = 0u64;
            let mut cache_loaded = false;

            loop {
                let db_cfg = ctx.db.load_adblock_config().await.unwrap_or_default();

                // Wait if disabled
                if !filter.is_enabled() {
                    info!("🛡️ Adblock: currently disabled, waiting for toggle or reload...");
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
                if !cache_loaded && cache_path.exists() {
                    if let Ok(metadata) = std::fs::metadata(cache_path)
                        && let Ok(modified) = metadata.modified()
                    {
                        let elapsed = modified.elapsed().unwrap_or_default().as_secs();
                        if elapsed < u64::from(db_cfg.refresh_hours) * 3600 {
                            info!("🛡️ Adblock: loading cached blocklist from disk...");
                            match DiskBlocklist::load(cache_path, 50000) {
                                Ok(bl) => {
                                    info!("🛡️ Adblock: loaded {} domains from cache", bl.len());
                                    filter.replace_blocklist(bl);
                                    if let Ok(hash_str) = std::fs::read_to_string(hash_path)
                                        && let Ok(h) = hash_str.trim().parse::<u64>()
                                    {
                                        last_blocklist_hash = h;
                                        skip_download_pass = true;
                                        info!(
                                            "🛡️ Adblock: cached blocklist is fresh (hash: {:016x}) — skipping startup download",
                                            h
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "❌ Adblock: cached FST file corrupted or invalid ({e}). Deleting cache and forcing rebuild..."
                                    );
                                    let _ = std::fs::remove_file(cache_path);
                                    let _ = std::fs::remove_file(hash_path);
                                }
                            }
                        }
                    }
                    cache_loaded = true;
                }

                let start = Instant::now();

                // Load URLs from the database (the DB is the source of truth after the refactor)
                let (blocklist_urls, allowlist_urls) = match ctx.db.load_adblock_urls().await {
                    Ok(urls) => {
                        let mut block = Vec::new();
                        let mut allow = Vec::new();
                        for (_id, url, kind) in urls {
                            match kind {
                                AdblockUrlKind::Blocklist => block.push(url),
                                AdblockUrlKind::Allowlist => allow.push(url),
                            }
                        }
                        info!(
                            "🛡️ Adblock: loaded {} blocklist and {} allowlist URLs from database",
                            block.len(),
                            allow.len()
                        );
                        (block, allow)
                    }
                    Err(e) => {
                        error!("❌ Adblock: failed to load URLs from database: {e}");
                        let sleep_dur = if filter.blocklist_size() == 0 {
                            warn!("🛡️ Adblock: no blocklist loaded in memory, retrying in 60s...");
                            Duration::from_secs(60)
                        } else {
                            warn!("🛡️ Adblock: will retry on next refresh cycle");
                            compute_next_refresh(
                                db_cfg.refresh_hours,
                                db_cfg.refresh_at_night,
                            )
                        };
                        tokio::select! {
                            _ = tokio::time::sleep(sleep_dur) => {}
                            Ok(evt) = rx.recv() => {
                                if let LanforgeEvent::Dns(DnsEvent::AdblockReload) = evt.event {
                                    info!("🛡️ Adblock: manual reload triggered (retrying after error)");
                                }
                            }
                        }
                        continue;
                    }
                };

                if skip_download_pass {
                    info!("🛡️ Adblock: skipping blocklist download pass (cached FST is fresh)");
                } else if blocklist_urls.is_empty() {
                    warn!(
                        "🛡️ Adblock: no blocklist URLs configured in database — skipping download"
                    );
                    filter.clear_blocklist();
                    last_blocklist_hash = 0;
                    let _ = std::fs::remove_file(hash_path);
                } else {
                    info!(
                        "🛡️ Adblock: downloading {} blocklist sources...",
                        blocklist_urls.len()
                    );
                    match filter.load_from_urls("blocklist", &blocklist_urls) {
                        Ok(new_list) => {
                            let count = new_list.len();
                            let current_hash = hash_set_unordered(&new_list);

                            if current_hash == last_blocklist_hash && last_blocklist_hash != 0 {
                                info!(
                                    "🛡️ Adblock: blocklist content unchanged (hash: {:016x}) — skipping rebuild",
                                    current_hash
                                );
                            } else {
                                info!(
                                    "🛡️ Adblock: downloaded {} unique domains, building FST at {}...",
                                    count,
                                    cache_path.display()
                                );
                                match DiskBlocklist::build(new_list, cache_path, 50000) {
                                    Ok(bl) => {
                                        filter.replace_blocklist(bl);
                                        last_blocklist_hash = current_hash;
                                        let _ = std::fs::write(hash_path, current_hash.to_string());
                                        info!(
                                            "🛡️ Adblock: blocklist built and saved — {} domains in {:.1}s",
                                            count,
                                            start.elapsed().as_secs_f32()
                                        );
                                    }
                                    Err(e) => {
                                        error!("❌ Adblock: failed to build disk blocklist: {e}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("❌ Adblock: failed to download blocklist sources: {e}");
                        }
                    }
                }

                if !allowlist_urls.is_empty() {
                    info!(
                        "🛡️ Adblock: downloading {} allowlist sources...",
                        allowlist_urls.len()
                    );
                    match filter.load_from_urls("allowlist", &allowlist_urls) {
                        Ok(new_allow) => filter.replace_allowlist(new_allow),
                        Err(e) => error!("❌ Adblock: failed to download allowlist sources: {e}"),
                    }
                }

                // Ensure enabled after first successful load (if it was intended to be enabled)
                if !filter.is_enabled() && filter.blocklist_size() > 0 && db_cfg.enabled {
                    filter.set_enabled(true);
                    info!(
                        "🛡️ Adblock: enabled with {} blocked domains",
                        filter.blocklist_size()
                    );
                }

                // Refresh scheduling
                let sleep_dur = compute_next_refresh(
                    db_cfg.refresh_hours,
                    db_cfg.refresh_at_night,
                );
                info!(
                    "🛡️ Adblock: next refresh in {:.1}h",
                    sleep_dur.as_secs_f64() / 3600.0
                );

                // Wait for next refresh or reload signal
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(sleep_dur) => {
                            info!("🛡️ Adblock: scheduled refresh starting...");
                            break;
                        }
                        Ok(evt) = rx.recv() => {
                            match evt.event {
                                LanforgeEvent::Dns(DnsEvent::AdblockReload) => {
                                    info!("🛡️ Adblock: manual reload triggered via event bus");
                                    break;
                                }
                                LanforgeEvent::Dns(DnsEvent::AdblockToggle { enabled: true, .. }) => {
                                    info!("🛡️ Adblock: re-enabled, triggering refresh");
                                    break;
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
