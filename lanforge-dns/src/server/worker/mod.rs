pub mod tcp;
pub mod udp;

use crate::{resolver::filter::DiskBlocklist, server::DnsContext};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Spawns the adblock list refresh manager.
pub fn spawn_adblock_manager(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(filter) = &ctx.filter {
            let cache_path = Path::new("blocklist.rkyv");

            // 1. Try to load from disk on startup
            if cache_path.exists()
                && let Ok(metadata) = std::fs::metadata(cache_path)
                && let Ok(modified) = metadata.modified()
            {
                let elapsed = modified.elapsed().unwrap_or_default().as_secs();
                if elapsed < u64::from(ctx.cfg.adblock_refresh_hours) * 3600 {
                    info!("🛡️ Adblock: loading cached blocklist from disk...");
                    if let Ok(bl) = DiskBlocklist::load(cache_path, 50000) {
                        info!("🛡️ Adblock: loaded {} domains from cache", bl.len());
                        filter.replace_blocklist(bl);
                    }
                }
            }

            loop {
                let start = Instant::now();
                info!(
                    "🛡️ Adblock: downloading {} blocklist sources...",
                    ctx.cfg.adblock_urls.len()
                );

                if let Ok(new_list) = filter.load_from_urls(&ctx.cfg.adblock_urls) {
                    let count = new_list.len();
                    // Build DiskBlocklist (writes to disk + builds bloom)
                    match DiskBlocklist::build(new_list, cache_path, 50000) {
                        Ok(bl) => {
                            filter.replace_blocklist(bl);
                            info!(
                                "🛡️ Adblock: blocklist built and saved — {} domains in {:.1}s",
                                count,
                                start.elapsed().as_secs_f32()
                            );
                        }
                        Err(e) => {
                            error!("❌ Adblock: failed to build disk blocklist: {}", e);
                        }
                    }
                }

                if let Ok(new_allow) = filter.load_from_urls(&ctx.cfg.adblock_allowlist_urls) {
                    filter.replace_allowlist(new_allow);
                }

                // Ensure enabled after first successful load
                if !filter.is_enabled() && filter.blocklist_size() > 0 {
                    filter.set_enabled(true);
                    info!(
                        "🛡️ Adblock: enabled with {} blocked domains",
                        filter.blocklist_size()
                    );
                }

                // Refresh scheduling
                let sleep_dur = compute_next_refresh(
                    ctx.cfg.adblock_refresh_hours,
                    ctx.cfg.adblock_refresh_at_night,
                );
                tokio::time::sleep(sleep_dur).await;
            }
        }
    })
}

/// Computes how long to sleep before the next blocklist refresh.
/// If `prefer_night` is true, targets the next occurrence of 03:00 local time
/// that is at least `min_hours` in the future.
fn compute_next_refresh(min_hours: u32, prefer_night: bool) -> Duration {
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
