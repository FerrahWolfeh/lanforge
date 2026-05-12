pub mod tcp;
pub mod udp;

use crate::server::DnsContext;
use std::{sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tracing::info;

/// Spawns the adblock list refresh manager.
pub fn spawn_adblock_manager(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(filter) = &ctx.filter {
            loop {
                info!("Adblock manager: Refreshing blocklists...");
                if let Ok(new_list) = filter.load_from_urls(&ctx.cfg.adblock_sources) {
                    filter.replace_blocklist(new_list);
                }

                if let Ok(new_allow) = filter.load_from_urls(&ctx.cfg.adblock_allowlist_urls) {
                    filter.replace_allowlist(new_allow);
                }

                // Refresh every 12 hours
                tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
            }
        }
    })
}

/// Spawns the cache maintenance handler.
pub fn spawn_cache_handler(ctx: Arc<DnsContext>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            for mgr in &ctx.recursive.upstreams {
                mgr.cache.cleanup();
            }
        }
    })
}
