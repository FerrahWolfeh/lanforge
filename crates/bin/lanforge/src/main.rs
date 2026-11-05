//! `lanforge` — Central network identity manager (IPv6/IPv4).
#![allow(
    unused_crate_dependencies,
    reason = "binary target uses dependencies via library target"
)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::similar_names
)]

use anyhow::Result;
use lanforge::app::Daemon;
use lanforge::bootstrap::Bootstrapper;
#[cfg(feature = "ring")]
use rustls::crypto::ring;
use sd_notify::{NotifyState, notify};
use std::time::{Duration, Instant};
use std::{env, process};
use tokio::runtime::Builder;
use tokio::time::interval;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(all(feature = "jemalloc", not(feature = "hotpath-alloc")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<()> {
    // systemd's start timeout runs from exec: the readiness deadline counts from here too.
    let started = Instant::now();
    let rt = Builder::new_multi_thread()
        .enable_all()
        .thread_name("Async Worker")
        .build()?;

    let res = rt.block_on(async_main(started));

    if let Err(e) = res {
        eprintln!("❌ Fatal error: {e:#}");
        process::exit(1);
    }
    process::exit(0);
}

async fn async_main(started: Instant) -> Result<()> {
    // 0. Initialize Crypto Provider (Rustls 0.23+ requirement)
    #[cfg(feature = "ring")]
    let _ = ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 1. Setup Logging
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // 1.1 Setup Profiling
    #[cfg(feature = "hotpath")]
    let _hotpath = {
        let guard = hotpath::HotpathGuardBuilder::new("lanforged").build();
        hotpath::tokio_runtime!();
        guard
    };

    // 1.2 Setup Systemd Watchdog ping
    if let Ok(usec_str) = env::var("WATCHDOG_USEC")
        && let Ok(usec) = usec_str.parse::<u64>()
    {
        let interval_ms = (usec / 1000) / 2;
        if interval_ms > 0 {
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_millis(interval_ms));
                loop {
                    interval.tick().await;
                    let _ = notify(&[NotifyState::Watchdog]);
                }
            });
            info!("Systemd watchdog enabled with interval {interval_ms}ms");
        }
    }

    // 2. Run Bootstrap
    let (bootstrap, ctx) = Bootstrapper::run().await?;

    // 3. Initialize and run Daemon
    let daemon = Daemon::new(bootstrap, ctx, started.into());
    daemon.run().await
}
