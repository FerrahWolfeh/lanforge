//! `lanforge` — Central network identity manager (IPv6/IPv4).
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::similar_names
)]

use anyhow::Result;
use lanforge::app::Daemon;
use lanforge::bootstrap::Bootstrapper;
use tokio::runtime::Builder;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(all(feature = "jemalloc", not(feature = "hotpath-alloc")))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<()> {
    let rt = Builder::new_multi_thread()
        .enable_all()
        .thread_name("Async Worker")
        .build()?;

    let res = rt.block_on(async_main());

    if let Err(e) = res {
        eprintln!("❌ Fatal error: {e:#}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

async fn async_main() -> Result<()> {
    // 0. Initialize Crypto Provider (Rustls 0.23+ requirement)
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 1. Setup Logging
    init_logging();

    // 1.1 Setup Profiling
    #[cfg(feature = "hotpath")]
    let _hotpath = {
        let guard = hotpath::HotpathGuardBuilder::new("lanforged").build();
        hotpath::tokio_runtime!();
        guard
    };

    // 2. Run Bootstrap
    let (bootstrap, ctx) = Bootstrapper::run().await?;

    // 3. Initialize and run Daemon
    let daemon = Daemon::new(bootstrap, ctx);
    daemon.run().await
}

fn init_logging() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let is_systemd = std::env::var_os("JOURNAL_STREAM").is_some()
        || std::env::var_os("INVOCATION_ID").is_some();

    if is_systemd && let Ok(journal_layer) = tracing_journald::layer() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(journal_layer)
            .init();
        return;
    }

    // Default / Interactive terminal / Container fallback
    tracing_subscriber::fmt()
        .without_time()
        .with_ansi(true)
        .with_env_filter(env_filter)
        .init();
}
