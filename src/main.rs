//! `lanforge` — Gerenciador central de identidades de rede (IPv6/IPv4).
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
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let rt = Builder::new_current_thread()
        .enable_all()
        .thread_name("lanforge-main")
        .build()?;

    let res = rt.block_on(async_main());

    if let Err(e) = res {
        eprintln!("❌ Erro fatal: {e:#}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

async fn async_main() -> Result<()> {
    // 1. Setup Logging
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // 2. Run Bootstrap
    let (bootstrap, ctx) = Bootstrapper::run().await?;

    // 3. Initialize and run Daemon
    let daemon = Daemon::new(bootstrap, ctx);
    daemon.run().await
}
