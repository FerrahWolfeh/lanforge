mod bus;
mod config;
mod hosts;
mod netlink;
mod ra;
mod slaac;
mod state;
mod supervisor;

use anyhow::Result;
use clap::Parser;
use config::Config;
use futures::StreamExt;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, Instant, interval, sleep_until};
use tracing::{debug, error, info};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::parse();

    info!("Starting lanforge (event-driven netlink monitor)");
    info!("  leases_file   = {}", cfg.leases_file);
    info!("  output_file   = {}", cfg.output_file);
    info!("  target_prefix = {}", cfg.target_prefix);
    info!("  dnsmasq_config= {}", cfg.dnsmasq_config);
    info!("  dns_process   = {}", cfg.dns_process);
    info!("  debounce      = {}s", cfg.debounce_secs);
    info!("  fallback scan = every {}min", cfg.fallback_mins);

    if !std::path::Path::new(&cfg.dnsmasq_config).exists() {
        error!(
            "CRITICAL: config file {} not found. Aborting.",
            cfg.dnsmasq_config
        );
        std::process::exit(1);
    }

    // -----------------------------------------------------------------------
    // Single netlink connection for the whole daemon lifetime.
    // Subscribe to RTNLGRP_NEIGH (group 3) for unsolicited neighbour events,
    // and keep the Handle for periodic on-demand RTM_GETNEIGH queries.
    // -----------------------------------------------------------------------
    let (mut connection, handle, mut messages) = new_connection()?;

    // RTNLGRP_NEIGH = 3 (Linux kernel constant, stable since 2.6)
    connection.socket_mut().socket_mut().add_membership(3)?;
    tokio::spawn(connection);

    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    let debounce_window = Duration::from_secs(cfg.debounce_secs);
    let mut scan_deadline: Option<Instant> = None;

    // Periodic fallback timer. Consume the first tick so it doesn't fire immediately
    // (we run an initial scan manually right below).
    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    // Initial scan on startup
    info!("Running initial scan...");
    if let Err(e) = run_scan(&cfg, &handle).await {
        error!("Error in initial scan: {:?}", e);
    }

    info!("Listening for neighbour events (SIGUSR1 = manual scan)...");

    loop {
        tokio::select! {
            // ── Netlink neighbour event ──────────────────────────────────
            Some((msg, _)) = messages.next() => {
                if netlink::is_relevant_neigh_event(&msg, &cfg.target_prefix) {
                    if scan_deadline.is_none() {
                        debug!("Neighbour event detected, debouncing {}s...", cfg.debounce_secs);
                    }
                    // Push the deadline forward on every burst event
                    scan_deadline = Some(Instant::now() + debounce_window);
                }
            }

            // ── Debounce timer fires ─────────────────────────────────────
            _ = async {
                match scan_deadline {
                    Some(dl) => sleep_until(dl).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                scan_deadline = None;
                debug!("Debounce window elapsed, running scan...");
                if let Err(e) = run_scan(&cfg, &handle).await {
                    error!("Error in event-triggered scan: {:?}", e);
                }
            }

            // ── Periodic fallback scan ───────────────────────────────────
            _ = fallback.tick() => {
                debug!("Periodic fallback scan...");
                if let Err(e) = run_scan(&cfg, &handle).await {
                    error!("Error in fallback scan: {:?}", e);
                }
            }

            // ── Manual SIGUSR1 ───────────────────────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, running immediate scan...");
                scan_deadline = None;
                if let Err(e) = run_scan(&cfg, &handle).await {
                    error!("Error in manual scan: {:?}", e);
                }
            }
        }
    }
}

/// Wrapper que delegates to slaac::process_cycle with the config fields.
async fn run_scan(cfg: &Config, handle: &rtnetlink::Handle) -> Result<()> {
    slaac::process_cycle(
        &cfg.leases_file,
        &cfg.dnsmasq_config,
        &cfg.target_prefix,
        &cfg.output_file,
        &cfg.dns_process,
        handle,
    )
    .await
}
