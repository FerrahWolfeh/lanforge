mod bus;
mod config;
mod db;
mod dhcp;
mod dns;
mod hosts;
mod netlink;
mod ra;
mod slaac;
mod state;
mod supervisor;

use anyhow::Result;
use bus::EventBus;
use config::Config;
use futures::StreamExt;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use state::DeviceTable;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant, interval, sleep_until};
use tracing::{debug, error, info, warn};

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

    let cfg = Config::load()?;

    info!("Starting lanforge");
    info!("  hosts_file    = {}", cfg.hosts_file);
    info!("  target_prefix = {}", cfg.target_prefix);
    info!("  dns_process   = {}", cfg.dns_process);
    info!("  debounce      = {}s", cfg.debounce_secs);
    info!("  fallback scan = every {}min", cfg.fallback_mins);
    info!("  ra_enabled    = {}", cfg.ra_enabled);
    info!("  dhcpv4_enabled= {}", cfg.dhcpv4_enabled);
    info!("devices       = {} static entries", cfg.devices.len());

    // -----------------------------------------------------------------------
    // DeviceTable — shared state for all services
    // -----------------------------------------------------------------------
    let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);
    let db = match db::LeaseDb::open(&leases_db_path) {
        Ok(d) => Arc::new(Mutex::new(d)),
        Err(e) => {
            error!("[main] Fatal error opening leases DB: {e:?}");
            return Err(e);
        }
    };

    let mut initial_table = db.lock().unwrap().load_table().unwrap_or_else(|e| {
        warn!("Failed to load previous leases from DB ({e:?}), starting fresh");
        DeviceTable::new()
    });

    // Load static devices from TOML config
    if !cfg.devices.is_empty() {
        info!("Loading static devices from config:");
        initial_table.load_static_devices(&cfg.devices);
    }

    let table = Arc::new(RwLock::new(initial_table));

    // -----------------------------------------------------------------------
    // EventBus — shared between all services
    // -----------------------------------------------------------------------
    let bus = Arc::new(EventBus::new());

    // -----------------------------------------------------------------------
    // DB Writer Task
    // -----------------------------------------------------------------------
    let mut db_bus_rx = bus.subscribe();
    let db_table = table.clone();
    let db_worker_db = db.clone();
    tokio::spawn(async move {
        // Debounce window to avoid thrashing SD card on high traffic
        let mut db_debounce = None;
        loop {
            tokio::select! {
                res = db_bus_rx.recv() => match res {
                    Ok(bus::LanforgeEvent::DeviceTableDirty) => {
                        db_debounce = Some(tokio::time::sleep(Duration::from_secs(5)));
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = async {
                    #[allow(path_statements)]
                    if let Some(d) = &mut db_debounce {
                        d;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if db_debounce.is_some() => {
                    db_debounce = None;
                    let snapshot = db_table.read().await.clone();
                    let db_cl = db_worker_db.clone();
                    match tokio::task::spawn_blocking(move || {
                        if let Ok(guard) = db_cl.lock() {
                            guard.save_table(&snapshot)
                        } else {
                            Err(anyhow::anyhow!("Mutex poisoned"))
                        }
                    }).await {
                        Ok(Err(e)) => error!("Failure saving leases: {e:?}"),
                        Err(e) => error!("SQLite worker panicked: {e:?}"),
                        _ => {}
                    }
                }
            }
        }
    });

    // -----------------------------------------------------------------------
    // Netlink connection
    // -----------------------------------------------------------------------
    let (mut connection, handle, mut messages) = new_connection()?;
    connection.socket_mut().socket_mut().add_membership(3)?;
    tokio::spawn(connection);

    // -----------------------------------------------------------------------
    // Spawn RA service (if enabled) via supervisor
    // -----------------------------------------------------------------------
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();
        let ra_bus = bus.clone();

        info!(
            "RA service enabled: iface={}, M={}, O={}, MaxInterval={}s",
            ra_cfg.iface,
            ra_cfg.managed as u8,
            ra_cfg.other_config as u8,
            ra_cfg.max_interval.as_secs(),
        );

        tokio::spawn(supervisor::supervise_task(
            "ra",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = ra_cfg.clone();
                let bus = ra_bus.clone();
                async move { ra::ra_service(cfg, bus).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // Spawn DHCPv4 service (if enabled) via supervisor
    // -----------------------------------------------------------------------
    if cfg.dhcpv4_enabled {
        let dhcp_cfg = cfg.to_dhcpv4_config();
        let dhcp_bus = bus.clone();
        let dhcp_table = table.clone();

        info!(
            "DHCPv4 service enabled: range {}–{}, lease {}s",
            dhcp_cfg.range_start, dhcp_cfg.range_end, dhcp_cfg.lease_time,
        );

        tokio::spawn(supervisor::supervise_task(
            "dhcpv4",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = dhcp_cfg.clone();
                let bus = dhcp_bus.clone();
                let table = dhcp_table.clone();
                async move { dhcp::v4::dhcpv4_service(cfg, bus, table).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // Spawn DHCPv6 service (if enabled) via supervisor
    // -----------------------------------------------------------------------
    if cfg.dhcpv6_enabled {
        let dhcp_cfg = cfg.to_dhcpv6_config();
        let dhcp_bus = bus.clone();
        let dhcp_table = table.clone();
        let dhcp_handle = handle.clone();

        info!(
            "DHCPv6 service enabled on {}, lease {}s",
            dhcp_cfg.iface, dhcp_cfg.lease_time,
        );

        tokio::spawn(supervisor::supervise_task(
            "dhcpv6",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let handle = dhcp_handle.clone();
                let cfg = dhcp_cfg.clone();
                let bus = dhcp_bus.clone();
                let table = dhcp_table.clone();
                async move { dhcp::v6::dhcpv6_service(cfg, table, bus, &handle).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // Spawn DNS service (if enabled) via supervisor
    // -----------------------------------------------------------------------
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();
        let dns_table = table.clone();
        tokio::spawn(supervisor::supervise_task(
            "dns",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = dns_cfg.clone();
                let table = dns_table.clone();
                async move { dns::dns_service(cfg, table).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // EventBus consumer
    // -----------------------------------------------------------------------
    let mut bus_rx = bus.subscribe();

    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    let debounce_window = Duration::from_secs(cfg.debounce_secs);
    let mut scan_deadline: Option<Instant> = None;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600)); // 10 minutes
    stale_timer.tick().await;

    // Initial scan on startup
    info!("Running initial scan...");
    if let Err(e) = run_scan(&cfg, &handle, &table).await {
        error!("Error in initial scan: {e:?}");
    }

    info!("Listening for neighbour events (SIGUSR1 = manual scan)...");

    loop {
        tokio::select! {
            // ── Netlink neighbour event ──────────────────────────────────
            Some((msg, _)) = messages.next() => {
                // 1. Otimização: Alimentar cache NDP em tempo real na sua tabela
                if let Some((ip, mac_bytes)) = netlink::extract_neigh_info(&msg) {
                    let mut t = table.write().await;
                    // Implemente este método no DeviceTable (ou crie um HashMap separado no state.rs)
                    t.update_ndp_cache(ip, state::MacAddr(mac_bytes));
                }

                // 2. Lógica original para acionar o SLAAC scan
                if netlink::is_relevant_neigh_event(&msg, &cfg.target_prefix) {
                    if scan_deadline.is_none() {
                        debug!("Neighbour event detected, debouncing {}s...", cfg.debounce_secs);
                    }
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
                if let Err(e) = run_scan(&cfg, &handle, &table).await {
                    error!("Error in event-triggered scan: {e:?}");
                }
            }

            // ── Periodic fallback scan ───────────────────────────────────
            _ = fallback.tick() => {
                debug!("Periodic fallback scan...");
                if let Err(e) = run_scan(&cfg, &handle, &table).await {
                    error!("Error in fallback scan: {e:?}");
                }
            }

            // ── Periodic stale lease expiration ──────────────────────────
            _ = stale_timer.tick() => {
                let mut t = table.write().await;
                if t.expire_stale() {
                    drop(t); // avoid holding lock during publish
                    bus.publish(bus::LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── Manual SIGUSR1 ───────────────────────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, running immediate scan...");
                scan_deadline = None;
                if let Err(e) = run_scan(&cfg, &handle, &table).await {
                    error!("Error in manual scan: {e:?}");
                }
            }

            // ── EventBus events ──────────────────────────────────────────
            event = bus_rx.recv() => {
                match event {
                    Ok(bus::LanforgeEvent::PrefixChanged { gua }) => {
                        info!("EventBus: GUA prefix changed to {gua:?}, triggering scan");
                        if let Err(e) = run_scan(&cfg, &handle, &table).await {
                            error!("Error in prefix-change scan: {e:?}");
                        }
                    }
                    Ok(bus::LanforgeEvent::DeviceTableDirty) => {
                        debug!("EventBus: DeviceTable dirty, regenerating hosts file");
                        let t = table.read().await;
                        if let Ok(true) = hosts::write_hosts_from_table(&t, &cfg.hosts_file) {
                            drop(t);
                            hosts::reload_dns(&cfg.dns_process).await;
                        }
                    }
                    Ok(event) => {
                        debug!("EventBus: {event:?}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("EventBus: consumer lagged, missed {n} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        error!("EventBus: channel closed unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Scan using DeviceTable v2 path.
async fn run_scan(
    cfg: &Config,
    handle: &rtnetlink::Handle,
    table: &Arc<RwLock<DeviceTable>>,
) -> Result<()> {
    slaac::process_cycle_v2(
        &cfg.target_prefix,
        &cfg.hosts_file,
        &cfg.dns_process,
        handle,
        table,
    )
    .await
}
