mod bus;
mod config;
mod db;
mod dhcp;
mod dns;
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
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio::sync::broadcast::error::RecvError;
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

    info!("🚀 Lanforge starting up...");
    debug!("  target_prefix = {}", cfg.target_prefix);
    debug!("  debounce      = {}s", cfg.debounce_secs);
    debug!("  fallback scan = every {}min", cfg.fallback_mins);
    info!(
        "🔧 Configuration loaded (RA={}, DHCPv4={}, DHCPv6={}, DNS={})",
        cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
    );

    // -----------------------------------------------------------------------
    // DeviceTable — shared state for all services
    // -----------------------------------------------------------------------
    let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);
    let db = match db::LeaseDb::open(&leases_db_path) {
        Ok(d) => {
            info!("📦 Database: {} initialized", cfg.leases_db);
            Arc::new(Mutex::new(d))
        }
        Err(e) => {
            error!("❌ Fatal error opening leases DB: {e:?}");
            return Err(e);
        }
    };

    let mut initial_table = db.lock().unwrap().load_table().unwrap_or_else(|e| {
        warn!("Failed to load previous leases from DB ({e:?}), starting fresh");
        DeviceTable::new()
    });

    // Load static devices from TOML config
    if !cfg.devices.is_empty() {
        let count = cfg.devices.len();
        initial_table.load_static_devices(&cfg.devices);
        info!("👥 Clients: {count} static reservations loaded");
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
        // Envolvendo o Sleep num Pin Box para permitir o .await
        let mut db_debounce: Option<Pin<Box<tokio::time::Sleep>>> = None;
        loop {
            tokio::select! {
                res = db_bus_rx.recv() => match res {
                    Ok(bus::LanforgeEvent::DeviceTableDirty) => {
                        db_debounce = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                },
                _ = async {
                    if let Some(d) = &mut db_debounce {
                        d.await;
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
            "⚡ Starting service: RA (iface={}, M={}, O={})",
            ra_cfg.iface, ra_cfg.managed as u8, ra_cfg.other_config as u8
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
            "⚡ Starting service: DHCPv4 ({}–{}, mask={})",
            dhcp_cfg.range_start, dhcp_cfg.range_end, dhcp_cfg.subnet_mask
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

        info!("⚡ Starting service: DHCPv6 ({})", dhcp_cfg.iface);

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

        info!("⚡ Starting service: DNS");

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
    if let Err(e) = run_scan(&cfg, &handle, &table).await {
        error!("❌ Error in initial scan: {e:?}");
    }

    info!("✅ System is ready. Listening for network events.");

    loop {
        tokio::select! {
            // ── Netlink neighbour event ──────────────────────────────────
            Some((msg, _)) = messages.next() => {
                // 1. Otimização: Alimentar cache NDP em tempo real na sua tabela
                if let Some((ip, mac_bytes)) = netlink::extract_neigh_info(&msg) {
                    let mut t = table.write().await;
                    t.update_ndp_cache(ip, state::MacAddr(mac_bytes));

                    drop(t); // Libera a tabela antes de avisar
                    bus.publish(bus::LanforgeEvent::DeviceTableDirty);
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
                } else {
                bus.publish(bus::LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── Periodic fallback scan ───────────────────────────────────
            _ = fallback.tick() => {
                debug!("Periodic fallback scan...");
                if let Err(e) = run_scan(&cfg, &handle, &table).await {
                    error!("Error in fallback scan: {e:?}");
                } else {
                bus.publish(bus::LanforgeEvent::DeviceTableDirty);
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
                } else {
                bus.publish(bus::LanforgeEvent::DeviceTableDirty);
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
                        debug!("EventBus: DeviceTable dirty");
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
    slaac::process_cycle_v2(&cfg.target_prefix, handle, table).await
}
