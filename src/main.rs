//! `lanforge` — Gerenciador central de identidades de rede (IPv6/IPv4).
//!
//! Este daemon coordena o estado dos dispositivos na rede local integrando
//! múltiplos protocolos (`DHCPv4`, `DHCPv6`, RA, SLAAC, DNS).
//!
//! ## Ciclo de Vida e Bootstrap
//!
//! ```text
//!    [ Bootstrap ]             [ Event Loop ]             [ Shutdown ]
//!          │                         │                         │
//!  1. Load Config (TOML)             │                         │
//!          │           ┌─────────────┼─────────────┐           │
//!  2. Init EventBus    │             ▼             │           │
//!          │           │     Eventos Netlink       │      1. SIGTERM
//!  3. Load State (DB)  │             │             │           │
//!          │           │             ▼             │      2. Publish
//!  4. Load Statics     │      Update ManagedTable  │         Shutdown
//!          │           │             │             │           │
//!  5. Spawn Workers ───┼──────────►  │ ────────────┼───►  3. DB Flush
//!     (DHCP, DNS, RA,  │             ▼             │           │
//!      DB, Control)    │      Publish EventBus     │      4. Exit
//!          │           │             │             │
//!          │           │      Consumers React      │
//!          ▼           └─────────────┬─────────────┘
//!    Ready State                     │
//! ```
//!
//! ## Componentes Principais
//!
//! - **`ManagedTable`**: Autoridade central de estado (Thread-safe).
//! - **`EventBus`**: Barramento de eventos reativo asincrono.
//! - **Supervisores**: Garantem que tasks de protocolo continuem rodando após erros.

mod config;
mod supervisor;
mod threads;

use crate::config::load_devices_only;
use crate::threads::{spawn_service_thread, wait_for_service_threads};

use anyhow::Result;
use config::Config;
use futures::StreamExt;
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::DeviceUpdate;
use lanforge_db::engine::LeaseDb;
use lanforge_db::worker::db_worker;
use lanforge_dns::dns_service;
use lanforge_network::dhcp::v4::dhcpv4_service;
use lanforge_network::dhcp::v6::dhcpv6_service;
use lanforge_network::mdns::MdnsProber;
use lanforge_network::netlink::extract_neigh_info;
use lanforge_network::ra::ra_service;
use lanforge_network::slaac::bootstrap_table;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, interval};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use lanforge_db::worker::DbWorkerCmd;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// DEPOIS: main síncrona + runtime current_thread + função async separada
fn main() -> Result<()> {
    let res = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("lanforge-main")
        .build()?
        .block_on(async_main());

    // Forçamos a saída imediata para evitar hangs em destrutores globais
    // ou runtimes que se recusam a morrer após o "Lanforge encerrado".
    if let Err(e) = res {
        eprintln!("❌ Erro fatal: {e:#}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Ponto de entrada principal do daemon.
///
/// Configura o logging, carrega a configuração TOML, inicia o banco de dados
/// `SQLite` e dispara os serviços de rede (RA, DHCP, DNS, Control) como tasks do Tokio.
async fn async_main() -> Result<()> {
    #[cfg(feature = "debug-commands")]
    let mut cfg = Config::load();

    #[cfg(not(feature = "debug-commands"))]
    let cfg = Config::load();

    #[cfg(feature = "debug-commands")]
    if let config::Command::Run { only: Some(s) } = &cfg.command {
        let modules: Vec<&str> = s.split(',').collect();
        cfg.ra_enabled = modules.contains(&"ra");
        cfg.dhcpv4_enabled = modules.contains(&"dhcpv4") || modules.contains(&"dhcp");
        cfg.dhcpv6_enabled = modules.contains(&"dhcpv6") || modules.contains(&"dhcp");
        cfg.dns_enabled = modules.contains(&"dns");
        info!("🎯 Running ONLY (Debug Mode): {:?}", modules);
    }

    let cfg = Arc::new(cfg);

    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("🚀 Lanforge starting up...");
    debug!("  target_prefix = {}", cfg.target_prefix);
    debug!("  debounce      = {}s", cfg.debounce_secs);
    debug!("  fallback scan = every {}min", cfg.fallback_mins);
    info!(
        "🔧 Configuration loaded (RA={}, DHCPv4={}, DHCPv6={}, DNS={})",
        cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
    );

    // -----------------------------------------------------------------------
    // EventBus — instanciado antes de tudo para que o ManagedTable possa
    // publicar durante o bootstrap
    // -----------------------------------------------------------------------
    let bus = Arc::new(EventBus::new());

    // -----------------------------------------------------------------------
    // ManagedTable — autoridade central de estado
    //
    // Sequência de bootstrap:
    //   1. Carrega estado persistido do SQLite (apply_update, respeita invariantes)
    //   2. Aplica entradas estáticas do TOML (têm precedência sobre o DB)
    //   3. Cria ManagedTable encapsulando a tabela inicial completa
    // -----------------------------------------------------------------------
    let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);

    // 1. Criamos a tabela inicial direto na stack da thread principal (Lock-free)
    let mut initial_table = match LeaseDb::open(&leases_db_path) {
        Ok(db) => match db.load_table() {
            Ok(persisted) => {
                info!("📦 Estado persistido carregado de {}", cfg.leases_db);
                persisted
            }
            Err(e) => {
                warn!("Falha ao carregar DB ({e}), iniciando do zero");
                DeviceTable::new()
            }
        },
        Err(e) => {
            error!("❌ Erro fatal abrindo leases DB: {e}");
            return Err(e.into());
        }
    };

    // 2. Lemos o TOML (StaticDeviceCfg) e populamos a tabela AQUI no main
    let mut all_static_devices = cfg.devices.clone();

    // 2b. Carrega devices extras de arquivo externo (CLI override)
    if let Some(ref extra_path) = cfg.devices_file {
        info!("📂 Carregando devices adicionais de {extra_path}");
        let mut extra = load_devices_only(extra_path);
        all_static_devices.append(&mut extra);
    }

    if !all_static_devices.is_empty() {
        let count = all_static_devices.len();

        for e in &all_static_devices {
            // Parsing das strings sujas
            let Some(mac) = MacAddr::parse(&e.mac) else {
                warn!("Invalid MAC in config: '{}', skipping", e.mac);
                continue;
            };

            let v4_ip = e.v4_ip.as_ref().and_then(|s| {
                s.parse::<std::net::Ipv4Addr>().ok().or_else(|| {
                    warn!("Invalid v4_ip for {}: '{s}'", e.hostname);
                    None
                })
            });

            let v6_suffix = e.v6_suffix.as_ref().and_then(|s| {
                Ipv6AddrOrSuffix::parse(s).or_else(|| {
                    warn!("Invalid v6_suffix for {}: '{s}'", e.hostname);
                    None
                })
            });

            initial_table.add_static_device(mac, e.hostname.clone(), v4_ip, v6_suffix);
        }

        info!("👥 {count} reservas estáticas carregadas (TOML + Overrides)");
    }

    // 3. Montamos os índices O(1) do DNS apenas UMA vez após tudo ser carregado
    initial_table.apply_update(DeviceUpdate::RebuildDnsIndices);

    // 4. Transformamos em ManagedTable reativa (Arc<RwLock<DeviceTable>>)
    let table = Arc::new(ManagedTable::from_table(bus.clone(), initial_table));

    // TaskTracker não é necessário — cada serviço vira uma thread
    let cancel = CancellationToken::new();
    let mut service_threads: Vec<(&'static str, std::thread::JoinHandle<()>)> = Vec::new();

    // -----------------------------------------------------------------------
    // Sync Bridges & Service Channels
    // -----------------------------------------------------------------------
    let (db_tx, db_rx) = std::sync::mpsc::channel::<DbWorkerCmd>();
    let (ra_tx, ra_rx) = std::sync::mpsc::channel::<LanforgeEvent>();
    let (d4_tx, d4_rx) = std::sync::mpsc::channel::<LanforgeEvent>();
    let (d6_tx, d6_rx) = std::sync::mpsc::channel::<LanforgeEvent>();

    // Bridge task: forward EventBus to sync mpsc channels
    let mut bridge_sub = bus.subscribe();
    let bridge_table = table.clone();
    let db_tx_bridge = db_tx.clone();
    let ra_tx_bridge = ra_tx.clone();
    let d4_tx_bridge = d4_tx.clone();
    let d6_tx_bridge = d6_tx.clone();

    tokio::spawn(async move {
        while let Ok(event) = bridge_sub.recv().await {
            // Forward relevant signals to protocols
            let _ = ra_tx_bridge.send(event.clone());
            let _ = d4_tx_bridge.send(event.clone());
            let _ = d6_tx_bridge.send(event.clone());

            // Process DB commands based on events
            match event {
                LanforgeEvent::DeviceTableDirty => {
                    let snapshot = bridge_table.read().clone();
                    let _ = db_tx_bridge.send(DbWorkerCmd::Save(Box::new(snapshot)));
                }
                LanforgeEvent::DbVacuum => {
                    let _ = db_tx_bridge.send(DbWorkerCmd::Vacuum);
                }
                LanforgeEvent::Shutdown => {
                    let _ = db_tx_bridge.send(DbWorkerCmd::Shutdown);
                    break;
                }
                other => {
                    // All other events are recorded in the log DB
                    let _ = db_tx_bridge.send(DbWorkerCmd::RecordLog(other));
                }
            }
        }
    });

    // -----------------------------------------------------------------------
    // DB worker — sync OS thread
    // -----------------------------------------------------------------------
    {
        let leases_db_path = leases_db_path.clone();
        let log_db = cfg.log_db.clone();
        service_threads.push((
            "DB",
            crate::threads::spawn_sync_service_thread("DB Worker", 768, move || {
                db_worker(leases_db_path, log_db.into(), db_rx);
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // mDNS Prober — descoberta ativa e passiva de hostnames
    // -----------------------------------------------------------------------
    let prober = Arc::new(MdnsProber::new(bus.clone(), table.clone()));

    // -----------------------------------------------------------------------
    // Netlink connection
    // -----------------------------------------------------------------------
    let (mut connection, handle, mut messages) = new_connection()?;
    connection.socket_mut().socket_mut().add_membership(3)?;
    let netlink_task = tokio::spawn(connection);

    // -----------------------------------------------------------------------
    // RA service — sync OS thread
    // -----------------------------------------------------------------------
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();
        let ra_bus = bus.clone();
        let ra_handle = handle.clone();

        service_threads.push((
            "ra",
            crate::threads::spawn_sync_service_thread("RA", 256, move || {
                if let Err(e) = ra_service(ra_cfg, ra_bus, ra_rx, ra_handle) {
                    error!("RA service failed: {e}");
                }
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv4 service — sync OS thread
    // -----------------------------------------------------------------------
    if cfg.dhcpv4_enabled {
        let dhcp_cfg = cfg.to_dhcpv4_config();
        let dhcp_table = table.clone();

        service_threads.push((
            "dhcpv4",
            crate::threads::spawn_sync_service_thread("DHCPv4 Server", 384, move || {
                if let Err(e) = dhcpv4_service(dhcp_cfg, dhcp_table, d4_rx) {
                    error!("DHCPv4 service failed: {e}");
                }
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv6 service — sync OS thread
    // -----------------------------------------------------------------------
    if cfg.dhcpv6_enabled {
        let dhcp_cfg = cfg.to_dhcpv6_config();
        let dhcp_table = table.clone();
        let dhcp_handle = handle.clone();

        service_threads.push((
            "dhcpv6",
            crate::threads::spawn_sync_service_thread("DHCPv6 Server", 384, move || {
                if let Err(e) = dhcpv6_service(dhcp_cfg, dhcp_table, &dhcp_handle, d6_rx) {
                    error!("DHCPv6 service failed: {e}");
                }
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // DNS service
    // -----------------------------------------------------------------------
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();
        let dns_table = table.clone();
        let dns_cancel = cancel.clone();

        service_threads.push((
            "dns",
            spawn_service_thread("DNS Server", 384, move || async move {
                supervisor::supervise_task(
                    "dns",
                    true,
                    0,
                    Duration::from_secs(5),
                    Duration::from_secs(60),
                    dns_cancel,
                    move || {
                        let cfg = dns_cfg.clone();
                        let table = dns_table.clone();
                        async move { dns_service(cfg, table).await.map_err(anyhow::Error::from) }
                    },
                )
                .await
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // Control service (UDS) — Interface de controle via JSON-RPC
    // -----------------------------------------------------------------------
    let ctrl_table = table.clone();
    let ctrl_bus = bus.clone();
    let api_cfg = Arc::new(cfg.to_api_config());
    let api_cfg_ctrl = api_cfg.clone();
    let api_cfg_http = api_cfg.clone();
    let ctrl_cancel = cancel.clone();

    service_threads.push((
        "control",
        spawn_service_thread("Control Service", 256, move || async move {
            supervisor::supervise_task(
                "control",
                true,
                0,
                Duration::from_secs(2),
                Duration::from_secs(30),
                ctrl_cancel,
                move || {
                    let table = ctrl_table.clone();
                    let bus = ctrl_bus.clone();
                    let cfg = api_cfg_ctrl.clone();
                    async move {
                        lanforge_api::server::control_service(table, bus, cfg)
                            .await
                            .map_err(anyhow::Error::from)
                    }
                },
            )
            .await
        }),
    ));

    // -----------------------------------------------------------------------
    // HTTP API responder — Axum service
    // -----------------------------------------------------------------------
    if cfg.http_listen.is_some() {
        let http_table = table.clone();
        let http_api_cfg = api_cfg_http.clone();
        let http_cancel = cancel.clone();

        service_threads.push((
            "http",
            spawn_service_thread("http", 1536, move || async move {
                supervisor::supervise_task(
                    "http",
                    true,
                    0,
                    Duration::from_secs(2),
                    Duration::from_secs(30),
                    http_cancel,
                    move || {
                        let table = http_table.clone();
                        let cfg = http_api_cfg.clone();
                        async move {
                            lanforge_api::http::http_service(table, cfg)
                                .await
                                .map_err(anyhow::Error::from)
                        }
                    },
                )
                .await
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // Prefixo GUA — aprendido dinamicamente via PrefixChanged do RA.
    // Começa como None; é atualizado no handler do EventBus abaixo.
    // Passado para o scan SLAAC para distinguir SlaacObserved de NdpSeen.
    // -----------------------------------------------------------------------
    let mut current_gua: Option<std::net::Ipv6Addr> = None;

    // -----------------------------------------------------------------------
    // Loop principal — eventos Netlink, timers, sinais
    // -----------------------------------------------------------------------
    let mut bus_rx = bus.subscribe();
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600));
    stale_timer.tick().await;

    // Scan inicial (sem GUA ainda — RA ainda não anunciou)
    if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
        error!("❌ Erro no scan inicial: {e:#}");
    }

    info!("✅ Sistema pronto. Escutando eventos de rede.");

    loop {
        tokio::select! {
            // ── Netlink — Eventos Reativos (Delta) ───────────────────────
            Some((msg, _)) = messages.next() => {
                // Alimenta o Manager APENAS com o IP/MAC reportado pelo kernel no momento.
                // Zero overhead de varredura completa. CPU agradece.
                if let Some(event) = extract_neigh_info(&msg) {
                    let update = event.to_device_update(current_gua.as_ref());

                    // Trigger passive mDNS probe for new/named-less devices
                    match update {
                        DeviceUpdate::NdpSeen { mac, ip } => {
                            let table_read = table.read();
                            if let Some(dev) = table_read.get_device(&mac)
                                && dev.hostname.name.is_empty() {
                                    let p = prober.clone();
                                    tokio::spawn(async move { p.probe_ip(ip.into()).await });
                                }
                        }
                        DeviceUpdate::ArpSeen { mac, ip } => {
                            let table_read = table.read();
                            if let Some(dev) = table_read.get_device(&mac)
                                && dev.hostname.name.is_empty() {
                                    let p = prober.clone();
                                    tokio::spawn(async move { p.probe_ip(ip.into()).await });
                                }
                        }
                        _ => {}
                    }

                    let _ = table.update(update);
                }
            }

            // ── Fallback — Garantia de Consistência ──────────────────────
            _ = fallback.tick() => {
                debug!("Sincronização periódica de SLAAC (Fallback)...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro no fallback: {e:#}");
                }
            }

            // ── Stale — Expiração de leases e IPs antigos ────────────────
            _ = stale_timer.tick() => {
                let changed = table.write().expire_stale();
                if changed {
                    let _ = bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── SIGUSR1 — Sincronização manual ───────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, forçando sincronização de estado...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro na sincronização manual: {e:#}");
                }
            }

            // ── SIGINT/SIGTERM — Shutdown gracioso ──────────────────────
            _ = sigterm.recv() => {
                info!("SIGTERM recebido — iniciando encerramento gracioso...");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT recebido — iniciando encerramento gracioso...");
                break;
            }

            // ── EventBus — Eventos internos ──────────────────────────────
            event = bus_rx.recv() => {
                match event {
                    Ok(LanforgeEvent::PrefixChanged { gua, .. }) => {
                        if current_gua != gua {
                            info!("Prefixo GUA alterado: {:?} → {:?}", current_gua, gua);
                            current_gua = gua;
                        }
                        // Novo prefixo exige repopular o estado do zero
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                            error!("Erro ao atualizar prefixo: {e:#}");
                        }
                    }
                    Ok(LanforgeEvent::DeviceDiscovered { mac }) => {
                        debug!("Novo device descoberto: {mac}");
                    }
                    Ok(LanforgeEvent::DeviceExpired { mac }) => {
                        debug!("Device expirado: {mac}");
                    }
                    Ok(LanforgeEvent::ReloadConfig) => {
                        info!("ReloadConfig: Forçando sincronização via sinalizador manual!");
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                            error!("Erro no reload: {e:#}");
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("EventBus: consumer atrasado, perdeu {n} eventos");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        error!("EventBus: canal fechado inesperadamente");
                        break;
                    }
                }
            }
        }
    }

    info!("🛑 Iniciando sequência de shutdown...");
    let _ = bus.publish(LanforgeEvent::Shutdown);
    cancel.cancel();
    netlink_task.abort();

    // O wait é bloqueante mas estamos fora do hot path — o runtime main
    // pode ficar idle enquanto as threads de serviço terminam.
    wait_for_service_threads(service_threads, Duration::from_secs(5));

    info!("👋 Lanforge encerrado.");
    Ok(())
}

/// Executa um ciclo de scan SLAAC via netlink.
///
/// Este helper centraliza a chamada ao módulo `slaac` para descobrir
/// endereços IPv6 ativos (GUA e link-local) no segmento de rede.
async fn run_scan(
    cfg: &Config,
    handle: &rtnetlink::Handle,
    table: &Arc<ManagedTable>,
    gua: Option<Ipv6Addr>,
) -> Result<()> {
    bootstrap_table(&cfg.target_prefix, handle, table, gua)
        .await
        .map_err(anyhow::Error::from)
}
