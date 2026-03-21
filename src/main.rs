//! `lanforge` — Gerenciador central de identidades de rede (IPv6/IPv4).
//!
//! Este daemon coordena o estado dos dispositivos na rede local integrando
//! múltiplos protocolos (DHCPv4, DHCPv6, RA, SLAAC, DNS).
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
//! - **ManagedTable**: Autoridade central de estado (Thread-safe).
//! - **EventBus**: Barramento de eventos reativo asincrono.
//! - **Supervisores**: Garantem que tasks de protocolo continuem rodando após erros.

#[warn(clippy::all, clippy::pedantic, clippy::nursery)]
mod bus;
mod cli;
mod config;
mod control;
mod db;
mod dhcp;
mod dns;
mod netlink;
mod ra;
mod slaac;
mod state;
mod supervisor;

use anyhow::Result;
use bus::{EventBus, LanforgeEvent, ManagedTable};
use config::Config;
use futures::StreamExt;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, Instant, interval, sleep_until};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Ponto de entrada principal do daemon.
///
/// Configura o logging, carrega a configuração TOML, inicia o banco de dados
/// SQLite e dispara os serviços de rede (RA, DHCP, DNS, Control) como tasks do Tokio.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut cfg = Config::load()?;

    // Se for comando cliente (Devices, Status, Reload), executa e sai sem subir o daemon (nem env filter/logging)
    match &cfg.command {
        config::Command::Devices { .. }
        | config::Command::Status
        | config::Command::Reload
        | config::Command::Watch
        | config::Command::Log { .. }
        | config::Command::Lease { .. }
        | config::Command::Scan
        | config::Command::Host { .. }
        | config::Command::Db { .. }
        | config::Command::Shutdown => {
            return cli::run_client(cfg.command.clone(), &cfg.control_socket).await;
        }
        config::Command::Run { only: Some(s) } => {
            cfg.ra_enabled = s == "ra";
            cfg.dhcpv4_enabled = s == "dhcpv4" || s == "dhcp";
            cfg.dhcpv6_enabled = s == "dhcpv6" || s == "dhcp";
            cfg.dns_enabled = s == "dns";
        }
        config::Command::Run { only: None } => {}
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
    //   1. Cria ManagedTable vazia
    //   2. Carrega estado persistido do SQLite (apply_update, respeita invariantes)
    //   3. Aplica entradas estáticas do TOML (têm precedência sobre o DB)
    // -----------------------------------------------------------------------
    let table = Arc::new(ManagedTable::new(bus.clone()));

    let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);

    match db::LeaseDb::open(&leases_db_path) {
        Ok(db) => {
            match db.load_table() {
                Ok(persisted) => {
                    // Importa o estado persistido diretamente na tabela interna.
                    // Fazemos isso via write() direto pois é bootstrap síncrono
                    // — os serviços ainda não estão rodando.
                    *table.write().await = persisted;
                    info!("📦 Estado persistido carregado de {}", cfg.leases_db);
                }
                Err(e) => {
                    warn!("Falha ao carregar DB ({e:#}), iniciando do zero");
                }
            }
        }
        Err(e) => {
            error!("❌ Erro fatal abrindo leases DB: {e:#}");
            return Err(e);
        }
    }

    if !cfg.devices.is_empty() {
        let count = cfg.devices.len();
        table.write().await.load_static_devices(&cfg.devices);
        info!("👥 {count} reservas estáticas carregadas");
    }

    // -----------------------------------------------------------------------
    // DB worker — persiste reativamente via EventBus
    // -----------------------------------------------------------------------
    tokio::spawn(db::db_worker(leases_db_path, table.clone(), bus.clone()));

    // -----------------------------------------------------------------------
    // Netlink connection
    // -----------------------------------------------------------------------
    let (mut connection, handle, mut messages) = new_connection()?;
    connection.socket_mut().socket_mut().add_membership(3)?;
    tokio::spawn(connection);

    // -----------------------------------------------------------------------
    // RA service
    // -----------------------------------------------------------------------
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();
        let ra_bus = bus.clone();

        info!(
            "⚡ Iniciando: RA (iface={}, M={}, O={})",
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
    // DHCPv4 service
    // -----------------------------------------------------------------------
    if cfg.dhcpv4_enabled {
        let dhcp_cfg = cfg.to_dhcpv4_config();
        let dhcp_table = table.clone();

        info!(
            "⚡ Iniciando: DHCPv4 ({}–{}, mask={})",
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
                let table = dhcp_table.clone();
                async move { dhcp::v4::dhcpv4_service(cfg, table).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv6 service
    // -----------------------------------------------------------------------
    if cfg.dhcpv6_enabled {
        let dhcp_cfg = cfg.to_dhcpv6_config();
        let dhcp_table = table.clone();
        let dhcp_handle = handle.clone();

        info!("⚡ Iniciando: DHCPv6 ({})", dhcp_cfg.iface);

        tokio::spawn(supervisor::supervise_task(
            "dhcpv6",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let handle = dhcp_handle.clone();
                let cfg = dhcp_cfg.clone();
                let table = dhcp_table.clone();
                async move { dhcp::v6::dhcpv6_service(cfg, table, &handle).await }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // DNS service
    // -----------------------------------------------------------------------
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();
        let dns_table = table.clone();

        info!("⚡ Iniciando: DNS");

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
    // Control service (UDS)
    // -----------------------------------------------------------------------
    let ctrl_path = cfg.control_socket.clone();
    let ctrl_table = table.clone();
    let ctrl_bus = bus.clone();
    let ctrl_ifaces = control::Interfaces {
        lan: cfg.iface_lan.clone(),
    };
    let ctrl_cfg = cfg.clone();

    tokio::spawn(supervisor::supervise_task(
        "control",
        true,
        0,
        Duration::from_secs(2),
        Duration::from_secs(30),
        move || {
            let path = ctrl_path.clone();
            let table = ctrl_table.clone();
            let bus = ctrl_bus.clone();
            let ifaces = ctrl_ifaces.clone();
            let cfg_srv = ctrl_cfg.clone();
            async move { control::control_service(path, ifaces, table, bus, cfg_srv).await }
        },
    ));

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

    let debounce_window = Duration::from_secs(cfg.debounce_secs);
    let mut scan_deadline: Option<Instant> = None;

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
            // ── Netlink — eventos de vizinhos ────────────────────────────
            Some((msg, _)) = messages.next() => {
                // Alimenta o Manager com o que o kernel aprendeu
                if let Some(event) = netlink::extract_neigh_info(&msg) {
                    let update = event.to_device_update(current_gua.as_ref());
                    table.update(update).await;
                }

                // Aciona o scan de SLAAC se o evento for relevante para o prefixo
                if netlink::is_relevant_neigh_event(&msg, &cfg.target_prefix) {
                    if scan_deadline.is_none() {
                        debug!("Evento de vizinho detectado, debouncing {}s...", cfg.debounce_secs);
                    }
                    scan_deadline = Some(Instant::now() + debounce_window);
                }
            }

            // ── Debounce — scan pós-evento ───────────────────────────────
            _ = async {
                match scan_deadline {
                    Some(dl) => sleep_until(dl).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                scan_deadline = None;
                debug!("Janela de debounce encerrada, executando scan...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro no scan pós-evento: {e:#}");
                }
            }

            // ── Fallback — scan periódico ────────────────────────────────
            _ = fallback.tick() => {
                debug!("Scan periódico de fallback...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro no scan periódico: {e:#}");
                }
            }

            // ── Stale — expiração de leases ──────────────────────────────
            _ = stale_timer.tick() => {
                let changed = table.write().await.expire_stale();
                if changed {
                    bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── SIGUSR1 — scan manual ────────────────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, executando scan imediato...");
                scan_deadline = None;
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro no scan manual: {e:#}");
                }
            }

            // ── SIGTERM — shutdown gracioso ──────────────────────────────
            _ = sigterm.recv() => {
                info!("SIGTERM recebido — encerrando...");
                bus.publish(LanforgeEvent::Shutdown);
                // Dá tempo ao db_worker de fazer flush
                tokio::time::sleep(Duration::from_secs(2)).await;
                break;
            }

            // ── EventBus — eventos internos ──────────────────────────────
            event = bus_rx.recv() => {
                match event {
                    Ok(LanforgeEvent::PrefixChanged { gua }) => {
                        // Atualiza o GUA local — usado nos próximos scans
                        if current_gua != gua {
                            info!("Prefixo GUA alterado: {:?} → {:?}", current_gua, gua);
                            current_gua = gua;
                        }
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                            error!("Erro no scan por mudança de prefixo: {e:#}");
                        }
                    }
                    Ok(LanforgeEvent::DeviceDiscovered { mac }) => {
                        debug!("Novo device descoberto: {mac}");
                    }
                    Ok(LanforgeEvent::DeviceExpired { mac }) => {
                        debug!("Device expirado: {mac}");
                    }
                    Ok(LanforgeEvent::ReloadConfig) => {
                        info!("Recarregando config / Forçando scan via sinalizador manual!");
                        scan_deadline = None;
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                            error!("Erro no scan por reload: {e:#}");
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
    gua: Option<std::net::Ipv6Addr>,
) -> Result<()> {
    slaac::process_cycle_v2(&cfg.target_prefix, handle, table, gua).await
}
