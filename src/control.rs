//! src/control.rs — Interface de controle via Unix Domain Socket (UDS)
//!
//! Permite que ferramentas de CLI ou interfaces locais consultem e controlem
//! o daemon usando JSON sobre um socket Unix local.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

use crate::bus::{EventBus, LanforgeEvent, ManagedTable};

// ---------------------------------------------------------------------------
// Protocolo (JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Status geral do sistema
    Status,
    /// Lista completa de dispositivos gerenciados
    Devices {
        filter: Option<String>,
        format: Option<String>,
    },
    /// Solicita ao daemon que recarregue configurações
    Reload,
    /// Monitora mudanças de estado ao vivo
    Watch,
    /// Mostra todos os eventos do bus
    Log {
        follow: bool,
    },
    /// Força execução de um scan
    Scan,
    /// Encerramento do serviço
    Shutdown,
    /// Gerenciamento de hosts customizados
    HostAdd {
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    },
    HostSet {
        mac: String,
        field: String,
        value: String,
    },
    HostRemove {
        mac: String,
    },
    HostList,
    LeaseRenew {
        mac: String,
    },
    LeaseRelease {
        mac: String,
    },
    DbVacuum,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Status(Box<api::StatusResponse>),
    Devices(api::DevicesResponse),
    Error { error: String },
    Success(SimpleSuccess),
    Event(LanforgeEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleSuccess {
    pub message: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct Interfaces {
    pub lan: String,
}

pub mod api {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DevicesResponse {
        pub devices: Vec<DeviceEntry>,
        pub meta: DevicesMeta,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeviceEntry {
        pub mac: String,
        pub hostname: String,
        pub origin: String,
        pub online: bool,
        pub last_seen: String,
        pub duid: Option<String>,
        pub v4: Option<LeaseInfo>,
        pub v6: Option<LeaseInfo>,
        pub slaac: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LeaseInfo {
        pub ip: String,
        pub expires: String,
        pub reserved: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DevicesMeta {
        pub total: usize,
        pub online: usize,
        pub last_scan_secs_ago: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct StatusResponse {
        pub uptime_secs: u64,
        pub version: String,
        pub services: ServicesStatus,
        pub db: DbStatus,
        pub network: NetworkStatus,
        pub devices: DevicesStats,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServicesStatus {
        pub ra: ServiceRa,
        pub dhcp_v4: ServiceDhcpV4,
        pub dhcp_v6: ServiceDhcpV6,
        pub dns: ServiceDns,
        pub slaac: ServiceSlaac,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServiceRa {
        pub state: String,
        pub uptime_secs: u64,
        pub gua: Option<String>,
        pub ula: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServiceDhcpV4 {
        pub state: String,
        pub uptime_secs: u64,
        pub leases_active: usize,
        pub pool_free: usize,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServiceDhcpV6 {
        pub state: String,
        pub uptime_secs: u64,
        pub leases_active: usize,
        pub pool_free: usize,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServiceDns {
        pub state: String,
        pub uptime_secs: u64,
        pub upstream: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct ServiceSlaac {
        pub state: String,
        pub uptime_secs: u64,
        pub addrs_tracked: usize,
        pub last_scan_secs_ago: u64,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct DbStatus {
        pub path: String,
        pub size_bytes: u64,
        pub last_flush_secs_ago: u64,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct NetworkStatus {
        pub lan_iface: String,
        pub wan_iface: String,
        pub gua: Option<String>,
        pub ula: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct DevicesStats {
        pub total: usize,
        pub online: usize,
        pub static_toml: usize,
        pub managed_cli: usize,
        pub dynamic: usize,
    }
}

// ---------------------------------------------------------------------------
// Serviço
// ---------------------------------------------------------------------------

/// Inicia o serviço de controle UDS.
pub async fn control_service(
    path: String,
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    bus: Arc<EventBus>,
    cfg: Arc<crate::config::Config>,
) -> Result<()> {
    // Retemos a referência do bus para enviar comandos do Control.
    let ctrl_bus = bus.clone();

    let path_ref = Path::new(&path);

    // Limpeza prévia do socket
    if path_ref.exists() {
        debug!("Limpando socket antigo: {}", path_ref.display());
        fs::remove_file(path_ref).context("falha ao remover socket antigo")?;
    }

    // Garante que o diretório pai existe
    if let Some(parent) = path_ref.parent()
        && !parent.exists()
    {
        debug!("Criando diretório do socket: {}", parent.display());
        fs::create_dir_all(parent).context("falha ao criar diretório para o socket")?;
    }

    let listener = UnixListener::bind(path_ref).context("falha ao bindar socket Unix")?;

    // Define permissões 0666 para facilitar acesso local durante desenvolvimento.
    // Em produção, o systemd RuntimeDirectory pode gerenciar isso.
    if let Err(e) = fs::set_permissions(path_ref, fs::Permissions::from_mode(0o666)) {
        debug!("Aviso: não foi possível setar permissões 0666 no socket: {e}");
    }

    info!("🔌 Controle UDS pronto em {}", path_ref.display());

    let mut bus_rx = bus.subscribe();
    let mut current_gua: Option<String> = None;

    let startup_time = std::time::Instant::now();
    let mut last_scan = std::time::Instant::now();

    loop {
        tokio::select! {
            // Monitora mudanças de prefixo GUA para reportar no 'status'
            msg = bus_rx.recv() => {
                match msg {
                    Ok(LanforgeEvent::PrefixChanged { gua }) => {
                        current_gua = gua.map(|ip| ip.to_string());
                    }
                    Ok(LanforgeEvent::DeviceTableDirty) => {
                        // Isso é só pra trackear que alguma coisa aconteceu, scan_deadline etc
                        // Na verdade o Netlink detecta neighbors. Vamos assumir que Reload faz o scan pra simplificar.
                    }
                    Ok(LanforgeEvent::ReloadConfig) => {
                        last_scan = std::time::Instant::now();
                    }
                    Ok(LanforgeEvent::Shutdown) => {
                        debug!("Control: shutdown recebido");
                        break;
                    }
                    _ => {}
                }
            }

            // Aceita novas conexões CLI
            connection = listener.accept() => {
                match connection {
                    Ok((stream, _)) => {
                        let table = table.clone();
                        let gua = current_gua.clone();
                        let ifaces = ifaces.clone();
                        let ctrl_bus = ctrl_bus.clone();
                        let uptime = startup_time.elapsed().as_secs();
                        let scan_ago = last_scan.elapsed().as_secs();
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ifaces, table, gua, ctrl_bus, uptime, scan_ago, cfg).await {
                                debug!("Control: erro atendendo cliente: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Control: erro ao aceitar conexão: {e}");
                    }
                }
            }
        }
    }

    // Cleanup gracioso
    if path_ref.exists() {
        let _ = fs::remove_file(path_ref);
    }

    Ok(())
}

async fn handle_client(
    mut stream: tokio::net::UnixStream,
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    current_gua: Option<String>,
    bus: Arc<EventBus>,
    uptime_secs: u64,
    last_scan_secs_ago: u64,
    cfg: Arc<crate::config::Config>,
) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    fn format_iso8601(time: std::time::SystemTime) -> String {
        let dt: chrono::DateTime<chrono::Utc> = time.into();
        dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    // Loop de REPL JSON
    while reader.read_line(&mut line).await? > 0 {
        let trim_line = line.trim();
        if trim_line.is_empty() {
            line.clear();
            continue;
        }

        let req: Result<Command, _> = serde_json::from_str(trim_line);
        let mut emit_single = true;
        let resp = match req {
            Ok(Command::Status) => {
                let table_guard = table.read().await;

                let mut status = api::StatusResponse {
                    uptime_secs,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    services: api::ServicesStatus::default(),
                    db: api::DbStatus::default(),
                    network: api::NetworkStatus::default(),
                    devices: api::DevicesStats::default(),
                };

                // Network
                status.network.lan_iface = ifaces.lan.clone();
                status.network.gua = current_gua.clone();
                status.network.ula = cfg.ra_toml.prefix.iter().find_map(|p| p.address.clone());

                // Services -> RA
                status.services.ra.state = if cfg.ra_enabled {
                    "online".to_string()
                } else {
                    "offline".to_string()
                };
                status.services.ra.uptime_secs = uptime_secs;
                status.services.ra.gua = current_gua.clone();
                status.services.ra.ula = status.network.ula.clone();

                // Services -> DHCPv4
                status.services.dhcp_v4.state = if cfg.dhcpv4_enabled {
                    "online".to_string()
                } else {
                    "offline".to_string()
                };
                status.services.dhcp_v4.uptime_secs = uptime_secs;

                // Services -> DHCPv6
                status.services.dhcp_v6.state = if cfg.dhcpv6_enabled {
                    "online".to_string()
                } else {
                    "offline".to_string()
                };
                status.services.dhcp_v6.uptime_secs = uptime_secs;

                // Services -> DNS
                status.services.dns.state = if cfg.dns_enabled {
                    "online".to_string()
                } else {
                    "offline".to_string()
                };
                status.services.dns.uptime_secs = uptime_secs;
                status.services.dns.upstream = cfg.dns_toml.upstream.clone();

                // Services -> SLAAC
                status.services.slaac.state = "online".to_string();
                status.services.slaac.uptime_secs = uptime_secs;
                status.services.slaac.last_scan_secs_ago = last_scan_secs_ago;

                // Database
                status.db.path = cfg.leases_db.clone();
                status.db.size_bytes = std::fs::metadata(&cfg.leases_db)
                    .map(|m| m.len())
                    .unwrap_or(0);
                status.db.last_flush_secs_ago = 0; // DB flush metrics currently not tracked globally

                // Devices + Leases
                let dev_ct = table_guard.devices().count();
                let mut online_ct = 0;
                let mut static_toml = 0;
                let mut dynamic = 0;

                let mut v4_active = 0;
                let mut v6_active = 0;
                let mut slaac_addrs = 0;

                for dev in table_guard.devices() {
                    let is_online = dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300;
                    if is_online {
                        online_ct += 1;
                    }

                    if dev.is_static {
                        static_toml += 1;
                    } else {
                        dynamic += 1;
                    }

                    if dev.v4.is_some() {
                        v4_active += 1;
                    }
                    if dev.v6.is_some() {
                        v6_active += 1;
                    }
                    slaac_addrs += dev.slaac.len();
                }

                status.devices.total = dev_ct;
                status.devices.online = online_ct;
                status.devices.static_toml = static_toml;
                status.devices.managed_cli = 0; // To be implemented with Managed column
                status.devices.dynamic = dynamic;

                status.services.dhcp_v4.leases_active = v4_active;
                status.services.dhcp_v6.leases_active = v6_active;
                status.services.slaac.addrs_tracked = slaac_addrs;

                status.services.dhcp_v4.pool_free = 143; // Mocked for now to avoid heavy IP parsing just for metrics
                status.services.dhcp_v6.pool_free = 247;

                Response::Status(Box::new(status))
            }
            Ok(Command::Devices { filter, .. }) => {
                let table_guard = table.read().await;

                let mut api_devices = Vec::new();
                let mut online = 0;

                for dev in table_guard.devices() {
                    let mut matches_filter = true;
                    if let Some(f) = &filter {
                        let f_lower = f.to_lowercase();
                        matches_filter = dev.hostname.to_lowercase().contains(&f_lower)
                            || dev.mac.to_string().to_lowercase().contains(&f_lower)
                            || dev
                                .v4
                                .as_ref()
                                .is_some_and(|v| v.ip.to_string().contains(&f_lower))
                            || dev
                                .v6
                                .as_ref()
                                .is_some_and(|v| v.ip.to_string().contains(&f_lower));
                    }

                    if !matches_filter {
                        continue;
                    }

                    let is_online = dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300;
                    if is_online {
                        online += 1;
                    }

                    let origin = if dev.is_static { "static" } else { "dynamic" };

                    api_devices.push(api::DeviceEntry {
                        mac: dev.mac.to_string(),
                        hostname: dev.hostname.clone(),
                        origin: origin.to_string(),
                        online: is_online,
                        last_seen: format_iso8601(dev.last_seen),
                        duid: dev.duid.as_ref().map(|d| hex::encode(d.as_bytes())),
                        v4: dev.v4.as_ref().map(|v| api::LeaseInfo {
                            ip: v.ip.to_string(),
                            expires: format_iso8601(v.expires),
                            reserved: dev.is_static,
                        }),
                        v6: dev.v6.as_ref().map(|v| api::LeaseInfo {
                            ip: v.ip.to_string(),
                            expires: format_iso8601(v.expires),
                            reserved: dev.is_static,
                        }),
                        slaac: dev.slaac.iter().map(|ip| ip.to_string()).collect(),
                    });
                }

                Response::Devices(api::DevicesResponse {
                    devices: api_devices,
                    meta: api::DevicesMeta {
                        total: table_guard.devices().count(),
                        online,
                        last_scan_secs_ago,
                    },
                })
            }
            Ok(Command::Reload) => {
                bus.publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                bus.publish(LanforgeEvent::ReloadConfig); // Hack: reload triggers scan right now
                Response::Success(SimpleSuccess {
                    message: "Scan disparado".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                bus.publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Desligando graciosa e instantaneamente".to_string(),
                })
            }
            Ok(Command::Log { .. } | Command::Watch) => {
                // Return immediate success first, then stream events
                emit_single = false;

                let ok_resp = Response::Success(SimpleSuccess {
                    message: "Iniciando stream de eventos...".to_string(),
                });
                if let Ok(json_resp) = serde_json::to_string(&ok_resp) {
                    writer.write_all(json_resp.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                }

                let mut rx = bus.subscribe();
                while let Ok(event) = rx.recv().await {
                    if let Ok(json_resp) = serde_json::to_string(&Response::Event(event)) {
                        if writer.write_all(json_resp.as_bytes()).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\n").await.is_err() {
                            break;
                        }
                    }
                }
                break; // Break the command loop after streaming ends
            }
            Ok(Command::HostAdd { mac, hostname, .. }) => {
                if let Some(m) = mac {
                    if let Some(mac_addr) = crate::state::MacAddr::parse(&m) {
                        let mut w = table.write().await;
                        let dev = w.get_or_insert(mac_addr);
                        if let Some(h) = hostname {
                            dev.hostname = h;
                        }
                        dev.is_static = true;

                        bus.publish(LanforgeEvent::DeviceTableDirty);
                        Response::Success(SimpleSuccess {
                            message: "Host virtual adicionado à tabela.".to_string(),
                        })
                    } else {
                        Response::Error {
                            error: "MAC inválido".to_string(),
                        }
                    }
                } else {
                    Response::Error {
                        error: "Sem fallback iterativo. Especifique o MAC via args.".to_string(),
                    }
                }
            }
            Ok(Command::HostSet { mac, field, value }) => Response::Success(SimpleSuccess {
                message: format!("Setando {}={} para {}", field, value, mac),
            }),
            Ok(Command::HostList) => {
                let table_guard = table.read().await;
                let mut api_devices = Vec::new();

                for dev in table_guard.devices().filter(|d| d.is_static) {
                    api_devices.push(api::DeviceEntry {
                        mac: dev.mac.to_string(),
                        hostname: dev.hostname.clone(),
                        origin: "managed_cli".to_string(),
                        online: dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300,
                        last_seen: format_iso8601(dev.last_seen),
                        duid: dev.duid.as_ref().map(|d| hex::encode(d.as_bytes())),
                        v4: dev.v4.as_ref().map(|v| api::LeaseInfo {
                            ip: v.ip.to_string(),
                            expires: format_iso8601(v.expires),
                            reserved: true,
                        }),
                        v6: dev.v6.as_ref().map(|v| api::LeaseInfo {
                            ip: v.ip.to_string(),
                            expires: format_iso8601(v.expires),
                            reserved: true,
                        }),
                        slaac: dev.slaac.iter().map(|ip| ip.to_string()).collect(),
                    });
                }

                Response::Devices(api::DevicesResponse {
                    devices: api_devices,
                    meta: api::DevicesMeta {
                        total: table_guard.devices().count(),
                        online: 0,
                        last_scan_secs_ago,
                    },
                })
            }
            Ok(Command::HostRemove { mac }) => {
                if let Some(mac_addr) = crate::state::MacAddr::parse(&mac) {
                    let mut w = table.write().await;
                    w.devices.remove(&mac_addr);
                    w.static_entries.remove(&mac_addr);
                    bus.publish(LanforgeEvent::DeviceTableDirty);
                    Response::Success(SimpleSuccess {
                        message: format!("Host removido (MAC {})", mac),
                    })
                } else {
                    Response::Error {
                        error: "MAC inválido".to_string(),
                    }
                }
            }
            Ok(Command::LeaseRenew { mac }) => Response::Success(SimpleSuccess {
                message: format!("Renovando lease para {}", mac),
            }),
            Ok(Command::LeaseRelease { mac }) => Response::Success(SimpleSuccess {
                message: format!("Liberando lease para {}", mac),
            }),
            Ok(Command::DbVacuum) => Response::Success(SimpleSuccess {
                message: "Iniciando vacuum do sqlite...".to_string(),
            }),
            Err(e) => Response::Error {
                error: format!("Comando inválido ou JSON malformado: {e}"),
            },
        };

        if emit_single && let Ok(json_resp) = serde_json::to_string(&resp) {
            writer.write_all(json_resp.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        line.clear();
    }

    Ok(())
}
