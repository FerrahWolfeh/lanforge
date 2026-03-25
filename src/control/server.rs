use anyhow::{Context, Result};
use std::fs;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

use crate::bus::{EventBus, LanforgeEvent, ManagedTable};
use crate::control::api::{self, Command, Interfaces, Response, SimpleSuccess};
use crate::device::{IPv6State, Ipv6AddrOrSuffix, MacAddr, Origin};
use crate::state::DeviceUpdate;

fn format_iso8601(time: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn get_v6_kind(addr: &Ipv6Addr) -> &'static str {
    if addr.is_loopback() || addr.is_unspecified() {
        return "Internal";
    }
    let segments = addr.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return "ULA";
    }
    if (segments[0] & 0xffc0) == 0xfe80 {
        return "LinkLocal";
    }
    "GUA"
}

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
                    Ok(LanforgeEvent::PrefixChanged {gua, .. }) => {
                        current_gua = gua.map(|ip| ip.to_string());
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
                            let ctx = ClientContext {
                                ifaces,
                                table,
                                current_gua: gua,
                                bus: ctrl_bus,
                                uptime_secs: uptime,
                                last_scan_secs_ago: scan_ago,
                                cfg,
                            };
                            if let Err(e) = handle_client(stream, ctx).await {
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

struct ClientContext {
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    current_gua: Option<String>,
    bus: Arc<EventBus>,
    uptime_secs: u64,
    last_scan_secs_ago: u64,
    cfg: Arc<crate::config::Config>,
}

impl ClientContext {
    async fn handle_status(&self) -> Response {
        let table_guard = self.table.read();

        let mut status = api::StatusResponse {
            uptime_secs: self.uptime_secs,
            version: env!("CARGO_PKG_VERSION").to_string(),
            services: api::ServicesStatus::default(),
            db: api::DbStatus::default(),
            network: api::NetworkStatus::default(),
            devices: api::DevicesStats::default(),
        };

        // Network
        status.network.lan_iface.clone_from(&self.ifaces.lan);
        status.network.gua.clone_from(&self.current_gua);
        status.network.ula = self
            .cfg
            .ra_toml
            .prefix
            .iter()
            .find_map(|p| p.address.clone());

        // Services -> RA
        status.services.ra.state = if self.cfg.ra_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.ra.uptime_secs = self.uptime_secs;
        status.services.ra.gua.clone_from(&self.current_gua);
        status.services.ra.ula.clone_from(&status.network.ula);

        // Services -> DHCPv4
        status.services.dhcp_v4.state = if self.cfg.dhcpv4_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.dhcp_v4.uptime_secs = self.uptime_secs;

        // Services -> DHCPv6
        status.services.dhcp_v6.state = if self.cfg.dhcpv6_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.dhcp_v6.uptime_secs = self.uptime_secs;

        // Services -> DNS
        status.services.dns.state = if self.cfg.dns_enabled {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        status.services.dns.uptime_secs = self.uptime_secs;
        status
            .services
            .dns
            .upstream
            .clone_from(&self.cfg.dns_toml.upstream);

        // Services -> SLAAC
        status.services.slaac.state = "online".to_string();
        status.services.slaac.uptime_secs = self.uptime_secs;
        status.services.slaac.last_scan_secs_ago = self.last_scan_secs_ago;

        // Database
        status.db.path.clone_from(&self.cfg.leases_db);
        status.db.size_bytes = std::fs::metadata(&self.cfg.leases_db)
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

            if dev.is_static() {
                static_toml += 1;
            } else {
                dynamic += 1;
            }

            if dev.v4.ip().is_some() {
                v4_active += 1;
            }
            if dev
                .v6
                .iter()
                .any(|s| matches!(s, IPv6State::Dynamic(_) | IPv6State::Static(_)))
            {
                v6_active += 1;
            }
            slaac_addrs += dev
                .v6
                .iter()
                .filter(|s| matches!(s, IPv6State::Slaac(_)))
                .count();
        }

        status.devices.total = dev_ct;
        status.devices.online = online_ct;
        status.devices.static_toml = static_toml;
        status.devices.managed_cli = table_guard
            .devices()
            .filter(|d| d.origin == Origin::Cli)
            .count();

        drop(table_guard);

        status.devices.dynamic = dynamic;

        status.services.dhcp_v4.leases_active = v4_active;
        status.services.dhcp_v6.leases_active = v6_active;
        status.services.slaac.addrs_tracked = slaac_addrs;

        status.services.dhcp_v4.pool_free = 143; // Mocked for now to avoid heavy IP parsing just for metrics
        status.services.dhcp_v6.pool_free = 247;

        Response::Status(Box::new(status))
    }

    async fn handle_devices(&self, filter: Option<String>) -> Response {
        let table_guard = self.table.read();

        let mut api_devices = Vec::new();
        let mut online = 0;

        for dev in table_guard.devices() {
            let matches_filter = filter.as_ref().is_none_or(|f| {
                let f_lower = f.to_lowercase();
                dev.hostname.to_lowercase().contains(&f_lower)
                    || dev.mac.to_string().to_lowercase().contains(&f_lower)
                    || dev
                        .v4
                        .ip()
                        .map(|ip| ip.to_string())
                        .is_some_and(|s| s.contains(&f_lower))
                    || dev.v6.iter().any(|s| {
                        s.ip()
                            .map(|ip| ip.to_string())
                            .is_some_and(|s| s.contains(&f_lower))
                    })
            });

            if !matches_filter {
                continue;
            }

            let is_online = dev.last_seen.elapsed().unwrap_or_default().as_secs() < 300;
            if is_online {
                online += 1;
            }

            api_devices.push(api::DeviceEntry {
                mac: dev.mac.to_string(),
                hostname: dev.hostname.clone(),
                origin: dev.origin.as_str().to_string(),
                online: is_online,
                last_seen: format_iso8601(dev.last_seen),
                duid: dev.duid.as_ref().map(|d| hex::encode(d.as_bytes())),
                v4: match &dev.v4 {
                    crate::device::IPv4State::Static(ip) => Some(api::LeaseInfo {
                        ip: ip.to_string(),
                        expires: "Static".to_string(),
                        reserved: true,
                    }),
                    crate::device::IPv4State::Dynamic(v) => Some(api::LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    crate::device::IPv4State::None => None,
                },
                seen_v4: dev.seen_v4.iter().map(|ip| ip.to_string()).collect(),
                v6: dev.v6.iter().find_map(|s| match s {
                    crate::device::IPv6State::Dynamic(v) => Some(api::LeaseInfo {
                        ip: v.ip.to_string(),
                        expires: format_iso8601(v.expires),
                        reserved: dev.is_static(),
                    }),
                    crate::device::IPv6State::Static(crate::device::Ipv6AddrOrSuffix::Full(ip)) => {
                        Some(api::LeaseInfo {
                            ip: ip.to_string(),
                            expires: "Static".to_string(),
                            reserved: true,
                        })
                    }
                    _ => None,
                }),
                ipv6_addrs: {
                    let mut list = Vec::new();
                    for state in &dev.v6 {
                        if let crate::device::IPv6State::Slaac(ip) = state {
                            list.push(api::Ipv6Entry {
                                addr: ip.to_string(),
                                kind: get_v6_kind(ip).to_string(),
                            });
                        }
                    }
                    list
                },
            });
        }

        Response::Devices(api::DevicesResponse {
            devices: api_devices,
            meta: api::DevicesMeta {
                total: table_guard.devices().count(),
                online,
                last_scan_secs_ago: self.last_scan_secs_ago,
            },
        })
    }

    async fn handle_hosts(&self) -> Response {
        let table_guard = self.table.read();
        let mut hosts = Vec::new();

        for dev in table_guard.devices() {
            if dev.origin == crate::device::Origin::Dynamic {
                continue;
            }

            hosts.push(api::HostConfigEntry {
                mac: dev.mac.to_string(),
                hostname: dev.hostname.clone(),
                v4_fixed: match &dev.v4 {
                    crate::device::IPv4State::Static(ip) => Some(ip.to_string()),
                    _ => None,
                },
                v6_suffix: dev.v6.iter().find_map(|s| {
                    if let crate::device::IPv6State::Static(suffix) = s {
                        Some(suffix.to_string())
                    } else {
                        None
                    }
                }),
                origin: dev.origin.as_str().to_string(),
            });
        }

        Response::Hosts(api::HostsResponse { hosts })
    }
}

async fn handle_client(mut stream: tokio::net::UnixStream, ctx: ClientContext) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Loop de REPL JSON
    while reader.read_line(&mut line).await? > 0 {
        let trim_line = line.trim();
        if trim_line.is_empty() {
            line.clear();
            continue;
        }

        let req: Result<Command, _> = serde_json::from_str(trim_line);
        let resp = match req {
            Ok(Command::Status) => ctx.handle_status().await,
            Ok(Command::Devices { filter, .. }) => ctx.handle_devices(filter).await,
            Ok(Command::Reload) => {
                ctx.bus.publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                ctx.bus.publish(LanforgeEvent::ReloadConfig); // Hack: reload triggers scan right now
                Response::Success(SimpleSuccess {
                    message: "Scan disparado".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                ctx.bus.publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Desligando graciosa e instantaneamente".to_string(),
                })
            }
            Ok(Command::Log { .. } | Command::Watch) => {
                // Return immediate success first, then stream events
                let ok_resp = Response::Success(SimpleSuccess {
                    message: "Iniciando stream de eventos...".to_string(),
                });
                if let Ok(json_resp) = serde_json::to_string(&ok_resp) {
                    writer.write_all(json_resp.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                }

                let mut rx = ctx.bus.subscribe();
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
            Ok(Command::HostAdd {
                mac,
                hostname,
                v4,
                v6_suffix,
            }) => {
                if let Some(m) = mac {
                    if let Some(mac_addr) = MacAddr::parse(&m) {
                        let v4_static = v4.and_then(|s| s.parse().ok());
                        let v6_suffix_parsed = v6_suffix.and_then(|s| Ipv6AddrOrSuffix::parse(&s));
                        ctx.table
                            .update(DeviceUpdate::CliHostUpdated {
                                mac: mac_addr,
                                hostname: hostname.map(Some),
                                v4_static: Some(v4_static),
                                v6_suffix: Some(v6_suffix_parsed),
                            })
                            .await;

                        Response::Success(SimpleSuccess {
                            message: "Host adicionado e persistido.".to_string(),
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
            Ok(Command::HostSet { mac, field, value }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let mut hn = None;
                    let mut v4s = None;
                    let mut v6s = None;

                    let err_msg = match field.as_str() {
                        "hostname" => {
                            hn = Some(Some(value.clone()));
                            None
                        }
                        "v4" | "ipv4" => {
                            if value.is_empty() {
                                v4s = Some(None);
                                None
                            } else if let Ok(ip) = value.parse() {
                                v4s = Some(Some(ip));
                                None
                            } else {
                                Some("IPv4 inválido")
                            }
                        }
                        "v6_suffix" | "v6" => {
                            if value.is_empty() {
                                v6s = Some(None);
                                None
                            } else if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
                                v6s = Some(Some(suf));
                                None
                            } else {
                                Some("Interface ID (sufixo) ou IPv6 inválido")
                            }
                        }
                        _ => Some("Campo desconhecido"),
                    };

                    if let Some(e) = err_msg {
                        Response::Error {
                            error: e.to_string(),
                        }
                    } else {
                        ctx.table
                            .update(DeviceUpdate::CliHostUpdated {
                                mac: mac_addr,
                                hostname: hn,
                                v4_static: v4s,
                                v6_suffix: v6s,
                            })
                            .await;

                        Response::Success(SimpleSuccess {
                            message: format!("Host {mac} atualizado: {field}={value}"),
                        })
                    }
                } else {
                    Response::Error {
                        error: "MAC inválido".to_string(),
                    }
                }
            }
            Ok(Command::HostList) => ctx.handle_hosts().await,

            Ok(Command::HostRemove { mac }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let mut w = ctx.table.write();
                    w.devices.remove(&mac_addr);
                    w.static_entries.remove(&mac_addr);
                    drop(w);
                    ctx.bus.publish(LanforgeEvent::DeviceTableDirty);
                    Response::Success(SimpleSuccess {
                        message: format!("Host removido (MAC {mac})"),
                    })
                } else {
                    Response::Error {
                        error: "MAC inválido".to_string(),
                    }
                }
            }
            Ok(Command::LeaseRenew { mac }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    ctx.bus.publish(LanforgeEvent::LeaseRenew { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Solicitando renovação (forcerenew) para {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("MAC inválido: {mac}"),
                    }
                }
            }
            Ok(Command::LeaseRelease { mac }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    ctx.table
                        .update(DeviceUpdate::LeaseReleased { mac: mac_addr })
                        .await;
                    ctx.bus
                        .publish(LanforgeEvent::LeaseRelease { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Liberando lease para {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("MAC inválido: {mac}"),
                    }
                }
            }
            Ok(Command::DbVacuum) => {
                ctx.bus.publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Iniciando vacuum do sqlite...".to_string(),
                })
            }
            Err(e) => Response::Error {
                error: format!("Comando inválido ou JSON malformado: {e}"),
            },
        };

        if let Ok(json_resp) = serde_json::to_string(&resp) {
            writer.write_all(json_resp.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        line.clear();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;
    use crate::config::{Config, DhcpV4Cfg, DhcpV6Cfg, DnsCfg, RaCfg, StaticDeviceCfg};
    use crate::control::api::Response;
    use crate::device::MacAddr;
    use crate::state::DeviceUpdate;

    fn make_dummy_config() -> Config {
        Config {
            command: crate::config::Command::Run { only: None },
            iface_lan: "eth0".to_string(),
            target_prefix: "fd00::/64".to_string(),
            leases_db: "/tmp/leases.db".to_string(),
            debounce_secs: 5,
            fallback_mins: 60,
            control_socket: "/tmp/lanforge.sock".to_string(),
            ra_enabled: true,
            ra_toml: RaCfg::default(),
            dhcpv4_enabled: true,
            dhcpv4_toml: DhcpV4Cfg::default(),
            dhcpv6_enabled: true,
            dhcpv6_toml: DhcpV6Cfg::default(),
            dns_enabled: true,
            dns_toml: DnsCfg::default(),
            devices: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_host_list_returns_static_and_cli_only() {
        let bus = Arc::new(EventBus::new());
        let table = Arc::new(ManagedTable::new(bus.clone()));
        let cfg = Arc::new(make_dummy_config());
        let ifaces = Interfaces {
            lan: "eth0".to_string(),
        };

        let ctx = ClientContext {
            ifaces,
            table: table.clone(),
            current_gua: None,
            bus: bus.clone(),
            uptime_secs: 10,
            last_scan_secs_ago: 5,
            cfg,
        };

        // 1. Add a CLI device
        let mac_cli = MacAddr::parse("00:00:00:00:00:01").unwrap();
        table
            .update(DeviceUpdate::CliHostUpdated {
                mac: mac_cli,
                hostname: Some(Some("cli-host".to_string())),
                v4_static: None,
                v6_suffix: None,
            })
            .await;

        // 2. Add a Dynamic device
        let mac_dyn = MacAddr::parse("00:00:00:00:00:02").unwrap();
        table
            .update(DeviceUpdate::V4LeaseGranted {
                mac: mac_dyn,
                ip: "192.168.1.10".parse().unwrap(),
                expires: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            })
            .await;

        // 3. Add a TOML device
        let mac_toml = MacAddr::parse("00:00:00:00:00:03").unwrap();
        {
            let mut w = table.write();
            w.load_static_devices(&[StaticDeviceCfg {
                mac: mac_toml.to_string(),
                hostname: "toml-host".to_string(),
                v4_ip: Some("192.168.1.5".to_string()),
                v6_suffix: None,
            }]);
        }

        // 4. handle_hosts (called by HostList) should return ONLY CLI and TOML
        let resp = ctx.handle_hosts().await;
        if let Response::Hosts(d) = resp {
            assert_eq!(
                d.hosts.len(),
                2,
                "Should return ONLY CLI and TOML devices, NOT dynamic ones"
            );
            assert!(
                d.hosts
                    .iter()
                    .any(|dev| dev.mac == mac_cli.to_string() && dev.origin == "cli")
            );
            assert!(
                d.hosts
                    .iter()
                    .any(|dev| dev.mac == mac_toml.to_string() && dev.origin == "toml")
            );
            // Dynamic host should not be in d.hosts
            assert!(!d.hosts.iter().any(|dev| dev.mac == mac_dyn.to_string()));
        } else {
            panic!("Expected Response::Hosts, got {:?}", resp);
        }

        // 5. handle_devices (called by Devices) should still return all 3
        let resp = ctx.handle_devices(None).await;
        if let Response::Devices(d) = resp {
            assert_eq!(
                d.devices.len(),
                3,
                "Devices list should still show everything"
            );
        }
    }
}
