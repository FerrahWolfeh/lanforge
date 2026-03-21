use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use inquire::{Confirm, Select, Text as InquireText};
use iocraft::prelude::*;

use crate::config::Command;
use crate::control::{Command as ControlCommand, Response, api};

pub async fn run_client(command: Command, socket_path: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "Falha ao conectar no daemon em '{}'. O daemon está rodando?",
            socket_path
        )
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let is_streaming = matches!(command, Command::Watch | Command::Log { .. });

    let json_req = match &command {
        Command::Status => serde_json::to_string(&ControlCommand::Status)?,
        Command::Devices { filter, format, .. } => {
            serde_json::to_string(&ControlCommand::Devices {
                filter: filter.clone(),
                format: format.clone(),
            })?
        }
        Command::Reload => serde_json::to_string(&ControlCommand::Reload)?,
        Command::Watch => serde_json::to_string(&ControlCommand::Watch)?,
        Command::Log { follow } => serde_json::to_string(&ControlCommand::Log { follow: *follow })?,
        Command::Scan => serde_json::to_string(&ControlCommand::Scan)?,
        Command::Shutdown => serde_json::to_string(&ControlCommand::Shutdown)?,
        Command::Host { action } => match action {
            crate::config::HostCommand::Add {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => {
                let final_mac = if let Some(m) = mac {
                    m.clone()
                } else {
                    let ans = InquireText::new("MAC address:").prompt()?;
                    if ans.trim().is_empty() {
                        return Ok(());
                    }
                    ans.trim().to_string()
                };

                let final_hostname = if let Some(h) = hostname {
                    h.clone()
                } else {
                    let ans = InquireText::new("Hostname:").prompt()?;
                    if ans.trim().is_empty() {
                        return Ok(());
                    }
                    ans.trim().to_string()
                };

                let mut final_v4 = v4.clone();
                let mut final_v6 = v6_suffix.clone();

                if v4.is_none() && v6_suffix.is_none() {
                    let opts = vec![
                        "[1] Só hostname (IP dinâmico do pool)",
                        "[2] Hostname + IPv4 fixo",
                        "[3] Hostname + IPv4 fixo + sufixo ULA",
                    ];
                    let choice = Select::new("Nível de configuração:", opts).prompt()?;
                    if choice.starts_with("[2]") || choice.starts_with("[3]") {
                        let ans = InquireText::new("IPv4 fixo:").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v4 = Some(ans.trim().to_string());
                        }
                    }
                    if choice.starts_with("[3]") {
                        let ans = InquireText::new("Sufixo ULA (ex: ::1234):").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v6 = Some(ans.trim().to_string());
                        }
                    }

                    println!("\nConfirmar?");
                    println!("  MAC       {}", final_mac);
                    println!("  hostname  {}", final_hostname);
                    if let Some(ref v) = final_v4 {
                        println!("  V4 fixo   {}", v);
                    }
                    if let Some(ref v) = final_v6 {
                        println!("  V6 sufixo {}", v);
                    }
                    println!();

                    let confirm = Confirm::new("Confirmar adição?")
                        .with_default(true)
                        .prompt()?;
                    if !confirm {
                        println!("Cancelado.");
                        return Ok(());
                    }
                }

                serde_json::to_string(&ControlCommand::HostAdd {
                    mac: Some(final_mac),
                    hostname: Some(final_hostname),
                    v4: final_v4,
                    v6_suffix: final_v6,
                })?
            }
            crate::config::HostCommand::Set { mac, field, value } => {
                serde_json::to_string(&ControlCommand::HostSet {
                    mac: mac.clone(),
                    field: field.clone(),
                    value: value.clone(),
                })?
            }
            crate::config::HostCommand::Remove { mac } => {
                serde_json::to_string(&ControlCommand::HostRemove { mac: mac.clone() })?
            }
            crate::config::HostCommand::List => serde_json::to_string(&ControlCommand::HostList)?,
        },
        Command::Lease { action } => match action {
            crate::config::LeaseCommand::Renew { mac } => {
                serde_json::to_string(&ControlCommand::LeaseRenew { mac: mac.clone() })?
            }
            crate::config::LeaseCommand::Release { mac } => {
                serde_json::to_string(&ControlCommand::LeaseRelease { mac: mac.clone() })?
            }
        },
        Command::Db { action } => match action {
            crate::config::DbCommand::Vacuum => serde_json::to_string(&ControlCommand::DbVacuum)?,
        },
        _ => {
            println!("Este comando ainda não está implementado na CLI.");
            return Ok(());
        }
    };

    writer.write_all(json_req.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut response_line = String::new();
    let chars_read = reader.read_line(&mut response_line).await?;
    if chars_read == 0 {
        return Ok(());
    }

    let response: Response = serde_json::from_str(&response_line)
        .with_context(|| format!("Falha ao analisar a resposta do daemon: {}", response_line))?;

    match response {
        Response::Error { error } => {
            println!("Erro: {}", error);
            return Ok(());
        }
        Response::Success(success) => {
            println!("✓ {}", success.message);
            // Continua se for streaming
        }
        Response::Status(status) => {
            render_status(*status);
            return Ok(());
        }
        Response::Devices(devices_resp) => {
            let is_verbose = match command {
                Command::Devices { verbose, .. } => verbose,
                _ => false,
            };
            render_devices(devices_resp, is_verbose);
            return Ok(());
        }
        Response::Event(e) => {
            println!("Event: {:?}", e);
            return Ok(());
        }
    }

    if is_streaming {
        loop {
            response_line.clear();
            if reader.read_line(&mut response_line).await? == 0 {
                break;
            }
            if response_line.trim().is_empty() {
                continue;
            }
            let resp: Result<Response, _> = serde_json::from_str(&response_line);
            match resp {
                Ok(Response::Event(e)) => println!("{:?}", e),
                Ok(Response::Error { error }) => {
                    println!("Erro no stream: {}", error);
                    break;
                }
                Ok(other) => println!("Resposta inesperada: {:?}", other),
                Err(_) => println!("JSON malformado no stream: {}", response_line),
            }
        }
    }

    Ok(())
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{}d {}h {}m", d, h, m)
    } else if h > 0 {
        format!("{}h {}m", h, m)
    } else if m > 0 {
        format!("{}m", m)
    } else {
        format!("{}s", secs)
    }
}

fn format_relative_iso8601(iso: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
        let now = Utc::now();
        let diff = dt.with_timezone(&Utc).signed_duration_since(now);

        let mut secs = diff.num_seconds();
        let is_future = secs > 0;
        if !is_future {
            secs = -secs;
        }

        let d = secs / 86400;
        let h = (secs % 86400) / 3600;

        if is_future {
            if d > 0 {
                return "até amanhã".to_string(); // Simplification for "tomorrow" or "in X days"
            }
            if h > 0 {
                return format!("expira em {}h", h);
            }
            return format!("expira em {}m", (secs % 3600) / 60);
        } else {
            if d > 0 {
                return format!("há {} dias", d);
            }
            if h > 0 {
                return format!("há {}h", h);
            }
            let m = (secs % 3600) / 60;
            if m > 0 {
                return format!("há {}m", m);
            }
            return format!("há {}s", secs);
        }
    }
    iso.to_string()
}

use tabled::settings::Style;
use tabled::{Table, Tabled};

pub fn render_status(st: api::StatusResponse) {
    let gua = st
        .services
        .ra
        .gua
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let ula = st
        .services
        .ra
        .ula
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let upstream = st
        .services
        .dns
        .upstream
        .clone()
        .unwrap_or_else(|| "—".to_string());

    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "LANFORGE  ·  uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.uptime_secs))
                Text(content: "  ·  v", color: Color::DarkGrey)
                Text(content: st.version.clone())
            }
            View(margin_top: 1) {
                Text(content: "SERVIÇOS")
            }
            View {
                Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "● RA          ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.ra.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.ra.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        GUA  {gua}"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        ULA  {ula}"))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DHCPv4      ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dhcp_v4.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dhcp_v4.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} leases ativos  ·  {} livres", st.services.dhcp_v4.leases_active, st.services.dhcp_v4.pool_free))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DHCPv6      ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dhcp_v6.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dhcp_v6.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} leases ativos  ·  {} livres", st.services.dhcp_v6.leases_active, st.services.dhcp_v6.pool_free))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● DNS         ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.dns.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.dns.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        upstream {upstream}"))
            }

            View(margin_top: 1, flex_direction: FlexDirection::Row) {
                Text(content: "● SLAAC       ", color: Color::Cyan)
                Text(content: format!("{:<9}", st.services.slaac.state))
                Text(content: " uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.services.slaac.uptime_secs))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        {} endereços rastreados", st.services.slaac.addrs_tracked))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("                        último scan há {}s", st.services.slaac.last_scan_secs_ago))
            }

            View(margin_top: 1) { Text(content: "DEVICES") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} conhecidos  ·  {} online", st.devices.total, st.devices.online))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} do TOML  ·  {} gerenciados via CLI  ·  {} dinâmicos", st.devices.static_toml, st.devices.managed_cli, st.devices.dynamic))
            }

            View(margin_top: 1) { Text(content: "PERSISTÊNCIA") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("SQLite   {}  ·  {} bytes", st.db.path, st.db.size_bytes))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("         último flush há {}s", st.db.last_flush_secs_ago))
            }

            View(margin_top: 1) { Text(content: "REDE") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("LAN      {}", st.network.lan_iface))
            }
            View(margin_bottom: 1) { }
        }
    }.print();
}

#[derive(Tabled)]
struct DeviceRow {
    #[tabled(rename = "HOST")]
    host: String,
    #[tabled(rename = "MAC")]
    mac: String,
    #[tabled(rename = "V4")]
    v4: String,
    #[tabled(rename = "V6 / SLAAC")]
    v6: String,
    #[tabled(rename = "STATUS")]
    status: String,
}

pub fn render_devices(resp: api::DevicesResponse, verbose: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "DEVICES  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} known", resp.meta.total))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} online", resp.meta.online))
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("last scan {}s ago", resp.meta.last_scan_secs_ago))
            }
            View(margin_top: 1) { }
        }
    }
    .print();

    let mut rows = Vec::new();

    for dev in &resp.devices {
        let mut host = dev.hostname.clone();
        if host.is_empty() {
            host = "?".to_string();
        }

        let symbol = match dev.origin.as_str() {
            "static" => "★",
            "managed_cli" => "·",
            _ => "–",
        };

        if verbose {
            let host_display = format!(" {} {} ", host, symbol);

            let mut v4_str = "V4         —".to_string();
            if let Some(ref v) = dev.v4 {
                v4_str = format!("V4         {:<24}", v.ip.clone());
            }

            let mut v6_lines = Vec::new();
            if let Some(v) = &dev.v6 {
                v6_lines.push(format!("V6         {:<24}", v.ip.clone()));
            }
            for (i, s) in dev.slaac.iter().enumerate() {
                let label = if i == 0 && v6_lines.is_empty() {
                    "SLAAC      "
                } else {
                    "           "
                };
                v6_lines.push(format!("{}{} ↑", label, s));
            }
            if v6_lines.is_empty() {
                v6_lines.push("V6 / SLAAC —".to_string());
            }

            let duid_str = match &dev.duid {
                Some(d) => d.clone(),
                None => "—".to_string(),
            };

            let v6_join = v6_lines.join("\n");
            let mac_str = dev.mac.clone();
            let origin_str = dev.origin.clone();
            let last_seen_str = format_relative_iso8601(&dev.last_seen);

            element! {
                View(flex_direction: FlexDirection::Column, padding_left: 2, padding_right: 2, padding_bottom: 1) {
                    View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                        View(flex_direction: FlexDirection::Row, padding_bottom: 1, margin_top: -1) {
                            Text(content: host_display, color: Color::Cyan)
                        }
                        View(flex_direction: FlexDirection::Row) {
                            Text(content: "MAC        ", color: Color::DarkGrey)
                            Text(content: mac_str)
                        }
                        View(flex_direction: FlexDirection::Row) {
                            Text(content: "DUID       ", color: Color::DarkGrey)
                            Text(content: duid_str)
                        }
                        View(flex_direction: FlexDirection::Row) {
                            Text(content: "last seen  ", color: Color::DarkGrey)
                            Text(content: last_seen_str)
                        }
                        View(flex_direction: FlexDirection::Row, padding_bottom: 1) {
                            Text(content: "origem     ", color: Color::DarkGrey)
                            Text(content: origin_str)
                        }
                        View(flex_direction: FlexDirection::Row) {
                            Text(content: v4_str)
                        }
                        View(flex_direction: FlexDirection::Row) {
                            Text(content: v6_join)
                        }
                        View(padding_bottom: 1) { }
                    }
                }
            }.print();
        } else {
            host = format!("{} {}", host, symbol);

            let v4 = if let Some(v) = &dev.v4 {
                v.ip.clone()
            } else {
                "—".to_string()
            };

            let mut v6_lines = Vec::new();
            if let Some(v) = &dev.v6 {
                v6_lines.push(v.ip.clone());
            }
            for s in &dev.slaac {
                v6_lines.push(format!("{} ↑", s));
            }
            if v6_lines.is_empty() {
                v6_lines.push("—".to_string());
            }
            let v6 = v6_lines.join("\n");

            let status = if dev.online {
                "Online".to_string()
            } else {
                "Offline".to_string()
            };

            rows.push(DeviceRow {
                host,
                mac: dev.mac.clone(),
                v4,
                v6,
                status,
            });
        }
    }

    if !verbose && !rows.is_empty() {
        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{}", table);
    }

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, padding_top: 1) {
            Text(content: "★ TOML estático   · gerenciado via CLI   – dinâmico   ↑ SLAAC ativo", color: Color::DarkGrey)
            View(padding_bottom: 1) { }
        }
    }.print();
}
