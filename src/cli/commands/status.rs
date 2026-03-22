use anyhow::Result;
use iocraft::prelude::*;
use crate::control::api::StatusResponse;
use crate::control::{Command as ControlCommand, Response};
use super::{CliCommand, format_uptime};

pub struct StatusHandler;

impl CliCommand for StatusHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Status)
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Status(st) => {
                render_status(st);
            }
            Response::Error { error } => {
                println!("Erro: {error}");
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Resposta inesperada para status: {response:?}");
            }
        }
        Ok(())
    }
}

pub fn render_status(st: &StatusResponse) {
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

    print_status_header(st);
    print_status_services(st, &gua, &ula, &upstream);
    print_status_devices(st);
    print_status_persistence(st);
    print_status_network(st);
}

fn print_status_header(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: "LANFORGE  ·  uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.uptime_secs))
                Text(content: "  ·  v", color: Color::DarkGrey)
                Text(content: st.version.clone())
            }
        }
    }
    .print();
}

fn print_status_services(st: &StatusResponse, gua: &str, ula: &str, upstream: &str) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "SERVIÇOS") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
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
        }
    }.print();
}

fn print_status_devices(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "DEVICES") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} conhecidos  ·  {} online", st.devices.total, st.devices.online))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{} do TOML  ·  {} gerenciados via CLI  ·  {} dinâmicos", st.devices.static_toml, st.devices.managed_cli, st.devices.dynamic))
            }
        }
    }.print();
}

fn print_status_persistence(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "PERSISTÊNCIA") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("SQLite   {}  ·  {} bytes", st.db.path, st.db.size_bytes))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("         último flush há {}s", st.db.last_flush_secs_ago))
            }
        }
    }.print();
}

fn print_status_network(st: &StatusResponse) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View { Text(content: "REDE") }
            View { Text(content: "---------------------------------------------------------------------------", color: Color::DarkGrey) }
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("LAN      {}", st.network.lan_iface))
            }
            View(margin_bottom: 1) { }
        }
    }.print();
}
