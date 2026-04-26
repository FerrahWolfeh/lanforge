use super::{CliCommand, format_uptime};
use bytesize::ByteSize;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::Command as ControlCommand;
use lanforge_api::api::Response;
use lanforge_api::api::ServiceStatusInfo;
use lanforge_api::api::StatusResponse;

pub struct StatusHandler;

impl CliCommand for StatusHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::new(
            lanforge_api::api::CommandAction::Status,
        ))
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Status(st) => {
                render_status(st);
            }
            Response::Error { error } => {
                println!("Error: {error}");
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Unexpected response for status: {response:?}");
            }
        }
        Ok(None)
    }
}

pub fn render_status(st: &StatusResponse) {
    // -----------------------------------------------------------------------
    // HEADER
    // -----------------------------------------------------------------------
    element! {
        View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " LANFORGE ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("v{}", st.version), color: Color::White)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: "uptime ", color: Color::DarkGrey)
                Text(content: format_uptime(st.uptime_secs), color: Color::White)
            }
        }
    }
    .print();

    // -----------------------------------------------------------------------
    // INFRASTRUCTURE (Network & Resources)
    // -----------------------------------------------------------------------
    let gua = st.network.gua.as_deref().unwrap_or("stabilizing...");
    let ula = st.network.ula.as_deref().unwrap_or("unavailable");
    let ipv4 = st
        .network
        .lan_ipv4_cidr
        .as_deref()
        .unwrap_or(st.network.lan_ipv4.as_deref().unwrap_or("—"));
    let rss = ByteSize::b(st.resources.memory_rss_bytes);

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: " INFRASTRUCTURE ", color: Color::Yellow, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Iface      ", color: Color::DarkGrey)
                    Text(content: st.network.lan_iface.as_str())
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "IPv4       ", color: Color::DarkGrey)
                    Text(content: ipv4)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "GUA Prefix ", color: Color::DarkGrey)
                    Text(content: gua, color: if st.network.gua.is_some() { Color::White } else { Color::Cyan })
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "ULA Prefix ", color: Color::DarkGrey)
                    Text(content: ula, color: Color::DarkGrey)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Memory RSS ", color: Color::DarkGrey)
                    Text(content: rss.to_string(), color: Color::Green)
                }
            }
        }
    }.print();

    // -----------------------------------------------------------------------
    // SERVICES
    // -----------------------------------------------------------------------

    let ra_state = st.services.ra.state.as_str();
    let dhcp_v4_state = st.services.dhcp_v4.state.as_str();
    let dhcp_v4_meta = &*format!(
        "{} leases · {} free",
        st.services.dhcp_v4.leases_active, st.services.dhcp_v4.pool_free
    );
    let dhcp_v6_state = st.services.dhcp_v6.state.as_str();
    let dhcp_v6_meta = &*format!(
        "{} leases · prefix delegation",
        st.services.dhcp_v6.leases_active
    );
    let dns_state = st.services.dns.state.as_str();
    let dns_meta = &*format!(
        "upstream {}",
        st.services.dns.upstream.as_deref().unwrap_or("—")
    );
    let ndp_state = st.services.ndp_monitor.state.as_str();
    let ndp_meta = &*format!(
        "{} tracked · scan {}s ago",
        st.services.ndp_monitor.addrs_tracked, st.services.ndp_monitor.last_scan_secs_ago
    );

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: " SERVICES ", color: Color::Yellow, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                // --- CORE ---
                ServiceLine(
                    name: "DB Worker",
                    state: st.services.db_worker.state.as_str(),
                    online_val: "online",
                    meta: "Persistence & I/O"
                )
                ServiceLine(
                    name: "mDNS",
                    state: st.services.mdns_prober.state.as_str(),
                    online_val: "active",
                    meta: "Device Discovery Prober"
                )
                ServiceLine(
                    name: "Iface Mon",
                    state: st.services.iface_monitor.state.as_str(),
                    online_val: "online",
                    meta: "Interface Address Watcher"
                )
                ServiceLine(
                    name: "NDP Mon",
                    state: ndp_state,
                    online_val: "online",
                    meta: ndp_meta
                )
                ServiceLine(
                    name: "Control",
                    state: st.services.control_api.state.as_str(),
                    online_val: "online",
                    meta: "UDS Management API"
                )
                HttpServiceLine(info: st.services.http_api.clone())

                View(margin_top: 1, margin_bottom: 1) {
                    Text(content: "  ────────── Protocols ──────────", color: Color::DarkGrey)
                }

                // --- PROTOCOLS ---
                ServiceLine(
                    name: "RA",
                    state: ra_state,
                    online_val: "online",
                    meta: "Neighbor Discovery & Prefixes"
                )
                ServiceLine(
                    name: "DHCPv4",
                    state: dhcp_v4_state,
                    online_val: "active",
                    meta: dhcp_v4_meta
                )
                ServiceLine(
                    name: "DHCPv6",
                    state: dhcp_v6_state,
                    online_val: "active",
                    meta: dhcp_v6_meta
                )
                ServiceLine(
                    name: "DNS",
                    state: dns_state,
                    online_val: "online",
                    meta: dns_meta
                )
            }
        }
    }.print();

    // -----------------------------------------------------------------------
    // INSIGHTS (Devices & Persistence)
    // -----------------------------------------------------------------------
    let db_size = ByteSize::b(st.db.size_bytes);
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: " INSIGHTS ", color: Color::Yellow, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Devices    ", color: Color::DarkGrey)
                    Text(content: format!("{} / {} online", st.devices.online, st.devices.total), color: Color::Green)
                    Text(content: "  ★", color: Color::DarkGrey)
                    Text(content: format!("{}", st.devices.static_toml), color: Color::DarkGrey)
                    Text(content: "  ·", color: Color::DarkGrey)
                    Text(content: format!("{}", st.devices.managed_cli), color: Color::DarkGrey)
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "SQLite     ", color: Color::DarkGrey)
                    Text(content: db_size.to_string(), color: Color::Cyan)
                    Text(content: "  at ", color: Color::DarkGrey)
                    Text(content: st.db.path.as_str())
                }
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Last Sync  ", color: Color::DarkGrey)
                    Text(content: format!("{} ago", format_uptime(st.db.last_flush_secs_ago)))
                }
            }
        }
    }.print();

    element! {
        View(padding_left: 2, margin_bottom: 1) {
            Text(content: "★ TOML static  · CLI managed", color: Color::DarkGrey)
        }
    }
    .print();
}

#[component]
fn ServiceLine<'a>(props: &ServiceLineProps<'a>) -> impl Into<AnyElement<'a>> {
    let is_online = props.state == props.online_val;
    let color = if is_online { Color::Green } else { Color::Red };

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "● ", color: color)
            Text(content: format!("{:<10}", props.name))
            Text(content: format!("{:<10}", props.state), color: color)
            Text(content: props.meta, color: Color::DarkGrey)
        }
    }
}

#[derive(Default, Props)]
struct ServiceLineProps<'a> {
    name: &'a str,
    state: &'a str,
    online_val: &'a str,
    meta: &'a str,
}

#[component]
fn HttpServiceLine(props: &HttpServiceLineProps) -> impl Into<AnyElement<'_>> {
    if let Some(info) = &props.info {
        element! {
            ServiceLine(
                name: "HTTP API",
                state: info.state.as_str(),
                online_val: "online",
                meta: "REST Interface"
            )
        }
        .into_any()
    } else {
        element! { View() }.into_any()
    }
}

#[derive(Props, Default, Clone)]
struct HttpServiceLineProps {
    pub info: Option<ServiceStatusInfo>,
}
