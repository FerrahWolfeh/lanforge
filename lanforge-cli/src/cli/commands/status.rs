use super::format_uptime;
use crate::cli::{Execute, LanforgeClient};
use bytesize::ByteSize;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::ServiceStatusInfo;
use lanforge_api::api::StatusResponse;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct StatusArgs {}

impl Execute for StatusArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let st = client.status().await?;
        if client.json {
            println!("{}", serde_json::to_string_pretty(&st)?);
            return Ok(());
        }
        render_status(&st, client.ascii);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ServicesArgs {}

impl Execute for ServicesArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.service_banners().await?;
        if client.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        render_services_in_depth(&resp, client.ascii);
        Ok(())
    }
}

pub fn render_services_in_depth(resp: &lanforge_api::api::ServiceBannersResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" RUNNING SERVICES (DEEP-DIVE) \n");
    println!(
        "  {:<20} | {:<10} | {:<15} | STATS & METRICS",
        "NAME", "STATE", "UPTIME"
    );
    println!("{}", hline.repeat(90));
    for banner in &resp.banners {
        let uptime_str = format_uptime(banner.uptime_secs);
        let stats_str = banner
            .stats
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {:<20} | {:<10} | {:<15} | {}",
            banner.name, banner.state, uptime_str, stats_str
        );
    }
}

pub fn render_status(st: &StatusResponse, ascii: bool) {
    render_header(st);
    render_infrastructure(st, ascii);
    render_services(st, ascii);
    render_insights(st, ascii);

    let star = if ascii { "*" } else { "★" };
    element! {
        View(padding_left: 2, margin_bottom: 1) {
            Text(content: format!("{star} TOML static  · CLI managed"), color: Color::DarkGrey)
        }
    }
    .print();
}

fn render_header(st: &StatusResponse) {
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
}

fn render_infrastructure(st: &StatusResponse, ascii: bool) {
    let gua = st.network.gua.as_deref().unwrap_or("stabilizing...");
    let ula = st.network.ula.as_deref().unwrap_or("unavailable");
    let ipv4 = st
        .network
        .lan_ipv4_cidr
        .as_deref()
        .unwrap_or_else(|| st.network.lan_ipv4.as_deref().unwrap_or("—"));
    let rss = ByteSize::b(st.resources.memory_rss_bytes);
    let border = if ascii {
        BorderStyle::Classic
    } else {
        BorderStyle::Round
    };

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: " INFRASTRUCTURE ", color: Color::Yellow, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
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
}

fn render_services(st: &StatusResponse, ascii: bool) {
    let border = if ascii {
        BorderStyle::Classic
    } else {
        BorderStyle::Round
    };
    let hline = if ascii { "-" } else { "─" };

    if st.service_banners.is_empty() {
        let ndp_meta = format!(
            "{} tracked · scan {}s ago",
            st.services.ndp_monitor.addrs_tracked, st.services.ndp_monitor.last_scan_secs_ago
        );
        let dhcp_v4_meta = format!(
            "{} leases · {} free",
            st.services.dhcp_v4.leases_active, st.services.dhcp_v4.pool_free
        );
        let dhcp_v6_meta = format!(
            "{} leases · prefix delegation",
            st.services.dhcp_v6.leases_active
        );
        let dns_meta = format!(
            "upstream {}",
            st.services.dns.upstream.as_deref().unwrap_or("—")
        );

        element! {
            View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " SERVICES ", color: Color::Yellow, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                    ServiceLine(name: "DB Worker", state: st.services.db_worker.state.as_str(), online_val: "online", meta: "Persistence & I/O", ascii: ascii)
                    ServiceLine(name: "mDNS", state: st.services.mdns_prober.state.as_str(), online_val: "active", meta: "Device Discovery Prober", ascii: ascii)
                    ServiceLine(name: "Iface Mon", state: st.services.iface_monitor.state.as_str(), online_val: "online", meta: "Interface Address Watcher", ascii: ascii)
                    ServiceLine(
                        name: "NDP Mon",
                        state: st.services.ndp_monitor.state.as_str(),
                        online_val: "online",
                        meta: ndp_meta.as_str(),
                        ascii: ascii
                    )
                    ServiceLine(name: "Control", state: st.services.control_api.state.as_str(), online_val: "online", meta: "UDS Management API", ascii: ascii)
                    HttpServiceLine(info: st.services.http_api.clone(), ascii: ascii)

                    View(margin_top: 1, margin_bottom: 1) {
                        Text(content: format!("  {0}{0}{0}{0}{0}{0}{0}{0}{0}{0} Protocols {0}{0}{0}{0}{0}{0}{0}{0}{0}{0}", hline), color: Color::DarkGrey)
                    }

                    ServiceLine(name: "RA", state: st.services.ra.state.as_str(), online_val: "online", meta: "Neighbor Discovery & Prefixes", ascii: ascii)
                    ServiceLine(
                        name: "DHCPv4",
                        state: st.services.dhcp_v4.state.as_str(),
                        online_val: "active",
                        meta: dhcp_v4_meta.as_str(),
                        ascii: ascii
                    )
                    ServiceLine(
                        name: "DHCPv6",
                        state: st.services.dhcp_v6.state.as_str(),
                        online_val: "active",
                        meta: dhcp_v6_meta.as_str(),
                        ascii: ascii
                    )
                    ServiceLine(
                        name: "DNS",
                        state: st.services.dns.state.as_str(),
                        online_val: "online",
                        meta: dns_meta.as_str(),
                        ascii: ascii
                    )
                }
            }
        }.print();
    } else {
        let metas: Vec<String> = st
            .service_banners
            .iter()
            .map(|banner| format!("uptime: {}", format_uptime(banner.uptime_secs)))
            .collect();

        element! {
            View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " SERVICES ", color: Color::Yellow, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                    #(st.service_banners.iter().zip(metas.iter()).map(|(banner, meta)| element! {
                        ServiceLine(
                            name: banner.name.as_str(),
                            state: banner.state.as_str(),
                            online_val: "online",
                            meta: meta.as_str(),
                            ascii: ascii
                        )
                    }))
                }
            }
        }.print();
    }
}

fn render_insights(st: &StatusResponse, ascii: bool) {
    let db_size = ByteSize::b(st.db.size_bytes);
    let border = if ascii {
        BorderStyle::Classic
    } else {
        BorderStyle::Round
    };
    let star = if ascii { "*" } else { "★" };

    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: " INSIGHTS ", color: Color::Yellow, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                View(flex_direction: FlexDirection::Row) {
                    Text(content: "Devices    ", color: Color::DarkGrey)
                    Text(content: format!("{} / {} online", st.devices.online, st.devices.total), color: Color::Green)
                    Text(content: format!("  {star}"), color: Color::DarkGrey)
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
}

#[component]
fn ServiceLine<'a>(props: &ServiceLineProps<'a>) -> impl Into<AnyElement<'a>> {
    let is_online = props.state == props.online_val;
    let color = if is_online { Color::Green } else { Color::Red };
    let bullet = if props.ascii { "*" } else { "●" };

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: format!("{bullet} "), color: color)
            Text(content: format!("{:<15}", props.name))
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
    ascii: bool,
}

#[component]
fn HttpServiceLine(props: &HttpServiceLineProps) -> impl Into<AnyElement<'_>> {
    let ascii = props.ascii;
    props.info.as_ref().map_or_else(
        || element! { View() }.into_any(),
        |info| {
            element! {
                ServiceLine(
                    name: "HTTP API",
                    state: info.state.as_str(),
                    online_val: "online",
                    meta: "REST Interface",
                    ascii: ascii
                )
            }
            .into_any()
        },
    )
}

#[derive(Props, Default, Clone)]
struct HttpServiceLineProps {
    pub info: Option<ServiceStatusInfo>,
    pub ascii: bool,
}
