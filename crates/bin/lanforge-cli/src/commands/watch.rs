use std::io::ErrorKind;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use color_eyre::eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::Printer;
use lanforge_api::rpc::{LanforgeRpcError, RpcResponse};
use lanforge_types::device::DeviceStatus;
use lanforge_types::events::{
    AdminChange, DeviceEvent, DnsEvent, FirewallEvent, LanforgeEvent, NetworkChange, NetworkEvent,
    PppoeEvent, StorageEvent, SystemEvent, TimedEvent,
};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchArgs {
    /// Show verbose background and discovery activity (e.g. neighbor scans)
    #[arg(short, long)]
    pub verbose: bool,
}

impl WatchArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        #[cfg(feature = "remote")]
        if client.remote.is_some() {
            return stream_remote_events(client, printer, self.verbose).await;
        }

        stream_uds_events(client, printer, self.verbose).await
    }
}

async fn stream_uds_events(
    client: &LanforgeClient,
    printer: &Printer,
    verbose: bool,
) -> Result<()> {
    let mut rpc = client.connect_rpc().await?;
    rpc.log(true, None, None)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("{e}"))?;

    if !printer.json {
        println!(
            "{}",
            "● Watching live daemon events... (Ctrl+C to stop)\n"
                .cyan()
                .bold()
        );
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if !printer.json {
                    println!("\nStopped watching events.");
                }
                break;
            }
            resp = rpc.next_response() => {
                match resp {
                    Ok(RpcResponse::Event(event)) => {
                        render_event(&event, printer, verbose);
                    }
                    Ok(RpcResponse::Error(err)) => {
                        printer.error(&format!("Daemon error: {err}"));
                    }
                    Ok(_) => {}
                    Err(LanforgeRpcError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                        if !printer.json {
                            println!("Connection closed by daemon.");
                        }
                        break;
                    }
                    Err(e) => {
                        printer.error(&format!("Stream error: {e}"));
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "remote")]
async fn stream_remote_events(
    client: &LanforgeClient,
    printer: &Printer,
    verbose: bool,
) -> Result<()> {
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::{Method, Request, Uri};

    let base = client.remote.as_ref().unwrap();
    let url = format!("{base}/api/v1/events?follow=true");
    let uri: Uri = url.parse()?;

    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(t) = &client.token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }

    let req = builder.body(http_body_util::Full::<Bytes>::default())?;
    let resp = client.http_client.request(req).await?;

    if !printer.json {
        println!(
            "{}",
            "● Watching remote daemon events... (Ctrl+C to stop)\n"
                .cyan()
                .bold()
        );
    }

    let mut body = resp.into_body();
    let mut buffer = String::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if !printer.json {
                    println!("\nStopped watching events.");
                }
                break;
            }
            frame = body.frame() => {
                let Some(frame) = frame else { break; };
                let frame = frame?;
                if let Some(data) = frame.data_ref() {
                    buffer.push_str(&String::from_utf8_lossy(data));
                    while let Some(pos) = buffer.find("\n\n") {
                        let block = buffer[..pos].to_string();
                        buffer.drain(..pos + 2);

                        for line in block.lines() {
                            if let Some(json_str) = line.strip_prefix("data: ")
                                && let Ok(event) = serde_json::from_str::<TimedEvent>(json_str)
                            {
                                render_event(&event, printer, verbose);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn render_event(e: &TimedEvent, printer: &Printer, verbose: bool) {
    if printer.json {
        if let Ok(json_str) = serde_json::to_string(e) {
            println!("{json_str}");
        }
        return;
    }

    let time_str = format_time(e.timestamp);

    match &e.event {
        LanforgeEvent::Device(dev_evt) => render_device_event(&time_str, dev_evt, printer, verbose),
        LanforgeEvent::Pppoe(pppoe_evt) => render_pppoe_event(&time_str, pppoe_evt, printer),
        LanforgeEvent::Firewall(fw_evt) => render_firewall_event(&time_str, fw_evt, printer),
        LanforgeEvent::Dns(dns_evt) => render_dns_event(&time_str, dns_evt, printer),
        LanforgeEvent::System(sys_evt) => render_system_event(&time_str, sys_evt, printer),
        LanforgeEvent::Network(net_evt) => render_network_event(&time_str, net_evt, printer),
        LanforgeEvent::Storage(storage_evt) => {
            render_storage_event(&time_str, storage_evt, printer)
        }
        LanforgeEvent::Traffic(_) => {}
    }
}

fn format_time(ts: SystemTime) -> String {
    let dt: DateTime<Local> = ts.into();
    dt.format("%H:%M:%S").to_string()
}

fn render_device_event(time_str: &str, evt: &DeviceEvent, printer: &Printer, verbose: bool) {
    match evt {
        DeviceEvent::Discovered { mac, hostname } => {
            let host = hostname.as_deref().unwrap_or("<unknown>");
            print_log(
                time_str,
                "DEVICE",
                "NEW".green().bold(),
                format!("{host} ({mac})"),
                printer,
            );
        }
        DeviceEvent::NetworkUpdate {
            mac,
            hostname,
            change,
        }
        | DeviceEvent::NetworkActivity {
            mac,
            hostname,
            change,
        } => {
            let is_activity = matches!(evt, DeviceEvent::NetworkActivity { .. });
            if is_activity && !verbose {
                return;
            }

            let host = hostname.as_deref().unwrap_or("<unknown>");
            let change_desc = match &**change {
                NetworkChange::V4Assigned { ip } => {
                    format!("IPv4 assigned: {}", ip.to_string().yellow())
                }
                NetworkChange::V6Assigned { ip, .. } => {
                    format!("IPv6 assigned: {}", ip.to_string().yellow())
                }
                NetworkChange::V6PrefixAssigned { prefix, len, .. } => {
                    format!("IPv6 prefix delegated: {prefix}/{len}")
                }
                NetworkChange::LeaseExpired { target } => {
                    format!("Lease expired ({target:?})").red().to_string()
                }
                NetworkChange::SlaacObserved { addr } => format!("Observed SLAAC: {addr}"),
                NetworkChange::StatusChanged { status, .. } => match status {
                    DeviceStatus::Online => "Device online".green().to_string(),
                    DeviceStatus::Stale => "Device stale".yellow().to_string(),
                    DeviceStatus::Offline => "Device offline".red().to_string(),
                },
                NetworkChange::HostnameHint { hostname } => format!("Hostname updated: {hostname}"),
                NetworkChange::DuidAssociated { duid } => format!("DUID associated: {duid}"),
                NetworkChange::NdpActivity { ip } => {
                    if !verbose {
                        return;
                    }
                    format!("NDP activity: {ip}")
                }
                NetworkChange::ArpActivity { ip } => {
                    if !verbose {
                        return;
                    }
                    format!("ARP activity: {ip}")
                }
                NetworkChange::IpDeleted { ip } => format!("IP removed: {ip}").red().to_string(),
                NetworkChange::IpOffline { ip } => format!("IP offline: {ip}").dimmed().to_string(),
            };

            print_log(
                time_str,
                "DEVICE",
                "UPDATE".cyan(),
                format!("{host} ({mac}) -> {change_desc}"),
                printer,
            );
        }
        DeviceEvent::AdminUpdate {
            mac,
            hostname,
            change,
        } => {
            let host = hostname.as_deref().unwrap_or("<unknown>");
            let desc = match &**change {
                AdminChange::CliHostUpdated => "CLI config updated".to_string(),
                AdminChange::HostnameChanged { hostname } => format!("Hostname set to: {hostname}"),
                AdminChange::V4StaticChanged { ip } => format!("Static IPv4 set to: {ip:?}"),
                AdminChange::V6SuffixChanged { suffix } => {
                    format!("Static IPv6 suffix set to: {suffix:?}")
                }
                AdminChange::Classified { class } => format!("Classified as: {class:?}"),
                AdminChange::HostRemoved => "Static host removed".red().to_string(),
            };
            print_log(
                time_str,
                "DEVICE",
                "CONFIG".blue().bold(),
                format!("{host} ({mac}) -> {desc}"),
                printer,
            );
        }
        DeviceEvent::Expired { mac } => {
            print_log(
                time_str,
                "DEVICE",
                "EXPIRED".red(),
                mac.to_string(),
                printer,
            );
        }
        DeviceEvent::Purged { mac } => {
            print_log(
                time_str,
                "DEVICE",
                "PURGED".red().bold(),
                mac.to_string(),
                printer,
            );
        }
        DeviceEvent::DhcpV4Transaction {
            mac,
            msg_type,
            details,
        } => {
            let det = details.as_deref().unwrap_or("");
            print_log(
                time_str,
                "DHCPv4",
                format!("{msg_type:?}").magenta().bold(),
                format!("{mac} {det}"),
                printer,
            );
        }
        DeviceEvent::DhcpV6Transaction {
            mac,
            msg_type,
            details,
        } => {
            let det = details.as_deref().unwrap_or("");
            print_log(
                time_str,
                "DHCPv6",
                format!("{msg_type:?}").magenta().bold(),
                format!("{mac} {det}"),
                printer,
            );
        }
        DeviceEvent::LeaseRelease { mac, target } => {
            print_log(
                time_str,
                "DHCP",
                "RELEASE".yellow(),
                format!("{mac} target={target:?}"),
                printer,
            );
        }
        DeviceEvent::LeaseRenew { mac, target } => {
            print_log(
                time_str,
                "DHCP",
                "RENEW".green(),
                format!("{mac} target={target:?}"),
                printer,
            );
        }
        DeviceEvent::NeighborBatchSummary {
            total,
            new,
            duration_ms,
        } => {
            if verbose || *new > 0 {
                print_log(
                    time_str,
                    "DISCOVERY",
                    "SCAN".dimmed(),
                    format!("Scanned {total} neighbors ({new} new) in {duration_ms}ms"),
                    printer,
                );
            }
        }
    }
}

fn render_pppoe_event(time_str: &str, evt: &PppoeEvent, printer: &Printer) {
    match evt {
        PppoeEvent::SessionUp(session) => {
            let ip_str = session
                .ipv4
                .map_or_else(|| "none".to_string(), |ip| ip.to_string());
            let ac_str = session.ac_name.as_deref().unwrap_or("unknown AC");
            print_log(
                time_str,
                "PPPOE",
                "UP".green().bold(),
                format!(
                    "Connected on {} via {} (IP: {}, DNS: {})",
                    session.interface,
                    ac_str,
                    ip_str.yellow(),
                    session.dns.len()
                ),
                printer,
            );
        }
        PppoeEvent::SessionDown { reason } => {
            print_log(
                time_str,
                "PPPOE",
                "DOWN".red().bold(),
                reason.clone(),
                printer,
            );
        }
        PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        } => {
            print_log(
                time_str,
                "PPPOE",
                "RETRY".yellow().bold(),
                format!("Attempt {attempt}, next retry in {next_retry_secs}s"),
                printer,
            );
        }
        PppoeEvent::AuthFailed { reason } => {
            print_log(
                time_str,
                "PPPOE",
                "AUTH FAIL".red().bold(),
                reason.clone(),
                printer,
            );
        }
        PppoeEvent::KeepaliveWarning {
            consecutive_failures,
            max_failures,
        } => {
            print_log(
                time_str,
                "PPPOE",
                "LCP WARN".yellow(),
                format!("{consecutive_failures}/{max_failures} echo keepalives missed"),
                printer,
            );
        }
        PppoeEvent::KeepaliveRestored => {
            print_log(
                time_str,
                "PPPOE",
                "LCP OK".green(),
                "Echo keepalive restored".to_string(),
                printer,
            );
        }
    }
}

fn render_firewall_event(time_str: &str, evt: &FirewallEvent, printer: &Printer) {
    match evt {
        FirewallEvent::RulesetApplied(summary) => {
            let wan_desc = summary.wan_iface.as_deref().unwrap_or("none");
            print_log(
                time_str,
                "FIREWALL",
                "APPLIED".green().bold(),
                format!(
                    "Ruleset applied: {} rules on table '{}' (WAN: {wan_desc})",
                    summary.rules_count, summary.table
                ),
                printer,
            );
        }
        FirewallEvent::ApplyFailed { error } => {
            print_log(
                time_str,
                "FIREWALL",
                "ERROR".red().bold(),
                format!("Apply failed: {error}"),
                printer,
            );
        }
        FirewallEvent::RulesetFlushed => {
            print_log(
                time_str,
                "FIREWALL",
                "FLUSHED".yellow(),
                "Ruleset flushed".to_string(),
                printer,
            );
        }
        FirewallEvent::RulesetChanged => {
            print_log(
                time_str,
                "FIREWALL",
                "CHANGED".cyan(),
                "Ruleset modification queued".to_string(),
                printer,
            );
        }
        FirewallEvent::PortOpenRequested(req) => {
            print_log(
                time_str,
                "FIREWALL",
                "PORT OPEN".cyan(),
                format!("{req:?}"),
                printer,
            );
        }
        FirewallEvent::PortReleaseRequested {
            service,
            port,
            protocol,
        } => {
            print_log(
                time_str,
                "FIREWALL",
                "PORT REL".dimmed(),
                format!("{service} {protocol:?}/{port}"),
                printer,
            );
        }
    }
}

fn render_dns_event(time_str: &str, evt: &DnsEvent, printer: &Printer) {
    match evt {
        DnsEvent::AdblockToggle {
            enabled,
            duration_secs,
        } => {
            let state = if *enabled { "Enabled" } else { "Paused" };
            let dur = duration_secs.map_or(String::new(), |d| format!(" for {d}s"));
            print_log(
                time_str,
                "DNS",
                "ADBLOCK".magenta(),
                format!("{state}{dur}"),
                printer,
            );
        }
        DnsEvent::AdblockReload => {
            print_log(
                time_str,
                "DNS",
                "ADBLOCK".magenta(),
                "Adblock rules reloaded".to_string(),
                printer,
            );
        }
        DnsEvent::AdblockBlock(domain) => {
            print_log(
                time_str,
                "DNS",
                "BLOCK".red(),
                format!("Domain blocked: {domain}"),
                printer,
            );
        }
        DnsEvent::AdblockAllow(domain) => {
            print_log(
                time_str,
                "DNS",
                "ALLOW".green(),
                format!("Domain allowed: {domain}"),
                printer,
            );
        }
        DnsEvent::QueryBlocked { src_addr, domain } => {
            print_log(
                time_str,
                "DNS",
                "BLOCKED".red(),
                format!("{domain} from {src_addr}"),
                printer,
            );
        }
        DnsEvent::CacheFlush => {
            print_log(
                time_str,
                "DNS",
                "CACHE".yellow(),
                "DNS cache flushed".to_string(),
                printer,
            );
        }
        DnsEvent::ConfigRewritesChanged => {
            print_log(
                time_str,
                "DNS",
                "REWRITE".cyan(),
                "DNS rewrite rules updated".to_string(),
                printer,
            );
        }
        DnsEvent::ConfigUpstreamsChanged => {
            print_log(
                time_str,
                "DNS",
                "UPSTREAM".cyan(),
                "DNS upstream resolvers updated".to_string(),
                printer,
            );
        }
        _ => {}
    }
}

fn render_system_event(time_str: &str, evt: &SystemEvent, printer: &Printer) {
    match evt {
        SystemEvent::SystemReady => {
            print_log(
                time_str,
                "SYSTEM",
                "READY".green().bold(),
                "All daemon services online and initialized".to_string(),
                printer,
            );
        }
        SystemEvent::ReloadConfig => {
            print_log(
                time_str,
                "SYSTEM",
                "RELOAD".yellow().bold(),
                "Configuration reload signal absorbed".to_string(),
                printer,
            );
        }
        SystemEvent::Shutdown => {
            print_log(
                time_str,
                "SYSTEM",
                "SHUTDOWN".red().bold(),
                "Daemon shutdown initiated".to_string(),
                printer,
            );
        }
        SystemEvent::ServiceStatusBanner(banner) => {
            print_log(
                time_str,
                "SERVICE",
                printer.service_badge(banner.state.as_str()),
                format!("{} ({})", banner.name, banner.id),
                printer,
            );
        }
        SystemEvent::ServiceControl { id, action } => {
            print_log(
                time_str,
                "SERVICE",
                "ACTION".cyan(),
                format!("{id}: {action:?}"),
                printer,
            );
        }
        _ => {}
    }
}

fn render_network_event(time_str: &str, evt: &NetworkEvent, printer: &Printer) {
    match evt {
        NetworkEvent::PrefixChanged(prefix) => {
            print_log(
                time_str,
                "NETWORK",
                "PREFIX".magenta(),
                format!(
                    "IPv6 prefix changed (GUA: {:?}, ULA: {:?})",
                    prefix.gua, prefix.ula
                ),
                printer,
            );
        }
        NetworkEvent::InterfaceUpdated { ifindex } => {
            print_log(
                time_str,
                "NETWORK",
                "IFACE".blue(),
                format!("Interface ifindex {ifindex} status updated"),
                printer,
            );
        }
        NetworkEvent::WolTriggered { mac, .. } => {
            print_log(
                time_str,
                "NETWORK",
                "WOL".green().bold(),
                format!("Wake-on-LAN magic packet sent to {mac}"),
                printer,
            );
        }
        _ => {}
    }
}

fn render_storage_event(time_str: &str, evt: &StorageEvent, printer: &Printer) {
    match evt {
        StorageEvent::DbLogClean => {
            print_log(
                time_str,
                "DATABASE",
                "CLEAN".cyan(),
                "Old audit logs pruned".to_string(),
                printer,
            );
        }
        StorageEvent::DbReset => {
            print_log(
                time_str,
                "DATABASE",
                "RESET".red().bold(),
                "Database reset initiated".to_string(),
                printer,
            );
        }
        StorageEvent::DbResetCompleted => {
            print_log(
                time_str,
                "DATABASE",
                "RESET OK".green().bold(),
                "Database reset completed".to_string(),
                printer,
            );
        }
        _ => {}
    }
}

fn print_log(
    time_str: &str,
    domain: &str,
    tag: impl std::fmt::Display,
    msg: impl std::fmt::Display,
    printer: &Printer,
) {
    if printer.no_color {
        println!("[{time_str}] [{domain:<8}] [{tag:<8}] {msg}");
    } else {
        println!(
            "{} {:<10} {:<12} {}",
            format!("[{time_str}]").dimmed(),
            format!("[{domain}]").bold().white(),
            format!("[{tag}]"),
            msg
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_types::events::PppoeSessionUp;
    use lanforge_types::identifiers::MacAddr;

    #[test]
    fn test_render_various_events() {
        let printer = Printer::new(false, false, false);

        let dev_event = TimedEvent::new(LanforgeEvent::Device(DeviceEvent::Discovered {
            mac: MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            hostname: Some("my-phone".to_string()),
        }));
        render_event(&dev_event, &printer, false);

        let pppoe_event = TimedEvent::new(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
            PppoeSessionUp {
                interface: "ppp0".to_string(),
                ac_mac: None,
                ac_name: Some("BRAS-01".to_string()),
                session_id: 1,
                mru: 1492,
                ipv4: Some("100.64.0.1".parse().unwrap()),
                ipv4_peer: None,
                dns: vec![],
                ipv6_link_local: true,
            },
        ))));
        render_event(&pppoe_event, &printer, false);

        let fw_event = TimedEvent::new(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
        render_event(&fw_event, &printer, false);

        let json_printer = Printer::new(true, false, false);
        render_event(&dev_event, &json_printer, false);
    }
}
