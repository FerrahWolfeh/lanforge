use colored::Colorize;
use lanforge_types::events::{
    AdminChange, DeviceEvent, DnsEvent, LanforgeEvent, NetworkChange, NetworkEvent, PppoeEvent,
    StorageEvent, SystemEvent,
};
use lanforge_types::{identifiers::MacAddr, update::LeaseTarget};

use super::CliFormat;

impl CliFormat for LanforgeEvent {
    fn format_cli(&self, now: &str, verbose: bool, ascii: bool) {
        match self {
            Self::Device(e) => format_device_event(now, e, verbose, ascii),
            Self::Dns(e) => format_dns_event(now, e, verbose, ascii),
            Self::Network(e) => format_network_event(now, e, ascii),
            Self::Storage(e) => format_storage_event(now, e, ascii),
            Self::System(e) => format_system_event(now, e, verbose, ascii),
            Self::Pppoe(e) => format_pppoe_event(now, e, ascii),
        }
    }
}

fn format_pppoe_event(now: &str, event: &PppoeEvent, _ascii: bool) {
    match event {
        PppoeEvent::SessionUp(session) => {
            let ip_str = session.ipv4.map_or_else(|| "none".to_string(), |ip| ip.to_string());
            let ac_str = session.ac_name.as_deref().unwrap_or("unknown AC");
            println!(
                "[{now}] {} PPPoE Session UP on {} via {} (IP: {}, DNS count: {})",
                "PPPOE".magenta().bold(),
                session.interface.cyan(),
                ac_str.yellow(),
                ip_str.yellow(),
                session.dns.len()
            );
        }
        PppoeEvent::SessionDown { reason } => {
            println!(
                "[{now}] {} PPPoE Session DOWN ({reason})",
                "PPPOE".red().bold()
            );
        }
        PppoeEvent::Reconnecting {
            attempt,
            next_retry_secs,
        } => {
            println!(
                "[{now}] {} PPPoE Reconnecting (attempt {attempt}, next retry in {next_retry_secs}s)",
                "PPPOE".yellow().bold()
            );
        }
        PppoeEvent::AuthFailed { reason } => {
            println!(
                "[{now}] {} PPPoE Authentication Failed ({reason})",
                "PPPOE".red().bold()
            );
        }
        PppoeEvent::KeepaliveWarning {
            consecutive_failures,
            max_failures,
        } => {
            println!(
                "[{now}] {} LCP Echo Keepalive Warning ({consecutive_failures}/{max_failures} missed)",
                "PPPOE".yellow().bold()
            );
        }
        PppoeEvent::KeepaliveRestored => {
            println!(
                "[{now}] {} LCP Echo Keepalive Restored",
                "PPPOE".green().bold()
            );
        }
    }
}

fn format_device_event(now: &str, event: &DeviceEvent, verbose: bool, _ascii: bool) {
    match event {
        DeviceEvent::Discovered { mac, hostname } => {
            let name = hostname
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown");
            println!(
                "[{now}] {} {} {} ({})",
                "NEW".green().bold(),
                "Device discovered:".white(),
                name.bold().bright_yellow(),
                mac.to_string().dimmed()
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
            print_device_update_net(now, *mac, hostname.as_deref(), change, verbose);
        }
        DeviceEvent::AdminUpdate {
            mac,
            hostname,
            change,
        } => {
            print_device_update_admin(now, *mac, hostname.as_deref(), change, verbose);
        }
        DeviceEvent::Expired { mac } => {
            println!(
                "[{now}] {} {} {}",
                "EXP".red().bold(),
                "Device expired:".dimmed(),
                mac.to_string().red()
            );
        }
        DeviceEvent::Purged { mac } => {
            println!(
                "[{now}] {} {} {}",
                "DEL".red().bold(),
                "Device purged:".red().bold(),
                mac.to_string().red()
            );
        }
        DeviceEvent::LeaseRelease { mac, target } => {
            println!(
                "[{now}] {} {} {} ({target:?})",
                "CMD".cyan().bold(),
                "Forced Release:".white(),
                mac
            );
        }
        DeviceEvent::LeaseRenew { mac, target } => {
            println!(
                "[{now}] {} {} {} ({target:?})",
                "CMD".cyan().bold(),
                "Force Renew:".white(),
                mac
            );
        }
        DeviceEvent::DhcpV4Transaction { mac, msg_type, .. } => {
            println!(
                "[{now}] {} {} for {}",
                "DHCP4".blue().bold(),
                format!("{msg_type:?}").bright_magenta().bold(),
                mac.to_string().yellow()
            );
        }
        DeviceEvent::DhcpV6Transaction { mac, msg_type, .. } => {
            println!(
                "[{now}] {} {} for {}",
                "DHCP6".magenta().bold(),
                format!("{msg_type:?}").bright_magenta().bold(),
                mac.to_string().yellow()
            );
        }
        DeviceEvent::NeighborBatchSummary {
            total,
            new,
            duration_ms,
        } => {
            println!(
                "[{now}] {} Scan: {total} total, {} new in {duration_ms}ms",
                "SCAN".cyan().bold(),
                new.to_string().green().bold()
            );
        }
    }
}

fn print_device_update_net(
    now: &str,
    mac: MacAddr,
    hostname: Option<&str>,
    change: &NetworkChange,
    verbose: bool,
) {
    let name = hostname.filter(|s| !s.is_empty()).unwrap_or("unknown");
    match change {
        NetworkChange::ArpActivity { .. } | NetworkChange::NdpActivity { .. } => {
            if verbose {
                let change_str = format_change_net(change);
                println!(
                    "[{now}] {} {} ({}) -> {}",
                    "TRC".dimmed(),
                    name.bright_yellow(),
                    mac.to_string().dimmed(),
                    change_str.dimmed()
                );
            }
        }
        _ => {
            let change_str = format_change_net(change);
            println!(
                "[{now}] {} {} ({}) -> {change_str}",
                "UPD".blue().bold(),
                name.bright_yellow(),
                mac.to_string().dimmed()
            );
        }
    }
}

fn print_device_update_admin(
    now: &str,
    mac: MacAddr,
    hostname: Option<&str>,
    change: &AdminChange,
    _verbose: bool,
) {
    let name = hostname.filter(|s| !s.is_empty()).unwrap_or("unknown");
    let change_str = format_change_admin(change);
    println!(
        "[{now}] {} {} ({}) -> {change_str}",
        "UPD".blue().bold(),
        name.bright_yellow(),
        mac.to_string().dimmed()
    );
}

fn format_dns_event(now: &str, event: &DnsEvent, verbose: bool, _ascii: bool) {
    match event {
        DnsEvent::AdblockToggle {
            enabled,
            duration_secs,
        } => {
            let status = if *enabled {
                "ENABLED".green().bold()
            } else {
                "DISABLED".red().bold()
            };
            let suffix = duration_secs
                .map(|s| format!(" for {s}s"))
                .unwrap_or_default();
            println!("[{now}] {status} DNS Adblocker{suffix}");
        }
        DnsEvent::AdblockReload => {
            println!("[{now}] {} Reloading blocklists...", "DNS".cyan().bold());
        }
        DnsEvent::QueryBlocked { src_addr, domain } if verbose => {
            println!(
                "[{now}] {} {} -> {}",
                "BLOCK".red().bold(),
                src_addr.to_string().bright_cyan(),
                domain.bright_red()
            );
        }
        DnsEvent::QueryResolved(entry) if verbose => {
            println!(
                "[{now}] {} {} -> {} ({:?})",
                "DNS".cyan().bold(),
                entry.src_ip.to_string().bright_cyan(),
                entry.domain.bright_yellow(),
                entry.result
            );
        }
        _ => {}
    }
}

fn format_network_event(now: &str, event: &NetworkEvent, _ascii: bool) {
    match event {
        NetworkEvent::WolTriggered { mac, .. } => {
            println!(
                "[{now}] {} {} {}",
                "WOL".bright_green().bold(),
                "Wake-on-LAN sent to:".white(),
                mac.to_string().bright_yellow()
            );
        }
        NetworkEvent::PrefixChanged {
            gua,
            preferred,
            valid,
            ula,
        } => {
            if let Some(u) = ula {
                println!(
                    "[{now}] {} {} {u:?} (pref={preferred}, valid={valid})",
                    "NET".magenta().bold(),
                    "ULA Prefix changed:".white()
                );
            } else {
                println!(
                    "[{now}] {} {} {gua:?} (pref={preferred}, valid={valid})",
                    "NET".magenta().bold(),
                    "GUA Prefix changed:".white()
                );
            }
        }

        NetworkEvent::InterfaceUpdated { ifindex } => {
            println!(
                "[{now}] {} {} (ifindex={ifindex})",
                "NET".magenta().bold(),
                "Local interface IP configuration changed".white()
            );
        }
        NetworkEvent::RsReceived { mac } => {
            println!(
                "[{now}] {} {} ({mac})",
                "NET".magenta().bold(),
                "Router Solicitation:".white()
            );
        }

        NetworkEvent::LeaseRenewRequested { mac, target } => {
            let tag = match target {
                Some(LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. }) => {
                    "DHCP6".magenta().bold()
                }
                _ => "DHCP4".blue().bold(),
            };
            let target_str = target
                .as_ref()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            println!(
                "[{now}] {tag} {} {mac}{target_str}",
                "Lease Renew Requested:".white()
            );
        }
        NetworkEvent::LeaseReleaseRequested { mac, target } => {
            let tag = match target {
                Some(LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. }) => {
                    "DHCP6".magenta().bold()
                }
                _ => "DHCP4".blue().bold(),
            };
            let target_str = target
                .as_ref()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            println!(
                "[{now}] {tag} {} {mac}{target_str}",
                "Lease Release Requested:".white()
            );
        }
        NetworkEvent::RaTriggerRequested => {
            println!(
                "[{now}] {} {}",
                "RA".magenta().bold(),
                "Immediate advertisement burst requested".white()
            );
        }
    }

}

fn format_storage_event(now: &str, event: &StorageEvent, _ascii: bool) {
    match event {
        StorageEvent::DbVacuum => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Database VACUUM requested".dimmed()
        ),
        StorageEvent::DbLogClean => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Transient logs cleared manually".dimmed()
        ),
        StorageEvent::DbWrite { devices } => println!(
            "[{now}] {} {} ({devices} devices)",
            "SYS".yellow().bold(),
            "Main database persisted".white()
        ),
        StorageEvent::DbPrune => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Zombie devices manually pruned from DB".dimmed()
        ),
        StorageEvent::DbReset => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "System-wide database reset requested!".red().bold()
        ),
        StorageEvent::DbResetCompleted => println!(
            "[{now}] {} {}",
            "SYS".green().bold(),
            "Database reset completed. Reloading state...".bright_green()
        ),
        StorageEvent::TableDirty => {}
    }
}

fn format_system_event(now: &str, event: &SystemEvent, verbose: bool, _ascii: bool) {
    match event {
        SystemEvent::ReloadConfig => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Config reload requested".dimmed()
        ),
        SystemEvent::StateReady => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Internal state ready".white()
        ),
        SystemEvent::DbReady => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Database engine ready".white()
        ),
        SystemEvent::InterfaceReady => println!(
            "[{now}] {} {}",
            "SYS".yellow().bold(),
            "Network interfaces ready".white()
        ),
        SystemEvent::ServiceReady { name } => println!(
            "[{now}] {} {} {name}",
            "SYS".yellow().bold(),
            "Service ready:".white()
        ),
        SystemEvent::SystemReady => println!(
            "[{now}] {} {}",
            "SYS".green().bold(),
            "System fully operational!".bright_green().bold()
        ),
        SystemEvent::ConfigUpdate { .. } => {
            if verbose {
                println!(
                    "[{now}] {} API configuration updated",
                    "CFG".magenta().bold()
                );
            }
        }
        SystemEvent::Shutdown => println!(
            "[{now}] {} {}",
            "SYS".red().bold(),
            "Daemon is shutting down...".dimmed()
        ),
        SystemEvent::ServiceStatusBanner(banner) => {
            if verbose {
                println!(
                    "[{now}] {} Service status broadcast: {} is {}",
                    "SYS".yellow().bold(),
                    banner.name.white(),
                    banner.state.as_str().bright_green()
                );
            }
        }
        SystemEvent::ServiceControl { id, action } => {
            if verbose {
                println!(
                    "[{now}] {} Service control action on {}: {:?}",
                    "SYS".yellow().bold(),
                    id.white(),
                    action
                );
            }
        }
        SystemEvent::ConfigDhcpV4Changed
        | SystemEvent::ConfigDhcpV6Changed
        | SystemEvent::ConfigRaChanged
        | SystemEvent::ConfigTftpChanged
        | SystemEvent::ConfigDhcpOptionsChanged => {
            if verbose {
                let service = match event {
                    SystemEvent::ConfigDhcpV4Changed => "DHCPv4",
                    SystemEvent::ConfigDhcpV6Changed => "DHCPv6",
                    SystemEvent::ConfigRaChanged => "RA",
                    SystemEvent::ConfigTftpChanged => "TFTP",
                    SystemEvent::ConfigDhcpOptionsChanged => "DHCP Options",
                    _ => unreachable!(),
                };
                println!(
                    "[{now}] {} {service} configuration updated in database",
                    "CFG".magenta().bold()
                );
            }
        }
    }
}

fn format_change_net(change: &NetworkChange) -> String {
    match change {
        NetworkChange::V4Assigned { ip } => {
            format!("IPv4 assigned: {}", ip.to_string().bright_cyan())
        }
        NetworkChange::LeaseExpired { target } => {
            let target_str = match target {
                LeaseTarget::V4 => "IPv4 lease".to_string(),
                LeaseTarget::V6 { iaid } => {
                    format!("IPv6 lease (IAID: {iaid})")
                }
                LeaseTarget::V6Prefix { iaid } => {
                    format!("IPv6 Prefix (IAID: {iaid})")
                }
            };
            format!("{target_str} expired").dimmed().to_string()
        }
        NetworkChange::SlaacObserved { addr } => {
            format!(
                "{} {}",
                "New SLAAC discovered:".bold(),
                addr.to_string().bright_magenta()
            )
        }
        NetworkChange::DuidAssociated { duid } => {
            format!("DUID associated: {}", duid.to_string().cyan())
        }
        NetworkChange::V6Assigned { ip, .. } => {
            format!("IPv6 assigned: {}", ip.to_string().bright_cyan())
        }
        NetworkChange::V6PrefixAssigned { prefix, len, .. } => {
            format!(
                "IA_PD assigned: {}/{}",
                prefix.to_string().bright_cyan(),
                len
            )
        }
        NetworkChange::NdpActivity { ip } => {
            format!("IPv6 activity at {}", ip.to_string().bright_magenta())
        }
        NetworkChange::ArpActivity { ip } => {
            format!("Neighbor seen at {}", ip.to_string().bright_cyan())
        }
        NetworkChange::StatusChanged { online, .. } => {
            if *online {
                format!("is now {}", "Online".bright_green().bold())
            } else {
                format!("has gone {}", "Offline".red().bold())
            }
        }

        NetworkChange::IpDeleted { ip } => {
            format!("IP deleted: {}", ip.to_string().red())
        }
        NetworkChange::IpOffline { ip } => {
            format!("IP offline: {}", ip.to_string().yellow())
        }
        NetworkChange::HostnameHint { hostname } => {
            format!("Hostname hint: {}", hostname.cyan())
        }
    }
}

fn format_change_admin(change: &AdminChange) -> String {
    match change {
        AdminChange::CliHostUpdated => "Host updated via CLI".bright_blue().to_string(),
        AdminChange::HostnameChanged { hostname } => {
            format!("Static Hostname: {}", hostname.bold())
        }
        AdminChange::V4StaticChanged { ip } => ip.as_ref().map_or_else(
            || "Static IPv4 removed".dimmed().to_string(),
            |v| format!("Static IPv4 set: {}", v.to_string().bright_green()),
        ),
        AdminChange::V6SuffixChanged { suffix } => suffix.as_ref().map_or_else(
            || "Static IPv6 suffix removed".dimmed().to_string(),
            |s| format!("Static IPv6 suffix set: {}", s.to_string().bold()),
        ),
        AdminChange::Classified { class } => {
            format!(
                "classified as {}",
                class.as_str().to_string().bright_magenta().bold()
            )
        }
        AdminChange::HostRemoved => "Host removed".red().to_string(),
    }
}
