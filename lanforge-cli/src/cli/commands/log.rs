use super::CliCommand;
use chrono::DateTime;
use chrono::Local;
use color_eyre::eyre::Result;
use colored::Colorize;
use lanforge_api::api::Response;
use lanforge_api::api::SimpleSuccess;
use lanforge_api::api::{Command as ControlCommand, CommandAction};
use lanforge_core::bus::TimedEvent;
use lanforge_core::bus::{
    DeviceChange, DeviceEvent, DnsEvent, LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent,
};
use lanforge_core::context::state::LeaseTarget;

pub struct LogHandler {
    pub follow: bool,
    pub verbose: bool,
    pub lines: usize,
}

impl CliCommand for LogHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::new(CommandAction::Log {
            follow: self.follow,
            n: Some(self.lines),
        }))
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Success(SimpleSuccess { message }) => {
                println!("{} {}", "i".blue(), message.italic());
            }
            Response::Error { error } => {
                eprintln!("{} {}", "✘".red().bold(), error);
            }
            Response::Event(event) => self.print_event(event),
            _ => {} // Ignore other responses in log stream
        }
        Ok(None)
    }

    fn is_streaming(&self) -> bool {
        // We always return true because even if follow is false,
        // we expect the daemon to stream historical entries.
        true
    }
}

impl LogHandler {
    fn print_event(&self, timed_event: &TimedEvent) {
        let now = DateTime::<Local>::from(timed_event.timestamp)
            .format("%H:%M:%S")
            .to_string()
            .dimmed();
        let event = &timed_event.event;
        match event {
            LanforgeEvent::Device(e) => self.print_device_event(&now, e),
            LanforgeEvent::Dns(e) => self.print_dns_event(&now, e),
            LanforgeEvent::Network(e) => Self::print_network_event(&now, e),
            LanforgeEvent::Storage(e) => Self::print_storage_event(&now, e),
            LanforgeEvent::System(e) => self.print_system_event(&now, e),
        }
    }

    fn print_device_event(&self, now: &colored::ColoredString, event: &DeviceEvent) {
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
            DeviceEvent::Updated {
                mac,
                hostname,
                change,
            } => {
                self.print_device_update(now, *mac, hostname.as_deref(), change);
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

    fn print_device_update(
        &self,
        now: &colored::ColoredString,
        mac: lanforge_core::identifiers::MacAddr,
        hostname: Option<&str>,
        change: &DeviceChange,
    ) {
        let name = hostname.filter(|s| !s.is_empty()).unwrap_or("unknown");
        match change {
            DeviceChange::StatusChanged { online, .. } => {
                let status = if *online {
                    "ONLINE".bright_green().bold()
                } else {
                    "OFFLINE".red().bold()
                };
                println!(
                    "[{now}] {} Device {} ({}) is now {status}",
                    "UPD".blue().bold(),
                    name.bright_yellow(),
                    mac.to_string().dimmed()
                );
            }
            DeviceChange::ArpActivity { .. } | DeviceChange::NdpActivity { .. } => {
                if self.verbose {
                    let change_str = Self::format_change(change);
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
                let change_str = Self::format_change(change);
                println!(
                    "[{now}] {} {} ({}) -> {change_str}",
                    "UPD".blue().bold(),
                    name.bright_yellow(),
                    mac.to_string().dimmed()
                );
            }
        }
    }

    fn print_dns_event(&self, now: &colored::ColoredString, event: &DnsEvent) {
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
            DnsEvent::QueryBlocked { src_addr, domain } if self.verbose => {
                println!(
                    "[{now}] {} {} -> {}",
                    "BLOCK".red().bold(),
                    src_addr.to_string().bright_cyan(),
                    domain.bright_red()
                );
            }
            _ => {}
        }
    }

    fn print_network_event(now: &colored::ColoredString, event: &NetworkEvent) {
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
            NetworkEvent::SubnetScanStarted { subnet } => {
                println!(
                    "[{now}] {} {} {}",
                    "ARP".bright_yellow().bold(),
                    "Unleashing massive ARP scan for:".white(),
                    subnet.bright_cyan().bold()
                );
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
            NetworkEvent::ScanRequested | NetworkEvent::NeighborScanRequested => {
                let msg = if matches!(event, NetworkEvent::ScanRequested) {
                    "mDNS Scan requested"
                } else {
                    "Manual Neighbor Scan (ARP) requested"
                };
                println!("[{now}] {} {}", "SYS".yellow().bold(), msg.dimmed());
            }
        }
    }

    fn print_storage_event(now: &colored::ColoredString, event: &StorageEvent) {
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

    fn print_system_event(&self, now: &colored::ColoredString, event: &SystemEvent) {
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
                if self.verbose {
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
        }
    }

    #[must_use]
    fn format_change(change: &DeviceChange) -> String {
        match change {
            DeviceChange::V4Assigned { ip } => {
                format!("IPv4 assigned: {}", ip.to_string().bright_cyan())
            }
            DeviceChange::LeaseExpired { target } => {
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
            DeviceChange::SlaacObserved { addr } => {
                format!(
                    "{} {}",
                    "New SLAAC discovered:".bold(),
                    addr.to_string().bright_magenta()
                )
            }
            DeviceChange::HostnameChanged { hostname } => format!("Hostname: {}", hostname.bold()),
            DeviceChange::V4StaticChanged { ip } => ip.as_ref().map_or_else(
                || "Static IPv4 removed".dimmed().to_string(),
                |v| format!("Static IPv4 set: {}", v.to_string().bright_green()),
            ),
            DeviceChange::V6SuffixChanged { suffix } => suffix.as_ref().map_or_else(
                || "Static IPv6 suffix removed".dimmed().to_string(),
                |s| format!("Static IPv6 suffix set: {}", s.to_string().bold()),
            ),
            DeviceChange::DuidAssociated { duid } => {
                format!("DUID associated: {}", duid.to_string().cyan())
            }
            DeviceChange::V6Assigned { ip, .. } => {
                format!("IPv6 assigned: {}", ip.to_string().bright_cyan())
            }
            DeviceChange::V6PrefixAssigned { prefix, len, .. } => {
                format!(
                    "IA_PD assigned: {}/{}",
                    prefix.to_string().bright_cyan(),
                    len
                )
            }
            DeviceChange::HostRemoved => "Host removed".red().to_string(),
            DeviceChange::NdpActivity { ip } => {
                format!("IPv6 activity at {}", ip.to_string().bright_magenta())
            }
            DeviceChange::ArpActivity { ip } => {
                format!("Neighbor seen at {}", ip.to_string().bright_cyan())
            }
            DeviceChange::StatusChanged { online, .. } => {
                if *online {
                    format!("is now {}", "Online".bright_green().bold())
                } else {
                    format!("has gone {}", "Offline".red().bold())
                }
            }
            DeviceChange::Classified { class } => {
                format!(
                    "classified as {}",
                    class.as_str().to_string().bright_magenta().bold()
                )
            }
            DeviceChange::TopologyChanged { parent_mac, port } => {
                let parent = parent_mac.map_or_else(|| "Local".to_string(), |m| m.to_string());
                let port = port.as_deref().unwrap_or("?");
                format!(
                    "topology updated: behind {} on port {}",
                    parent.bright_cyan(),
                    port.bright_yellow()
                )
            }
            DeviceChange::IpDeleted { ip } => {
                format!("IP deleted: {}", ip.to_string().red())
            }
            DeviceChange::IpOffline { ip } => {
                format!("IP offline: {}", ip.to_string().yellow())
            }
            DeviceChange::CliHostUpdated => "Host updated via CLI".bright_blue().to_string(),
        }
    }
}
