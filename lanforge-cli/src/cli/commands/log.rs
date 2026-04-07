use super::CliCommand;
use chrono::DateTime;
use chrono::Local;
use color_eyre::eyre::Result;
use colored::*;
use lanforge_api::api::Command as ControlCommand;
use lanforge_api::api::Response;
use lanforge_api::api::SimpleSuccess;
use lanforge_core::bus::TimedEvent;
use lanforge_core::bus::{DeviceChange, LanforgeEvent};
use lanforge_core::state::LeaseTarget;

pub struct LogHandler {
    pub follow: bool,
    pub verbose: bool,
}

impl CliCommand for LogHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Log {
            follow: self.follow,
        })
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
        self.follow
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
            LanforgeEvent::DeviceDiscovered { mac, hostname } => {
                let name = hostname
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown");
                println!(
                    "[{}] {} {} {} ({})",
                    now,
                    "NEW".green().bold(),
                    "Device discovered:".white(),
                    name.bold().bright_yellow(),
                    mac.to_string().dimmed()
                );
            }
            LanforgeEvent::DeviceUpdated {
                mac,
                hostname,
                change,
            } => {
                let name = hostname
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown");

                match change {
                    DeviceChange::StatusChanged { online, .. } => {
                        let status = if *online {
                            "ONLINE".bright_green().bold()
                        } else {
                            "OFFLINE".red().bold()
                        };
                        println!(
                            "[{}] {} Device {} ({}) is now {}",
                            now,
                            "UPD".blue().bold(),
                            name.bright_yellow(),
                            mac.to_string().dimmed(),
                            status
                        );
                    }
                    DeviceChange::ArpActivity { .. } | DeviceChange::NdpActivity { .. } => {
                        if self.verbose {
                            let change_str = self.format_change(change);
                            println!(
                                "[{}] {} {} ({}) -> {}",
                                now,
                                "TRC".dimmed(),
                                name.bright_yellow(),
                                mac.to_string().dimmed(),
                                change_str.dimmed()
                            );
                        }
                    }
                    _ => {
                        let change_str = self.format_change(change);
                        println!(
                            "[{}] {} {} ({}) -> {}",
                            now,
                            "UPD".blue().bold(),
                            name.bright_yellow(),
                            mac.to_string().dimmed(),
                            change_str
                        );
                    }
                }
            }
            LanforgeEvent::DeviceExpired { mac } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "EXP".red().bold(),
                    "Device expired:".dimmed(),
                    mac.to_string().red()
                );
            }
            LanforgeEvent::DevicePurged { mac } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "DEL".red().bold(),
                    "Device purged:".red().bold(),
                    mac.to_string().red()
                );
            }
            LanforgeEvent::WolTriggered { mac, .. } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "WOL".bright_green().bold(),
                    "Wake-on-LAN sent to:".white(),
                    mac.to_string().bright_yellow()
                );
            }
            LanforgeEvent::PrefixChanged {
                gua,
                preferred,
                valid,
                ula,
            } => {
                if let Some(ula) = ula {
                    println!(
                        "[{}] {} {} {:?} (pref={}, valid={})",
                        now,
                        "NET".magenta().bold(),
                        "ULA Prefix changed:".white(),
                        ula,
                        preferred,
                        valid,
                    );
                } else {
                    println!(
                        "[{}] {} {} {:?} (pref={}, valid={})",
                        now,
                        "NET".magenta().bold(),
                        "GUA Prefix changed:".white(),
                        gua,
                        preferred,
                        valid,
                    );
                }
            }
            LanforgeEvent::LeaseRelease { mac, target } => {
                println!(
                    "[{}] {} {} {} ({:?})",
                    now,
                    "CMD".cyan().bold(),
                    "Forced Release:".white(),
                    mac,
                    target
                );
            }
            LanforgeEvent::LeaseRenew { mac, target } => {
                println!(
                    "[{}] {} {} {} ({:?})",
                    now,
                    "CMD".cyan().bold(),
                    "Force Renew:".white(),
                    mac,
                    target
                );
            }
            LanforgeEvent::DbVacuum => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Database VACUUM requested".dimmed()
                );
            }
            LanforgeEvent::ReloadConfig => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Config reload requested".dimmed()
                );
            }
            LanforgeEvent::ScanRequested => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "mDNS Scan requested".dimmed()
                );
            }
            LanforgeEvent::SubnetScanStarted { subnet } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "ARP".bright_yellow().bold(),
                    "Unleashing massive ARP scan for:".white(),
                    subnet.bright_cyan().bold()
                );
            }
            LanforgeEvent::NeighborScanRequested => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Manual Neighbor Scan (ARP) requested".dimmed()
                );
            }
            LanforgeEvent::InterfaceUpdated { ifindex } => {
                println!(
                    "[{}] {} {} (ifindex={})",
                    now,
                    "NET".magenta().bold(),
                    "Local interface IP configuration changed".white(),
                    ifindex
                );
            }
            LanforgeEvent::StateReady => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Internal state ready".white()
                );
            }
            LanforgeEvent::DbReady => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Database engine ready".white()
                );
            }
            LanforgeEvent::InterfaceReady => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Network interfaces ready".white()
                );
            }
            LanforgeEvent::ServiceReady { name } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Service ready:".white(),
                    name.cyan()
                );
            }
            LanforgeEvent::SystemReady => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".green().bold(),
                    "System fully operational!".bright_green().bold()
                );
            }
            LanforgeEvent::DbLogClean => {
                println!(
                    "[{}] {} {}",
                    now,
                    "SYS".yellow().bold(),
                    "Transient logs cleared manually".dimmed()
                );
            }
            LanforgeEvent::DeviceTableDirty | LanforgeEvent::Shutdown => {
                // Ignore these or print subtly if needed
            }
        }
    }

    fn format_change(&self, change: &DeviceChange) -> String {
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
                format!("{} expired", target_str).dimmed().to_string()
            }
            DeviceChange::SlaacObserved { addr } => {
                format!("SLAAC observed: {}", addr.to_string().bright_magenta())
            }
            DeviceChange::HostnameChanged { hostname } => format!("Hostname: {}", hostname.bold()),
            DeviceChange::V4StaticChanged { ip } => match ip {
                Some(v) => format!("Static IPv4 set: {}", v.to_string().bright_green()),
                None => "Static IPv4 removed".dimmed().to_string(),
            },
            DeviceChange::V6SuffixChanged { suffix } => match suffix {
                Some(s) => format!("Static IPv6 suffix set: {}", s.to_string().bold()),
                None => "Static IPv6 suffix removed".dimmed().to_string(),
            },
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
            DeviceChange::SlaacSynced { addresses } => {
                format!(
                    "SLAAC synced: {} addresses",
                    addresses.len().to_string().bright_magenta()
                )
            }
            DeviceChange::HostRemoved => "Host removed".red().to_string(),
            DeviceChange::NdpActivity { ip } => {
                format!("Neighbor seen at {}", ip.to_string().bright_magenta())
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
        }
    }
}
