use super::CliCommand;
use crate::bus::{DeviceChange, LanforgeEvent};
use crate::control::{Command as ControlCommand, Response, api::SimpleSuccess};
use anyhow::Result;
use colored::*;

pub struct LogHandler {
    pub follow: bool,
}

impl CliCommand for LogHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Log {
            follow: self.follow,
        })
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Success(SimpleSuccess { message }) => {
                println!("{} {}", "ℹ".blue(), message.italic());
            }
            Response::Error { error } => {
                eprintln!("{} {}", "✘".red().bold(), error);
            }
            Response::Event(event) => self.print_event(event),
            _ => {} // Ignore other responses in log stream
        }
        Ok(())
    }

    fn is_streaming(&self) -> bool {
        self.follow
    }
}

impl LogHandler {
    fn print_event(&self, event: &LanforgeEvent) {
        let now = chrono::Local::now().format("%H:%M:%S").to_string().dimmed();

        match event {
            LanforgeEvent::DeviceDiscovered { mac } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "NEW".green().bold(),
                    "Device discovered:".white(),
                    mac.to_string().bright_yellow()
                );
            }
            LanforgeEvent::DeviceUpdated { mac, change } => {
                let change_str = self.format_change(change);
                println!(
                    "[{}] {} {} -> {}",
                    now,
                    "UPD".blue().bold(),
                    mac.to_string().bright_yellow(),
                    change_str
                );
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
            LanforgeEvent::PrefixChanged {
                gua,
                preferred,
                valid,
            } => {
                println!(
                    "[{}] {} {} {:?} (pref={}, valid={})",
                    now,
                    "NET".magenta().bold(),
                    "GUA Prefix changed:".white(),
                    gua,
                    preferred,
                    valid
                );
            }
            LanforgeEvent::LeaseRelease { mac } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "CMD".cyan().bold(),
                    "Forced Release:".white(),
                    mac
                );
            }
            LanforgeEvent::LeaseRenew { mac } => {
                println!(
                    "[{}] {} {} {}",
                    now,
                    "CMD".cyan().bold(),
                    "Force Renew:".white(),
                    mac
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
            DeviceChange::V4Expired => "IPv4 lease expired".dimmed().to_string(),
            DeviceChange::V6Assigned { ip } => {
                format!("IPv6 assigned: {}", ip.to_string().bright_cyan())
            }
            DeviceChange::V6Expired => "IPv6 lease expired".dimmed().to_string(),
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
            DeviceChange::DuidAssociated => "DUID associated".to_string(),
            DeviceChange::V6PrefixAssigned { prefix, len } => {
                format!(
                    "IA_PD assigned: {}/{}",
                    prefix.to_string().bright_cyan(),
                    len
                )
            }
        }
    }
}
