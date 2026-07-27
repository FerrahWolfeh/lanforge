use std::{collections::HashMap, io::ErrorKind};

use crate::cli::{
    Execute, LanforgeClient,
    wizard::{confirm_destructive, fuzzy_select_device, prompt_text},
};
use color_eyre::eyre::Result;
use lanforge_api::rpc::{LanforgeRpcError, RpcResponse};
use lanforge_types::device::DeviceStatus;
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
#[cfg(feature = "remote")]
use reqwest::Client;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ReloadArgs {}

impl Execute for ReloadArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.reload().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ShutdownArgs {}

impl Execute for ShutdownArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.shutdown().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PurgeArgs {
    pub mac: Option<String>,
}

impl Execute for PurgeArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let mac = if let Some(m) = self.mac {
            m.parse::<MacAddr>()
                .map_err(|e| color_eyre::eyre::eyre!("{e}"))?
        } else {
            let dev = fuzzy_select_device(client, "Select device to purge:").await?;
            dev.mac
        };

        if !confirm_destructive(
            client,
            &format!("Are you sure you want to purge device {mac}?"),
        )? {
            return Ok(());
        }

        let resp = client.purge(mac).await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ContextArgs {
    #[arg(long)]
    pub only_devices: bool,
    #[arg(long)]
    pub only_orphans: bool,
}

impl Execute for ContextArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let dump = client
            .context_dump(self.only_devices, self.only_orphans)
            .await?;
        println!("{}", serde_json::to_string_pretty(&dump)?);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LoginArgs {
    /// Remote daemon URL (e.g., <https://192.168.1.1:8080>)
    pub url: Option<String>,
    /// Plaintext API token or password
    pub secret: Option<String>,
}

impl Execute for LoginArgs {
    async fn execute(self, _client: &LanforgeClient) -> Result<()> {
        let url = match self.url {
            Some(u) => u,
            None => prompt_text(
                "Daemon URL (e.g. https://localhost:8080):",
                Some("https://localhost:8080"),
            )?,
        };
        let secret = match self.secret {
            Some(s) => s,
            None => prompt_text("API Token:", None)?,
        };

        // Create temporary client to validate token
        let temp_client = LanforgeClient {
            socket: String::new(),
            #[cfg(feature = "remote")]
            remote: Some(url.clone()),
            #[cfg(feature = "remote")]
            token: Some(secret.clone()),
            no_compress: false,
            json: false,
            no_color: false,
            ascii: false,
            yes: false,
            #[cfg(feature = "remote")]
            http_client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?,
        };

        #[cfg(feature = "remote")]
        {
            use directories::ProjectDirs;
            use inquire::Confirm;

            temp_client.ak_validate(&secret).await?;
            if let Some(proj_dirs) = ProjectDirs::from("", "lanforge", "lanforge") {
                let data_dir = proj_dirs.data_dir();
                std::fs::create_dir_all(data_dir)?;
                let login_path = data_dir.join("login.json");

                let mut default_url = None;
                let mut servers = serde_json::Map::new();

                if let Ok(content) = std::fs::read_to_string(&login_path)
                    && let Ok(val) = serde_json::from_str::<serde_json::Value>(&content)
                {
                    if let Some(s) = val.get("servers").and_then(|v| v.as_object()) {
                        s.clone_into(&mut servers);
                        default_url = val
                            .get("default")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                    } else if let Some(old_url) = val.get("url").and_then(|v| v.as_str())
                        && let Some(old_token) = val.get("token").and_then(|v| v.as_str())
                    {
                        default_url = Some(old_url.to_string());
                        servers.insert(old_url.to_string(), serde_json::json!(old_token));
                    }
                }

                let is_first = default_url.is_none();
                let set_default = if is_first {
                    true
                } else {
                    Confirm::new(&format!("Set {url} as the default remote?"))
                        .with_default(true)
                        .prompt()?
                };

                if set_default {
                    default_url = Some(url.clone());
                }

                servers.insert(url.clone(), serde_json::json!(secret));

                let creds = serde_json::json!({
                    "default": default_url,
                    "servers": servers
                });

                std::fs::write(login_path, serde_json::to_string_pretty(&creds)?)?;
                println!("✓ Login successful. Credentials saved to login.json");
            }
        }
        #[cfg(not(feature = "remote"))]
        {
            use color_eyre::eyre::bail;

            bail!("Remote feature not enabled in this build.");
        }

        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WatchArgs {
    /// Show verbose periodic events (e.g. background neighbor scan summaries)
    #[arg(short, long)]
    pub verbose: bool,
}

impl Execute for WatchArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let device_map = fetch_device_map(client).await;
        let verbose = self.verbose;

        #[cfg(feature = "remote")]
        if let Some(base) = &client.remote {
            use futures::StreamExt;

            let url = format!("{base}/api/v1/events?follow=true&n=50&filter=dhcp,dns");
            let mut req = client.http_client.get(&url);
            if let Some(t) = &client.token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            let mut resp = req.send().await?.bytes_stream();
            println!("Watching for remote events... (Ctrl+C to stop)");
            while let Some(chunk) = resp.next().await {
                if let Ok(bytes) = chunk {
                    let s = String::from_utf8_lossy(&bytes);
                    for line in s.lines() {
                        if let Some(json_str) = line.strip_prefix("data: ")
                            && let Ok(event) = serde_json::from_str::<TimedEvent>(json_str)
                        {
                            render_watch_event(&event, &device_map, verbose);
                        }
                    }
                }
            }
            return Ok(());
        }

        let mut rpc = client.connect_rpc().await?;
        rpc.log(true, None, None).await?;
        println!("Watching for events... (Ctrl+C to stop)");
        loop {
            match rpc.next_response().await {
                Ok(RpcResponse::Event(event)) => {
                    render_watch_event(&event, &device_map, verbose);
                }
                Ok(RpcResponse::Error(e)) => eprintln!("Error: {e}"),
                Ok(_) => {}
                Err(LanforgeRpcError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

async fn fetch_device_map(client: &LanforgeClient) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(dev_resp) = client
        .list_devices(None, None, None, None, Some(10000), None)
        .await
    {
        for dev in dev_resp.devices {
            if !dev.hostname.is_empty() && dev.hostname != "<unknown>" {
                if let Some(v4) = dev.v4 {
                    map.insert(v4.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.seen_v4 {
                    map.insert(ip.to_string(), dev.hostname.clone());
                }
                if let Some(v6) = dev.v6 {
                    map.insert(v6.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.ipv6_addrs {
                    map.insert(ip.addr.to_string(), dev.hostname.clone());
                }
            }
        }
    }
    map
}

#[allow(clippy::too_many_lines)]
fn render_watch_event(e: &TimedEvent, device_map: &HashMap<String, String>, verbose: bool) {
    use chrono::{DateTime, Local};
    use colored::Colorize;
    use lanforge_types::events::{
        AdminChange, DeviceEvent, DnsEvent, LanforgeEvent, NetworkChange, NetworkEvent,
    };

    let dt: DateTime<Local> = e.timestamp.into();
    let time_str = dt.format("%Y-%m-%d %H:%M:%S").to_string().dimmed();

    match &e.event {
        LanforgeEvent::Device(dev_evt) => match dev_evt {
            DeviceEvent::Discovered { mac, hostname } => {
                let host = hostname.as_deref().unwrap_or("<unknown>");
                println!(
                    " [{time_str}] {} {} ({mac})",
                    "DEVICE DISCOVERED".bold().green(),
                    host.cyan()
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
                let host = hostname.as_deref().unwrap_or("<unknown>");
                let tag = if matches!(dev_evt, DeviceEvent::NetworkActivity { .. }) {
                    "DEVICE ACTIVITY".bold().dimmed()
                } else {
                    "DEVICE UPDATED".bold().blue()
                };
                let change_str = match &**change {
                    NetworkChange::V4Assigned { ip } => {
                        format!("Assigned IPv4: {}", ip.to_string().yellow())
                    }
                    NetworkChange::V6Assigned { ip, iaid } => {
                        format!("Assigned IPv6: {} (IAID: {iaid})", ip.to_string().yellow())
                    }
                    NetworkChange::V6PrefixAssigned { prefix, len, iaid } => format!(
                        "Assigned IPv6 Prefix: {}/{len} (IAID: {iaid})",
                        prefix.to_string().yellow()
                    ),
                    NetworkChange::LeaseExpired { target } => {
                        format!("Lease Expired: {target:?}").red().to_string()
                    }
                    NetworkChange::SlaacObserved { addr } => {
                        format!("Observed SLAAC: {}", addr.to_string().yellow())
                    }
                    NetworkChange::StatusChanged {
                        online: _,
                        status,
                        hostname: _,
                    } => match status {
                        DeviceStatus::Online => "Status: Online".green().to_string(),
                        DeviceStatus::Stale => "Status: Stale".yellow().to_string(),
                        DeviceStatus::Offline => "Status: Offline".red().to_string(),
                    },
                    NetworkChange::HostnameHint { hostname } => {
                        format!("Hostname updated to: {}", hostname.cyan())
                    }
                    NetworkChange::DuidAssociated { duid } => format!("DUID associated: {duid}"),
                    NetworkChange::NdpActivity { ip } => {
                        let ip_str = ip.to_string();
                        let mapped = device_map
                            .get(&ip_str)
                            .map(|h| format!("({h})"))
                            .unwrap_or_default();
                        format!("NDP Activity: {} {}", ip_str.yellow(), mapped.cyan())
                    }
                    NetworkChange::ArpActivity { ip } => {
                        let ip_str = ip.to_string();
                        let mapped = device_map
                            .get(&ip_str)
                            .map(|h| format!("({h})"))
                            .unwrap_or_default();
                        format!("ARP Activity: {} {}", ip_str.yellow(), mapped.cyan())
                    }

                    NetworkChange::IpDeleted { ip } => {
                        format!("IP Deleted: {ip}").red().to_string()
                    }
                    NetworkChange::IpOffline { ip } => {
                        format!("IP Offline: {ip}").yellow().to_string()
                    }
                };
                println!(
                    " [{time_str}] {} {} ({mac}) -> {change_str}",
                    tag,
                    host.cyan()
                );
            }
            DeviceEvent::AdminUpdate {
                mac,
                hostname,
                change,
            } => {
                let host = hostname.as_deref().unwrap_or("<unknown>");
                let tag = "DEVICE ADMIN UPDATED".bold().cyan();
                let change_str = match &**change {
                    AdminChange::CliHostUpdated => "CLI Host Updated".blue().to_string(),
                    AdminChange::HostnameChanged { hostname } => {
                        format!("Static hostname updated to: {}", hostname.cyan())
                    }
                    AdminChange::V4StaticChanged { ip } => {
                        format!("Static IPv4 updated: {ip:?}")
                    }
                    AdminChange::V6SuffixChanged { suffix } => {
                        format!("Static IPv6 Suffix updated: {suffix:?}")
                    }
                    AdminChange::Classified { class } => {
                        format!("Classified as: {class:?}").magenta().to_string()
                    }
                    AdminChange::HostRemoved => "Host Removed".red().to_string(),
                };
                println!(
                    " [{time_str}] {} {} ({mac}) -> {change_str}",
                    tag,
                    host.cyan()
                );
            }
            DeviceEvent::Expired { mac } => {
                println!(" [{time_str}] {} ({mac})", "DEVICE EXPIRED".bold().red());
            }
            DeviceEvent::Purged { mac } => {
                println!(" [{time_str}] {} ({mac})", "DEVICE PURGED".bold().red());
            }
            DeviceEvent::LeaseRelease { mac, target } => {
                println!(
                    " [{time_str}] {} ({mac}) target={:?}",
                    "LEASE RELEASED".bold().yellow(),
                    target
                );
            }
            DeviceEvent::LeaseRenew { mac, target } => {
                println!(
                    " [{time_str}] {} ({mac}) target={:?}",
                    "LEASE RENEWED".bold().green(),
                    target
                );
            }
            DeviceEvent::DhcpV4Transaction {
                mac,
                msg_type,
                details,
            } => {
                let det = details.as_deref().unwrap_or("");
                println!(
                    " [{time_str}] {} ({mac}) {:?} {det}",
                    "DHCPv4".bold().magenta(),
                    msg_type
                );
            }
            DeviceEvent::DhcpV6Transaction {
                mac,
                msg_type,
                details,
            } => {
                let det = details.as_deref().unwrap_or("");
                println!(
                    " [{time_str}] {} ({mac}) {:?} {det}",
                    "DHCPv6".bold().magenta(),
                    msg_type
                );
            }
            DeviceEvent::NeighborBatchSummary {
                total,
                new,
                duration_ms,
            } => {
                if verbose || *new > 0 {
                    println!(
                        " [{time_str}] {} scanned {} neighbors ({} new) in {}ms",
                        "NEIGHBOR SCAN".bold().cyan(),
                        total.to_string().yellow(),
                        new.to_string().green(),
                        duration_ms.to_string().yellow()
                    );
                }
            }
        },
        LanforgeEvent::Network(net_evt) => match net_evt {
            NetworkEvent::PrefixChanged {
                gua,
                ula,
                preferred,
                valid,
            } => {
                println!(
                    " [{time_str}] {} GUA={:?} ULA={:?} (pref={}s, valid={}s)",
                    "PREFIX CHANGED".bold().magenta(),
                    gua,
                    ula,
                    preferred,
                    valid
                );
            }
            NetworkEvent::InterfaceUpdated { ifindex } => {
                println!(
                    " [{time_str}] {} ifindex={ifindex}",
                    "INTERFACE UPDATED".bold().blue()
                );
            }

            NetworkEvent::WolTriggered { mac, ip_hint } => {
                println!(
                    " [{time_str}] {} mac={mac} ip_hint={:?}",
                    "WOL TRIGGERED".bold().yellow(),
                    ip_hint
                );
            }
            NetworkEvent::RsReceived { mac } => {
                println!(
                    " [{time_str}] {} mac={mac}",
                    "ROUTER SOLICITATION".bold().magenta()
                );
            }
            NetworkEvent::LeaseRenewRequested { mac, target } => {
                println!(
                    " [{time_str}] {} mac={mac} target={:?}",
                    "LEASE RENEW REQUESTED".bold().green(),
                    target
                );
            }
            NetworkEvent::LeaseReleaseRequested { mac, target } => {
                println!(
                    " [{time_str}] {} mac={mac} target={:?}",
                    "LEASE RELEASE REQUESTED".bold().yellow(),
                    target
                );
            }
        },
        LanforgeEvent::System(sys_evt) => {
            println!(
                " [{time_str}] {} {:?}",
                "SYSTEM EVENT".bold().yellow(),
                sys_evt
            );
        }
        LanforgeEvent::Storage(sto_evt) => {
            println!(
                " [{time_str}] {} {:?}",
                "STORAGE EVENT".bold().blue(),
                sto_evt
            );
        }
        LanforgeEvent::Dns(dns_evt) => match dns_evt {
            DnsEvent::QueryResolved(q) => {
                let ip_str = q.src_ip.to_string();
                let client_display = if let Some(host) = device_map.get(&ip_str) {
                    format!("{host} ({ip_str})")
                } else {
                    ip_str
                };
                let status_color = match format!("{:?}", q.result).as_str() {
                    "CachedBlock" | "Blocked" => format!("{:?}", q.result).red(),
                    "Rewritten" | "Cached" => format!("{:?}", q.result).cyan(),
                    "Forwarded" | "Local" => format!("{:?}", q.result).green(),
                    other => other.yellow(),
                };
                println!(
                    " [{time_str}] {} {} queried {:<25} {:<5} [{status_color}] {}ms",
                    "DNS QUERY".bold().cyan(),
                    client_display.magenta(),
                    q.domain,
                    q.qtype.to_string().cyan(),
                    q.upstream_us / 1000
                );
            }
            other => {
                println!(" [{time_str}] {} {:?}", "DNS EVENT".bold().cyan(), other);
            }
        },
        LanforgeEvent::Pppoe(pppoe_evt) => {
            println!(
                " [{time_str}] {} {:?}",
                "PPPOE EVENT".bold().magenta(),
                pppoe_evt
            );
        }
    }
}
