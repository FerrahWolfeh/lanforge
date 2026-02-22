use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::TryStreamExt;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use rtnetlink::{IpVersion, new_connection};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// CLI / environment configuration
// ---------------------------------------------------------------------------

/// IPv6 SLAAC host tracker for dnsmasq / pihole-FTL.
///
/// All options can also be supplied via the matching environment variable
/// shown in brackets.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Config {
    /// dnsmasq leases file
    #[arg(
        long,
        env = "IPV6N_LEASES_FILE",
        default_value = "/mnt/ram/dnsmasq/dnsmasq.leases"
    )]
    leases_file: String,

    /// Output hosts file written for dnsmasq
    #[arg(
        long,
        env = "IPV6N_OUTPUT_FILE",
        default_value = "/mnt/ram/dnsmasq/ipv6_slaac_hosts"
    )]
    output_file: String,

    /// IPv6 prefix to watch (only neighbours matching this prefix are recorded)
    #[arg(
        long,
        env = "IPV6N_TARGET_PREFIX",
        default_value = "fd97:f00d:cafe:3731"
    )]
    target_prefix: String,

    /// dnsmasq static-host config file (parsed for dhcp-host entries)
    #[arg(
        long,
        env = "IPV6N_DNSMASQ_CONFIG",
        default_value = "/etc/dnsmasq-dhcp.conf"
    )]
    dnsmasq_config: String,

    /// Name of the DNS process to send SIGHUP to after updating the hosts file
    #[arg(long, env = "IPV6N_DNS_PROCESS", default_value = "pihole-FTL")]
    dns_process: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Logging — systemd already adds timestamps, so we skip them.
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::parse();

    info!("Starting ipv6_namer daemon (waiting for SIGUSR1)...");
    info!("  leases_file   = {}", cfg.leases_file);
    info!("  output_file   = {}", cfg.output_file);
    info!("  target_prefix = {}", cfg.target_prefix);
    info!("  dnsmasq_config= {}", cfg.dnsmasq_config);
    info!("  dns_process   = {}", cfg.dns_process);

    // Robustness check: config must exist before we even enter the loop.
    if !std::path::Path::new(&cfg.dnsmasq_config).exists() {
        error!(
            "CRITICAL: config file {} not found. Aborting.",
            cfg.dnsmasq_config
        );
        std::process::exit(1);
    }

    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    loop {
        if let Err(e) = process_cycle(&cfg).await {
            error!("Error in processing cycle: {:?}", e);
        }

        info!("Cycle complete. Waiting for SIGUSR1...");
        sigusr1.recv().await;
        info!("SIGUSR1 received! Starting scan...");
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

async fn process_cycle(cfg: &Config) -> Result<()> {
    let mac_map = get_mac_hostname_map(&cfg.leases_file).unwrap_or_else(|e| {
        warn!("Could not read leases (may be temporary): {}", e);
        HashMap::new()
    });

    if mac_map.is_empty() {
        info!("No leases found at the moment.");
    }

    let static_suffixes = get_static_suffixes(&cfg.dnsmasq_config).unwrap_or_else(|e| {
        warn!("Failed to read {}: {}", cfg.dnsmasq_config, e);
        HashMap::new()
    });

    let neighbors = get_ipv6_neighbors(&cfg.target_prefix).await?;

    let mut new_lines: HashSet<String> = HashSet::new();

    for (ip, mac) in neighbors {
        let mac_norm = mac.to_lowercase();

        if let Some(hostname) = mac_map.get(&mac_norm) {
            let is_static_ip = static_suffixes
                .get(&mac_norm)
                .map(|suffix| ip.ends_with(suffix.trim_matches(|c| c == '[' || c == ']')))
                .unwrap_or(false);

            let entry = if is_static_ip {
                format!("{} {}", ip, hostname)
            } else {
                format!("{} {} {}-slaac", ip, hostname, hostname)
            };
            new_lines.insert(entry);
        }
    }

    update_file_if_changed(&cfg.output_file, new_lines)?;
    reload_dns(&cfg.dns_process).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

fn get_mac_hostname_map(leases_file: &str) -> Result<HashMap<String, String>> {
    let file =
        File::open(leases_file).with_context(|| format!("Failed to open {}", leases_file))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let mac = parts[1].to_lowercase();
            let hostname = parts[3].to_lowercase();
            if hostname != "*" {
                map.insert(mac, hostname);
            }
        }
    }
    Ok(map)
}

fn get_static_suffixes(dnsmasq_config: &str) -> Result<HashMap<String, String>> {
    let file =
        File::open(dnsmasq_config).with_context(|| format!("Failed to open {}", dnsmasq_config))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("dhcp-host=") {
            continue;
        }

        // Example: dhcp-host=e0:d5:5e:e2:d4:89,[::1057:cafe],192.168.0.2,Archie,infinite
        let content = line.trim_start_matches("dhcp-host=");
        let parts: Vec<&str> = content.split(',').collect();

        let mut mac = None;
        let mut ipv6_suffix = None;

        for part in parts {
            let part = part.trim();
            if part.contains(':') && !part.contains('[') && part.len() == 17 {
                mac = Some(part.to_string());
            } else if part.starts_with('[') && part.ends_with(']') {
                ipv6_suffix = Some(part.to_string());
            }
        }

        if let (Some(m), Some(s)) = (mac, ipv6_suffix) {
            map.insert(m, s);
        }
    }
    Ok(map)
}

fn update_file_if_changed(output_file: &str, new_lines: HashSet<String>) -> Result<()> {
    let mut old_lines: HashSet<String> = HashSet::new();

    if let Ok(file) = File::open(output_file) {
        for l in BufReader::new(file).lines().map_while(Result::ok) {
            old_lines.insert(l.trim().to_string());
        }
    }

    let added: Vec<_> = new_lines.difference(&old_lines).collect();
    let removed: Vec<_> = old_lines.difference(&new_lines).collect();

    if !added.is_empty() {
        info!("Changes detected. Adding:");
        for item in &added {
            info!("  + {}", item);
        }
    }
    if !removed.is_empty() {
        info!("Changes detected. Removing:");
        for item in &removed {
            info!("  - {}", item);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        info!("Writing updated hosts file...");
        let mut content: Vec<_> = new_lines.into_iter().collect();
        content.sort();

        let mut file = File::create(output_file).context("Error writing hosts file")?;
        for line in &content {
            writeln!(file, "{}", line)?;
        }
    } else {
        info!("No changes detected.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Netlink neighbour discovery
// ---------------------------------------------------------------------------

async fn get_ipv6_neighbors(target_prefix: &str) -> Result<Vec<(String, String)>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some((ip, mac)) = parse_neighbor(msg)
            && ip.starts_with(target_prefix)
        {
            neighbors.push((ip, mac));
        }
    }

    Ok(neighbors)
}

fn parse_neighbor(msg: NeighbourMessage) -> Option<(String, String)> {
    if msg.header.state == NeighbourState::Incomplete || msg.header.state == NeighbourState::Failed
    {
        return None;
    }

    let mut ip_str = String::new();
    let mut mac_str = String::new();

    for attr in msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ipv6)) => {
                ip_str = ipv6.to_string();
            }
            NeighbourAttribute::LinkLocalAddress(mac_bytes) => {
                mac_str = mac_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
            _ => {}
        }
    }

    if !ip_str.is_empty() && !mac_str.is_empty() {
        Some((ip_str, mac_str))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// DNS process reload  (lightweight: just pkill -HUP <name>)
// ---------------------------------------------------------------------------

async fn reload_dns(process_name: &str) {
    // Use pkill to send SIGHUP by process name — no sysinfo needed, minimal overhead.
    match tokio::process::Command::new("pkill")
        .args(["-HUP", process_name])
        .status()
        .await
    {
        Ok(status) if status.success() => {
            info!("Sent SIGHUP to '{}'.", process_name);
        }
        Ok(_) => {
            warn!("Could not find process '{}' to reload.", process_name);
        }
        Err(e) => {
            warn!("Failed to run pkill: {}", e);
        }
    }
}
