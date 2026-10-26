use std::io::IsTerminal;
use std::time::Duration;

use color_eyre::Result;
use color_eyre::eyre::bail;
use colored::Colorize;

use lanforge_types::network::traffic::{
    CakeQdiscStats, ConntrackStats, SqmDiffserv, SqmOverhead, TrafficTelemetryResponse,
};
use lanforge_types::system::TrafficStatusResponse;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficArgs {
    #[command(subcommand)]
    pub subcommand: Option<TrafficSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum TrafficSubcommand {
    /// Show traffic service operational overview, `NIC` tuning, and `SQM` status (default)
    Status,
    /// Real-time throughput rates, packet counters, and conntrack table metrics
    #[command(alias = "telemetry", alias = "top")]
    Rates(TrafficRatesArgs),
    /// Deep-dive diagnostics into `CAKE` queuing disciplines (WAN egress and IFB ingress)
    #[command(alias = "cake")]
    Sqm(TrafficSqmArgs),
    /// View or update declarative traffic shaping and `NIC` tuning configuration
    #[command(alias = "cfg", alias = "set")]
    Config(TrafficConfigArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficRatesArgs {
    /// Continuously watch throughput metrics, refreshing every interval
    #[arg(short = 'w', long)]
    pub watch: bool,

    /// Watch refresh interval in seconds
    #[arg(short = 'i', long, default_value = "2")]
    pub interval: u64,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficSqmArgs {
    /// Show detailed per-tin (priority queue) statistics
    #[arg(long, default_value_t = true)]
    pub tins: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficConfigArgs {
    #[command(subcommand)]
    pub subcommand: Option<TrafficConfigSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum TrafficConfigSubcommand {
    /// Show current declarative traffic configuration (default)
    Show,
    /// Enable `SQM` (`CAKE`) traffic shaping
    SqmEnable,
    /// Disable `SQM` (`CAKE`) traffic shaping
    SqmDisable,
    /// Configure `SQM` (`CAKE`) parameters
    SqmSet(Box<SqmSetArgs>),
    /// Enable `NIC` hardware tuning (`RPS`, `XPS`, `GRO`, `EEE`)
    TuningEnable,
    /// Disable `NIC` hardware tuning
    TuningDisable,
    /// Configure `NIC` hardware tuning parameters
    TuningSet(Box<TuningSetArgs>),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct SqmSetArgs {
    /// Ingress download bandwidth limit in Mbps (0 = unlimited)
    #[arg(long)]
    pub download: Option<u32>,

    /// Egress upload bandwidth limit in Mbps (0 = unlimited)
    #[arg(long)]
    pub upload: Option<u32>,

    /// WAN interface name (e.g. eth0, wan0, auto)
    #[arg(long)]
    pub interface: Option<String>,

    /// `DiffServ` traffic classification profile (diffserv4, diffserv3, besteffort)
    #[arg(long)]
    pub diffserv: Option<String>,

    /// Framing overhead compensation profile (auto, pppoe, ethernet, docsis, none)
    #[arg(long)]
    pub overhead: Option<String>,

    /// Enable or disable per-host fairness isolation
    #[arg(long)]
    pub per_host: Option<bool>,

    /// Target `RTT` estimate override in milliseconds (default: 100ms)
    #[arg(long)]
    pub rtt: Option<u32>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct TuningSetArgs {
    /// Target network interfaces for tuning, comma-separated (e.g. eth0,eth1)
    #[arg(long, value_delimiter = ',')]
    pub interfaces: Option<Vec<String>>,

    /// CPU affinity mask for `RPS`/`XPS` packet steering (e.g. auto, f, ff)
    #[arg(long)]
    pub cpu_mask: Option<String>,

    /// Enable or disable UDP Generic Receive Offload (`GRO`) forwarding
    #[arg(long)]
    pub gro: Option<bool>,

    /// Disable Energy-Efficient Ethernet (`EEE`) to reduce latency
    #[arg(long)]
    pub disable_eee: Option<bool>,
}

impl TrafficArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(TrafficSubcommand::Status) {
            TrafficSubcommand::Status => show_status(client, printer).await,
            TrafficSubcommand::Rates(args) => show_rates(client, printer, args).await,
            TrafficSubcommand::Sqm(args) => show_sqm(client, printer, args).await,
            TrafficSubcommand::Config(args) => execute_config(client, printer, args).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand: status
// ---------------------------------------------------------------------------

async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.traffic_status().await?;
    let telemetry = client.traffic_telemetry().await.ok();

    if printer.json {
        return printer.print_json(&status);
    }

    println!();
    let state_badge = format!("[{}]", status.service_state);
    let colored_badge = match status.service_state {
        lanforge_types::system::ServiceState::Online
        | lanforge_types::system::ServiceState::Active => state_badge.green().bold(),
        lanforge_types::system::ServiceState::Degraded => state_badge.yellow().bold(),
        lanforge_types::system::ServiceState::Inactive => state_badge.dimmed(),
        _ => state_badge.red().bold(),
    };

    println!(
        " {} {}  {}",
        "●".bright_cyan(),
        "TRAFFIC ORCHESTRATOR & SQM".bold().white(),
        colored_badge
    );
    println!();

    render_nic_tuning_status(&status);
    println!();
    render_sqm_status(&status);

    if let Some(conntrack) = telemetry.as_deref().and_then(|t| t.conntrack.as_ref()) {
        println!();
        render_conntrack_summary(conntrack, printer);
    }

    println!();
    Ok(())
}

fn render_nic_tuning_status(status: &TrafficStatusResponse) {
    let tuning_state = if status.tuning_applied {
        "ENABLED (APPLIED)".green().bold().to_string()
    } else {
        "DISABLED".dimmed().to_string()
    };
    println!("  Hardware NIC Tuning: {tuning_state}");

    let ifaces = if status.tuned_interfaces.is_empty() {
        "none".dimmed().to_string()
    } else {
        status
            .tuned_interfaces
            .join(", ")
            .white()
            .bold()
            .to_string()
    };
    println!("    {:<28} {ifaces}", "Tuned Interfaces:".dimmed());
    println!(
        "    {:<28} {}",
        "Effective CPU Mask:".dimmed(),
        status.effective_cpu_mask.white()
    );
}

fn render_sqm_status(status: &TrafficStatusResponse) {
    let sqm_state = if status.sqm_active {
        "ACTIVE".green().bold().to_string()
    } else {
        "INACTIVE".dimmed().to_string()
    };
    println!("  Smart Queue Management (SQM / CAKE): {sqm_state}");

    let wan = status.wan_interface.as_deref().unwrap_or("auto");
    println!(
        "    {:<28} {}",
        "WAN Interface:".dimmed(),
        wan.cyan().bold()
    );

    if let Some(ing) = &status.ingress_device {
        println!(
            "    {:<28} {}",
            "Ingress Device (IFB):".dimmed(),
            ing.cyan()
        );
    }

    let dl_str = if status.download_mbps == 0 {
        "unshaped".dimmed().to_string()
    } else {
        format!("{} Mbps", status.download_mbps)
            .green()
            .bold()
            .to_string()
    };
    let ul_str = if status.upload_mbps == 0 {
        "unshaped".dimmed().to_string()
    } else {
        format!("{} Mbps", status.upload_mbps)
            .green()
            .bold()
            .to_string()
    };
    println!(
        "    {:<28} Down: {dl_str}  ·  Up: {ul_str}",
        "Bandwidth Shaping:".dimmed()
    );

    println!(
        "    {:<28} {:?}",
        "Classification (DiffServ):".dimmed(),
        status.diffserv
    );
    println!(
        "    {:<28} {:?}",
        "Framing Overhead:".dimmed(),
        status.overhead
    );

    let offload_desc = if status.flow_offload_suppressed {
        "Suppressed (Ensures Queue Shaping)".yellow()
    } else {
        "Hardware Accelerated (Bypasses SQM)".dimmed()
    };
    println!("    {:<28} {offload_desc}", "Flow Offload:".dimmed());
}

fn render_conntrack_summary(ct: &ConntrackStats, printer: &Printer) {
    println!("  Netfilter Conntrack Table:");
    let bar = render_progress_bar(ct.utilization_percent, 12, printer.ascii);
    println!(
        "    {:<28} {bar} {:.1}% ({}/{} connections)",
        "Table Utilization:".dimmed(),
        ct.utilization_percent,
        ct.active_connections.to_string().cyan().bold(),
        ct.max_connections
    );
}

// ---------------------------------------------------------------------------
// Subcommand: rates
// ---------------------------------------------------------------------------

async fn show_rates(
    client: &LanforgeClient,
    printer: &Printer,
    args: TrafficRatesArgs,
) -> Result<()> {
    if !args.watch {
        let telemetry = client.traffic_telemetry().await?;
        if printer.json {
            return printer.print_json(&telemetry);
        }
        render_rates_snapshot(&telemetry, printer);
        return Ok(());
    }

    // Watch loop
    let is_tty = std::io::stdout().is_terminal();
    loop {
        let telemetry = client.traffic_telemetry().await?;
        if printer.json {
            printer.print_json(&telemetry)?;
        } else {
            if is_tty {
                print!("\x1B[2J\x1B[1;1H");
            }
            render_rates_snapshot(&telemetry, printer);
        }
        tokio::time::sleep(Duration::from_secs(args.interval.max(1))).await;
    }
}

fn render_rates_snapshot(tel: &TrafficTelemetryResponse, printer: &Printer) {
    println!();
    println!(
        " {} {}  ·  {}",
        "●".bright_cyan(),
        "REAL-TIME NETWORK TELEMETRY".bold().white(),
        chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .dimmed()
    );
    println!();

    if tel.interfaces.is_empty() {
        println!("  {}", "No interface metrics collected yet.".yellow());
    } else {
        let mut table = printer.new_table();
        table.set_header(vec![
            "Interface",
            "RX Rate",
            "TX Rate",
            "RX Total",
            "TX Total",
            "Packets (RX/TX)",
            "Drops (RX/TX)",
            "Errors",
        ]);

        for iface in &tel.interfaces {
            let rx_rate = format_rate_bps(iface.rx_rate_bps);
            let tx_rate = format_rate_bps(iface.tx_rate_bps);

            let drops_str = if iface.rx_dropped > 0 || iface.tx_dropped > 0 {
                format!("{}/{}", iface.rx_dropped, iface.tx_dropped)
                    .yellow()
                    .to_string()
            } else {
                "0/0".dimmed().to_string()
            };

            let errors_str = if iface.rx_errors > 0 || iface.tx_errors > 0 {
                format!("{}/{}", iface.rx_errors, iface.tx_errors)
                    .red()
                    .bold()
                    .to_string()
            } else {
                "0/0".dimmed().to_string()
            };

            let pkts_str = format!("{}/{}", iface.rx_packets, iface.tx_packets);

            table.add_row(vec![
                iface.interface.clone().bold().cyan().to_string(),
                rx_rate.green().bold().to_string(),
                tx_rate.blue().bold().to_string(),
                format_bytes(iface.rx_bytes).white().to_string(),
                format_bytes(iface.tx_bytes).white().to_string(),
                pkts_str.dimmed().to_string(),
                drops_str,
                errors_str,
            ]);
        }
        println!("{table}");
    }

    if let Some(ct) = &tel.conntrack {
        println!();
        println!(
            "  Conntrack: {}/{} ({:.1}%)  ·  Search: {}  ·  New: {}  ·  Drop: {}  ·  Invalid: {}",
            ct.active_connections.to_string().cyan().bold(),
            ct.max_connections,
            ct.utilization_percent,
            ct.search.to_string().dimmed(),
            ct.new.to_string().green(),
            ct.drop.to_string().yellow(),
            ct.invalid.to_string().red()
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Subcommand: sqm
// ---------------------------------------------------------------------------

async fn show_sqm(client: &LanforgeClient, printer: &Printer, args: TrafficSqmArgs) -> Result<()> {
    let telemetry = client.traffic_telemetry().await?;

    if printer.json {
        return printer.print_json(&telemetry.sqm);
    }

    let Some(sqm) = &telemetry.sqm else {
        printer.info("No SQM telemetry collected yet or SQM is not running.");
        return Ok(());
    };

    if !sqm.active {
        printer.info(
            "SQM (CAKE) is currently INACTIVE. Enable it via 'lanforge traffic config sqm-enable'.",
        );
        return Ok(());
    }

    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        "CAKE QUEUING DISCIPLINE DIAGNOSTICS".bold().white()
    );
    println!();

    if let Some(egress) = &sqm.egress {
        render_cake_qdisc("Egress (WAN)", egress, printer, args.tins);
    }

    if let Some(ingress) = &sqm.ingress {
        println!();
        render_cake_qdisc("Ingress (IFB)", ingress, printer, args.tins);
    }

    println!();
    Ok(())
}

fn render_cake_qdisc(label: &str, qdisc: &CakeQdiscStats, printer: &Printer, show_tins: bool) {
    let bw_str = if qdisc.bandwidth == 0 {
        "unlimited".dimmed().to_string()
    } else {
        format_rate_bps(qdisc.bandwidth).cyan().bold().to_string()
    };

    println!("  {label} — Device: {}", qdisc.dev.cyan().bold());
    println!(
        "    Target Bandwidth: {bw_str}  ·  Capacity Estimate: {}",
        if qdisc.capacity_estimate == 0 {
            "—".to_string()
        } else {
            format_rate_bps(qdisc.capacity_estimate)
        }
    );
    println!(
        "    Sent: {} ({} pkts)  ·  Backlog: {} ({} pkts)",
        format_bytes(qdisc.bytes).white(),
        qdisc.packets,
        format_bytes(qdisc.backlog).white(),
        qdisc.qlen
    );
    println!(
        "    Memory: {} / {}  ·  Drops: {}  ·  Overlimits: {}",
        format_bytes(qdisc.memory_used),
        format_bytes(qdisc.memory_limit),
        if qdisc.drops > 0 {
            qdisc.drops.to_string().yellow().bold().to_string()
        } else {
            "0".to_string()
        },
        qdisc.overlimits
    );

    if show_tins && !qdisc.tins.is_empty() {
        println!();
        let mut table = printer.new_table();
        table.set_header(vec![
            "Tin / Priority",
            "Threshold",
            "Sent",
            "Backlog",
            "Peak Delay",
            "Avg Delay",
            "Base Delay",
            "Drops",
            "ECN",
            "Flows (S/B/U)",
        ]);

        for tin in &qdisc.tins {
            let flows_str = format!(
                "{}/{}/{}",
                tin.sparse_flows, tin.bulk_flows, tin.unresponsive_flows
            );
            let drops_str = if tin.drops > 0 {
                tin.drops.to_string().yellow().bold().to_string()
            } else {
                "0".dimmed().to_string()
            };
            let ecn_str = if tin.ecn_mark > 0 {
                tin.ecn_mark.to_string().cyan().to_string()
            } else {
                "0".dimmed().to_string()
            };

            table.add_row(vec![
                tin.name.clone().bold().white().to_string(),
                format_rate_bps(tin.threshold_rate).dimmed().to_string(),
                format_bytes(tin.sent_bytes).white().to_string(),
                format_bytes(tin.backlog_bytes).dimmed().to_string(),
                format_delay_us(tin.peak_delay_us),
                format_delay_us(tin.avg_delay_us),
                format_delay_us(tin.base_delay_us),
                drops_str,
                ecn_str,
                flows_str.dimmed().to_string(),
            ]);
        }
        println!("{table}");
    }
}

// ---------------------------------------------------------------------------
// Subcommand: config
// ---------------------------------------------------------------------------

async fn execute_config(
    client: &LanforgeClient,
    printer: &Printer,
    args: TrafficConfigArgs,
) -> Result<()> {
    match args.subcommand.unwrap_or(TrafficConfigSubcommand::Show) {
        TrafficConfigSubcommand::Show => show_config(client, printer).await,
        TrafficConfigSubcommand::SqmEnable => {
            let mut cfg = *client.traffic_config().await?;
            cfg.sqm.enabled = true;
            client.update_traffic_config(cfg).await?;
            printer.success("SQM (CAKE) traffic shaping enabled.");
            Ok(())
        }
        TrafficConfigSubcommand::SqmDisable => {
            let mut cfg = *client.traffic_config().await?;
            cfg.sqm.enabled = false;
            client.update_traffic_config(cfg).await?;
            printer.success("SQM (CAKE) traffic shaping disabled.");
            Ok(())
        }
        TrafficConfigSubcommand::SqmSet(set_args) => {
            apply_sqm_set(client, printer, *set_args).await
        }
        TrafficConfigSubcommand::TuningEnable => {
            let mut cfg = *client.traffic_config().await?;
            cfg.tuning.enabled = true;
            client.update_traffic_config(cfg).await?;
            printer.success("Hardware NIC tuning enabled.");
            Ok(())
        }
        TrafficConfigSubcommand::TuningDisable => {
            let mut cfg = *client.traffic_config().await?;
            cfg.tuning.enabled = false;
            client.update_traffic_config(cfg).await?;
            printer.success("Hardware NIC tuning disabled.");
            Ok(())
        }
        TrafficConfigSubcommand::TuningSet(set_args) => {
            apply_tuning_set(client, printer, *set_args).await
        }
    }
}

async fn show_config(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let cfg = client.traffic_config().await?;

    if printer.json {
        return printer.print_json(&cfg);
    }

    println!();
    println!(
        " {} {}",
        "●".bright_cyan(),
        "TRAFFIC CONFIGURATION".bold().white()
    );
    println!();

    println!(
        "  Hardware NIC Tuning: {}",
        if cfg.tuning.enabled {
            "ENABLED".green().bold()
        } else {
            "DISABLED".dimmed()
        }
    );
    let ifaces = if cfg.tuning.interfaces.is_empty() {
        "auto (all physical)".dimmed().to_string()
    } else {
        cfg.tuning.interfaces.join(", ")
    };
    println!("    {:<28} {ifaces}", "Interfaces:".dimmed());
    println!("    {:<28} {}", "CPU Mask:".dimmed(), cfg.tuning.cpu_mask);
    println!(
        "    {:<28} {} / {}",
        "RPS Flow Entries / Cnt:".dimmed(),
        cfg.tuning.rps_flow_entries,
        cfg.tuning.rps_flow_cnt
    );
    println!(
        "    {:<28} RX: {}  ·  TX: {}",
        "Ring Buffer Sizes:".dimmed(),
        cfg.tuning.rx_ring,
        cfg.tuning.tx_ring
    );
    println!(
        "    {:<28} {}",
        "Disable EEE:".dimmed(),
        cfg.tuning.disable_eee
    );
    println!(
        "    {:<28} {}",
        "UDP GRO Forwarding:".dimmed(),
        cfg.tuning.udp_gro_forwarding
    );

    println!();
    println!(
        "  Smart Queue Management (SQM): {}",
        if cfg.sqm.enabled {
            "ENABLED".green().bold()
        } else {
            "DISABLED".dimmed()
        }
    );
    println!(
        "    {:<28} {}",
        "Target Interface:".dimmed(),
        cfg.sqm.interface.cyan()
    );
    println!(
        "    {:<28} Down: {} Mbps  ·  Up: {} Mbps",
        "Bandwidth Limits:".dimmed(),
        cfg.sqm.download_mbps,
        cfg.sqm.upload_mbps
    );
    println!(
        "    {:<28} {:?}",
        "Classification (DiffServ):".dimmed(),
        cfg.sqm.diffserv
    );
    println!(
        "    {:<28} {:?}",
        "Framing Overhead:".dimmed(),
        cfg.sqm.overhead
    );
    println!(
        "    {:<28} {}",
        "Per-Host Isolation:".dimmed(),
        cfg.sqm.per_host_isolation
    );
    if let Some(rtt) = cfg.sqm.rtt_ms {
        println!("    {:<28} {rtt} ms", "Target RTT Override:".dimmed());
    }

    println!();
    Ok(())
}

async fn apply_sqm_set(client: &LanforgeClient, printer: &Printer, args: SqmSetArgs) -> Result<()> {
    let changed = args.download.is_some()
        || args.upload.is_some()
        || args.interface.is_some()
        || args.diffserv.is_some()
        || args.overhead.is_some()
        || args.per_host.is_some()
        || args.rtt.is_some();

    if !changed {
        printer
            .info("No SQM settings changed. Use flags like --download, --upload, or --diffserv.");
        return Ok(());
    }

    let mut cfg = *client.traffic_config().await?;

    if let Some(dl) = args.download {
        cfg.sqm.download_mbps = dl;
    }
    if let Some(ul) = args.upload {
        cfg.sqm.upload_mbps = ul;
    }
    if let Some(iface) = args.interface {
        cfg.sqm.interface = iface;
    }
    if let Some(diff) = &args.diffserv {
        cfg.sqm.diffserv = parse_sqm_diffserv(diff)?;
    }
    if let Some(ovh) = &args.overhead {
        cfg.sqm.overhead = parse_sqm_overhead(ovh)?;
    }
    if let Some(ph) = args.per_host {
        cfg.sqm.per_host_isolation = ph;
    }
    if let Some(rtt) = args.rtt {
        cfg.sqm.rtt_ms = Some(rtt);
    }

    client.update_traffic_config(cfg).await?;
    printer.success("SQM (CAKE) configuration updated successfully.");
    Ok(())
}

async fn apply_tuning_set(
    client: &LanforgeClient,
    printer: &Printer,
    args: TuningSetArgs,
) -> Result<()> {
    let changed = args.interfaces.is_some()
        || args.cpu_mask.is_some()
        || args.gro.is_some()
        || args.disable_eee.is_some();

    if !changed {
        printer
            .info("No tuning settings changed. Use flags like --interfaces, --cpu-mask, or --gro.");
        return Ok(());
    }

    let mut cfg = *client.traffic_config().await?;

    if let Some(ifaces) = args.interfaces {
        cfg.tuning.interfaces = ifaces;
    }
    if let Some(mask) = args.cpu_mask {
        cfg.tuning.cpu_mask = mask;
    }
    if let Some(gro) = args.gro {
        cfg.tuning.udp_gro_forwarding = gro;
    }
    if let Some(eee) = args.disable_eee {
        cfg.tuning.disable_eee = eee;
    }

    client.update_traffic_config(cfg).await?;
    printer.success("Hardware NIC tuning configuration updated successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers & Formatters
// ---------------------------------------------------------------------------

pub fn parse_sqm_diffserv(s: &str) -> Result<SqmDiffserv> {
    match s.to_ascii_lowercase().as_str() {
        "diffserv4" | "4" => Ok(SqmDiffserv::Diffserv4),
        "diffserv3" | "3" => Ok(SqmDiffserv::Diffserv3),
        "besteffort" | "be" => Ok(SqmDiffserv::Besteffort),
        other => {
            bail!(
                "Invalid DiffServ profile '{other}'. Valid options: diffserv4, diffserv3, besteffort"
            );
        }
    }
}

pub fn parse_sqm_overhead(s: &str) -> Result<SqmOverhead> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(SqmOverhead::Auto),
        "pppoe" => Ok(SqmOverhead::Pppoe),
        "ethernet" | "eth" => Ok(SqmOverhead::Ethernet),
        "docsis" => Ok(SqmOverhead::Docsis),
        "none" => Ok(SqmOverhead::None),
        other => {
            bail!(
                "Invalid framing overhead '{other}'. Valid options: auto, pppoe, ethernet, docsis, none"
            );
        }
    }
}

#[must_use]
pub fn format_rate_bps(rate: u64) -> String {
    if rate >= 1_000_000_000 {
        #[allow(clippy::cast_precision_loss)]
        let val = rate as f64 / 1_000_000_000.0;
        format!("{val:.2} Gbps")
    } else if rate >= 1_000_000 {
        #[allow(clippy::cast_precision_loss)]
        let val = rate as f64 / 1_000_000.0;
        format!("{val:.2} Mbps")
    } else if rate >= 1000 {
        #[allow(clippy::cast_precision_loss)]
        let val = rate as f64 / 1000.0;
        format!("{val:.1} Kbps")
    } else {
        format!("{rate} bps")
    }
}

#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        #[allow(clippy::cast_precision_loss)]
        let val = bytes as f64 / 1_073_741_824.0;
        format!("{val:.2} GB")
    } else if bytes >= 1_048_576 {
        #[allow(clippy::cast_precision_loss)]
        let val = bytes as f64 / 1_048_576.0;
        format!("{val:.1} MB")
    } else if bytes >= 1024 {
        #[allow(clippy::cast_precision_loss)]
        let val = bytes as f64 / 1024.0;
        format!("{val:.1} KB")
    } else {
        format!("{bytes} B")
    }
}

#[must_use]
pub fn format_delay_us(us: u32) -> String {
    if us == 0 {
        "0 µs".to_string()
    } else if us >= 1000 {
        #[allow(clippy::cast_precision_loss)]
        let val = f64::from(us) / 1000.0;
        format!("{val:.2} ms")
    } else {
        format!("{us} µs")
    }
}

#[must_use]
pub fn render_progress_bar(percent: f32, width: usize, ascii: bool) -> String {
    let p = percent.clamp(0.0, 100.0) / 100.0;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = (p * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);

    if ascii {
        format!("[{}{}]", "=".repeat(filled), " ".repeat(empty))
    } else {
        format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_rate_bps() {
        assert_eq!(format_rate_bps(0), "0 bps");
        assert_eq!(format_rate_bps(500), "500 bps");
        assert_eq!(format_rate_bps(1_500), "1.5 Kbps");
        assert_eq!(format_rate_bps(25_000_000), "25.00 Mbps");
        assert_eq!(format_rate_bps(1_500_000_000), "1.50 Gbps");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(10_485_760), "10.0 MB");
        assert_eq!(format_bytes(5_368_709_120), "5.00 GB");
    }

    #[test]
    fn test_format_delay_us() {
        assert_eq!(format_delay_us(0), "0 µs");
        assert_eq!(format_delay_us(450), "450 µs");
        assert_eq!(format_delay_us(1500), "1.50 ms");
        assert_eq!(format_delay_us(25000), "25.00 ms");
    }

    #[test]
    fn test_parse_diffserv_and_overhead() {
        assert_eq!(
            parse_sqm_diffserv("diffserv4").unwrap(),
            SqmDiffserv::Diffserv4
        );
        assert_eq!(parse_sqm_diffserv("4").unwrap(), SqmDiffserv::Diffserv4);
        assert_eq!(
            parse_sqm_diffserv("besteffort").unwrap(),
            SqmDiffserv::Besteffort
        );
        assert!(parse_sqm_diffserv("invalid").is_err());

        assert_eq!(parse_sqm_overhead("auto").unwrap(), SqmOverhead::Auto);
        assert_eq!(parse_sqm_overhead("pppoe").unwrap(), SqmOverhead::Pppoe);
        assert_eq!(parse_sqm_overhead("none").unwrap(), SqmOverhead::None);
        assert!(parse_sqm_overhead("invalid").is_err());
    }

    #[test]
    fn test_render_progress_bar() {
        assert_eq!(render_progress_bar(50.0, 10, true), "[=====     ]");
        assert_eq!(render_progress_bar(50.0, 10, false), "[█████░░░░░]");
    }
}
