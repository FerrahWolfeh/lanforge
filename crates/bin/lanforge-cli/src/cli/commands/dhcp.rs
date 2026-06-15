use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{DhcpPoolEntry, DhcpPoolType, LeaseKind, LeasesResponse};
use lanforge_types::identifiers::MacAddr;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpArgs {
    #[command(subcommand)]
    pub action: DhcpAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpAction {
    /// Show DHCP pool utilization and availability
    Pool,
    /// Active lease table
    Leases {
        #[arg(long)]
        v4: bool,
        #[arg(long)]
        v6: bool,
    },
}

impl Execute for DhcpArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DhcpAction::Pool => {
                let pools = client.dhcp_pools().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&pools)?);
                    return Ok(());
                }

                let ascii = client.ascii;
                element! {
                    View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                        View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                            Text(content: " DHCP POOL UTILIZATION ", color: Color::White, weight: Weight::Bold)
                        }

                        #(pools.v4_pools.is_empty().then(|| element! {
                             Text(content: "No IPv4 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v4_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv4 Subnet".to_string(), pool: p.clone(), ascii: ascii)
                        }))

                        View(margin_top: 1)

                        #(pools.v6_pools.is_empty().then(|| element! {
                             Text(content: "No IPv6 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v6_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv6 Prefix".to_string(), pool: p.clone(), ascii: ascii)
                        }))
                    }
                }.print();
            }
            DhcpAction::Leases { v4, v6 } => {
                let resp = client.leases(false).await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dhcp_leases(&resp, v4, v6, client.ascii);
            }
        }
        Ok(())
    }
}

pub fn render_dhcp_leases(resp: &LeasesResponse, v4_only: bool, v6_only: bool, ascii: bool) {
    element! {
        View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: " ACTIVE DHCP LEASES ", color: Color::White, weight: Weight::Bold)
                Text(content: "  ·  ", color: Color::DarkGrey)
                Text(content: format!("{} total entries", resp.leases.len()))
            }
        }
    }
    .print();

    let mut merged: HashMap<MacAddr, MergedLease> = HashMap::new();
    for l in &resp.leases {
        if v4_only && l.kind != LeaseKind::V4 {
            continue;
        }
        if v6_only && l.kind == LeaseKind::V4 {
            continue;
        }

        let entry = merged.entry(l.mac).or_insert_with(|| MergedLease {
            hostname: if l.hostname.is_empty() {
                "—".to_string()
            } else {
                l.hostname.clone()
            },
            mac: l.mac,
            v4: None,
            v6: None,
            v6_prefix: None,
            expires: l.expires,
        });
        entry.expires = entry.expires.max(l.expires);

        match l.kind {
            LeaseKind::V4 => {
                if let IpAddr::V4(ip) = l.address {
                    entry.v4 = Some(ip);
                }
            }
            LeaseKind::V6 => {
                if let IpAddr::V6(ip) = l.address {
                    entry.v6 = Some(ip);
                }
            }
            LeaseKind::V6Prefix => {
                if let IpAddr::V6(ip) = l.address {
                    entry.v6_prefix = Some(ip);
                }
            }
        }
    }

    let mut sorted: Vec<MergedLease> = merged.into_values().collect();
    sorted.sort_by(|a, b| {
        a.hostname
            .to_lowercase()
            .cmp(&b.hostname.to_lowercase())
            .then(a.mac.cmp(&b.mac))
    });

    let hline = if ascii { "-" } else { "─" };
    element! {
        View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
            // Header
            View(flex_direction: FlexDirection::Row, padding_bottom: 0) {
                Text(content: format!("  {:<23}", "HOST"), color: Color::DarkGrey)
                Text(content: format!("{:<20}", "MAC ADDRESS"), color: Color::DarkGrey)
                Text(content: format!("{:<18}", "IPv4"), color: Color::DarkGrey)
                Text(content: format!("{:<35}", "IPv6"), color: Color::DarkGrey)
                Text(content: "EXPIRES", color: Color::DarkGrey)
            }
            // Separator
            Text(content: hline.repeat(100), color: Color::DarkGrey)

            // Rows
            View(flex_direction: FlexDirection::Column) {
                #(sorted.into_iter().map(|m| element! { MergedLeaseRow(lease: m) }))
            }
            View(padding_bottom: 1) { }
        }
    }
    .print();
}

#[derive(Default)]
struct MergedLease {
    hostname: String,
    mac: MacAddr,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    v6_prefix: Option<Ipv6Addr>,
    expires: u64,
}

#[component]
fn MergedLeaseRow(props: &MergedLeaseRowProps) -> impl Into<AnyElement<'_>> {
    let m = &props.lease;
    let v4_str = m.v4.map_or_else(|| "-".to_string(), |ip| ip.to_string());
    let v6_str = match (m.v6, m.v6_prefix) {
        (Some(v6), Some(pfx)) => format!("{v6} / {pfx}/64"),
        (Some(v6), None) => v6.to_string(),
        (None, Some(pfx)) => format!("{pfx}/64"),
        (None, None) => "-".to_string(),
    };
    let expires_str = &m.expires;

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: "  ")
            Text(content: format!("{:<23}", m.hostname))
            Text(content: format!("{:<20}", m.mac), color: Color::Cyan)
            Text(content: format!("{:<18}", v4_str), color: Color::Green)
            Text(content: format!("{:<35}", v6_str), color: Color::Yellow)
            Text(content: expires_str.to_string(), color: Color::DarkGrey)
        }
    }
}

#[derive(Props, Default)]
struct MergedLeaseRowProps {
    lease: MergedLease,
}

#[component]
fn PoolSection(props: &PoolSectionProps) -> impl Into<AnyElement<'_>> {
    let p = &props.pool;
    let bar_color = if p.utilization_percent > 90.0 {
        Color::Red
    } else if p.utilization_percent > 75.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    let name = match p.pool_type {
        DhcpPoolType::V4 => {
            let start = p
                .range_start
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let end = p
                .range_end
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            format!("{start} - {end}")
        }
        DhcpPoolType::V6 => {
            let prefix = p
                .prefix
                .map_or_else(|| "-".to_string(), |ip| ip.to_string());
            let len = p.prefix_len.map_or(64, |l| l);
            format!("{prefix}/{len}")
        }
    };

    element! {
        View(flex_direction: FlexDirection::Column, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{}: ", props.title), color: Color::DarkGrey)
                Text(content: name, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row, margin_top: 1) {
                ProgressBar(percent: p.utilization_percent, color: bar_color, ascii: props.ascii)
                Text(content: format!("  {:.1}%", p.utilization_percent), color: bar_color)
            }
            View(flex_direction: FlexDirection::Row, margin_top: 1) {
                Text(content: format!("Used: {} / Total: {}", p.used, p.total), color: Color::White)
                View(flex_grow: 1.0)
                Text(content: format!("Available: {}", p.available), color: Color::Cyan)
            }
        }
    }
}

#[derive(Props, Clone, Default)]
struct PoolSectionProps {
    pub title: String,
    pub pool: DhcpPoolEntry,
    pub ascii: bool,
}

#[component]
fn ProgressBar(props: &ProgressBarProps) -> impl Into<AnyElement<'_>> {
    let width: usize = 40;
    let filled = {
        #[allow(clippy::cast_precision_loss)]
        let f = (props.percent / 100.0).clamp(0.0, 1.0) * width as f32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            f as usize
        }
    };
    let empty = width.saturating_sub(filled);

    let filled_str = if props.ascii {
        "#".repeat(filled)
    } else {
        "█".repeat(filled)
    };
    let empty_str = if props.ascii {
        "-".repeat(empty)
    } else {
        "░".repeat(empty)
    };

    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: filled_str, color: props.color)
            Text(content: empty_str, color: Color::DarkGrey)
        }
    }
}

#[derive(Props)]
struct ProgressBarProps {
    pub percent: f32,
    pub color: Color,
    pub ascii: bool,
}

impl Default for ProgressBarProps {
    fn default() -> Self {
        Self {
            percent: 0.0,
            color: Color::White,
            ascii: false,
        }
    }
}
