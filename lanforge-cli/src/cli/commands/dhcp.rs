use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::DhcpPoolEntry;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DhcpArgs {
    #[command(subcommand)]
    pub action: DhcpAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpAction {
    /// Show DHCP pool utilization and availability
    Pool,
}

impl Execute for DhcpArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(DhcpHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct DhcpHandler {
    pub action: DhcpAction,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for DhcpHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match &self.action {
            DhcpAction::Pool => {
                let pools = client.dhcp_pools().await?;
                element! {
                        View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                                Text(content: " DHCP POOL UTILIZATION ", color: Color::White, weight: Weight::Bold)
                            }

                            #(pools.v4_pools.is_empty().then(|| element! {
                                 Text(content: "No IPv4 pools configured.", color: Color::DarkGrey)
                            }))

                            #(pools.v4_pools.iter().map(|p| element! {
                                PoolSection(title: "IPv4 Subnet".to_string(), pool: p.clone())
                            }))

                            View(margin_top: 1)

                            #(pools.v6_pools.is_empty().then(|| element! {
                                 Text(content: "No IPv6 pools configured.", color: Color::DarkGrey)
                            }))

                            #(pools.v6_pools.iter().map(|p| element! {
                                PoolSection(title: "IPv6 Prefix".to_string(), pool: p.clone())
                            }))
                        }
                    }.print();
            }
        }
        Ok(())
    }
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

    element! {
        View(flex_direction: FlexDirection::Column, margin_bottom: 1) {
            View(flex_direction: FlexDirection::Row) {
                Text(content: format!("{}: ", props.title), color: Color::DarkGrey)
                Text(content: p.subnet.clone(), weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row, margin_top: 1) {
                ProgressBar(percent: p.utilization_percent, color: bar_color)
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

    let filled_str = "█".repeat(filled);
    let empty_str = "░".repeat(empty);

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
}

impl Default for ProgressBarProps {
    fn default() -> Self {
        Self {
            percent: 0.0,
            color: Color::White,
        }
    }
}
