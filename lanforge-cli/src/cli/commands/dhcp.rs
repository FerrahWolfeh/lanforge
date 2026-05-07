use crate::{args, cli::commands::CliCommand};
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{Command as ControlCommand, CommandAction, DhcpPoolEntry, Response};

pub struct DhcpHandler {
    pub action: args::DhcpCommand,
}

impl CliCommand for DhcpHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            args::DhcpCommand::Pool => Ok(ControlCommand::new(CommandAction::DhcpPools)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::DhcpPools(pools) => {
                element! {
                    View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                        View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                            Text(content: " DHCP POOL UTILIZATION ", color: Color::White, weight: Weight::Bold)
                        }
                        
                        #(pools.v4_pools.is_empty().then(|| element! {
                             Text(content: "No IPv4 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v4_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv4 Subnet", pool: p.clone())
                        }))

                        View(margin_top: 1)
                        
                        #(pools.v6_pools.is_empty().then(|| element! {
                             Text(content: "No IPv6 pools configured.", color: Color::DarkGrey)
                        }))

                        #(pools.v6_pools.iter().map(|p| element! {
                            PoolSection(title: "IPv6 Prefix", pool: p.clone())
                        }))
                    }
                }.print();
            }
            Response::Error { error } => {
                println!("Error: {error}");
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
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
    let filled = ((props.percent / 100.0) * width as f32) as usize;
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
