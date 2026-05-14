use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::Result;
use color_eyre::eyre::bail;
use inquire::{Confirm, Select, Text as InquireText};
use iocraft::prelude::*;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct HostArgs {
    #[command(subcommand)]
    pub action: HostAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum HostAction {
    Add {
        /// Prefix MAC with this argument, or run interactively
        mac: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        v4: Option<String>,
        #[arg(long)]
        v6_suffix: Option<String>,
    },
    Set {
        mac: String,
        field: String,
        value: String,
    },
    List,
    Remove {
        mac: String,
    },
}

impl Execute for HostArgs {
    #[allow(clippy::too_many_lines)]
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(HostHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct HostHandler {
    pub action: HostAction,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for HostHandler {
    #[allow(clippy::too_many_lines)]
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match &self.action {
            HostAction::Add {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => {
                let final_mac = if let Some(m) = mac {
                    m.clone()
                } else {
                    let ans = InquireText::new("MAC address:").prompt()?;
                    if ans.trim().is_empty() {
                        bail!("MAC address is required");
                    }
                    ans.trim().to_string()
                };

                let final_hostname = if let Some(h) = hostname {
                    h.clone()
                } else {
                    let ans = InquireText::new("Hostname:").prompt()?;
                    if ans.trim().is_empty() {
                        bail!("Hostname is required");
                    }
                    ans.trim().to_string()
                };

                let mut final_v4 = v4.clone();
                let mut final_v6 = v6_suffix.clone();

                if v4.is_none() && v6_suffix.is_none() {
                    let opts = vec![
                        "[1] Hostname only (dynamic IP from pool)",
                        "[2] Hostname + Fixed IPv4",
                        "[3] Hostname + Fixed IPv4 + ULA suffix",
                    ];
                    let choice = Select::new("Configuration level:", opts).prompt()?;
                    if choice.starts_with("[2]") || choice.starts_with("[3]") {
                        let ans = InquireText::new("Fixed IPv4:").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v4 = Some(ans.trim().to_string());
                        }
                    }
                    if choice.starts_with("[3]") {
                        let ans = InquireText::new("ULA Suffix (ex: ::1234):").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v6 = Some(ans.trim().to_string());
                        }
                    }

                    element! {
                            View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
                                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                                    Text(content: " CONFIRM ADDITION ", color: Color::White, weight: Weight::Bold)
                                }
                                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                                    SummaryLine(label: "MAC".to_string(), value: final_mac.clone(), color: Color::Cyan)
                                    SummaryLine(label: "Hostname".to_string(), value: final_hostname.clone(), color: Color::Cyan)
                                    #(final_v4.as_ref().map(|v| element! {
                                        SummaryLine(label: "Fixed IPv4".to_string(), value: v.clone(), color: Color::Green)
                                    }))
                                    #(final_v6.as_ref().map(|v| element! {
                                        SummaryLine(label: "V6 Suffix".to_string(), value: v.clone(), color: Color::Yellow)
                                    }))
                                }
                            }
                        }.print();

                    let confirm = Confirm::new("Save host configuration?")
                        .with_default(true)
                        .prompt()?;
                    if !confirm {
                        bail!("Cancelled.");
                    }
                }

                let resp = client
                    .host_add(Some(final_mac), Some(final_hostname), final_v4, final_v6)
                    .await?;
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "✓ ", color: Color::Green)
                        Text(content: resp.message, color: Color::Green, weight: Weight::Bold)
                    }
                }
                .print();
            }
            HostAction::Set { mac, field, value } => {
                let resp = client
                    .host_set(mac.clone(), field.clone(), value.clone())
                    .await?;
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "✓ ", color: Color::Green)
                        Text(content: resp.message, color: Color::Green, weight: Weight::Bold)
                    }
                }
                .print();
            }
            HostAction::Remove { mac } => {
                let resp = client.host_remove(mac.clone()).await?;
                element! {
                    View(padding_left: 2, margin_top: 1) {
                        Text(content: "✓ ", color: Color::Green)
                        Text(content: resp.message, color: Color::Green, weight: Weight::Bold)
                    }
                }
                .print();
            }
            HostAction::List => {
                let resp = client.host_list().await?;
                super::devices::render_hosts(&resp);
            }
        }
        Ok(())
    }
}

#[component]
fn SummaryLine(props: &SummaryLineProps) -> impl Into<AnyElement<'_>> {
    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: format!("{:<12}", props.label), color: Color::DarkGrey)
            Text(content: props.value.clone(), color: props.color)
        }
    }
}

#[derive(Props)]
struct SummaryLineProps {
    pub label: String,
    pub value: String,
    pub color: Color,
}

impl Default for SummaryLineProps {
    fn default() -> Self {
        Self {
            label: String::new(),
            value: String::new(),
            color: Color::White,
        }
    }
}
