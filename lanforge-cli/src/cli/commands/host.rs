use crate::cli::wizard::{fuzzy_select_host, prompt_select, prompt_text};
use crate::cli::{Execute, LanforgeClient};
use crate::render_output;
use clap::Subcommand;
use color_eyre::eyre::{Result, bail};
use inquire::{Confirm, Text as InquireText};
use iocraft::prelude::*;
use lanforge_api::api::HostConfigEntry;

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
        mac: Option<String>,
        field: Option<String>,
        value: Option<String>,
    },
    List,
    Remove {
        target: Option<String>,
    },
    Export {
        file: String,
    },
    Import {
        file: String,
    },
}

macro_rules! print_success {
    ($msg:expr) => {
        element! {
            View(padding_left: 2, margin_top: 1) {
                Text(content: "✓ ", color: Color::Green)
                Text(content: $msg, color: Color::Green, weight: Weight::Bold)
            }
        }
        .print();
    };
}

async fn execute_add(
    client: &LanforgeClient,
    mac: Option<String>,
    hostname: Option<String>,
    v4: Option<String>,
    v6_suffix: Option<String>,
) -> Result<()> {
    let final_mac = if let Some(m) = mac {
        m
    } else {
        let ans = InquireText::new("MAC address:").prompt()?;
        if ans.trim().is_empty() {
            bail!("MAC address is required");
        }
        ans.trim().to_string()
    };

    let final_hostname = if let Some(h) = hostname {
        h
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
        let ans_v4 = InquireText::new("Fixed IPv4 (Enter to leave empty/dynamic):").prompt()?;
        if !ans_v4.trim().is_empty() {
            final_v4 = Some(ans_v4.trim().to_string());
        }

        let ans_v6 =
            InquireText::new("ULA Suffix (ex: ::123, Enter to leave empty/none):").prompt()?;
        if !ans_v6.trim().is_empty() {
            final_v6 = Some(ans_v6.trim().to_string());
        }

        let border = if client.ascii {
            BorderStyle::Classic
        } else {
            BorderStyle::Round
        };

        element! {
            View(flex_direction: FlexDirection::Column, margin_top: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " CONFIRM ADDITION ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: border, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
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
            println!("Cancelled.");
            return Ok(());
        }
    }

    let entry = HostConfigEntry {
        mac: final_mac,
        hostname: final_hostname,
        v4_fixed: final_v4,
        v6_suffix: final_v6,
        origin: "Cli".to_string(),
    };
    let resp = client.host_add(entry).await?;
    print_success!(resp.message);
    Ok(())
}

async fn execute_set(
    client: &LanforgeClient,
    mac: Option<String>,
    field: Option<String>,
    value: Option<String>,
) -> Result<()> {
    let final_mac = if let Some(m) = mac {
        m
    } else {
        let host = fuzzy_select_host(client, "Select host to modify:").await?;
        host.mac
    };

    if let Some(f) = field {
        let final_value = match value {
            Some(v) => v,
            None => prompt_text(&format!("New value for {f}:"), None)?,
        };
        let api_field = if f == "v4" {
            println!("ℹ The device will receive the new IP in the next DHCP cycle");
            "v4_static".to_string()
        } else {
            f
        };
        let resp = client.host_set(final_mac, api_field, final_value).await?;
        print_success!(resp.message);
        return Ok(());
    }

    // Interactive loop mode
    let mut pending_updates = Vec::new();
    loop {
        let opts = vec![
            "hostname",
            "v4",
            "v6_suffix",
            "Confirm and apply changes",
            "Cancel",
        ];
        let chosen = prompt_select("Select field to modify (or confirm/cancel):", opts)?;
        if chosen == "Cancel" {
            println!("Cancelled.");
            return Ok(());
        }
        if chosen == "Confirm and apply changes" {
            if pending_updates.is_empty() {
                println!("No changes to apply.");
                return Ok(());
            }
            break;
        }

        let val = prompt_text(&format!("New value for {chosen}:"), None)?;
        let api_field = if chosen == "v4" {
            println!("ℹ The device will receive the new IP in the next DHCP cycle");
            "v4_static".to_string()
        } else {
            chosen.to_string()
        };
        pending_updates.push((api_field, val));
    }

    for (api_field, val) in pending_updates {
        let resp = client.host_set(final_mac.clone(), api_field, val).await?;
        print_success!(resp.message);
    }

    Ok(())
}

async fn execute_remove(client: &LanforgeClient, target: Option<String>) -> Result<()> {
    let final_mac = if let Some(t) = target {
        let resp = client.host_list().await?;
        if let Some(host) = resp
            .hosts
            .into_iter()
            .find(|h| h.mac.eq_ignore_ascii_case(&t) || h.hostname.eq_ignore_ascii_case(&t))
        {
            host.mac
        } else {
            bail!("Host '{t}' not found.");
        }
    } else {
        let host = fuzzy_select_host(client, "Select host to remove:").await?;
        host.mac
    };
    let resp = client.host_remove(final_mac).await?;
    print_success!(resp.message);
    Ok(())
}

impl Execute for HostArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            HostAction::Add {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => execute_add(client, mac, hostname, v4, v6_suffix).await,
            HostAction::Set { mac, field, value } => execute_set(client, mac, field, value).await,
            HostAction::Remove { target } => execute_remove(client, target).await,
            HostAction::List => render_output!(
                client,
                client.host_list().await?,
                super::devices::render_hosts
            ),
            HostAction::Export { file } => {
                let resp = client.host_list().await?;
                let json = serde_json::to_string_pretty(&resp.hosts)?;
                std::fs::write(&file, json)?;
                println!("✓ Exported {} static hosts to {}", resp.hosts.len(), file);
                Ok(())
            }
            HostAction::Import { file } => {
                let content = std::fs::read_to_string(&file)?;
                let hosts: Vec<HostConfigEntry> = serde_json::from_str(&content)?;
                let resp = client.host_import(hosts).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
        }
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
