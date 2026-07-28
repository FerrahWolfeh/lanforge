use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_types::system::PppoeStatusResponse;



#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PppoeArgs {
    #[command(subcommand)]
    pub action: Option<PppoeAction>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PppoeAction {
    /// Show `PPPoE` WAN status and details
    Status,
    /// Trigger immediate `PPPoE` reconnection
    Reconnect,
    /// Disconnect active `PPPoE` WAN session
    Disconnect,
}


impl Execute for PppoeArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let action = self.action.unwrap_or(PppoeAction::Status);
        match action {
            PppoeAction::Status => {
                let status = client.pppoe_status().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    return Ok(());
                }
                render_pppoe_status(&status, client.ascii);
            }
            PppoeAction::Reconnect => {
                let resp = client.pppoe_reconnect().await?;
                println!("✓ {}", resp.message);
            }
            PppoeAction::Disconnect => {
                let resp = client.pppoe_disconnect().await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}

fn render_pppoe_status(status: &PppoeStatusResponse, ascii: bool) {
    let state_str = format!("{:?}", status.state);
    let state_color = match status.state {
        lanforge_types::system::PppoeSessionState::Connected => Color::Green,
        lanforge_types::system::PppoeSessionState::Authenticating
        | lanforge_types::system::PppoeSessionState::Reconnecting => Color::Yellow,
        lanforge_types::system::PppoeSessionState::Disconnected => Color::Red,
    };

    let iface = status.interface.as_deref().unwrap_or("N/A");
    let wan_iface = status.wan_iface.as_deref().unwrap_or("N/A");
    let local_ip = status.local_ip.map_or_else(|| "N/A".to_string(), |ip| ip.to_string());
    let peer_ip = status.peer_ip.map_or_else(|| "N/A".to_string(), |ip| ip.to_string());
    let ac_mac = status.ac_mac.map_or_else(|| "N/A".to_string(), |m| m.to_string());
    let ac_name = status.ac_name.as_deref().unwrap_or("unknown");
    let session_id = status.session_id.map_or_else(|| "N/A".to_string(), |id| id.to_string());
    let mru = status.mru.map_or_else(|| "N/A".to_string(), |m| m.to_string());

    let dns_list = if status.dns_servers.is_empty() {
        "None (Fallback inactive)".to_string()
    } else {
        status
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    element! {
        View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
            View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                Text(content: if ascii { "--- PPPoE WAN STATUS ---" } else { "🌐 PPPoE WAN STATUS" }, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Session State: ", weight: Weight::Bold)
                Text(content: state_str, color: state_color, weight: Weight::Bold)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Virtual Interface: ", color: Color::DarkGrey)
                Text(content: iface.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Physical Interface: ", color: Color::DarkGrey)
                Text(content: wan_iface.to_string())
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Assigned WAN IP: ", color: Color::DarkGrey)
                Text(content: local_ip)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Peer Gateway IP: ", color: Color::DarkGrey)
                Text(content: peer_ip)
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Access Concentrator: ", color: Color::DarkGrey)
                Text(content: format!("{ac_name} ({ac_mac})"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "Session ID / MRU: ", color: Color::DarkGrey)
                Text(content: format!("{session_id} / {mru}"))
            }
            View(flex_direction: FlexDirection::Row) {
                Text(content: "ISP DNS (Fallback Only): ", color: Color::DarkGrey)
                Text(content: dns_list)
            }
        }
    }
    .print();
}
