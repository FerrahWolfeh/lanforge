use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;
use lanforge_api::api::{TopologyEntry, TopologyResponse};
use std::collections::HashMap;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct TopologyArgs {}

impl Execute for TopologyArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let resp = client.topology().await?;
        if client.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        render_topology(&resp, client.ascii);
        Ok(())
    }
}

pub fn render_topology(resp: &TopologyResponse, ascii: bool) {
    println!("Network Topology Hierarchy\n");

    let mut parent_to_children: HashMap<String, Vec<&TopologyEntry>> = HashMap::new();
    let mut orphans: Vec<&TopologyEntry> = Vec::new();

    for entry in &resp.entries {
        if let Some(parent) = &entry.parent_mac {
            parent_to_children
                .entry(parent.clone())
                .or_default()
                .push(entry);
        } else {
            orphans.push(entry);
        }
    }

    let mut roots: Vec<String> = parent_to_children
        .keys()
        .filter(|k| {
            !resp
                .entries
                .iter()
                .any(|e| &&e.mac == k && e.parent_mac.is_some())
        })
        .cloned()
        .collect();

    roots.sort();

    if roots.is_empty() && orphans.is_empty() {
        println!("No topology data available.");
        return;
    }

    let root_box = if ascii { "+-" } else { "┏━" };
    let net_icon = if ascii { "[NET]" } else { "🖧 " };
    let q_icon = if ascii { "[?]" } else { "❓" };
    let dev_icon = if ascii { "[DEV]" } else { "💻" };
    let vert = if ascii { "|  " } else { "┃  " };

    for root_mac in roots {
        let root_hostname = resp
            .entries
            .iter()
            .find(|e| e.mac == root_mac)
            .map_or("Unknown Switch", |e| e.hostname.as_str());

        println!("{root_box} {net_icon} {root_hostname} [{root_mac}]");
        print_children(&root_mac, &parent_to_children, vert, true, ascii);
        println!();
    }

    if !orphans.is_empty() {
        println!("{root_box} {q_icon} Unlinked Devices");
        for (i, orphan) in orphans.iter().enumerate() {
            let is_last = i == orphans.len() - 1;
            let prefix = if ascii {
                "+-"
            } else if is_last {
                "┗━"
            } else {
                "┣━"
            };
            println!("   {prefix} {dev_icon} {} [{}]", orphan.hostname, orphan.mac);
        }
    }
}

fn print_children(
    parent_mac: &str,
    map: &HashMap<String, Vec<&TopologyEntry>>,
    indent: &str,
    _is_root: bool,
    ascii: bool,
) {
    if let Some(children) = map.get(parent_mac) {
        let mut sorted = children.clone();
        sorted.sort_by(|a, b| {
            let port_a = a.port.as_deref().unwrap_or("");
            let port_b = b.port.as_deref().unwrap_or("");
            port_a.cmp(port_b).then_with(|| a.mac.cmp(&b.mac))
        });

        let dev_icon = if ascii { "[DEV]" } else { "💻" };

        for (i, child) in sorted.iter().enumerate() {
            let is_last = i == sorted.len() - 1;
            let branch = if ascii {
                "+-"
            } else if is_last {
                "┗━"
            } else {
                "┣━"
            };
            let sub_indent = if is_last {
                "   "
            } else if ascii {
                "|  "
            } else {
                "┃  "
            };

            let port_str = child
                .port
                .as_ref()
                .map(|p| format!(" (Port: {p})"))
                .unwrap_or_default();

            let ago = super::format_relative_iso8601(&child.last_updated);

            println!(
                "{indent}{branch} {dev_icon} {} [{}] {port_str} [seen: {ago}]",
                child.hostname, child.mac
            );

            let next_indent = format!("{indent}{sub_indent}");
            print_children(&child.mac, map, &next_indent, false, ascii);
        }
    }
}
