use super::{CliCommand, format_relative_iso8601};
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response, TopologyEntry};
use std::collections::HashMap;

pub struct TopologyHandler;

impl CliCommand for TopologyHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::new(CommandAction::Topology))
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Topology(resp) => {
                println!("Network Topology Hierarchy\n");

                // Build a tree of parent MAC -> list of children
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

                // If a parent is also a child, it shouldn't be printed as a root.
                // Roots are devices that are parents but not children themselves.
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
                    return Ok(None);
                }

                for root_mac in roots {
                    // Try to find the root's hostname if it exists in the entries
                    let root_hostname = resp
                        .entries
                        .iter()
                        .find(|e| e.mac == root_mac)
                        .map(|e| e.hostname.as_str())
                        .unwrap_or("Unknown Switch");

                    println!("┏━ 🖧  {root_hostname} [{root_mac}]");
                    print_children(&root_mac, &parent_to_children, "┃  ", true);
                    println!();
                }

                if !orphans.is_empty() {
                    println!("┏━ ❓ Unlinked Devices");
                    for (i, orphan) in orphans.iter().enumerate() {
                        let is_last = i == orphans.len() - 1;
                        let prefix = if is_last { "┗━" } else { "┣━" };
                        println!("   {prefix} 💻 {} [{}]", orphan.hostname, orphan.mac);
                    }
                }
            }
            Response::Error { error } => {
                println!("Error fetching topology: {error}");
            }
            _ => {
                println!("Unexpected response: {:?}", response);
            }
        }
        Ok(None)
    }
}

fn print_children(
    parent_mac: &str,
    map: &HashMap<String, Vec<&TopologyEntry>>,
    indent: &str,
    _is_root: bool,
) {
    if let Some(children) = map.get(parent_mac) {
        let mut sorted = children.clone();
        // Sort by port if available, then by MAC
        sorted.sort_by(|a, b| {
            let port_a = a.port.as_deref().unwrap_or("");
            let port_b = b.port.as_deref().unwrap_or("");
            port_a.cmp(port_b).then_with(|| a.mac.cmp(&b.mac))
        });

        for (i, child) in sorted.iter().enumerate() {
            let is_last = i == sorted.len() - 1;
            let branch = if is_last { "┗━" } else { "┣━" };
            let sub_indent = if is_last { "   " } else { "┃  " };

            let port_str = child
                .port
                .as_ref()
                .map(|p| format!(" (Port: {p})"))
                .unwrap_or_default();

            let ago = format_relative_iso8601(&child.last_updated);

            println!(
                "{indent}{branch} 💻 {} [{}] {port_str} [seen: {ago}]",
                child.hostname, child.mac
            );

            // Recursively print children of this child
            let next_indent = format!("{}{}", indent, sub_indent);
            print_children(&child.mac, map, &next_indent, false);
        }
    }
}
