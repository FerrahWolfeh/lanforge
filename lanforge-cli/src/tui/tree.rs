use crate::tui::{theme, utils};
use lanforge_api::api::StatusResponse;
use lanforge_core::context::state::State;
use lanforge_types::device::Device;
use lanforge_types::identifiers::MacAddr;
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use tui_tree_widget::TreeItem;

fn key_val(key: &str, val: String) -> Text<'static> {
    Text::from(Line::from(vec![
        Span::styled(format!("{key}: "), Style::default().fg(theme::KEY)),
        Span::styled(val, Style::default().fg(theme::VALUE)),
    ]))
}

#[must_use]
pub fn build_tree(
    state: &State,
    status: &Option<StatusResponse>,
) -> Vec<TreeItem<'static, String>> {
    let mut root_items = Vec::new();

    // 1. LanforgeContext Summary
    if let Some(s) = status {
        root_items.push(build_context_node(s));
    }

    // 2. State Detail
    let mut state_children = Vec::new();

    state_children.push(build_devices_node(state));

    if let Some(ndp) = build_ndp_node(state) {
        state_children.push(ndp);
    }

    if let Some(static_entries) = build_static_node(state) {
        state_children.push(static_entries);
    }

    if let Some(interfaces) = build_interfaces_node(state) {
        state_children.push(interfaces);
    }

    root_items
        .push(TreeItem::new("state".to_string(), Text::from("State"), state_children).unwrap());

    root_items
}

fn build_context_node(s: &StatusResponse) -> TreeItem<'static, String> {
    let ctx_children = vec![
        TreeItem::new_leaf(
            "ctx.running".to_string(),
            key_val("running", "true".to_string()),
        ),
        TreeItem::new_leaf(
            "ctx.iface".to_string(),
            key_val("interface", s.network.lan_iface.clone()),
        ),
        TreeItem::new_leaf(
            "ctx.v4".to_string(),
            key_val(
                "ipv4",
                s.network.lan_ipv4.as_deref().unwrap_or("—").to_string(),
            ),
        ),
    ];
    TreeItem::new(
        "ctx".to_string(),
        Text::from("LanforgeContext"),
        ctx_children,
    )
    .unwrap()
}

fn build_devices_node(state: &State) -> TreeItem<'static, String> {
    let mut device_nodes = Vec::new();
    let mut device_keys: Vec<_> = state.devices.keys().collect();
    device_keys.sort();

    for mac in device_keys {
        let dev = &state.devices[mac];
        device_nodes.push(build_device_node(*mac, dev));
    }

    TreeItem::new(
        "state.devices".to_string(),
        Text::from(format!("devices ({})", state.devices.len())),
        device_nodes,
    )
    .unwrap()
}

fn build_device_node(mac: MacAddr, dev: &Device) -> TreeItem<'static, String> {
    let mut dev_fields = vec![
        TreeItem::new_leaf(
            format!("dev.{mac}.vendor"),
            key_val(
                "vendor",
                crate::cli::vendor::resolve_vendor(&mac.to_string())
                    .unwrap_or_else(|| "Unknown".to_string()),
            ),
        ),
        TreeItem::new_leaf(
            format!("dev.{mac}.hostname"),
            key_val(
                "hostname",
                format!("{} ({:?})", dev.hostname.name, dev.hostname.origin),
            ),
        ),
        TreeItem::new_leaf(
            format!("dev.{mac}.origin"),
            key_val("origin", format!("{:?}", dev.origin)),
        ),
        TreeItem::new_leaf(
            format!("dev.{mac}.class"),
            key_val("class", format!("{:?}", dev.class)),
        ),
        TreeItem::new_leaf(
            format!("dev.{mac}.seen"),
            key_val("last_seen", utils::format_relative_time(dev.last_seen)),
        ),
    ];

    // Topology
    if let Some(t) = &dev.topology {
        let parent = t
            .parent_mac
            .map_or_else(|| "Local".to_string(), |m| m.to_string());
        let port = t.port.as_deref().unwrap_or("?");
        dev_fields.push(TreeItem::new_leaf(
            format!("dev.{mac}.topology"),
            key_val("topology", format!("{parent} @ {port}")),
        ));
    }

    // IPv4
    dev_fields.push(TreeItem::new_leaf(
        format!("dev.{mac}.v4"),
        key_val("v4", format!("{:?}", dev.v4)),
    ));

    // IPv6
    if !dev.v6.is_empty() {
        let v6_items: Vec<_> = dev
            .v6
            .iter()
            .enumerate()
            .map(|(i, s)| {
                TreeItem::new_leaf(
                    format!("dev.{mac}.v6.{i}"),
                    Text::from(format!("[{}] {}", i, utils::format_v6_state(s))),
                )
            })
            .collect();
        dev_fields.push(
            TreeItem::new(
                format!("dev.{mac}.v6"),
                Text::from("v6 addresses"),
                v6_items,
            )
            .unwrap(),
        );
    }

    TreeItem::new(
        format!("dev.{mac}"),
        Text::from(Line::from(vec![
            Span::raw(format!("{} ", utils::get_class_icon(dev.class))),
            Span::styled(mac.to_string(), Style::default().fg(theme::MAC)),
            Span::raw(" — "),
            Span::styled(
                if dev.hostname.name.is_empty() {
                    "?"
                } else {
                    &dev.hostname.name
                }
                .to_string(),
                Style::default().fg(theme::HOSTNAME),
            ),
        ])),
        dev_fields,
    )
    .unwrap()
}

fn build_ndp_node(state: &State) -> Option<TreeItem<'static, String>> {
    if state.discovery.ndp_cache.is_empty() {
        return None;
    }

    let mut ndp_items = Vec::new();
    let mut ndp_keys: Vec<_> = state.discovery.ndp_cache.keys().collect();
    ndp_keys.sort();
    for ip in ndp_keys {
        let (mac, _) = &state.discovery.ndp_cache[ip];
        let host_info = state.devices.get(mac).map_or_else(String::new, |dev| {
            if dev.hostname.name.is_empty() {
                String::new()
            } else {
                format!(" ({})", dev.hostname.name)
            }
        });
        ndp_items.push(TreeItem::new_leaf(
            format!("ndp.{ip}"),
            Text::from(Line::from(vec![
                Span::styled(ip.to_string(), Style::default().fg(theme::IP)),
                Span::raw(" → "),
                Span::styled(mac.to_string(), Style::default().fg(theme::MAC)),
                Span::styled(host_info, Style::default().fg(theme::HOSTNAME)),
            ])),
        ));
    }
    Some(
        TreeItem::new(
            "state.ndp".to_string(),
            Text::from(format!("ndp_cache ({})", state.discovery.ndp_cache.len())),
            ndp_items,
        )
        .unwrap(),
    )
}

fn build_static_node(state: &State) -> Option<TreeItem<'static, String>> {
    if state.static_entries.is_empty() {
        return None;
    }

    let mut static_items = Vec::new();
    let mut static_keys: Vec<_> = state.static_entries.keys().collect();
    static_keys.sort();
    for mac in static_keys {
        let entry = &state.static_entries[mac];
        static_items.push(TreeItem::new_leaf(
            format!("static.{mac}"),
            Text::from(Line::from(vec![
                Span::styled(mac.to_string(), Style::default().fg(theme::MAC)),
                Span::raw(" → "),
                Span::styled(
                    utils::format_static_entry(entry),
                    Style::default().fg(theme::VALUE),
                ),
            ])),
        ));
    }
    Some(
        TreeItem::new(
            "state.static".to_string(),
            Text::from(format!("static_entries ({})", state.static_entries.len())),
            static_items,
        )
        .unwrap(),
    )
}

fn build_interfaces_node(state: &State) -> Option<TreeItem<'static, String>> {
    if state.interfaces.interface_ips.is_empty() {
        return None;
    }

    let mut if_items = Vec::new();
    let mut if_keys: Vec<_> = state.interfaces.interface_ips.keys().collect();
    if_keys.sort();
    for idx in if_keys {
        let if_state = &state.interfaces.interface_ips[idx];
        if_items.push(TreeItem::new_leaf(
            format!("if.{idx}"),
            Text::from(Line::from(vec![
                Span::styled(format!("ifindex {idx}"), Style::default().fg(theme::KEY)),
                Span::raw(": "),
                Span::styled(
                    utils::format_interface_state(if_state),
                    Style::default().fg(theme::VALUE),
                ),
            ])),
        ));
    }
    Some(
        TreeItem::new(
            "state.interfaces".to_string(),
            Text::from(format!(
                "interface_ips ({})",
                state.interfaces.interface_ips.len()
            )),
            if_items,
        )
        .unwrap(),
    )
}
