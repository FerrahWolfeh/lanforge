use crate::tui::{theme, utils};
use lanforge_api::api::StatusResponse;
use lanforge_core::context::state::State;
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use tui_tree_widget::TreeItem;

fn key_val(key: &str, val: String) -> Text<'static> {
    Text::from(Line::from(vec![
        Span::styled(format!("{}: ", key), Style::default().fg(theme::KEY)),
        Span::styled(val, Style::default().fg(theme::VALUE)),
    ]))
}

pub fn build_tree(
    state: &State,
    status: &Option<StatusResponse>,
) -> Vec<TreeItem<'static, String>> {
    let mut root_items = Vec::new();

    // 1. LanforgeContext Summary
    if let Some(s) = status {
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
        root_items.push(
            TreeItem::new(
                "ctx".to_string(),
                Text::from("LanforgeContext"),
                ctx_children,
            )
            .unwrap(),
        );
    }

    // 2. State Detail
    let mut state_children = Vec::new();

    // Devices Table
    let mut device_nodes = Vec::new();
    let mut device_keys: Vec<_> = state.devices.keys().collect();
    device_keys.sort();

    for mac in device_keys {
        let dev = &state.devices[mac];
        let mut dev_fields = vec![
            TreeItem::new_leaf(
                format!("dev.{}.hostname", mac),
                key_val(
                    "hostname",
                    format!("{} ({:?})", dev.hostname.name, dev.hostname.origin),
                ),
            ),
            TreeItem::new_leaf(
                format!("dev.{}.origin", mac),
                key_val("origin", format!("{:?}", dev.origin)),
            ),
            TreeItem::new_leaf(
                format!("dev.{}.class", mac),
                key_val("class", format!("{:?}", dev.class)),
            ),
            TreeItem::new_leaf(
                format!("dev.{}.seen", mac),
                key_val("last_seen", utils::format_relative_time(dev.last_seen)),
            ),
        ];

        // IPv4
        dev_fields.push(TreeItem::new_leaf(
            format!("dev.{}.v4", mac),
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
                        format!("dev.{}.v6.{}", mac, i),
                        Text::from(format!("[{}] {}", i, utils::format_v6_state(s))),
                    )
                })
                .collect();
            dev_fields.push(
                TreeItem::new(
                    format!("dev.{}.v6", mac),
                    Text::from("v6 addresses"),
                    v6_items,
                )
                .unwrap(),
            );
        }

        device_nodes.push(
            TreeItem::new(
                format!("dev.{}", mac),
                Text::from(Line::from(vec![
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
            .unwrap(),
        );
    }
    state_children.push(
        TreeItem::new(
            "state.devices".to_string(),
            Text::from(format!("devices ({})", state.devices.len())),
            device_nodes,
        )
        .unwrap(),
    );

    // NDP Cache
    if !state.ndp_cache.is_empty() {
        let mut ndp_items = Vec::new();
        let mut ndp_keys: Vec<_> = state.ndp_cache.keys().collect();
        ndp_keys.sort();
        for ip in ndp_keys {
            let (mac, _) = &state.ndp_cache[ip];
            let host_info = if let Some(dev) = state.devices.get(mac) {
                if !dev.hostname.name.is_empty() {
                    format!(" ({})", dev.hostname.name)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            ndp_items.push(TreeItem::new_leaf(
                format!("ndp.{}", ip),
                Text::from(Line::from(vec![
                    Span::styled(ip.to_string(), Style::default().fg(theme::IP)),
                    Span::raw(" → "),
                    Span::styled(mac.to_string(), Style::default().fg(theme::MAC)),
                    Span::styled(host_info, Style::default().fg(theme::HOSTNAME)),
                ])),
            ));
        }
        state_children.push(
            TreeItem::new(
                "state.ndp".to_string(),
                Text::from(format!("ndp_cache ({})", state.ndp_cache.len())),
                ndp_items,
            )
            .unwrap(),
        );
    }

    // Static Entries
    if !state.static_entries.is_empty() {
        let mut static_items = Vec::new();
        let mut static_keys: Vec<_> = state.static_entries.keys().collect();
        static_keys.sort();
        for mac in static_keys {
            let entry = &state.static_entries[mac];
            static_items.push(TreeItem::new_leaf(
                format!("static.{}", mac),
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
        state_children.push(
            TreeItem::new(
                "state.static".to_string(),
                Text::from(format!("static_entries ({})", state.static_entries.len())),
                static_items,
            )
            .unwrap(),
        );
    }

    // Interface IPs
    if !state.interface_ips.is_empty() {
        let mut if_items = Vec::new();
        let mut if_keys: Vec<_> = state.interface_ips.keys().collect();
        if_keys.sort();
        for idx in if_keys {
            let if_state = &state.interface_ips[idx];
            if_items.push(TreeItem::new_leaf(
                format!("if.{}", idx),
                Text::from(Line::from(vec![
                    Span::styled(format!("ifindex {}", idx), Style::default().fg(theme::KEY)),
                    Span::raw(": "),
                    Span::styled(
                        utils::format_interface_state(if_state),
                        Style::default().fg(theme::VALUE),
                    ),
                ])),
            ));
        }
        state_children.push(
            TreeItem::new(
                "state.interfaces".to_string(),
                Text::from(format!("interface_ips ({})", state.interface_ips.len())),
                if_items,
            )
            .unwrap(),
        );
    }

    root_items
        .push(TreeItem::new("state".to_string(), Text::from("State"), state_children).unwrap());

    root_items
}
