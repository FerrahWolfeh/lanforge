use crate::tui::app::{TuiApp, TuiMode};
use crate::tui::theme;
use lanforge_core::types::device::Device;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders};
use std::collections::HashMap;
use std::sync::Arc;
use tui_tree_widget::{Tree, TreeItem};

pub fn render(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let chunks = Layout::default()
        .constraints([Constraint::Min(10), Constraint::Length(3)])
        .split(area);

    let devices: Vec<_> = app
        .state
        .state
        .as_ref()
        .map_or_else(Vec::new, |st| st.devices.values().collect());

    let (parent_to_children, orphans, roots) = get_topology_data(app, &devices);
    let tree_items = build_tree_items(roots, &parent_to_children, orphans, &devices);

    render_tree(f, app, chunks[0], &tree_items);
    render_help_footer(f, app, chunks[1]);
}

fn get_topology_data<'a>(
    app: &TuiApp,
    devices: &'a [&Arc<Device>],
) -> (
    HashMap<String, Vec<&'a Device>>,
    Vec<&'a Device>,
    Vec<String>,
) {
    let mut parent_to_children: HashMap<String, Vec<&Device>> = HashMap::new();
    let mut orphans: Vec<&Device> = Vec::new();
    let filter = app.filter_text.to_lowercase();

    for dev in devices {
        // Apply filter
        if !filter.is_empty() {
            let matches = dev.hostname.name.to_lowercase().contains(&filter)
                || dev.mac.to_string().to_lowercase().contains(&filter);
            if !matches {
                continue;
            }
        }

        if let Some(topo) = &dev.topology {
            if let Some(parent) = &topo.parent_mac {
                parent_to_children
                    .entry(parent.to_string())
                    .or_default()
                    .push(dev);
            } else {
                orphans.push(dev);
            }
        } else {
            orphans.push(dev);
        }
    }

    let mut roots: Vec<String> = parent_to_children
        .keys()
        .filter(|k| {
            !devices.iter().any(|d| {
                d.mac.to_string() == **k
                    && d.topology.as_ref().is_some_and(|t| t.parent_mac.is_some())
            })
        })
        .cloned()
        .collect();

    roots.sort();

    (parent_to_children, orphans, roots)
}

fn build_tree_items(
    roots: Vec<String>,
    parent_to_children: &HashMap<String, Vec<&Device>>,
    orphans: Vec<&Device>,
    devices: &[&Arc<Device>],
) -> Vec<TreeItem<'static, String>> {
    let mut tree_items = Vec::new();

    for root_mac in roots {
        let root_hostname = devices
            .iter()
            .find(|d| d.mac.to_string() == root_mac)
            .map_or("Unknown Switch", |d| d.hostname.name.as_str());

        let text = Text::from(vec![Line::from(vec![
            Span::styled("🖧  ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{root_hostname} [{root_mac}]"),
                Style::default().fg(Color::White),
            ),
        ])]);

        if let Some(children) = build_children(&root_mac, parent_to_children)
            && let Ok(item) = TreeItem::new(root_mac, text, children)
        {
            tree_items.push(item);
        }
    }

    if !orphans.is_empty() {
        let mut orphan_items = Vec::new();
        for orphan in orphans {
            let text = Text::from(vec![Line::from(vec![
                Span::styled("❓ ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{} [{}]", orphan.hostname.name, orphan.mac)),
            ])]);
            let item = TreeItem::new_leaf(format!("orphan-{}", orphan.mac), text);
            orphan_items.push(item);
        }

        if let Ok(item) = TreeItem::new(
            "orphans".to_string(),
            Text::from("Unlinked Devices"),
            orphan_items,
        ) {
            tree_items.push(item);
        }
    }

    tree_items
}

fn render_tree(
    f: &mut Frame,
    app: &mut TuiApp,
    area: Rect,
    tree_items: &[TreeItem<'static, String>],
) {
    let tree_widget = Tree::new(tree_items)
        .unwrap()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Physical Topology ")
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .highlight_style(
            Style::default()
                .bg(theme::ACCENT)
                .fg(theme::HEADER_BG)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(tree_widget, area, &mut app.tree_state_topology);
}

fn render_help_footer(f: &mut Frame, app: &TuiApp, area: Rect) {
    let help_text = if app.mode == TuiMode::Filtering {
        Line::from(vec![
            Span::styled("Filter: ", Style::default().fg(theme::KEY)),
            Span::styled(&app.filter_text, Style::default().fg(theme::VALUE)),
            Span::styled(" █", Style::default().fg(theme::ACCENT)),
            Span::raw(" (Press Enter/Esc to finish)"),
        ])
    } else {
        Line::from(vec![
            Span::raw("Press "),
            Span::styled(
                "Space/Enter",
                Style::default().fg(theme::KEY).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to expand/collapse • "),
            Span::styled(
                "/",
                Style::default().fg(theme::KEY).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to filter • "),
            Span::styled(
                "Up/Down",
                Style::default().fg(theme::KEY).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to navigate"),
        ])
    };

    let footer = ratatui::widgets::Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(footer, area);
}

fn build_children(
    parent_mac: &str,
    map: &HashMap<String, Vec<&Device>>,
) -> Option<Vec<TreeItem<'static, String>>> {
    map.get(parent_mac).map(|children| {
        let mut items = Vec::new();
        let mut sorted = children.clone();
        sorted.sort_by(|a, b| {
            let port_a = a
                .topology
                .as_ref()
                .and_then(|t| t.port.as_deref())
                .unwrap_or("");
            let port_b = b
                .topology
                .as_ref()
                .and_then(|t| t.port.as_deref())
                .unwrap_or("");
            port_a.cmp(port_b).then_with(|| a.mac.cmp(&b.mac))
        });

        for child in sorted {
            let port_str = child
                .topology
                .as_ref()
                .and_then(|t| t.port.as_deref())
                .map(|p| format!(" (Port: {p})"))
                .unwrap_or_default();

            let text = Text::from(vec![Line::from(vec![
                Span::styled("💻 ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{} [{}]", child.hostname.name, child.mac),
                    Style::default().fg(Color::White),
                ),
                Span::styled(port_str, Style::default().fg(Color::DarkGray)),
            ])]);

            if let Some(sub_children) = build_children(&child.mac.to_string(), map) {
                if let Ok(item) = TreeItem::new(child.mac.to_string(), text, sub_children) {
                    items.push(item);
                }
            } else {
                let item = TreeItem::new_leaf(child.mac.to_string(), text);
                items.push(item);
            }
        }
        items
    })
}
