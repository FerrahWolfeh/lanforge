use crate::tui::app::{TuiApp, TuiMode};
use crate::tui::theme;
use lanforge_api::api::TopologyEntry;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders};
use std::collections::HashMap;
use tui_tree_widget::{Tree, TreeItem};

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let chunks = Layout::default()
        .constraints([Constraint::Min(10), Constraint::Length(3)])
        .split(area);

    let empty_vec = Vec::new();
    let entries = app
        .state
        .topology
        .as_ref()
        .map_or(&empty_vec, |t| &t.entries);

    let (parent_to_children, orphans, roots, entry_map) = get_topology_data(app, entries);
    let tree_items = build_tree_items(roots, &parent_to_children, orphans, &entry_map);

    render_tree(f, app, chunks[0], &tree_items);
    render_help_footer(f, app, chunks[1]);
}

#[allow(clippy::type_complexity)]
fn get_topology_data<'a>(
    app: &TuiApp,
    entries: &'a [TopologyEntry],
) -> (
    HashMap<String, Vec<&'a TopologyEntry>>,
    Vec<&'a TopologyEntry>,
    Vec<String>,
    HashMap<String, &'a TopologyEntry>,
) {
    let filter = app.filter_text.to_lowercase();
    let filtered_entries: Vec<&TopologyEntry> = entries
        .iter()
        .filter(|entry| {
            if filter.is_empty() {
                true
            } else {
                entry.hostname.to_lowercase().contains(&filter)
                    || entry.mac.to_string().to_lowercase().contains(&filter)
            }
        })
        .collect();

    let entry_map: HashMap<String, &TopologyEntry> = filtered_entries
        .iter()
        .map(|e| (e.mac.to_string(), *e))
        .collect();

    let mut parent_to_children: HashMap<String, Vec<&TopologyEntry>> = HashMap::new();
    for entry in &filtered_entries {
        if let Some(parent) = &entry.parent_mac {
            parent_to_children
                .entry(parent.to_string())
                .or_default()
                .push(entry);
        }
    }

    let mut roots: Vec<String> = Vec::new();
    for parent_mac in parent_to_children.keys() {
        let is_root = entry_map.get(parent_mac).is_none_or(|entry| {
            entry
                .parent_mac
                .as_ref()
                .is_none_or(|p| !entry_map.contains_key(&p.to_string()))
        });
        if is_root {
            roots.push(parent_mac.clone());
        }
    }
    roots.sort();

    let mut orphans = Vec::new();
    for entry in &filtered_entries {
        let parent_missing = entry
            .parent_mac
            .as_ref()
            .is_none_or(|p| !entry_map.contains_key(&p.to_string()));
        if parent_missing && !parent_to_children.contains_key(&entry.mac.to_string()) {
            orphans.push(*entry);
        }
    }

    (parent_to_children, orphans, roots, entry_map)
}

fn build_tree_items(
    roots: Vec<String>,
    parent_to_children: &HashMap<String, Vec<&TopologyEntry>>,
    orphans: Vec<&TopologyEntry>,
    entry_map: &HashMap<String, &TopologyEntry>,
) -> Vec<TreeItem<'static, String>> {
    let mut tree_items = Vec::new();

    for root_mac in roots {
        let root_hostname = entry_map
            .get(&root_mac)
            .map_or("Unknown Switch", |e| e.hostname.as_str());

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
                Span::raw(format!("{} [{}]", orphan.hostname, orphan.mac)),
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
    map: &HashMap<String, Vec<&TopologyEntry>>,
) -> Option<Vec<TreeItem<'static, String>>> {
    map.get(parent_mac).map(|children| {
        let mut items = Vec::new();
        let mut sorted = children.clone();
        sorted.sort_by(|a, b| {
            let port_a = a.port.as_deref().unwrap_or("");
            let port_b = b.port.as_deref().unwrap_or("");
            port_a.cmp(port_b).then_with(|| a.mac.cmp(&b.mac))
        });

        for child in sorted {
            let port_str = child
                .port
                .as_ref()
                .map(|p| format!(" (Port: {p})"))
                .unwrap_or_default();

            let text = Text::from(vec![Line::from(vec![
                Span::styled("💻 ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{} [{}]", child.hostname, child.mac),
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
