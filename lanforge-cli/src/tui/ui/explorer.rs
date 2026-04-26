use crate::tui::app::TuiApp;
use crate::tui::theme;
use crate::tui::tree::build_tree;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders},
};
use tui_tree_widget::Tree;

pub fn render(f: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items = if let Some(state) = &app.state.state {
        build_tree(state, &app.state.status)
    } else {
        vec![]
    };

    let tree = Tree::new(&items)
        .expect("Tree items should be valid")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" State Explorer "),
        )
        .highlight_style(
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(tree, area, &mut app.tree_state);
}
