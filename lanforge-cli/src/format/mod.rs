pub mod cli;
#[cfg(feature = "tui")]
pub mod tui;

/// Trait for formatting events for the CLI.
pub trait CliFormat {
    fn format_cli(&self, now: &str, verbose: bool);
}

/// Trait for formatting events for the TUI.
#[cfg(feature = "tui")]
pub trait TuiFormat {
    fn format_tui<'a>(&'a self, spans: &mut Vec<ratatui::text::Span<'a>>);
}
