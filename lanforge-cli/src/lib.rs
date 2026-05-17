#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod args;
pub mod cli;
pub mod format;
#[cfg(feature = "tui")]
pub mod tui;
