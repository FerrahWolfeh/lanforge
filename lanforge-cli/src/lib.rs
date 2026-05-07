#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod args;
pub mod cli;
pub mod format;
#[cfg(feature = "tui")]
pub mod tui;
