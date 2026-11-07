#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(missing_docs, clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[cfg(test)]
use lanforge_core as _;
#[cfg(test)]
use lanforge_db as _;
#[cfg(test)]
use lanforge_uds as _;
use libc as _;

pub mod args;
pub mod client;
pub mod commands;
pub mod output;
