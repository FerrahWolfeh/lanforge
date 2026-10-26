#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod app;
pub mod bootstrap;
pub mod config;
pub mod event_loop;
pub mod registry;
pub mod supervisor;
pub mod synthetic;
