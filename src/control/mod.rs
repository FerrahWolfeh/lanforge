//! src/control/mod.rs — Interface de controle via Unix Domain Socket (UDS)
//!
//! Permite que ferramentas de CLI ou interfaces locais consultem e controlem
//! o daemon usando JSON sobre um socket Unix local.

pub mod api;
pub mod handlers;
pub mod server;
#[cfg(test)]
pub mod tests;

pub use api::{Command, Interfaces, Response};
pub use server::control_service;
