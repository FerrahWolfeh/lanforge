//! lanforge-api — Interface de controle
//!
//! Permite que ferramentas de CLI ou interfaces locais consultem e controlem
//! o daemon usando JSON sobre um socket Unix local.

pub mod api;
pub mod config;
pub mod error;
pub mod handlers;
pub mod server;
#[cfg(test)]
pub mod tests;
