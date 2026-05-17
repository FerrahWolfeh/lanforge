//! # Lanforge Neighbor Monitor
//!
//! Netlink neighbor tracking and discovery for the Lanforge daemon.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;
pub mod ndp;
