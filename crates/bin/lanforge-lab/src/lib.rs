//! # Lanforge Lab Workbench & Test Harness
//!
//! Reusable testbed, high-throughput simulation engines, and automated regression
//! test harness for Lanforge (DHCP, DNS, IPv6 RA, and Discovery).
//!
//! Provides dual execution modes:
//! - **Direct / Socket Mode**: 100% rootless and unprivileged execution on local ports (no `sudo` needed).
//! - **Netns Mode**: Kernel network namespace and `veth` pair isolation (requires root/CAP_NET_ADMIN).

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::missing_const_for_fn,
    clippy::doc_markdown
)]

pub mod cli;
pub mod engine;
pub mod error;
pub mod harness;
pub mod netns;
pub mod report;
pub mod tui;

pub use error::LabError;
pub use harness::{LabHarness, LabMode};
pub use netns::{NetnsConfig, NetnsManager};
pub use report::{
    DhcpStormReport, DnsFloodReport, DnsQueryResult, DoraResult, RaDecodedInfo, SuiteReport,
};

/// Returns whether the current process has root privileges (EUID 0).
#[must_use]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
