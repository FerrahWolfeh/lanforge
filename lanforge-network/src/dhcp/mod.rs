//! DHCP (Dynamic Host Configuration Protocol) servers for IPv4 and IPv6.
//!
//! Implements RFC 2131 (`DHCPv4`) and RFC 8415 (`DHCPv6`) address assignment.
//!
//! ## Submodules
//!
//! | Module | Purpose |
//! | :--- | :--- |
//! | `identity` | `DeviceIdentity` — MAC + hostname + vendor class resolution |
//! | `v4` | `DHCPv4` server, pool (roaring bitmap), raw L2 packet injection |
//! | `v6` | `DHCPv6` server with `IA_NA` + `IA_PD`, multi-prefix ULA/GUA pools |
//!
//! ## Service Architecture
//!
//! Both `DHCPv4` and `DHCPv6` services run as `AsyncService` (non-blocking UDP I/O)
//! via the Tokio runtime. This ensures efficient resource usage and consistent
//! event handling across all Lanforge services.

pub mod identity;
pub mod v4;
pub mod v6;
