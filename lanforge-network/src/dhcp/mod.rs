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
//! Both `DHCPv4` and `DHCPv6` services run as `SyncService` (blocking UDP I/O)
//! with a 200ms read timeout. This avoids async runtime complexity in the
//! hot packet processing path. Bus events are processed synchronously between
//! packet reads.

pub mod identity;
pub mod v4;
pub mod v6;
