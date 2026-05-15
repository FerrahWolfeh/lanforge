//! Modular configuration system for Lanforge services.
//!
//! Each service defines its own configuration structure that can be
//! automatically mapped to a section in the main TOML file.

use serde::{Deserialize, Serialize};

/// Trait implemented by service-specific configuration structures.
///
/// This trait allows the main daemon to automatically identify which
/// TOML section belongs to which service and handle deserialization.
pub trait ServiceConfig: Serialize + for<'de> Deserialize<'de> + Default + Clone {
    /// The top-level key in the TOML file for this configuration.
    /// Example: "dns", "dhcp.v4", etc.
    const KEY: &'static str;

    /// Optional: Merge this configuration with another one (e.g., from CLI).
    /// By default, it just replaces the current value.
    fn merge(&mut self, other: Self) {
        *self = other;
    }
}
