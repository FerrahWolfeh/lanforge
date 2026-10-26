//! `FirewallConfigStore` implementation for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::{DbError, FirewallConfigStore, config_keys::FIREWALL};
use lanforge_types::network::firewall::FirewallConfig;

impl FirewallConfigStore for RedbDatabase {
    fn load_firewall_config(&self) -> Result<Option<FirewallConfig>, DbError> {
        self.get(FIREWALL)
    }

    fn save_firewall_config(&self, config: &FirewallConfig) -> Result<(), DbError> {
        self.put(FIREWALL, config)
    }
}
