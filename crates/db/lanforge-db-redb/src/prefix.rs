//! `PrefixStore` implementation for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::{ConfigKey, DbError, PrefixStore, config_keys::LAST_GUA_PREFIX};
use lanforge_types::network::Ipv6Prefix;
use std::net::Ipv6Addr;

impl PrefixStore for RedbDatabase {
    fn load_last_gua_prefix(&self) -> Result<Option<Ipv6Prefix>, DbError> {
        if let Ok(Some(prefix)) = self.get(LAST_GUA_PREFIX) {
            return Ok(Some(prefix));
        }
        // Fallback migration from legacy Ipv6Addr storage
        let legacy: ConfigKey<Ipv6Addr> = ConfigKey::new(LAST_GUA_PREFIX.name());
        if let Ok(Some(addr)) = self.get(legacy) {
            let prefix = Ipv6Prefix::from_addr(addr);
            let _ = self.save_last_gua_prefix(Some(prefix));
            return Ok(Some(prefix));
        }
        Ok(None)
    }

    fn save_last_gua_prefix(&self, prefix: Option<Ipv6Prefix>) -> Result<(), DbError> {
        if let Some(p) = prefix {
            self.put(LAST_GUA_PREFIX, &p)
        } else {
            self.write(|tx| tx.remove(LAST_GUA_PREFIX))
        }
    }
}
