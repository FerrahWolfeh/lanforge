//! `FirewallConfigStore` implementation for `RedbDatabase`.

use crate::{RedbDatabase, decode, encode};
use crate::tables::TABLE_CONFIG;
use lanforge_db_core::{DbError, FirewallConfigStore};
use lanforge_types::network::firewall::FirewallConfig;
use redb::ReadableDatabase;

impl FirewallConfigStore for RedbDatabase {
    fn load_firewall_config(&self) -> Result<Option<FirewallConfig>, DbError> {
        let read_txn = self.db
            .begin_read()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table
            .get("firewall_config")
            .map_err(|e| DbError::Backend(e.to_string()))?
        {
            Some(val) => {
                let cfg: FirewallConfig = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    fn save_firewall_config(&self, cfg: &FirewallConfig) -> Result<(), DbError> {
        let bytes = encode(cfg)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db
            .begin_write()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("firewall_config", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}
