//! `FirewallConfigStore` implementation for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::TABLE_CONFIG;
use lanforge_db_core::{BoxFuture, DbError, FirewallConfigStore};
use lanforge_types::network::firewall::FirewallConfig;
use redb::ReadableDatabase;

impl FirewallConfigStore for RedbDatabase {
    fn load_firewall_config(&self) -> BoxFuture<'_, Result<Option<FirewallConfig>, DbError>> {
        Box::pin(async move {
            let read_txn = self
                .db
                .read()
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
                    let cfg: FirewallConfig = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    Ok(Some(cfg))
                }
                None => Ok(None),
            }
        })
    }

    fn save_firewall_config<'a>(&'a self, cfg: &'a FirewallConfig) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let bytes = serde_json::to_vec(cfg)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let write_txn = self
                .db
                .read()
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
        })
    }
}
