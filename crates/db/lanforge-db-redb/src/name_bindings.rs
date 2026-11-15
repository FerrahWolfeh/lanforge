//! `NameBindingStore` implementation for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::{DbError, NameBindingStore, config_keys::NAME_BINDINGS};
use lanforge_types::identifiers::MacAddr;
use std::collections::BTreeMap;

impl NameBindingStore for RedbDatabase {
    fn load_name_bindings(&self) -> Result<BTreeMap<String, MacAddr>, DbError> {
        Ok(self.get(NAME_BINDINGS)?.unwrap_or_default())
    }

    fn save_name_bindings(&self, bindings: &BTreeMap<String, MacAddr>) -> Result<(), DbError> {
        if bindings.is_empty() {
            self.write(|tx| tx.remove(NAME_BINDINGS))
        } else {
            self.put(NAME_BINDINGS, bindings)
        }
    }
}
