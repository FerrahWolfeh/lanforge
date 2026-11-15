//! `NameBindingStore` and `LinkedAddressStore` implementations for `RedbDatabase`.

use crate::RedbDatabase;
use lanforge_db_core::config_keys::{LINKED_ADDRESSES, NAME_BINDINGS};
use lanforge_db_core::{DbError, LinkedAddressStore, NameBindingStore};
use lanforge_types::identifiers::MacAddr;
use std::collections::BTreeMap;
use std::net::IpAddr;

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

impl LinkedAddressStore for RedbDatabase {
    fn load_linked_addresses(&self) -> Result<BTreeMap<IpAddr, MacAddr>, DbError> {
        Ok(self.get(LINKED_ADDRESSES)?.unwrap_or_default())
    }

    fn save_linked_addresses(&self, links: &BTreeMap<IpAddr, MacAddr>) -> Result<(), DbError> {
        if links.is_empty() {
            self.write(|tx| tx.remove(LINKED_ADDRESSES))
        } else {
            self.put(LINKED_ADDRESSES, links)
        }
    }
}
