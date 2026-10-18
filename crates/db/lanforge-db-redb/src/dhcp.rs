//! DhcpConfigStore, RaConfigStore, and PppoeConfigStore implementations for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::TABLE_CONFIG;
use lanforge_db_core::{
    DbError, DhcpConfigStore, PppoeConfigStore, RaConfigStore, TrafficConfigStore,
};
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::TrafficConfig;
use redb::ReadableDatabase;
use std::net::Ipv6Addr;

impl DhcpConfigStore for RedbDatabase {
    fn load_dhcp_v4_pools(&self) -> Result<Vec<Dhcpv4Pool>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("dhcp_v4_pools").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let pools: Vec<Dhcpv4Pool> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(pools)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_dhcp_v4_pools(&self, pools: &[Dhcpv4Pool]) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(pools)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dhcp_v4_pools", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_dhcp_v6_pools(&self) -> Result<Vec<Dhcpv6Pool>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("dhcp_v6_pools").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let pools: Vec<Dhcpv6Pool> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(pools)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_dhcp_v6_pools(&self, pools: &[Dhcpv6Pool]) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(pools)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dhcp_v6_pools", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_dhcp_options(&self) -> Result<Option<DhcpOptionsConfig>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("dhcp_options").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let opts: DhcpOptionsConfig = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(opts))
            }
            None => Ok(None),
        }
    }

    fn save_dhcp_options(&self, options: &DhcpOptionsConfig) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(options)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("dhcp_options", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl RaConfigStore for RedbDatabase {
    fn load_ra_prefixes(&self) -> Result<Vec<RAPrefix>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("ra_prefixes").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let prefixes: Vec<RAPrefix> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(prefixes)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_ra_prefixes(&self, prefixes: &[RAPrefix]) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(prefixes)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("ra_prefixes", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_ra_rdnss(&self) -> Result<Vec<RdnssConfig>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("ra_rdnss").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let rdnss: Vec<RdnssConfig> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(rdnss)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_ra_rdnss(&self, rdnss: &[RdnssConfig]) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(rdnss)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("ra_rdnss", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_ra_dnssl(&self) -> Result<Vec<DnsslConfig>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("ra_dnssl").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let dnssl: Vec<DnsslConfig> = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(dnssl)
            }
            None => Ok(Vec::new()),
        }
    }

    fn save_ra_dnssl(&self, dnssl: &[DnsslConfig]) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(dnssl)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("ra_dnssl", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn load_last_gua_prefix(&self) -> Result<Option<Ipv6Addr>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("last_gua_prefix").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let addr: Ipv6Addr = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }

    fn save_last_gua_prefix(&self, prefix: Option<Ipv6Addr>) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            if let Some(p) = prefix {
                let bytes = serde_json::to_vec(&p)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                table
                    .insert("last_gua_prefix", bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            } else {
                let _ = table.remove("last_gua_prefix");
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl PppoeConfigStore for RedbDatabase {
    fn load_pppoe_config(&self) -> Result<Option<PppoeConfig>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("pppoe_config").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let cfg: PppoeConfig = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    fn save_pppoe_config(&self, cfg: &PppoeConfig) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(cfg)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("pppoe_config", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl TrafficConfigStore for RedbDatabase {
    fn load_traffic_config(&self) -> Result<Option<TrafficConfig>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_CONFIG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        match table.get("traffic_config").map_err(|e| DbError::Backend(e.to_string()))? {
            Some(val) => {
                let cfg: TrafficConfig = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    fn save_traffic_config(&self, cfg: &TrafficConfig) -> Result<(), DbError> {
        let bytes = serde_json::to_vec(cfg)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CONFIG)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert("traffic_config", bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}
