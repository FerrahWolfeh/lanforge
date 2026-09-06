//! DeviceStore implementation for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::{TABLE_DEVICES, TABLE_LEASE_HISTORY};
use lanforge_db_core::{BoxFuture, DbError, DeviceStore};
use lanforge_types::device::{Device, LeaseAction, LeaseHistoryEntry, LeaseKind};
use lanforge_types::identifiers::MacAddr;
use redb::{ReadableDatabase, ReadableTable};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

impl DeviceStore for RedbDatabase {
    fn is_in_memory(&self) -> bool {
        self.path.is_none()
    }

    fn is_provisioned(&self) -> Result<bool, DbError> {
        self.is_provisioned()
    }

    fn set_provisioned(&self, provisioned: bool) -> Result<(), DbError> {
        self.set_provisioned(provisioned)
    }

    fn load_all_devices(&self) -> BoxFuture<'_, Result<Vec<Device>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DEVICES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut devices = Vec::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let device: Device = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                devices.push(device);
            }
            Ok(devices)
        })
    }

    fn upsert_device<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let bytes = serde_json::to_vec(device)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DEVICES)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                table
                    .insert(device.mac.0.as_slice(), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn upsert_base_device_only<'a>(
        &'a self,
        device: &'a Device,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DEVICES)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let updated_device = match table
                    .get(device.mac.0.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?
                {
                    Some(val) => {
                        let mut existing: Device = serde_json::from_slice(val.value())
                            .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                        existing.hostname.clone_from(&device.hostname);
                        existing.origin = device.origin;
                        existing.managed_at = device.managed_at;
                        existing.class.clone_from(&device.class);
                        existing.duid.clone_from(&device.duid);
                        existing
                    }
                    None => device.clone(),
                };

                let bytes = serde_json::to_vec(&updated_device)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

                table
                    .insert(device.mac.0.as_slice(), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_devices<'a>(&'a self, macs: &'a [MacAddr]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DEVICES)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                for mac in macs {
                    let _ = table.remove(mac.0.as_slice());
                }
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn find_mac_by_hostname<'a>(
        &'a self,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<Option<MacAddr>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DEVICES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let device: Device = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if device.hostname.name.as_str().eq_ignore_ascii_case(hostname) {
                    return Ok(Some(device.mac));
                }
            }
            Ok(None)
        })
    }

    fn remove_device(&self, mac: MacAddr) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_DEVICES)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                let _ = table.remove(mac.0.as_slice());
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn vacuum(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let mut db_guard = self.db.write();
            let _ = db_guard.compact();
            Ok(())
        })
    }

    fn prune_zombies(&self) -> BoxFuture<'_, Result<usize, DbError>> {
        Box::pin(async move {
            let mut zombies = Vec::new();
            {
                let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
                let table = match read_txn.open_table(TABLE_DEVICES) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                    Err(e) => return Err(DbError::Backend(e.to_string())),
                };

                for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                    let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                    let device: Device = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    if device.hostname.name.is_empty()
                        && matches!(device.v4, lanforge_types::device::IPv4State::None)
                        && device.v6.is_empty()
                        && device.v6_prefixes.is_empty()
                        && device.seen_v4.is_empty()
                    {
                        zombies.push(device.mac);
                    }
                }
            }

            let count = zombies.len();
            if count > 0 {
                self.delete_devices(&zombies).await?;
            }
            Ok(count)
        })
    }

    fn reset(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let _ = write_txn.delete_table(TABLE_DEVICES);
                let _ = write_txn.delete_table(TABLE_LEASE_HISTORY);
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn record_lease_event<'a>(
        &'a self,
        mac: MacAddr,
        ip: &'a str,
        lease_type: &'a str,
        action: LeaseAction,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let parsed_ip: IpAddr = ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

            let entry = LeaseHistoryEntry {
                ip: parsed_ip,
                lease_type: match lease_type {
                    "v6" => LeaseKind::V6,
                    "v6_prefix" => LeaseKind::V6Prefix,
                    _ => LeaseKind::V4,
                },
                action,
                timestamp: SystemTime::now(),
            };

            let bytes = serde_json::to_vec(&entry)
                .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

            let id = self.next_id("lease_history")?;
            let mut key = Vec::with_capacity(14);
            key.extend_from_slice(&mac.0);
            key.extend_from_slice(&id.to_be_bytes());

            let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(TABLE_LEASE_HISTORY)
                    .map_err(|e| DbError::Backend(e.to_string()))?;

                table
                    .insert(key.as_slice(), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
            write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> BoxFuture<'_, Result<Vec<LeaseHistoryEntry>, DbError>> {
        Box::pin(async move {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_LEASE_HISTORY) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            let mut history = Vec::new();
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let k_bytes = k.value();
                if k_bytes.starts_with(&mac.0) {
                    let entry: LeaseHistoryEntry = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    history.push(entry);
                }
            }
            history.sort_by_key(|h| h.timestamp);
            history.reverse();
            if history.len() > 100 {
                history.truncate(100);
            }
            Ok(history)
        })
    }
}
