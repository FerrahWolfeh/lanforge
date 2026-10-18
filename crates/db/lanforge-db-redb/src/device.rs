//! DeviceStore implementation for `RedbDatabase`.

use crate::RedbDatabase;
use crate::tables::{TABLE_DEVICES, TABLE_LEASE_HISTORY};
use lanforge_db_core::{DbError, DeviceStore};
use lanforge_types::device::{Device, LeaseAction, LeaseHistoryEntry, LeaseKind};
use lanforge_types::identifiers::MacAddr;
use redb::{ReadableDatabase, ReadableTable};
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(serde::Deserialize)]
struct HostnameOnlyName<'a> {
    #[serde(borrow)]
    name: std::borrow::Cow<'a, str>,
}

#[derive(serde::Deserialize)]
struct DeviceHostnameOnly<'a> {
    #[serde(borrow)]
    hostname: HostnameOnlyName<'a>,
}

#[derive(serde::Deserialize)]
struct ZombieCheckDevice {
    #[serde(default)]
    hostname: lanforge_types::device::Hostname,
    #[serde(default)]
    v4: lanforge_types::device::IPv4State,
    #[serde(default)]
    v6: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    v6_prefixes: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    seen_v4: Vec<serde::de::IgnoredAny>,
}

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

    fn load_all_devices(&self) -> Result<Vec<Device>, DbError> {
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
    }

    fn upsert_device(&self, device: &Device) -> Result<(), DbError> {
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
    }

    fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError> {
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
    }

    fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError> {
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
    }

    fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DEVICES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
            let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let dev: DeviceHostnameOnly = serde_json::from_slice(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            if dev.hostname.name.as_ref().eq_ignore_ascii_case(hostname) {
                let k_bytes = k.value();
                if k_bytes.len() == 6 {
                    let mut mac_arr = [0u8; 6];
                    mac_arr.copy_from_slice(k_bytes);
                    return Ok(Some(MacAddr(mac_arr)));
                }
            }
        }
        Ok(None)
    }

    fn remove_device(&self, mac: MacAddr) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let _ = table.remove(mac.0.as_slice());
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn vacuum(&self) -> Result<(), DbError> {
        let mut db_guard = self.db.write();
        let _ = db_guard.compact();
        Ok(())
    }

    fn prune_zombies(&self) -> Result<usize, DbError> {
        let mut zombies = Vec::new();
        {
            let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DEVICES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let device: ZombieCheckDevice = serde_json::from_slice(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if device.hostname.name.is_empty()
                    && matches!(device.v4, lanforge_types::device::IPv4State::None)
                    && device.v6.is_empty()
                    && device.v6_prefixes.is_empty()
                    && device.seen_v4.is_empty()
                {
                    let k_bytes = k.value();
                    if k_bytes.len() == 6 {
                        let mut mac_arr = [0u8; 6];
                        mac_arr.copy_from_slice(k_bytes);
                        zombies.push(MacAddr(mac_arr));
                    }
                }
            }
        }

        let count = zombies.len();
        if count > 0 {
            self.delete_devices(&zombies)?;
        }
        Ok(count)
    }

    fn reset(&self) -> Result<(), DbError> {
        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_DEVICES);
            let _ = write_txn.delete_table(TABLE_LEASE_HISTORY);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: IpAddr,
        lease_kind: LeaseKind,
        action: LeaseAction,
    ) -> Result<(), DbError> {
        let entry = LeaseHistoryEntry {
            ip,
            lease_type: lease_kind,
            action,
            timestamp: SystemTime::now(),
        };

        let bytes = serde_json::to_vec(&entry)
            .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let id = Self::next_id_in_txn(&write_txn, "lease_history")?;
            let mut key = [0u8; 14];
            key[..6].copy_from_slice(&mac.0);
            key[6..].copy_from_slice(&id.to_be_bytes());

            let mut table = write_txn
                .open_table(TABLE_LEASE_HISTORY)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> Result<Vec<LeaseHistoryEntry>, DbError> {
        let read_txn = self.db.read().begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_LEASE_HISTORY) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut start_key = [0u8; 14];
        start_key[..6].copy_from_slice(&mac.0);
        let mut end_key = [0xffu8; 14];
        end_key[..6].copy_from_slice(&mac.0);

        let mut history = Vec::new();
        for item in table
            .range(start_key.as_slice()..=end_key.as_slice())
            .map_err(|e| DbError::Backend(e.to_string()))?
            .rev()
            .take(100)
        {
            let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
            let entry: LeaseHistoryEntry = serde_json::from_slice(val.value())
                .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
            history.push(entry);
        }
        Ok(history)
    }

    fn batch_sync_devices(
        &self,
        full_upserts: &[std::sync::Arc<Device>],
        base_upserts: &[std::sync::Arc<Device>],
        deletes: &[MacAddr],
    ) -> Result<(), DbError> {
        if full_upserts.is_empty() && base_upserts.is_empty() && deletes.is_empty() {
            return Ok(());
        }

        let write_txn = self.db.read().begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            for mac in deletes {
                let _ = table.remove(mac.0.as_slice());
            }

            let mut buf = Vec::with_capacity(512);
            for dev in full_upserts {
                buf.clear();
                serde_json::to_writer(&mut buf, dev)
                    .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                table
                    .insert(dev.mac.0.as_slice(), buf.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }

            for dev in base_upserts {
                let mut buf_written = false;
                if let Some(val) = table
                    .get(dev.mac.0.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?
                {
                    let mut existing: Device = serde_json::from_slice(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    existing.hostname.clone_from(&dev.hostname);
                    existing.origin = dev.origin;
                    existing.managed_at = dev.managed_at;
                    existing.class.clone_from(&dev.class);
                    existing.duid.clone_from(&dev.duid);
                    buf.clear();
                    serde_json::to_writer(&mut buf, &existing)
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                    buf_written = true;
                }
                if !buf_written {
                    buf.clear();
                    serde_json::to_writer(&mut buf, dev.as_ref())
                        .map_err(|e| DbError::Backend(format!("Serialization error: {e}")))?;
                }
                table
                    .insert(dev.mac.0.as_slice(), buf.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}
