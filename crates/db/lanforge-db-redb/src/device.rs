//! DeviceStore implementation for `RedbDatabase`.

use crate::{RedbDatabase, decode, encode, encode_into};
use crate::tables::{TABLE_DEVICES, TABLE_STATIC_HOSTS, TABLE_META};
use lanforge_db_core::{ConfigStore, DbError, DeviceStore, StaticHostEntry};
use lanforge_types::device::{Device, DeviceStatus, Origin, IPv4State, IPv6State};
use lanforge_types::identifiers::MacAddr;
use redb::{ReadableDatabase, ReadableTable};

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
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DEVICES) {
            Ok(t) => Some(t),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        let mut devices = Vec::new();
        if let Some(table) = table {
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (_, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                devices.push(decode(val.value())?);
            }
        }
        drop(read_txn);
        devices.extend(self.load_static_hosts()?.into_iter().map(static_host_to_device));
        Ok(devices)
    }

    fn upsert_device(&self, device: &Device) -> Result<(), DbError> {
        if device.origin != Origin::Dynamic {
            let bytes = encode(&static_host_from_device(device))?;
            let txn = self.begin_write()?;
            txn.open_table(TABLE_STATIC_HOSTS).map_err(|e| DbError::Backend(e.to_string()))?
                .insert(device.mac.0.as_slice(), bytes.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            if let Ok(mut dynamic) = txn.open_table(TABLE_DEVICES) {
                dynamic.remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
            return txn.commit().map_err(|e| DbError::Backend(e.to_string()));
        }
        let persistent = persistent_device(device);

        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            if let Some(persistent) = persistent {
                let bytes = encode(&persistent)?;
                table.insert(device.mac.0.as_slice(), bytes.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?;
            } else {
                table.remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
            drop(table);
            write_txn.open_table(TABLE_STATIC_HOSTS)
                .map_err(|e| DbError::Backend(e.to_string()))?
                .remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError> {
        if device.origin != Origin::Dynamic {
            return self.upsert_device(device);
        }
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            let updated_device = match table
                .get(device.mac.0.as_slice())
                .map_err(|e| DbError::Backend(e.to_string()))?
            {
                Some(val) => {
                    let mut existing: Device = decode(val.value())
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

            let persistent = persistent_device(&updated_device);
            if let Some(persistent) = persistent {
                let bytes = encode(&persistent)?;
                let unchanged = table.get(device.mac.0.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?
                    .is_some_and(|value| decode::<Device>(value.value()).is_ok_and(|stored| stored == persistent));
                if !unchanged {
                    table.insert(device.mac.0.as_slice(), bytes.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                }
            } else {
                table.remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        if let Ok(mut static_table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
            static_table.remove(device.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            for mac in macs {
                table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
            drop(table);
            if let Ok(mut table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
                for mac in macs {
                    table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError> {
        let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match read_txn.open_table(TABLE_DEVICES) {
            Ok(t) => Some(t),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };

        if let Some(table) = table {
            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let dev: Device = decode(val.value())?;
                if dev.hostname.name.eq_ignore_ascii_case(hostname) {
                    let k_bytes = k.value();
                    if k_bytes.len() == 6 {
                        let mut mac_arr = [0u8; 6];
                        mac_arr.copy_from_slice(k_bytes);
                        return Ok(Some(MacAddr(mac_arr)));
                    }
                }
            }
        }
        drop(read_txn);
        if let Some(host) = self.load_static_hosts()?.into_iter()
            .find(|host| host.hostname.name.eq_ignore_ascii_case(hostname))
        {
            return Ok(Some(host.mac));
        }
        Ok(None)
    }

    fn remove_device(&self, mac: MacAddr) -> Result<(), DbError> {
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            drop(table);
            if let Ok(mut table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
                table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }

    fn prune_zombies(&self) -> Result<usize, DbError> {
        let mut zombies = Vec::new();
        {
            let read_txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
            let table = match read_txn.open_table(TABLE_DEVICES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(DbError::Backend(e.to_string())),
            };

            for item in table.iter().map_err(|e| DbError::Backend(e.to_string()))? {
                let (k, val) = item.map_err(|e| DbError::Backend(e.to_string()))?;
                let device: Device = decode(val.value())
                    .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                if device.hostname.name.is_empty()
                    && matches!(device.v4, lanforge_types::device::IPv4State::None)
                    && device.v6.is_empty()
                    && device.v6_prefixes.is_empty()
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
        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let _ = write_txn.delete_table(TABLE_DEVICES);
            let _ = write_txn.delete_table(TABLE_STATIC_HOSTS);
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
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

        let write_txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_DEVICES)
                .map_err(|e| DbError::Backend(e.to_string()))?;
            let mut static_table = write_txn.open_table(TABLE_STATIC_HOSTS)
                .map_err(|e| DbError::Backend(e.to_string()))?;

            for mac in deletes {
                table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                static_table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
            }

            let mut buf = Vec::with_capacity(512);
            for dev in full_upserts {
                if dev.origin == Origin::Dynamic {
                    if let Some(persistent) = persistent_device(dev) {
                        encode_into(&persistent, &mut buf)?;
                        table.insert(dev.mac.0.as_slice(), buf.as_slice())
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                    } else {
                        table.remove(dev.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                    }
                    static_table.remove(dev.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                } else {
                    encode_into(&static_host_from_device(dev), &mut buf)?;
                    static_table.insert(dev.mac.0.as_slice(), buf.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                    table.remove(dev.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }

            for dev in base_upserts {
                if dev.origin != Origin::Dynamic {
                    encode_into(&static_host_from_device(dev), &mut buf)?;
                    static_table.insert(dev.mac.0.as_slice(), buf.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                    table.remove(dev.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                    continue;
                }
                let mut updated = None;
                if let Some(val) = table
                    .get(dev.mac.0.as_slice())
                    .map_err(|e| DbError::Backend(e.to_string()))?
                {
                    let mut existing: Device = decode(val.value())
                        .map_err(|e| DbError::Backend(format!("Deserialization error: {e}")))?;
                    existing.hostname.clone_from(&dev.hostname);
                    existing.origin = dev.origin;
                    existing.managed_at = dev.managed_at;
                    existing.class.clone_from(&dev.class);
                    existing.duid.clone_from(&dev.duid);
                    updated = persistent_device(&existing);
                }
                if updated.is_none() {
                    updated = persistent_device(dev);
                }
                if let Some(updated) = updated {
                    encode_into(&updated, &mut buf)?;
                    table.insert(dev.mac.0.as_slice(), buf.as_slice())
                        .map_err(|e| DbError::Backend(e.to_string()))?;
                } else {
                    table.remove(dev.mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
                }
            }
        }
        write_txn.commit().map_err(|e| DbError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl ConfigStore for RedbDatabase {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match txn.open_table(TABLE_META) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };
        Ok(table.get(key).map_err(|e| DbError::Backend(e.to_string()))?
            .map(|value| value.value().to_vec()))
    }

    fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), DbError> {
        let txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        txn.open_table(TABLE_META).map_err(|e| DbError::Backend(e.to_string()))?
            .insert(key, value).map_err(|e| DbError::Backend(e.to_string()))?;
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }

    fn load_static_hosts(&self) -> Result<Vec<StaticHostEntry>, DbError> {
        let txn = self.db.begin_read().map_err(|e| DbError::Backend(e.to_string()))?;
        let table = match txn.open_table(TABLE_STATIC_HOSTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(DbError::Backend(e.to_string())),
        };
        table.iter().map_err(|e| DbError::Backend(e.to_string()))?.map(|row| {
            let (_, value) = row.map_err(|e| DbError::Backend(e.to_string()))?;
            decode(value.value())
        }).collect()
    }

    fn upsert_static_host(&self, host: &StaticHostEntry) -> Result<(), DbError> {
        let bytes = encode(host)?;
        let txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        txn.open_table(TABLE_STATIC_HOSTS).map_err(|e| DbError::Backend(e.to_string()))?
            .insert(host.mac.0.as_slice(), bytes.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }

    fn remove_static_host(&self, mac: MacAddr) -> Result<(), DbError> {
        let txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        if let Ok(mut table) = txn.open_table(TABLE_STATIC_HOSTS) {
            table.remove(mac.0.as_slice()).map_err(|e| DbError::Backend(e.to_string()))?;
        }
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }

    fn clear_static_hosts(&self) -> Result<(), DbError> {
        let txn = self.begin_write().map_err(|e| DbError::Backend(e.to_string()))?;
        let _ = txn.delete_table(TABLE_STATIC_HOSTS);
        txn.commit().map_err(|e| DbError::Backend(e.to_string()))
    }
}

fn static_host_from_device(device: &Device) -> StaticHostEntry {
    StaticHostEntry {
        mac: device.mac,
        hostname: device.hostname.clone(),
        origin: device.origin,
        v4_fixed: match device.v4 { IPv4State::Static(ip) => Some(ip), _ => None },
        v6_suffix: device.v6.iter().find_map(|state| match state {
            IPv6State::Static(value, _) => Some(*value),
            _ => None,
        }),
        ignore_dns_log: device.ignore_dns_log,
        ignored_log_domains: device.ignored_log_domains.clone(),
    }
}

fn static_host_to_device(host: StaticHostEntry) -> Device {
    let mut device = Device::new(host.mac);
    device.hostname = host.hostname;
    device.origin = host.origin;
    device.v4 = host.v4_fixed.map_or(IPv4State::None, IPv4State::Static);
    if let Some(suffix) = host.v6_suffix {
        device.v6.push(IPv6State::Static(suffix, std::time::SystemTime::UNIX_EPOCH));
    }
    device.ignore_dns_log = host.ignore_dns_log;
    device.ignored_log_domains = host.ignored_log_domains;
    device
}

fn persistent_device(device: &Device) -> Option<Device> {
    let mut persistent = device.clone();
    persistent.last_seen = std::time::SystemTime::UNIX_EPOCH;
    persistent.status = DeviceStatus::Offline;
    persistent.v4 = match &persistent.v4 {
        IPv4State::Dynamic(lease) => IPv4State::Dynamic(lease.clone()),
        IPv4State::Static(ip) => IPv4State::Static(*ip),
        IPv4State::Discovery(_, _) | IPv4State::None => IPv4State::None,
    };
    persistent.v6.retain(|state| matches!(state, IPv6State::Static(..) | IPv6State::Dynamic(_)));
    persistent.iface = None;
    let has_lease = matches!(persistent.v4, IPv4State::Dynamic(_))
        || persistent.v6.iter().any(|state| matches!(state, IPv6State::Dynamic(_)))
        || !persistent.v6_prefixes.is_empty();
    let has_identity = !persistent.hostname.name.is_empty()
        || persistent.duid.is_some()
        || persistent.boot_file.is_some()
        || persistent.class != lanforge_types::device::DeviceClass::None
        || persistent.ignore_dns_log
        || !persistent.ignored_log_domains.is_empty();
    (has_lease || has_identity).then_some(persistent)
}
