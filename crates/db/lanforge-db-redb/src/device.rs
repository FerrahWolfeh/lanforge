//! DeviceStore implementation for `RedbDatabase`.

use crate::{RedbDatabase, decode, encode, encode_into};
use crate::tables::{TABLE_DEVICES, TABLE_STATIC_HOSTS, TABLE_META};
use lanforge_db_core::{ConfigStore, DbError, DeviceStore, StaticHostEntry};
use lanforge_types::device::{Device, DeviceStatus, Origin, IPv4State, IPv6State};
use lanforge_types::identifiers::MacAddr;
use redb::{ReadableTable, ReadableTableMetadata};

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
        let mut devices = self.read_table_or_default(TABLE_DEVICES, |table| {
            let count = table.len().unwrap_or(0) as usize;
            let mut list = Vec::with_capacity(count);
            for item in table.iter()? {
                let (_, val) = item?;
                list.push(decode(val.value())?);
            }
            Ok(list)
        })?;

        devices.extend(self.load_static_hosts()?.into_iter().map(static_host_to_device));
        Ok(devices)
    }

    fn upsert_device(&self, device: &Device) -> Result<(), DbError> {
        if device.origin == Origin::System {
            // Origin::System represents the host's own runtime interfaces;
            // it is injected dynamically at boot and must never be persisted in static_hosts.
            return Ok(());
        }
        if device.origin != Origin::Dynamic {
            let bytes = encode(&static_host_from_device(device))?;
            let txn = self.begin_write()?;
            txn.open_table(TABLE_STATIC_HOSTS)?
                .insert(device.mac.0, bytes.as_slice())?;
            if let Ok(mut dynamic) = txn.open_table(TABLE_DEVICES) {
                dynamic.remove(device.mac.0)?;
            }
            txn.commit()?;
            return Ok(());
        }
        let persistent = persistent_device(device);

        let write_txn = self.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEVICES)?;

            if let Some(persistent) = persistent {
                let bytes = encode(&persistent)?;
                table.insert(device.mac.0, bytes.as_slice())?;
            } else {
                table.remove(device.mac.0)?;
            }
            drop(table);
            if let Ok(mut static_table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
                static_table.remove(device.mac.0)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn upsert_base_device_only(&self, device: &Device) -> Result<(), DbError> {
        if device.origin != Origin::Dynamic {
            return self.upsert_device(device);
        }
        let write_txn = self.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEVICES)?;

            let updated_device = match table.get(device.mac.0)? {
                Some(val) => {
                    let mut existing: Device = decode(val.value())?;
                    let id = existing.identity_mut();
                    id.hostname.clone_from(&device.hostname);
                    id.origin = device.origin;
                    id.managed_at = device.managed_at;
                    id.class.clone_from(&device.class);
                    id.duid.clone_from(&device.duid);
                    existing
                }
                None => device.clone(),
            };

            let persistent = persistent_device(&updated_device);
            if let Some(persistent) = persistent {
                let bytes = encode(&persistent)?;
                let unchanged = table.get(device.mac.0)?
                    .is_some_and(|value| decode::<Device>(value.value()).is_ok_and(|stored| stored == persistent));
                if !unchanged {
                    table.insert(device.mac.0, bytes.as_slice())?;
                }
            } else {
                table.remove(device.mac.0)?;
            }
        }
        if let Ok(mut static_table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
            static_table.remove(device.mac.0)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn delete_devices(&self, macs: &[MacAddr]) -> Result<(), DbError> {
        let write_txn = self.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEVICES)?;

            for mac in macs {
                table.remove(mac.0)?;
            }
            drop(table);
            match write_txn.open_table(TABLE_STATIC_HOSTS) {
                Ok(mut table) => {
                    for mac in macs {
                        table.remove(mac.0)?;
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(DbError::from(e)),
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn find_mac_by_hostname(&self, hostname: &str) -> Result<Option<MacAddr>, DbError> {
        let found = self.read_table(TABLE_DEVICES, |table| {
            for item in table.iter()? {
                let (k, val) = item?;
                let dev: Device = decode(val.value())?;
                if dev.hostname.name.eq_ignore_ascii_case(hostname) {
                    return Ok(Some(MacAddr(k.value())));
                }
            }
            Ok(None)
        })?.flatten();

        if let Some(mac) = found {
            return Ok(Some(mac));
        }

        if let Some(host) = self.load_static_hosts()?.into_iter()
            .find(|host| host.hostname.name.eq_ignore_ascii_case(hostname))
        {
            return Ok(Some(host.mac));
        }
        Ok(None)
    }

    fn remove_device(&self, mac: MacAddr) -> Result<(), DbError> {
        let write_txn = self.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEVICES)?;
            table.remove(mac.0)?;
            drop(table);
            if let Ok(mut table) = write_txn.open_table(TABLE_STATIC_HOSTS) {
                table.remove(mac.0)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn prune_zombies(&self) -> Result<usize, DbError> {
        let zombies = self.read_table_or_default(TABLE_DEVICES, |table| {
            let mut list = Vec::new();
            for item in table.iter()? {
                let (k, val) = item?;
                let device: Device = decode(val.value())?;
                if device.hostname.name.is_empty()
                    && matches!(device.v4, lanforge_types::device::IPv4State::None)
                    && device.v6.is_empty()
                    && device.v6_prefixes.is_empty()
                {
                    list.push(MacAddr(k.value()));
                }
            }
            Ok(list)
        })?;

        let count = zombies.len();
        if count > 0 {
            self.delete_devices(&zombies)?;
        }
        Ok(count)
    }

    fn reset(&self) -> Result<(), DbError> {
        let write_txn = self.begin_write()?;
        {
            let _ = write_txn.delete_table(TABLE_DEVICES);
            let _ = write_txn.delete_table(TABLE_STATIC_HOSTS);
        }
        write_txn.commit()?;
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

        let write_txn = self.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEVICES)?;
            let mut static_table = write_txn.open_table(TABLE_STATIC_HOSTS)?;

            for mac in deletes {
                table.remove(mac.0)?;
                static_table.remove(mac.0)?;
            }

            let mut buf = Vec::with_capacity(512);
            for dev in full_upserts {
                if dev.origin == Origin::System {
                    continue;
                }
                if dev.origin == Origin::Dynamic {
                    if let Some(persistent) = persistent_device(dev) {
                        encode_into(&persistent, &mut buf)?;
                        table.insert(dev.mac.0, buf.as_slice())?;
                    } else {
                        table.remove(dev.mac.0)?;
                    }
                    static_table.remove(dev.mac.0)?;
                } else {
                    encode_into(&static_host_from_device(dev), &mut buf)?;
                    static_table.insert(dev.mac.0, buf.as_slice())?;
                    table.remove(dev.mac.0)?;
                }
            }

            for dev in base_upserts {
                if dev.origin == Origin::System {
                    continue;
                }
                if dev.origin != Origin::Dynamic {
                    encode_into(&static_host_from_device(dev), &mut buf)?;
                    static_table.insert(dev.mac.0, buf.as_slice())?;
                    table.remove(dev.mac.0)?;
                    continue;
                }
                let mut updated = None;
                if let Some(val) = table.get(dev.mac.0)? {
                    let mut existing: Device = decode(val.value())?;
                    let id = existing.identity_mut();
                    id.hostname.clone_from(&dev.hostname);
                    id.origin = dev.origin;
                    id.managed_at = dev.managed_at;
                    id.class.clone_from(&dev.class);
                    id.duid.clone_from(&dev.duid);
                    updated = persistent_device(&existing);
                }
                if updated.is_none() {
                    updated = persistent_device(dev);
                }
                if let Some(updated) = updated {
                    encode_into(&updated, &mut buf)?;
                    table.insert(dev.mac.0, buf.as_slice())?;
                } else {
                    table.remove(dev.mac.0)?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

impl ConfigStore for RedbDatabase {
    fn get<T: serde::de::DeserializeOwned>(&self, key: lanforge_db_core::ConfigKey<T>) -> Result<Option<T>, DbError> {
        self.get(key)
    }

    fn put<T: serde::Serialize>(&self, key: lanforge_db_core::ConfigKey<T>, val: &T) -> Result<(), DbError> {
        self.put(key, val)
    }

    fn put_if_absent<T: serde::Serialize + serde::de::DeserializeOwned>(
        &self,
        key: lanforge_db_core::ConfigKey<T>,
        val: &T,
    ) -> Result<bool, DbError> {
        self.put_if_absent(key, val)
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        self.read_table(TABLE_META, |table| {
            Ok(table.get(key)?.map(|value| value.value().to_vec()))
        }).map(|opt| opt.flatten())
    }

    fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), DbError> {
        let txn = self.begin_write()?;
        txn.open_table(TABLE_META)?
            .insert(key, value)?;
        txn.commit()?;
        Ok(())
    }

    fn load_static_hosts(&self) -> Result<Vec<StaticHostEntry>, DbError> {
        let hosts = self.read_table_or_default(TABLE_STATIC_HOSTS, |table| {
            let count = table.len().unwrap_or(0) as usize;
            let mut list = Vec::with_capacity(count);
            for row in table.iter()? {
                let (_, value) = row?;
                list.push(decode(value.value())?);
            }
            Ok(list)
        })?;
        Ok(hosts)
    }

    fn upsert_static_host(&self, host: &StaticHostEntry) -> Result<(), DbError> {
        let bytes = encode(host)?;
        let txn = self.begin_write()?;
        txn.open_table(TABLE_STATIC_HOSTS)?
            .insert(host.mac.0, bytes.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    fn remove_static_host(&self, mac: MacAddr) -> Result<(), DbError> {
        let txn = self.begin_write()?;
        if let Ok(mut table) = txn.open_table(TABLE_STATIC_HOSTS) {
            table.remove(mac.0)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn clear_static_hosts(&self) -> Result<(), DbError> {
        let txn = self.begin_write()?;
        let _ = txn.delete_table(TABLE_STATIC_HOSTS);
        txn.commit()?;
        Ok(())
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
    let id = device.identity_mut();
    id.hostname = host.hostname;
    id.origin = host.origin;
    id.ignore_dns_log = host.ignore_dns_log;
    id.ignored_log_domains = host.ignored_log_domains;
    device.v4 = host.v4_fixed.map_or(IPv4State::None, IPv4State::Static);
    if let Some(suffix) = host.v6_suffix {
        device.v6.push(IPv6State::Static(suffix, std::time::SystemTime::UNIX_EPOCH));
    }
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
    persistent.identity_mut().iface = None;
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
