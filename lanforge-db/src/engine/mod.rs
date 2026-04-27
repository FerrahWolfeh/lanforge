use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::SystemTime;
use tracing::{debug, info};

use lanforge_core::device::{
    Device, Hostname, HostnameOrigin, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin,
};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::{DeviceUpdate, State, StaticEntry};

pub mod types;
pub mod utils;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use crate::LeaseDbError;
pub use types::{DeviceRow, LeaseAction, LeaseHistoryEntry, Pool};
use utils::{system_time_to_unix, unix_to_system_time};

pub struct LeaseDb {
    pub pool: Pool,
}

impl LeaseDb {
    pub async fn open(url: &str) -> Result<Self, LeaseDbError> {
        // Ensure parent directory exists for local SQLite files
        if url.starts_with("sqlite:") && !url.contains(":memory:") {
            let path_str = url
                .strip_prefix("sqlite://")
                .or_else(|| url.strip_prefix("sqlite:"))
                .unwrap_or(url);

            let path_str = path_str.split('?').next().unwrap_or(path_str);
            let path = Path::new(path_str);

            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                let _ = std::fs::create_dir_all(parent);
            }

            // Manually create the file if it doesn't exist to avoid "unable to open database file"
            if !path.exists() {
                debug!("Creating new database file: {}", path_str);
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path);
            }
        }

        let pool = Pool::connect(url)
            .await
            .map_err(|e| LeaseDbError::ConnectionOpen(Path::new(url).to_path_buf(), e))?;

        match &pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                sqlx::query("PRAGMA journal_mode=WAL")
                    .execute(p)
                    .await
                    .map_err(|e| {
                        LeaseDbError::Migration("setting WAL mode".into(), e.to_string())
                    })?;
                sqlx::query("PRAGMA foreign_keys=ON")
                    .execute(p)
                    .await
                    .map_err(|e| {
                        LeaseDbError::Migration("enabling foreign keys".into(), e.to_string())
                    })?;
                sqlx::migrate!("migrations/sqlite")
                    .run(p)
                    .await
                    .map_err(|e| {
                        LeaseDbError::Migration("applying sqlite migrations".into(), e.to_string())
                    })?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                sqlx::migrate!("migrations/postgres")
                    .run(p)
                    .await
                    .map_err(|e| {
                        LeaseDbError::Migration(
                            "applying postgres migrations".into(),
                            e.to_string(),
                        )
                    })?;
            }
        }

        info!("Database opened at {}", url);
        Ok(Self { pool })
    }

    #[cfg(test)]
    pub async fn open_in_memory() -> Result<Self, LeaseDbError> {
        #[cfg(feature = "sqlite")]
        {
            let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
            sqlx::migrate!("migrations/sqlite")
                .run(&pool)
                .await
                .map_err(|e| LeaseDbError::Migration("memory migrations".into(), e.to_string()))?;
            Ok(Self {
                pool: Pool::Sqlite(pool),
            })
        }
        #[cfg(all(not(feature = "sqlite"), feature = "postgres"))]
        {
            Err(LeaseDbError::Migration(
                "postgres in-memory not implemented".into(),
                "".into(),
            ))
        }
    }

    pub async fn save_table(&self, table: &State) -> Result<(), LeaseDbError> {
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                let mut tx = p.begin().await?;
                let db_macs: Vec<String> = sqlx::query_scalar("SELECT mac FROM devices")
                    .fetch_all(&mut *tx)
                    .await?;

                for device in table.devices() {
                    sqlite::upsert_device(&mut tx, &device).await?;
                }

                for db_mac in db_macs {
                    if !table.devices().any(|d| d.mac.to_string() == db_mac) {
                        sqlx::query("DELETE FROM devices WHERE mac = ?")
                            .bind(&db_mac)
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                let mut tx = p.begin().await?;
                let db_macs: Vec<String> = sqlx::query_scalar("SELECT mac FROM devices")
                    .fetch_all(&mut *tx)
                    .await?;

                for device in table.devices() {
                    postgres::upsert_device(&mut tx, &device).await?;
                }

                for db_mac in db_macs {
                    if !table.devices().any(|d| d.mac.to_string() == db_mac) {
                        sqlx::query("DELETE FROM devices WHERE mac = $1")
                            .bind(&db_mac)
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
        }
        debug!("State persisted successfully");
        Ok(())
    }

    pub async fn upsert_device(&self, device: &Device) -> Result<(), LeaseDbError> {
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                let mut tx = p.begin().await?;
                sqlite::upsert_device(&mut tx, device).await?;
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                let mut tx = p.begin().await?;
                postgres::upsert_device(&mut tx, device).await?;
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
        }
        Ok(())
    }

    pub async fn upsert_many<'a, I>(&self, devices: I) -> Result<(), LeaseDbError>
    where
        I: IntoIterator<Item = &'a Device>,
    {
        let devices_vec: Vec<&Device> = devices.into_iter().collect();
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                let mut tx = p.begin().await?;
                for device in devices_vec {
                    sqlite::upsert_device(&mut tx, device).await?;
                }
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                let mut tx = p.begin().await?;
                for device in devices_vec {
                    postgres::upsert_device(&mut tx, device).await?;
                }
                tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;
            }
        }
        Ok(())
    }

    pub async fn find_mac_by_hostname(
        &self,
        hostname: &str,
        last_seen_since: SystemTime,
    ) -> Result<Option<MacAddr>, LeaseDbError> {
        let since_unix = utils::system_time_to_unix(last_seen_since);
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => sqlite::find_mac_by_hostname(p, hostname, since_unix).await,
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => postgres::find_mac_by_hostname(p, hostname, since_unix).await,
        }
    }

    pub async fn load_table(&self) -> Result<State, LeaseDbError> {
        let mut table = State::new();
        table.set_indexing_enabled(false);

        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                Self::populate_state(
                    &mut table,
                    sqlite::load_device_rows(p).await?,
                    sqlite::load_v4_leases(p).await?,
                    sqlite::load_v6_leases(p).await?,
                    sqlite::load_v6_prefixes(p).await?,
                    sqlite::load_slaac_addrs(p).await?,
                    sqlite::load_seen_v4(p).await?,
                );
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                Self::populate_state(
                    &mut table,
                    postgres::load_device_rows(p).await?,
                    postgres::load_v4_leases(p).await?,
                    postgres::load_v6_leases(p).await?,
                    postgres::load_v6_prefixes(p).await?,
                    postgres::load_slaac_addrs(p).await?,
                    postgres::load_seen_v4(p).await?,
                );
            }
        }

        info!("Loaded devices from database");
        table.set_indexing_enabled(true);
        Ok(table)
    }

    fn populate_state(
        table: &mut State,
        device_rows: Vec<DeviceRow>,
        v4_leases: Vec<(String, String, i64)>,
        v6_leases: Vec<(String, i64, String, i64)>,
        v6_prefixes: Vec<(String, i64, String, i32, i64)>,
        slaac_addrs: Vec<(String, String)>,
        seen_v4: Vec<(String, String)>,
    ) {
        Self::populate_devices(table, device_rows);
        Self::populate_v4_leases(table, v4_leases);
        Self::populate_v6_leases(table, v6_leases);
        Self::populate_v6_prefixes(table, v6_prefixes);
        Self::populate_slaac_addrs(table, slaac_addrs);
        Self::populate_seen_v4(table, seen_v4);
    }

    fn populate_devices(table: &mut State, rows: Vec<DeviceRow>) {
        for row in rows {
            if let Some(mac) = MacAddr::parse(&row.mac) {
                let mut device = Device::new(mac);
                device.hostname = Hostname {
                    name: row.hostname.clone(),
                    origin: match row.hostname_origin {
                        1 => HostnameOrigin::Mdns,
                        2 => HostnameOrigin::Dhcp,
                        3 => HostnameOrigin::Static,
                        _ => HostnameOrigin::None,
                    },
                };
                device.last_seen = unix_to_system_time(row.last_seen);
                device.origin = match row.origin.as_str() {
                    "toml" => Origin::Toml,
                    "cli" => Origin::Cli,
                    _ => Origin::Dynamic,
                };
                device.managed_at = row.managed_at.map(unix_to_system_time);

                if let Some(v4) = &row.v4_static
                    && let Ok(ip) = v4.parse::<Ipv4Addr>()
                {
                    device.v4 = IPv4State::Static(ip);
                }
                if let Some(v6) = &row.v6_suffix
                    && let Some(suf) = Ipv6AddrOrSuffix::parse(v6)
                {
                    device.v6.push(IPv6State::Static(suf));
                }
                if let Some(bytes) = &row.duid {
                    device.duid = Some(Duid::new(bytes.clone()));
                }

                if row.topo_updated > 0 {
                    device.topology = Some(lanforge_core::device::TopologyInfo {
                        parent_mac: row.parent_mac.as_ref().and_then(|m| MacAddr::parse(m)),
                        port: row.parent_port.clone(),
                        local_ifindex: u32::try_from(row.local_ifindex).unwrap_or(0),
                        last_updated: unix_to_system_time(row.topo_updated),
                    });
                }

                if row.origin == "cli" {
                    table.add_static_entry(
                        mac,
                        StaticEntry {
                            mac,
                            hostname: device.hostname.name.clone(),
                            duid: device.duid.clone(),
                            v4_static: match device.v4 {
                                IPv4State::Static(ip) => Some(ip),
                                _ => None,
                            },
                            v6_suffix: device.v6.iter().find_map(|s| {
                                if let IPv6State::Static(suffix) = s {
                                    Some(suffix.clone())
                                } else {
                                    None
                                }
                            }),
                            origin: device.origin,
                        },
                    );
                }
                table.insert_device(mac, device);
            }
        }
    }

    fn populate_v4_leases(table: &mut State, leases: Vec<(String, String, i64)>) {
        for (mac_s, ip_s, exp) in leases {
            if let Some(mac) = MacAddr::parse(&mac_s)
                && let Ok(ip) = ip_s.parse::<Ipv4Addr>()
            {
                table.apply_update(DeviceUpdate::V4LeaseGranted {
                    mac,
                    ip,
                    expires: unix_to_system_time(exp),
                });
            }
        }
    }

    fn populate_v6_leases(table: &mut State, leases: Vec<(String, i64, String, i64)>) {
        for (mac_s, iaid, ip_s, exp) in leases {
            if let Some(mac) = MacAddr::parse(&mac_s)
                && let Ok(ip) = ip_s.parse::<Ipv6Addr>()
            {
                let duid = table
                    .get_duid_by_mac(mac)
                    .cloned()
                    .unwrap_or_else(|| Duid::new(vec![]));
                table.apply_update(DeviceUpdate::V6LeaseGranted {
                    mac: Some(mac),
                    duid,
                    iaid: u32::try_from(iaid).unwrap_or(0),
                    ip,
                    expires: unix_to_system_time(exp),
                });
            }
        }
    }

    fn populate_v6_prefixes(table: &mut State, prefixes: Vec<(String, i64, String, i32, i64)>) {
        for (mac_s, iaid, px_s, len, exp) in prefixes {
            if let Some(mac) = MacAddr::parse(&mac_s)
                && let Ok(prefix) = px_s.parse::<Ipv6Addr>()
            {
                let duid = table
                    .get_duid_by_mac(mac)
                    .cloned()
                    .unwrap_or_else(|| Duid::new(vec![]));
                table.apply_update(DeviceUpdate::V6PrefixAssigned {
                    mac: Some(mac),
                    duid,
                    iaid: u32::try_from(iaid).unwrap_or(0),
                    prefix,
                    len: u8::try_from(len).unwrap_or(0),
                    expires: unix_to_system_time(exp),
                });
            }
        }
    }

    fn populate_slaac_addrs(table: &mut State, addrs: Vec<(String, String)>) {
        for (mac_s, ip_s) in addrs {
            if let Some(mac) = MacAddr::parse(&mac_s)
                && let Ok(ip) = ip_s.parse::<Ipv6Addr>()
            {
                table.apply_update(DeviceUpdate::SlaacObserved {
                    mac,
                    addr: ip,
                    is_active: false,
                });
            }
        }
    }

    fn populate_seen_v4(table: &mut State, seen: Vec<(String, String)>) {
        for (mac_s, ip_s) in seen {
            if let Some(mac) = MacAddr::parse(&mac_s)
                && let Ok(ip) = ip_s.parse::<Ipv4Addr>()
            {
                table.apply_update(DeviceUpdate::ArpSeen {
                    mac,
                    ip,
                    is_active: false,
                });
            }
        }
    }

    pub async fn remove_device(&self, mac: MacAddr) -> Result<(), LeaseDbError> {
        let mac_str = mac.to_string();
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                sqlx::query("DELETE FROM devices WHERE mac = ?")
                    .bind(&mac_str)
                    .execute(p)
                    .await?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                sqlx::query("DELETE FROM devices WHERE mac = $1")
                    .bind(&mac_str)
                    .execute(p)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn vacuum(&self) -> Result<(), LeaseDbError> {
        debug!("Running VACUUM on database...");
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => sqlite::vacuum(p)
                .await
                .map_err(LeaseDbError::VacuumFailed)?,
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => postgres::vacuum(p)
                .await
                .map_err(LeaseDbError::VacuumFailed)?,
        }
        Ok(())
    }

    pub async fn prune_zombies(&self) -> Result<usize, LeaseDbError> {
        debug!("[db] Pruning zombie entries...");
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => Ok(sqlite::prune_zombies(p).await?),
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => Ok(postgres::prune_zombies(p).await?),
        }
    }

    pub async fn reset(&self) -> Result<(), LeaseDbError> {
        info!("Resetting database (clearing all tables)...");
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                sqlx::query("DELETE FROM devices").execute(p).await?;
                sqlx::query("DELETE FROM lease_history").execute(p).await?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                sqlx::query("TRUNCATE TABLE devices CASCADE")
                    .execute(p)
                    .await?;
                sqlx::query("TRUNCATE TABLE lease_history")
                    .execute(p)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: &str,
        lease_type: &str,
        action: LeaseAction,
    ) -> Result<(), LeaseDbError> {
        let now = system_time_to_unix(SystemTime::now());
        let mac_str = mac.to_string();
        let action_str = action.as_str();

        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => {
                sqlite::record_lease_event(p, &mac_str, ip, lease_type, action_str, now).await?;
            }
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => {
                postgres::record_lease_event(p, &mac_str, ip, lease_type, action_str, now).await?;
            }
        }
        Ok(())
    }

    pub async fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> Result<Vec<LeaseHistoryEntry>, LeaseDbError> {
        let mac_str = mac.to_string();
        let rows = match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => sqlite::get_lease_history(p, &mac_str).await?,
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => postgres::get_lease_history(p, &mac_str).await?,
        };

        Ok(rows
            .into_iter()
            .map(|(ip, lt, act, ts)| LeaseHistoryEntry {
                ip,
                lease_type: lt,
                action: act.parse().unwrap_or(LeaseAction::Assigned),
                timestamp: unix_to_system_time(ts),
            })
            .collect())
    }
}
