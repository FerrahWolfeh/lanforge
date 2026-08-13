//! PostgreSQL persistence implementation for Lanforge.

pub mod dto;
pub mod mapping;

use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::pppoe::{AuthMethod, PppoeConfig, PppoeNftablesConfig};

// Helper macros to reduce query boilerplate
macro_rules! exec {
    ($query:expr, $executor:expr) => {
        $query.execute($executor).await.map_err(map_err)
    };
}

macro_rules! fetch_all {
    ($query:expr, $executor:expr) => {
        $query.fetch_all($executor).await.map_err(map_err)
    };
}

macro_rules! fetch_optional {
    ($query:expr, $executor:expr) => {
        $query.fetch_optional($executor).await.map_err(map_err)
    };
}

macro_rules! fetch_one {
    ($query:expr, $executor:expr) => {
        $query.fetch_one($executor).await.map_err(map_err)
    };
}
use lanforge_types::network::ra::{
    DnsslConfig, PrefixLifetime, PrefixSource, RAPrefix, RdnssConfig,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info};

use lanforge_core::context::PersistenceSnapshot;
use lanforge_core::context::state::State;
use lanforge_db_core::BoxFuture;
use lanforge_db_core::{
    AdblockStore, ApiTokenEntry, ApiTokenStore, DbError, DeviceStore, DhcpConfigStore, DnsStore,
    DnsUpstreamEntry, DnsUpstreamStore, PppoeConfigStore, RaConfigStore, UserEntry, UserStore,
};

use lanforge_types::auth::ApiScopes;
use lanforge_types::device::{
    Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, LeaseAction, LeaseHistoryEntry, LeaseKind,
    Origin,
};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockUrlKind, RewriteRule};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::{DnsReverseResolver, IpSubnet};
use lanforge_types::update::{DeviceUpdate, StaticEntry};

use dto::{
    AdblockConfigDto, AdblockRuleDto, AdblockSourceDto, ApiTokenDto, DeviceDto, DnsUpstreamDto,
    LeaseHistoryDto, ReverseResolverDto, RewriteRuleDto, SeenV4Dto, SlaacAddrDto, V4LeaseDto,
    V6LeaseDto, V6PrefixDto,
};
use mapping::{
    PgCidr, PgDeviceOrigin, PgHostnameOrigin, PgInet, PgLeaseAction, PgLeaseType, PgMacAddr,
    PgTimestampTz,
};

/// Helper function to convert `sqlx::Error` to `lanforge_db_core::DbError`.
fn map_err(e: sqlx::Error) -> DbError {
    DbError::Backend(e.to_string())
}

/// Helper function to strip `0x00` null bytes from string arguments before sending to PostgreSQL.
#[inline]
fn sanitize_pg_str(s: &str) -> String {
    s.replace('\0', "")
}

/// PostgreSQL database client.
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    /// Opens the PostgreSQL database and runs pending migrations.
    pub async fn open(
        url: &str,
        max_connections: u32,
        min_connections: u32,
    ) -> Result<Self, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .connect(url)
            .await
            .map_err(map_err)?;

        sqlx::migrate!()
            .run(&pool)
            .await
            .map_err(|e| DbError::Backend(format!("Failed to run migrations: {e}")))?;

        info!("PostgreSQL database opened at {url}");
        Ok(Self { pool })
    }

    /// Access raw database pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// Helper query loaders (private inside the postgres crate)
impl PostgresDatabase {
    async fn load_device_rows(&self) -> Result<Vec<DeviceDto>, DbError> {
        fetch_all!(
            sqlx::query_as!(
                DeviceDto,
                "SELECT 
                d.mac as \"mac!: PgMacAddr\", 
                d.hostname, 
                d.hostname_origin as \"hostname_origin!: PgHostnameOrigin\", 
                d.duid, 
                d.origin as \"origin!: PgDeviceOrigin\", 
                d.managed_at as \"managed_at?: PgTimestampTz\", 
                d.class as \"class!\",
                s.v4_static as \"v4_static?: PgInet\", 
                s.v6_suffix as \"v6_suffix?: PgInet\", 
                s.boot_file
             FROM net.devices d
             LEFT JOIN dhcp.static_devices s ON d.mac = s.mac"
            ),
            &self.pool
        )
    }

    async fn load_v4_leases(&self) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, DbError> {
        let rows = fetch_all!(
            sqlx::query_as!(
                V4LeaseDto,
                "SELECT 
                mac as \"mac!: PgMacAddr\", 
                ip as \"ip!: PgInet\", 
                expires as \"expires!: PgTimestampTz\" 
             FROM dhcp.v4_leases"
            ),
            &self.pool
        )?;
        Ok(rows.into_iter().map(V4LeaseDto::into_tuple).collect())
    }

    async fn load_v6_leases(&self) -> Result<Vec<(MacAddr, u32, Ipv6Addr, SystemTime)>, DbError> {
        let rows = fetch_all!(
            sqlx::query_as!(
                V6LeaseDto,
                "SELECT 
                mac as \"mac!: PgMacAddr\", 
                iaid as \"iaid!\", 
                ip as \"ip!: PgInet\", 
                expires as \"expires!: PgTimestampTz\" 
             FROM dhcp.v6_leases"
            ),
            &self.pool
        )?;
        Ok(rows.into_iter().map(V6LeaseDto::into_tuple).collect())
    }

    async fn load_v6_prefixes(
        &self,
    ) -> Result<Vec<(MacAddr, u32, Ipv6Addr, u8, SystemTime)>, DbError> {
        let rows = fetch_all!(
            sqlx::query_as!(
                V6PrefixDto,
                "SELECT 
                mac as \"mac!: PgMacAddr\", 
                iaid as \"iaid!\", 
                cidr as \"cidr!: PgCidr\", 
                expires as \"expires!: PgTimestampTz\" 
             FROM net.v6_prefixes"
            ),
            &self.pool
        )?;
        Ok(rows.into_iter().map(V6PrefixDto::into_tuple).collect())
    }

    async fn load_slaac_addrs(&self) -> Result<Vec<(MacAddr, Ipv6Addr, SystemTime)>, DbError> {
        let rows = fetch_all!(
            sqlx::query_as!(
                SlaacAddrDto,
                "SELECT 
                mac as \"mac!: PgMacAddr\", 
                ip as \"ip!: PgInet\", 
                last_seen as \"last_seen!: PgTimestampTz\" 
             FROM net.slaac_addrs"
            ),
            &self.pool
        )?;
        Ok(rows.into_iter().map(SlaacAddrDto::into_tuple).collect())
    }

    async fn load_seen_v4(&self) -> Result<Vec<(MacAddr, Ipv4Addr, SystemTime)>, DbError> {
        let rows = fetch_all!(
            sqlx::query_as!(
                SeenV4Dto,
                "SELECT 
                mac as \"mac!: PgMacAddr\", 
                ip as \"ip!: PgInet\", 
                last_seen as \"last_seen!: PgTimestampTz\" 
             FROM net.seen_v4"
            ),
            &self.pool
        )?;
        Ok(rows.into_iter().map(SeenV4Dto::into_tuple).collect())
    }
}

impl PostgresDatabase {
    pub async fn save_table(&self, table: &State) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let db_macs = fetch_all!(
            sqlx::query_scalar!(
                "SELECT 
                mac as \"mac: PgMacAddr\" 
             FROM net.devices"
            ),
            &mut *tx
        )?;

        let snapshot_macs: HashSet<PgMacAddr> =
            table.devices().map(|d| PgMacAddr::from(d.mac)).collect();

        for device in table.devices() {
            upsert_device_internal(&mut tx, &device).await?;
        }

        for db_mac in db_macs {
            if !snapshot_macs.contains(&db_mac) {
                exec!(
                    sqlx::query!(
                        "DELETE FROM net.devices 
                     WHERE mac = $1",
                        db_mac as PgMacAddr
                    ),
                    &mut *tx
                )?;
            }
        }
        tx.commit().await.map_err(map_err)?;
        debug!("State persisted successfully");
        Ok(())
    }

    pub async fn save_snapshot(&self, snapshot: &PersistenceSnapshot) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let db_devices = fetch_all!(
            sqlx::query!(
                "SELECT 
                mac as \"mac: PgMacAddr\", 
                origin as \"origin: PgDeviceOrigin\" 
             FROM net.devices"
            ),
            &mut *tx
        )?;

        let snapshot_macs: HashSet<PgMacAddr> = snapshot
            .devices
            .keys()
            .map(|m| PgMacAddr::from(*m))
            .collect();

        for device in snapshot.devices.values() {
            upsert_device_internal(&mut tx, device).await?;
        }

        for row in db_devices {
            if !snapshot_macs.contains(&row.mac) && row.origin == PgDeviceOrigin::Dynamic {
                exec!(
                    sqlx::query!(
                        "DELETE FROM net.devices 
                     WHERE mac = $1",
                        row.mac as PgMacAddr
                    ),
                    &mut *tx
                )?;
            }
        }

        tx.commit().await.map_err(map_err)?;
        debug!("Snapshot persisted successfully");
        Ok(())
    }

    pub async fn load_table(&self) -> Result<State, DbError> {
        let mut table = State::new();
        table.set_indexing_enabled(false);

        // Delete expired leases/prefixes from the database on startup
        let now_pg = PgTimestampTz::from(SystemTime::now());
        exec!(
            sqlx::query!(
                "DELETE FROM dhcp.v4_leases WHERE expires <= $1",
                now_pg as PgTimestampTz
            ),
            &self.pool
        )?;
        exec!(
            sqlx::query!(
                "DELETE FROM dhcp.v6_leases WHERE expires <= $1",
                now_pg as PgTimestampTz
            ),
            &self.pool
        )?;
        exec!(
            sqlx::query!(
                "DELETE FROM net.v6_prefixes WHERE expires <= $1",
                now_pg as PgTimestampTz
            ),
            &self.pool
        )?;

        let device_rows = self.load_device_rows().await?;
        let v4_leases = self.load_v4_leases().await?;
        let v6_leases = self.load_v6_leases().await?;
        let v6_prefixes = self.load_v6_prefixes().await?;
        let slaac_addrs = self.load_slaac_addrs().await?;
        let seen_v4 = self.load_seen_v4().await?;

        // Populate state devices
        for row in device_rows {
            let mac: MacAddr = row.mac.into();
            let device = row.into_device();

            if matches!(device.origin, Origin::Static) {
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
                            if let IPv6State::Static(suffix, _) = s {
                                Some(*suffix)
                            } else {
                                None
                            }
                        }),
                        origin: device.origin,
                        boot_file: device.boot_file.clone(),
                    },
                );
            }
            table.insert_device(mac, device);
        }

        // Leases and SLAAC
        let now = SystemTime::now();
        for (mac, ip, expires) in v4_leases {
            if expires > now {
                table.apply_update(DeviceUpdate::V4LeaseGranted { mac, ip, expires });
            }
        }
        for (mac, iaid, ip, expires) in v6_leases {
            if expires > now {
                let duid = table
                    .get_duid_by_mac(mac)
                    .cloned()
                    .unwrap_or_else(|| Duid::new(vec![]));
                table.apply_update(DeviceUpdate::V6LeaseGranted {
                    mac: Some(mac),
                    duid,
                    iaid,
                    ip,
                    expires,
                });
            }
        }
        for (mac, iaid, prefix, len, expires) in v6_prefixes {
            if expires > now {
                let duid = table
                    .get_duid_by_mac(mac)
                    .cloned()
                    .unwrap_or_else(|| Duid::new(vec![]));
                table.apply_update(DeviceUpdate::V6PrefixAssigned {
                    mac: Some(mac),
                    duid,
                    iaid,
                    prefix,
                    len,
                    expires,
                });
            }
        }
        for (mac, ip, last_seen) in slaac_addrs {
            if let Some(dev_arc) = table.devices.get_mut(&mac) {
                let dev = Arc::make_mut(dev_arc);
                let exists = dev.v6.iter().any(|state| {
                    if let IPv6State::Slaac(addr, _) = state {
                        *addr == ip
                    } else {
                        false
                    }
                });
                if !exists {
                    dev.v6.push(IPv6State::Slaac(ip, last_seen));
                }
            }
        }
        for (mac, ip, last_seen) in seen_v4 {
            if let Some(dev_arc) = table.devices.get_mut(&mac) {
                let dev = Arc::make_mut(dev_arc);
                let exists = dev.seen_v4.iter().any(|(addr, _)| *addr == ip);
                if !exists {
                    if dev.seen_v4.len() >= 4 {
                        dev.seen_v4.remove(0);
                    }
                    dev.seen_v4.push((ip, last_seen));
                }
            }
        }

        info!("Loaded devices from database");
        table.set_indexing_enabled(true);
        Ok(table)
    }

    pub async fn load_all_devices(&self) -> Result<Vec<Device>, DbError> {
        let state = self.load_table().await?;
        Ok(state.devices().map(|d| d.as_ref().clone()).collect())
    }
}

impl DeviceStore for PostgresDatabase {
    fn load_all_devices(&self) -> BoxFuture<'_, Result<Vec<Device>, DbError>> {
        Box::pin(async move { self.load_all_devices().await })
    }

    fn upsert_device<'a>(&'a self, device: &'a Device) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            upsert_device_internal(&mut tx, device).await?;
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn upsert_base_device_only<'a>(
        &'a self,
        device: &'a Device,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            upsert_base_device_only_internal(&mut tx, device).await?;
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn delete_devices<'a>(&'a self, macs: &'a [MacAddr]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            if macs.is_empty() {
                return Ok(());
            }
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            for mac in macs {
                let pg_mac = PgMacAddr::from(*mac);
                exec!(
                    sqlx::query!(
                        "DELETE FROM net.devices 
                     WHERE mac = $1",
                        pg_mac as PgMacAddr
                    ),
                    &mut *tx
                )?;
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn find_mac_by_hostname<'a>(
        &'a self,
        hostname: &'a str,
    ) -> BoxFuture<'a, Result<Option<MacAddr>, DbError>> {
        Box::pin(async move {
            let row = fetch_optional!(
                sqlx::query!(
                    "SELECT 
                    mac as \"mac: PgMacAddr\" 
                 FROM net.devices 
                 WHERE hostname = $1 OR LOWER(hostname) = LOWER($1) 
                 LIMIT 1",
                    hostname
                ),
                &self.pool
            )?;

            Ok(row.map(|r| r.mac.into()))
        })
    }

    fn remove_device(&self, mac: MacAddr) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let pg_mac = PgMacAddr::from(mac);
            exec!(
                sqlx::query!(
                    "DELETE FROM net.devices 
                 WHERE mac = $1",
                    pg_mac as PgMacAddr
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn vacuum(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { Ok(()) })
    }

    fn prune_zombies(&self) -> BoxFuture<'_, Result<usize, DbError>> {
        Box::pin(async move {
            let result = exec!(
                sqlx::query!(
                    "DELETE FROM net.devices
                 WHERE origin = 'dynamic'::device_origin
                   AND hostname = ''
                   AND mac NOT IN (SELECT mac FROM dhcp.v4_leases)
                   AND mac NOT IN (SELECT mac FROM dhcp.v6_leases)
                   AND mac NOT IN (SELECT mac FROM net.v6_prefixes)
                   AND mac NOT IN (SELECT mac FROM net.slaac_addrs)
                   AND mac NOT IN (SELECT mac FROM net.seen_v4)"
                ),
                &self.pool
            )?;
            Ok(result.rows_affected() as usize)
        })
    }

    fn reset(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(
                sqlx::query!("TRUNCATE TABLE net.devices CASCADE"),
                &self.pool
            )?;
            exec!(
                sqlx::query!("TRUNCATE TABLE dhcp.lease_history"),
                &self.pool
            )?;
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
            let ip_parsed = ip
                .parse::<IpAddr>()
                .map_err(|e| DbError::Validation(format!("Invalid IP: {e}")))?;
            let lease_type_parsed = lease_type
                .parse::<LeaseKind>()
                .map_err(DbError::Validation)?;

            let pg_mac = PgMacAddr::from(mac);
            let pg_ip = PgInet::from(ip_parsed);
            let pg_lease = PgLeaseType::from(lease_type_parsed);
            let pg_action = PgLeaseAction::from(action);
            let pg_now = PgTimestampTz::from(SystemTime::now());

            exec!(
                sqlx::query!(
                    "INSERT INTO dhcp.lease_history (mac, ip, lease_type, action, occurred_at)
                 VALUES ($1, $2, $3, $4, $5)",
                    pg_mac as PgMacAddr,
                    pg_ip as PgInet,
                    pg_lease as PgLeaseType,
                    pg_action as PgLeaseAction,
                    pg_now as PgTimestampTz
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn get_lease_history(
        &self,
        mac: MacAddr,
    ) -> BoxFuture<'_, Result<Vec<LeaseHistoryEntry>, DbError>> {
        Box::pin(async move {
            let pg_mac = PgMacAddr::from(mac);
            let rows = fetch_all!(
                sqlx::query_as!(
                    LeaseHistoryDto,
                    "SELECT 
                    ip as \"ip!: PgInet\", 
                    lease_type as \"lease_type!: PgLeaseType\", 
                    action as \"action!: PgLeaseAction\", 
                    occurred_at as \"occurred_at!: PgTimestampTz\"
                 FROM dhcp.lease_history 
                 WHERE mac = $1 
                 ORDER BY occurred_at DESC 
                 LIMIT 100",
                    pg_mac as PgMacAddr
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(LeaseHistoryDto::into_entry).collect())
        })
    }
}

// Inner helper methods for transactions
async fn upsert_device_internal(
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
) -> Result<(), DbError> {
    let pg_mac = PgMacAddr::from(device.mac);
    upsert_base_device_only_internal(tx, device).await?;

    // Prune stale child rows
    exec!(
        sqlx::query!(
            "DELETE FROM dhcp.v4_leases 
         WHERE mac = $1",
            pg_mac as PgMacAddr
        ),
        &mut **tx
    )?;
    exec!(
        sqlx::query!(
            "DELETE FROM dhcp.v6_leases 
         WHERE mac = $1",
            pg_mac as PgMacAddr
        ),
        &mut **tx
    )?;
    exec!(
        sqlx::query!(
            "DELETE FROM net.v6_prefixes 
         WHERE mac = $1",
            pg_mac as PgMacAddr
        ),
        &mut **tx
    )?;
    exec!(
        sqlx::query!(
            "DELETE FROM net.slaac_addrs 
         WHERE mac = $1",
            pg_mac as PgMacAddr
        ),
        &mut **tx
    )?;
    exec!(
        sqlx::query!(
            "DELETE FROM net.seen_v4 
         WHERE mac = $1",
            pg_mac as PgMacAddr
        ),
        &mut **tx
    )?;

    // Repopulate child tables
    if let IPv4State::Dynamic(lease) = &device.v4 {
        let pg_ip = PgInet::from(lease.ip);
        let pg_exp = PgTimestampTz::from(lease.expires);
        exec!(
            sqlx::query!(
                "INSERT INTO dhcp.v4_leases (mac, ip, expires) 
             VALUES ($1, $2, $3)",
                pg_mac as PgMacAddr,
                pg_ip as PgInet,
                pg_exp as PgTimestampTz
            ),
            &mut **tx
        )?;
    }

    for state in &device.v6 {
        if let IPv6State::Dynamic(lease) = state {
            let pg_ip = PgInet::from(lease.ip);
            let pg_exp = PgTimestampTz::from(lease.expires);
            exec!(
                sqlx::query!(
                    "INSERT INTO dhcp.v6_leases (mac, iaid, ip, expires) 
                 VALUES ($1, $2, $3, $4)",
                    pg_mac as PgMacAddr,
                    i64::from(lease.iaid),
                    pg_ip as PgInet,
                    pg_exp as PgTimestampTz
                ),
                &mut **tx
            )?;
        } else if let IPv6State::Slaac(ip, timestamp) = state {
            let pg_ip = PgInet::from(*ip);
            let pg_ts = PgTimestampTz::from(*timestamp);
            exec!(
                sqlx::query!(
                    "INSERT INTO net.slaac_addrs (mac, ip, last_seen)
                 VALUES ($1, $2, $3)
                 ON CONFLICT(mac, ip) DO UPDATE SET last_seen = EXCLUDED.last_seen",
                    pg_mac as PgMacAddr,
                    pg_ip as PgInet,
                    pg_ts as PgTimestampTz
                ),
                &mut **tx
            )?;
        }
    }

    for prefix in &device.v6_prefixes {
        let pg_cidr = PgCidr::from(IpSubnet {
            addr: IpAddr::V6(prefix.prefix),
            prefix_len: prefix.len,
        });
        let pg_exp = PgTimestampTz::from(prefix.expires);
        exec!(
            sqlx::query!(
                "INSERT INTO net.v6_prefixes (mac, iaid, cidr, expires) 
             VALUES ($1, $2, $3, $4)",
                pg_mac as PgMacAddr,
                i64::from(prefix.iaid),
                pg_cidr as PgCidr,
                pg_exp as PgTimestampTz
            ),
            &mut **tx
        )?;
    }

    for (ip, timestamp) in &device.seen_v4 {
        let pg_ip = PgInet::from(*ip);
        let pg_ts = PgTimestampTz::from(*timestamp);
        exec!(
            sqlx::query!(
                "INSERT INTO net.seen_v4 (mac, ip, last_seen) 
             VALUES ($1, $2, $3)",
                pg_mac as PgMacAddr,
                pg_ip as PgInet,
                pg_ts as PgTimestampTz
            ),
            &mut **tx
        )?;
    }

    // Static mapping
    let v4_static = match &device.v4 {
        IPv4State::Static(ip) => Some(PgInet::from(*ip)),
        _ => None,
    };
    let v6_suffix = device.v6.iter().find_map(|s| {
        if let IPv6State::Static(suf, _) = s {
            let ip = match suf {
                Ipv6AddrOrSuffix::Full(ip) => *ip,
                Ipv6AddrOrSuffix::Suffix(s) => Ipv6Addr::new(
                    0,
                    0,
                    0,
                    0,
                    u16::from_be_bytes([s.0[0], s.0[1]]),
                    u16::from_be_bytes([s.0[2], s.0[3]]),
                    u16::from_be_bytes([s.0[4], s.0[5]]),
                    u16::from_be_bytes([s.0[6], s.0[7]]),
                ),
            };
            Some(PgInet::from(ip))
        } else {
            None
        }
    });

    if v4_static.is_some() || v6_suffix.is_some() || device.boot_file.is_some() {
        let sanitized_boot_file = device.boot_file.as_deref().map(sanitize_pg_str);
        exec!(
            sqlx::query!(
                "INSERT INTO dhcp.static_devices (mac, v4_static, v6_suffix, boot_file)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(mac) DO UPDATE SET
                v4_static = EXCLUDED.v4_static,
                v6_suffix = EXCLUDED.v6_suffix,
                boot_file = EXCLUDED.boot_file",
                pg_mac as PgMacAddr,
                v4_static as Option<PgInet>,
                v6_suffix as Option<PgInet>,
                sanitized_boot_file.as_deref()
            ),
            &mut **tx
        )?;
    } else {
        exec!(
            sqlx::query!(
                "DELETE FROM dhcp.static_devices 
             WHERE mac = $1",
                pg_mac as PgMacAddr
            ),
            &mut **tx
        )?;
    }

    Ok(())
}

async fn upsert_base_device_only_internal(
    tx: &mut Transaction<'_, Postgres>,
    device: &Device,
) -> Result<(), DbError> {
    let pg_mac = PgMacAddr::from(device.mac);
    let sanitized_hostname = sanitize_pg_str(&device.hostname.name);
    let pg_hostname_origin = PgHostnameOrigin::from(device.hostname.origin);
    let pg_origin = PgDeviceOrigin::from(device.origin);
    let pg_managed_at = device.managed_at.map(PgTimestampTz::from);
    let pg_class = device.class as i32;

    exec!(sqlx::query!("INSERT INTO net.devices (mac, hostname, hostname_origin, duid, origin, managed_at, class)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT(mac) DO UPDATE SET
            hostname = EXCLUDED.hostname,
            hostname_origin = EXCLUDED.hostname_origin,
            duid = EXCLUDED.duid,
            origin = EXCLUDED.origin,
            managed_at = EXCLUDED.managed_at,
            class = EXCLUDED.class", pg_mac as PgMacAddr, sanitized_hostname, pg_hostname_origin as PgHostnameOrigin, device.duid.as_ref().map(|d| d.bytes.as_ref()), pg_origin as PgDeviceOrigin, pg_managed_at as Option<PgTimestampTz>, pg_class), &mut **tx)?;

    Ok(())
}

impl DnsStore for PostgresDatabase {
    fn load_dns_rewrites(&self) -> BoxFuture<'_, Result<Vec<RewriteRule>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    RewriteRuleDto,
                    "SELECT 
                    id as \"id!\", 
                    domain as \"domain!\", 
                    rtype as \"rtype!\", 
                    answer as \"answer!\" 
                 FROM dns.rewrites 
                 ORDER BY domain"
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(RewriteRuleDto::into_rule).collect())
        })
    }

    fn upsert_dns_rewrite<'a>(
        &'a self,
        domain: &'a str,
        rtype: DnsRecordType,
        answer: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let sanitized_domain = sanitize_pg_str(domain);
            let sanitized_answer = sanitize_pg_str(answer);
            let rtype_str = rtype.to_string();

            exec!(
                sqlx::query!(
                    "INSERT INTO dns.rewrites (domain, rtype, answer) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT(domain, rtype) DO UPDATE SET answer = EXCLUDED.answer",
                    sanitized_domain,
                    rtype_str,
                    sanitized_answer
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn delete_dns_rewrite_by_id(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let id_i32 = id as i32;
            exec!(
                sqlx::query!("DELETE FROM dns.rewrites WHERE id = $1", id_i32),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_dns_rewrites(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(sqlx::query!("DELETE FROM dns.rewrites"), &self.pool)?;
            Ok(())
        })
    }

    fn load_dns_allowlist(&self) -> BoxFuture<'_, Result<Vec<(i64, String)>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!("SELECT id, domain FROM dns.allowlist ORDER BY domain"),
                &self.pool
            )?;
            Ok(rows
                .into_iter()
                .map(|r| (i64::from(r.id), r.domain))
                .collect())
        })
    }

    fn add_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let sanitized_domain = sanitize_pg_str(domain);
            exec!(
                sqlx::query!(
                    "INSERT INTO dns.allowlist (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING",
                    sanitized_domain
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn remove_dns_allowlist<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let sanitized_domain = sanitize_pg_str(domain);
            exec!(
                sqlx::query!(
                    "DELETE FROM dns.allowlist WHERE domain = $1",
                    sanitized_domain
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_dns_allowlist(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(sqlx::query!("DELETE FROM dns.allowlist"), &self.pool)?;
            Ok(())
        })
    }

    fn load_dns_reverse_resolvers(
        &self,
    ) -> BoxFuture<'_, Result<Vec<DnsReverseResolver>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    ReverseResolverDto,
                    "SELECT 
                    subnet as \"subnet!: PgCidr\", 
                    resolver_target as \"resolver_target!\" 
                 FROM dns.reverse_resolvers"
                ),
                &self.pool
            )?;

            Ok(rows
                .into_iter()
                .filter_map(ReverseResolverDto::into_resolver)
                .collect())
        })
    }

    fn add_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
        resolver: &'a UpstreamTarget,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let pg_subnet = PgCidr::from(*subnet);
            let resolver_str = String::from(resolver.clone());
            exec!(
                sqlx::query!(
                    "INSERT INTO dns.reverse_resolvers (subnet, resolver_target) 
                 VALUES ($1, $2) 
                 ON CONFLICT(subnet) DO UPDATE SET resolver_target = EXCLUDED.resolver_target",
                    pg_subnet as PgCidr,
                    resolver_str
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn remove_dns_reverse_resolver<'a>(
        &'a self,
        subnet: &'a IpSubnet,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let pg_subnet = PgCidr::from(*subnet);
            exec!(
                sqlx::query!(
                    "DELETE FROM dns.reverse_resolvers 
                 WHERE subnet = $1",
                    pg_subnet as PgCidr
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_dns_reverse_resolvers(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(
                sqlx::query!("DELETE FROM dns.reverse_resolvers"),
                &self.pool
            )?;
            Ok(())
        })
    }
}

impl AdblockStore for PostgresDatabase {
    fn load_adblock_config(&self) -> BoxFuture<'_, Result<AdblockDbConfig, DbError>> {
        Box::pin(async move {
            let row = fetch_one!(
                sqlx::query_as!(
                    AdblockConfigDto,
                    "SELECT 
                    enabled as \"enabled!\", 
                    blocking_mode::TEXT as \"blocking_mode!\", 
                    blocking_ip_v4 as \"blocking_ip_v4: PgInet\", 
                    blocking_ip_v6 as \"blocking_ip_v6: PgInet\", 
                    refresh_hours as \"refresh_hours!\", 
                    refresh_at_night as \"refresh_at_night!\" 
                 FROM dns.adblock_config 
                 LIMIT 1"
                ),
                &self.pool
            )?;

            Ok(row.into_config())
        })
    }

    fn save_adblock_config<'a>(
        &'a self,
        cfg: &'a AdblockDbConfig,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let pg_ip_v4 = cfg.blocking_ip_v4.map(PgInet::from);
            let pg_ip_v6 = cfg.blocking_ip_v6.map(PgInet::from);
            let blocking_mode_str = cfg.blocking_mode.to_string();
            let refresh_hours = cfg.refresh_hours as i16;

            exec!(
                sqlx::query!(
                    "UPDATE dns.adblock_config SET 
                    enabled = $1, 
                    blocking_mode = $2::text::dns.blocking_mode, 
                    blocking_ip_v4 = $3, 
                    blocking_ip_v6 = $4, 
                    refresh_hours = $5, 
                    refresh_at_night = $6",
                    cfg.enabled,
                    blocking_mode_str,
                    pg_ip_v4 as Option<PgInet>,
                    pg_ip_v6 as Option<PgInet>,
                    refresh_hours,
                    cfg.refresh_at_night
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn set_adblock_config_value<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            use std::str::FromStr;
            let mut cfg = self.load_adblock_config().await?;
            match key {
                "enabled" => cfg.enabled = value == "true",
                "blocking_mode" => {
                    if let Ok(m) =
                        lanforge_types::network::dns::adblock::BlockingMode::from_str(value)
                    {
                        cfg.blocking_mode = m;
                    }
                }
                "blocking_ip_v4" => {
                    if value.is_empty() || value == "none" || value == "null" {
                        cfg.blocking_ip_v4 = None;
                    } else if let Ok(ip) = value.parse() {
                        cfg.blocking_ip_v4 = Some(ip);
                    }
                }
                "blocking_ip_v6" => {
                    if value.is_empty() || value == "null" || value == "none" {
                        cfg.blocking_ip_v6 = None;
                    } else if let Ok(ip) = value.parse() {
                        cfg.blocking_ip_v6 = Some(ip);
                    }
                }
                "refresh_hours" => {
                    if let Ok(h) = value.parse() {
                        cfg.refresh_hours = h;
                    }
                }
                "refresh_at_night" => cfg.refresh_at_night = value == "true",
                _ => {}
            }
            self.save_adblock_config(&cfg).await
        })
    }

    fn load_adblock_urls(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind)>, DbError>> {
        Box::pin(async move {
            let sources = self.load_adblock_sources().await?;
            Ok(sources
                .into_iter()
                .map(|(id, url, kind, _)| (id, url, kind))
                .collect())
        })
    }

    fn add_adblock_url<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move { self.add_adblock_source(url, kind).await.map(|_| ()) })
    }

    fn remove_adblock_url<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            exec!(
                sqlx::query!("DELETE FROM dns.adblock_urls WHERE url = $1", url),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_adblock_urls(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move { self.clear_adblock_sources().await })
    }

    fn load_adblock_sources(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, AdblockUrlKind, bool)>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    AdblockSourceDto,
                    "SELECT 
                    id as \"id!\", 
                    url as \"url!\", 
                    kind as \"kind!\", 
                    enabled as \"enabled!\" 
                 FROM dns.adblock_urls"
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(AdblockSourceDto::into_tuple).collect())
        })
    }

    fn add_adblock_source<'a>(
        &'a self,
        url: &'a str,
        kind: AdblockUrlKind,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            let kind_str = kind.to_string();
            let row = fetch_one!(
                sqlx::query!(
                    "INSERT INTO dns.adblock_urls (url, kind) 
                 VALUES ($1, $2) 
                 ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind 
                 RETURNING id",
                    url,
                    kind_str
                ),
                &self.pool
            )?;
            Ok(i64::from(row.id))
        })
    }

    fn remove_adblock_source(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let id_i32 = id as i32;
            exec!(
                sqlx::query!(
                    "DELETE FROM dns.adblock_urls 
                 WHERE id = $1",
                    id_i32
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn update_adblock_source_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let id_i32 = id as i32;
            exec!(
                sqlx::query!(
                    "UPDATE dns.adblock_urls 
                 SET enabled = $1 
                 WHERE id = $2",
                    enabled,
                    id_i32
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_adblock_sources(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(sqlx::query!("DELETE FROM dns.adblock_urls"), &self.pool)?;
            Ok(())
        })
    }

    fn load_adblock_rules(
        &self,
    ) -> BoxFuture<'_, Result<Vec<(i64, String, String, bool)>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    AdblockRuleDto,
                    "SELECT 
                    id as \"id!\", 
                    domain as \"domain!\", 
                    action::TEXT as \"action!\", 
                    enabled as \"enabled!\" 
                 FROM dns.adblock_rules"
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(AdblockRuleDto::into_tuple).collect())
        })
    }

    fn add_adblock_rule<'a>(
        &'a self,
        domain: &'a str,
        action: &'a str,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            let row = fetch_one!(
                sqlx::query!(
                    "INSERT INTO dns.adblock_rules (domain, action) 
                 VALUES ($1, $2::text::dns.adblock_action) 
                 ON CONFLICT(domain) DO UPDATE SET action = EXCLUDED.action 
                 RETURNING id",
                    domain,
                    action
                ),
                &self.pool
            )?;
            Ok(i64::from(row.id))
        })
    }

    fn remove_adblock_rule(&self, id: i64) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let id_i32 = id as i32;
            exec!(
                sqlx::query!(
                    "DELETE FROM dns.adblock_rules 
                 WHERE id = $1",
                    id_i32
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn update_adblock_rule_status(
        &self,
        id: i64,
        enabled: bool,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let id_i32 = id as i32;
            exec!(
                sqlx::query!(
                    "UPDATE dns.adblock_rules 
                 SET enabled = $1 
                 WHERE id = $2",
                    enabled,
                    id_i32
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_adblock_rules(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(sqlx::query!("DELETE FROM dns.adblock_rules"), &self.pool)?;
            Ok(())
        })
    }
}

impl ApiTokenStore for PostgresDatabase {
    fn store_api_token<'a>(
        &'a self,
        token: &'a str,
        name: &'a str,
        scopes: &'a ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            let scopes_str = scopes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let created_at_dt = chrono::DateTime::from_timestamp(now, 0)
                .ok_or_else(|| DbError::Validation("Invalid created_at timestamp".to_string()))?;
            let expires_at_dt = expires_at.and_then(|exp| chrono::DateTime::from_timestamp(exp, 0));

            let pg_created = PgTimestampTz(created_at_dt);
            let pg_expires = expires_at_dt.map(PgTimestampTz);

            let row = fetch_one!(
                sqlx::query!(
                    "INSERT INTO auth.api_tokens (token, name, created_at, scopes, expires_at) 
                 VALUES ($1, $2, $3, $4, $5) 
                 RETURNING id",
                    token,
                    name,
                    pg_created as PgTimestampTz,
                    scopes_str,
                    pg_expires as Option<PgTimestampTz>
                ),
                &self.pool
            )?;
            Ok(i64::from(row.id))
        })
    }

    fn validate_api_token<'a>(
        &'a self,
        token: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes)>, DbError>> {
        Box::pin(async move {
            let res = fetch_optional!(
                sqlx::query!(
                    "SELECT 
                    name as \"name!\", 
                    scopes as \"scopes!\", 
                    expires_at as \"expires_at?: PgTimestampTz\" 
                 FROM auth.api_tokens 
                 WHERE token = $1",
                    token
                ),
                &self.pool
            )?;

            if let Some(row) = res {
                if let Some(exp) = row.expires_at
                    && now > exp.0.timestamp()
                {
                    return Ok(None);
                }
                let now_dt = chrono::DateTime::from_timestamp(now, 0)
                    .ok_or_else(|| DbError::Validation("Invalid now timestamp".to_string()))?;
                let pg_now = PgTimestampTz(now_dt);
                exec!(
                    sqlx::query!(
                        "UPDATE auth.api_tokens 
                     SET last_used = $1 
                     WHERE token = $2",
                        pg_now as PgTimestampTz,
                        token
                    ),
                    &self.pool
                )?;
                let scopes = row
                    .scopes
                    .split(',')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                Ok(Some((row.name, scopes)))
            } else {
                Ok(None)
            }
        })
    }

    fn delete_api_token<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            exec!(
                sqlx::query!(
                    "DELETE FROM auth.api_tokens 
                 WHERE token = $1",
                    token
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn delete_api_token_by_id_or_name<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            if let Ok(id) = id_or_name.parse::<i32>() {
                exec!(
                    sqlx::query!(
                        "DELETE FROM auth.api_tokens 
                     WHERE id = $1",
                        id
                    ),
                    &self.pool
                )?;
            } else {
                exec!(
                    sqlx::query!(
                        "DELETE FROM auth.api_tokens 
                     WHERE name = $1",
                        id_or_name
                    ),
                    &self.pool
                )?;
            }
            Ok(())
        })
    }

    fn load_api_tokens(&self) -> BoxFuture<'_, Result<Vec<ApiTokenEntry>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    ApiTokenDto,
                    "SELECT 
                    id as \"id!\", 
                    token as \"token!\", 
                    name as \"name!\", 
                    created_at as \"created_at: PgTimestampTz\", 
                    last_used as \"last_used?: PgTimestampTz\", 
                    scopes as \"scopes!\", 
                    expires_at as \"expires_at?: PgTimestampTz\" 
                 FROM auth.api_tokens 
                 ORDER BY created_at DESC"
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(ApiTokenDto::into_entry).collect())
        })
    }

    fn get_api_token_info<'a>(
        &'a self,
        id_or_name: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, ApiScopes, Option<i64>)>, DbError>> {
        Box::pin(async move {
            let res = if let Ok(id) = id_or_name.parse::<i64>() {
                let id_i32 = id as i32;
                fetch_optional!(
                    sqlx::query!(
                        "SELECT 
                        name as \"name!\", 
                        scopes as \"scopes!\", 
                        expires_at as \"expires_at?: PgTimestampTz\" 
                     FROM auth.api_tokens 
                     WHERE id = $1",
                        id_i32
                    ),
                    &self.pool
                )?
                .map(|row| (row.name, row.scopes, row.expires_at))
            } else {
                fetch_optional!(
                    sqlx::query!(
                        "SELECT 
                        name as \"name!\", 
                        scopes as \"scopes!\", 
                        expires_at as \"expires_at?: PgTimestampTz\" 
                     FROM auth.api_tokens 
                     WHERE name = $1",
                        id_or_name
                    ),
                    &self.pool
                )?
                .map(|row| (row.name, row.scopes, row.expires_at))
            };
            if let Some((name, scopes_str, expires_at)) = res {
                let scopes = scopes_str
                    .split(',')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                Ok(Some((name, scopes, expires_at.map(|dt| dt.0.timestamp()))))
            } else {
                Ok(None)
            }
        })
    }
}

impl DnsUpstreamStore for PostgresDatabase {
    fn load_dns_upstreams(&self) -> BoxFuture<'_, Result<Vec<DnsUpstreamEntry>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query_as!(
                    DnsUpstreamDto,
                    "SELECT 
                    id as \"id!\", 
                    addr as \"addr!\", 
                    protocol as \"protocol!\", 
                    domain 
                 FROM dns.upstreams 
                 ORDER BY id ASC"
                ),
                &self.pool
            )?;

            Ok(rows.into_iter().map(DnsUpstreamDto::into_entry).collect())
        })
    }

    fn add_dns_upstream<'a>(
        &'a self,
        addr: &'a str,
        protocol: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<i64, DbError>> {
        Box::pin(async move {
            let row = fetch_one!(
                sqlx::query!(
                    "INSERT INTO dns.upstreams (addr, protocol, domain) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (addr, protocol) DO UPDATE SET domain = EXCLUDED.domain 
                 RETURNING id",
                    addr,
                    protocol,
                    domain
                ),
                &self.pool
            )?;
            Ok(i64::from(row.id))
        })
    }

    fn remove_dns_upstream<'a>(
        &'a self,
        addr: &'a str,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            exec!(
                sqlx::query!(
                    "DELETE FROM dns.upstreams 
                 WHERE addr = $1 AND protocol = $2",
                    addr,
                    protocol
                ),
                &self.pool
            )?;
            Ok(())
        })
    }

    fn clear_dns_upstreams(&self) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            exec!(sqlx::query!("DELETE FROM dns.upstreams"), &self.pool)?;
            Ok(())
        })
    }
}

impl PostgresDatabase {
    pub async fn set_adblock_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
        let pool = &self.pool;
        match key {
            "enabled" => {
                let val = value == "true";
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET enabled = $1",
                        val
                    ),
                    pool
                )?;
            }
            "blocking_mode" => {
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET blocking_mode = $1::text::dns.blocking_mode",
                        value
                    ),
                    pool
                )?;
            }
            "blocking_ip_v4" => {
                let ip_val = if value.is_empty() || value == "none" || value == "null" {
                    None
                } else {
                    Some(PgInet::from(value.parse::<IpAddr>().map_err(|e| {
                        DbError::Validation(format!("Invalid IP: {e}"))
                    })?))
                };
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET blocking_ip_v4 = $1",
                        ip_val as Option<PgInet>
                    ),
                    pool
                )?;
            }
            "blocking_ip_v6" => {
                let ip_val = if value.is_empty() || value == "none" || value == "null" {
                    None
                } else {
                    Some(PgInet::from(value.parse::<IpAddr>().map_err(|e| {
                        DbError::Validation(format!("Invalid IP: {e}"))
                    })?))
                };
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET blocking_ip_v6 = $1",
                        ip_val as Option<PgInet>
                    ),
                    pool
                )?;
            }
            "refresh_hours" => {
                let val = value.parse::<i16>().unwrap_or(12);
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET refresh_hours = $1",
                        val
                    ),
                    pool
                )?;
            }
            "refresh_at_night" => {
                let val = value == "true";
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET refresh_at_night = $1",
                        val
                    ),
                    pool
                )?;
            }
            _ => {
                let extras_str = fetch_one!(
                    sqlx::query_scalar!(
                        "SELECT 
                        extras::TEXT as \"extras!: String\" 
                     FROM dns.adblock_config 
                     LIMIT 1"
                    ),
                    pool
                )?;
                let mut extras_json: serde_json::Value =
                    serde_json::from_str(&extras_str).unwrap_or_else(|_| serde_json::json!({}));
                if let Ok(val_json) = serde_json::from_str::<serde_json::Value>(value) {
                    extras_json[key] = val_json;
                } else {
                    extras_json[key] = serde_json::Value::String(value.to_string());
                }
                exec!(
                    sqlx::query!(
                        "UPDATE dns.adblock_config 
                     SET extras = $1",
                        extras_json
                    ),
                    pool
                )?;
            }
        }
        Ok(())
    }

    pub async fn load_adblock_urls(&self) -> Result<Vec<(i64, String, AdblockUrlKind)>, DbError> {
        let rows = fetch_all!(
            sqlx::query!(
                "SELECT 
                id as \"id!\", 
                url as \"url!\", 
                kind as \"kind!\" 
             FROM dns.adblock_urls"
            ),
            &self.pool
        )?;

        Ok(rows
            .into_iter()
            .map(|row| {
                let kind = row.kind.parse().unwrap_or_default();
                (i64::from(row.id), row.url, kind)
            })
            .collect())
    }

    pub async fn add_adblock_url(&self, url: &str, kind: AdblockUrlKind) -> Result<(), DbError> {
        let kind_str = kind.to_string();
        exec!(
            sqlx::query!(
                "INSERT INTO dns.adblock_urls (url, kind) 
             VALUES ($1, $2) 
             ON CONFLICT(url) DO UPDATE SET kind = EXCLUDED.kind",
                url,
                kind_str
            ),
            &self.pool
        )?;
        Ok(())
    }

    pub async fn remove_adblock_url(&self, url: &str) -> Result<(), DbError> {
        exec!(
            sqlx::query!(
                "DELETE FROM dns.adblock_urls 
             WHERE url = $1",
                url
            ),
            &self.pool
        )?;
        Ok(())
    }

    pub async fn clear_adblock_urls(&self) -> Result<(), DbError> {
        exec!(sqlx::query!("DELETE FROM dns.adblock_urls"), &self.pool)?;
        Ok(())
    }
}

impl DhcpConfigStore for PostgresDatabase {
    fn load_dhcp_v4_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv4Pool>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!(
                    "SELECT 
                    range_start as \"range_start!: PgInet\", 
                    range_end as \"range_end!: PgInet\", 
                    lease_time 
                 FROM dhcp.v4_pools"
                ),
                &self.pool
            )?;

            let mut pools = Vec::new();
            for row in rows {
                let start = match row.range_start.0.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => {
                        return Err(DbError::Internal(
                            "Non-IPv4 address in v4_pools".to_string(),
                        ));
                    }
                };
                let end = match row.range_end.0.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => {
                        return Err(DbError::Internal(
                            "Non-IPv4 address in v4_pools".to_string(),
                        ));
                    }
                };
                let lease_time = if row.lease_time == 0 {
                    None
                } else {
                    Some(row.lease_time as u32)
                };
                pools.push(Dhcpv4Pool {
                    range_start: start,
                    range_end: end,
                    lease_time,
                });
            }
            Ok(pools)
        })
    }

    fn save_dhcp_v4_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv4Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            exec!(sqlx::query!("DELETE FROM dhcp.v4_pools"), &mut *tx)?;

            for pool in pools {
                let pg_start = PgInet::from(pool.range_start);
                let pg_end = PgInet::from(pool.range_end);
                let lease_time = pool.lease_time.unwrap_or(0) as i32;
                exec!(
                    sqlx::query!(
                        "INSERT INTO dhcp.v4_pools (range_start, range_end, lease_time) 
                     VALUES ($1, $2, $3)",
                        pg_start as PgInet,
                        pg_end as PgInet,
                        lease_time
                    ),
                    &mut *tx
                )?;
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn load_dhcp_v6_pools(&self) -> BoxFuture<'_, Result<Vec<Dhcpv6Pool>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!(
                    "SELECT 
                    range_start, 
                    range_end, 
                    address, 
                    lease_time 
                 FROM dhcp.v6_pools"
                ),
                &self.pool
            )?;

            let mut pools = Vec::new();
            for row in rows {
                let range_start = row.range_start.as_deref().and_then(Ipv6AddrOrSuffix::parse);
                let range_end = row.range_end.as_deref().and_then(Ipv6AddrOrSuffix::parse);
                let lease_time = if row.lease_time == 0 {
                    None
                } else {
                    Some(row.lease_time as u32)
                };
                pools.push(Dhcpv6Pool {
                    range_start,
                    range_end,
                    address: row.address,
                    lease_time,
                });
            }
            Ok(pools)
        })
    }

    fn save_dhcp_v6_pools<'a>(
        &'a self,
        pools: &'a [Dhcpv6Pool],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            exec!(sqlx::query!("DELETE FROM dhcp.v6_pools"), &mut *tx)?;

            for pool in pools {
                let start_str = pool.range_start.map(|x| x.to_string());
                let end_str = pool.range_end.map(|x| x.to_string());
                let lease_time = pool.lease_time.unwrap_or(0) as i32;
                exec!(
                    sqlx::query!(
                        "INSERT INTO dhcp.v6_pools (range_start, range_end, address, lease_time) 
                     VALUES ($1, $2, $3, $4)",
                        start_str,
                        end_str,
                        pool.address,
                        lease_time
                    ),
                    &mut *tx
                )?;
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }
}

impl RaConfigStore for PostgresDatabase {
    fn load_ra_prefixes(&self) -> BoxFuture<'_, Result<Vec<RAPrefix>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!(
                    "SELECT 
                    source, 
                    address as \"address?: PgInet\", 
                    prefix_len, 
                    on_link, 
                    autonomous, 
                    preferred_lifetime, 
                    valid_lifetime 
                 FROM ra.prefixes"
                ),
                &self.pool
            )?;

            let mut prefixes = Vec::new();
            for row in rows {
                let source = match row.source.as_str() {
                    "static" => PrefixSource::Static,
                    "ula" => PrefixSource::Ula,
                    "auto_gua" => PrefixSource::AutoGua,
                    _ => PrefixSource::AutoGua,
                };
                let address = row.address.map(|pg_inet| pg_inet.0.ip().to_string());
                let valid_lifetime = match row.valid_lifetime {
                    None => PrefixLifetime::Infinity,
                    Some(secs) => PrefixLifetime::Secs(secs as u32),
                };
                let preferred_lifetime = match row.preferred_lifetime {
                    None => PrefixLifetime::Infinity,
                    Some(secs) => PrefixLifetime::Secs(secs as u32),
                };
                prefixes.push(RAPrefix {
                    source,
                    address,
                    prefix_len: row.prefix_len as u8,
                    on_link: row.on_link,
                    autonomous: row.autonomous,
                    router_addr: true,
                    valid_lifetime,
                    preferred_lifetime,
                });
            }
            Ok(prefixes)
        })
    }

    fn save_ra_prefixes<'a>(
        &'a self,
        prefixes: &'a [RAPrefix],
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            exec!(sqlx::query!("DELETE FROM ra.prefixes"), &mut *tx)?;

            for prefix in prefixes {
                let source_str = match &prefix.source {
                    PrefixSource::Static => "static",
                    PrefixSource::Ula => "ula",
                    PrefixSource::AutoGua => "auto_gua",
                };
                let pg_addr = prefix.address.as_ref().and_then(|s| {
                    let ip_str = s.split('/').next()?;
                    ip_str.parse::<IpAddr>().ok().map(PgInet::from)
                });
                let valid_lifetime = match prefix.valid_lifetime {
                    PrefixLifetime::Infinity => None,
                    PrefixLifetime::Secs(secs) => Some(secs as i32),
                };
                let preferred_lifetime = match prefix.preferred_lifetime {
                    PrefixLifetime::Infinity => None,
                    PrefixLifetime::Secs(secs) => Some(secs as i32),
                };
                exec!(sqlx::query!("INSERT INTO ra.prefixes (source, address, prefix_len, on_link, autonomous, preferred_lifetime, valid_lifetime)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)", source_str, pg_addr as Option<PgInet>, prefix.prefix_len as i16, prefix.on_link, prefix.autonomous, preferred_lifetime, valid_lifetime), &mut *tx)?;
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn load_ra_rdnss(&self) -> BoxFuture<'_, Result<Vec<RdnssConfig>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!(
                    "SELECT 
                    r.id, 
                    r.lifetime, 
                    s.address as \"address!: PgInet\"
                 FROM ra.rdnss r
                 JOIN ra.rdnss_servers s ON r.id = s.rdnss_id
                 ORDER BY r.id"
                ),
                &self.pool
            )?;

            use std::collections::BTreeMap;
            let mut configs_map: BTreeMap<i32, RdnssConfig> = BTreeMap::new();
            for row in rows {
                let entry = configs_map.entry(row.id).or_insert_with(|| RdnssConfig {
                    servers: Vec::new(),
                    lifetime: row.lifetime.map(|t| t as u32),
                });
                if let IpAddr::V6(v6) = row.address.0.ip() {
                    entry.servers.push(v6);
                }
            }
            Ok(configs_map.into_values().collect())
        })
    }

    fn save_ra_rdnss<'a>(&'a self, rdnss: &'a [RdnssConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            exec!(sqlx::query!("DELETE FROM ra.rdnss"), &mut *tx)?;

            for cfg in rdnss {
                let lifetime = cfg.lifetime.map(|t| t as i32);
                let row = fetch_one!(
                    sqlx::query!(
                        "INSERT INTO ra.rdnss (lifetime) 
                     VALUES ($1) 
                     RETURNING id",
                        lifetime
                    ),
                    &mut *tx
                )?;

                for server in &cfg.servers {
                    let pg_server = PgInet::from(IpAddr::V6(*server));
                    exec!(
                        sqlx::query!(
                            "INSERT INTO ra.rdnss_servers (rdnss_id, address) 
                         VALUES ($1, $2)",
                            row.id,
                            pg_server as PgInet
                        ),
                        &mut *tx
                    )?;
                }
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn load_ra_dnssl(&self) -> BoxFuture<'_, Result<Vec<DnsslConfig>, DbError>> {
        Box::pin(async move {
            let rows = fetch_all!(
                sqlx::query!(
                    "SELECT 
                    d.id, 
                    d.lifetime, 
                    m.domain
                 FROM ra.dnssl d
                 JOIN ra.dnssl_domains m ON d.id = m.dnssl_id
                 ORDER BY d.id"
                ),
                &self.pool
            )?;

            use std::collections::BTreeMap;
            let mut configs_map: BTreeMap<i32, DnsslConfig> = BTreeMap::new();
            for row in rows {
                let entry = configs_map.entry(row.id).or_insert_with(|| DnsslConfig {
                    domains: Vec::new(),
                    lifetime: row.lifetime.map(|t| t as u32),
                });
                entry.domains.push(row.domain);
            }
            Ok(configs_map.into_values().collect())
        })
    }

    fn save_ra_dnssl<'a>(&'a self, dnssl: &'a [DnsslConfig]) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(map_err)?;
            exec!(sqlx::query!("DELETE FROM ra.dnssl"), &mut *tx)?;

            for cfg in dnssl {
                let lifetime = cfg.lifetime.map(|t| t as i32);
                let row = fetch_one!(
                    sqlx::query!(
                        "INSERT INTO ra.dnssl (lifetime) 
                     VALUES ($1) 
                     RETURNING id",
                        lifetime
                    ),
                    &mut *tx
                )?;

                for domain in &cfg.domains {
                    exec!(
                        sqlx::query!(
                            "INSERT INTO ra.dnssl_domains (dnssl_id, domain) 
                         VALUES ($1, $2)",
                            row.id,
                            domain
                        ),
                        &mut *tx
                    )?;
                }
            }
            tx.commit().await.map_err(map_err)?;
            Ok(())
        })
    }

    fn load_last_gua_prefix(&self) -> BoxFuture<'_, Result<Option<Ipv6Addr>, DbError>> {
        Box::pin(async move {
            use sqlx::Row;
            let row = sqlx::query("SELECT last_gua FROM ra.state WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;

            let pg_inet: Option<PgInet> = match row {
                Some(r) => r.try_get("last_gua").ok().flatten(),
                None => None,
            };

            Ok(pg_inet.and_then(|pg| match pg.0.ip() {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            }))
        })
    }

    fn save_last_gua_prefix(&self, prefix: Option<Ipv6Addr>) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let pg_gua = prefix.map(|v6| PgInet::from(IpAddr::V6(v6)));
            sqlx::query(
                "INSERT INTO ra.state (id, last_gua, updated_at) \
                 VALUES (1, $1, NOW()) \
                 ON CONFLICT (id) DO UPDATE SET last_gua = EXCLUDED.last_gua, updated_at = NOW()",
            )
            .bind(pg_gua)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;

            Ok(())
        })
    }
}

impl PppoeConfigStore for PostgresDatabase {
    fn load_pppoe_config(&self) -> BoxFuture<'_, Result<Option<PppoeConfig>, DbError>> {
        Box::pin(async move {
            use sqlx::Row;
            let row = sqlx::query(
                "SELECT enabled, wan_iface, username, password, auth, mru, lcp_echo_interval_secs, \
                 lcp_echo_max_failures, reconnect_delay_secs, nft_enabled, nft_table_name, \
                 nft_flow_offload, nft_mss_clamping, nft_bypass_dns, nft_bypass_vowifi, nft_custom_rules_file \
                 FROM pppoe.config WHERE id = 1"
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;

            if let Some(r) = row {
                let enabled: bool = r.try_get("enabled").map_err(map_err)?;
                let wan_iface: String = r.try_get("wan_iface").map_err(map_err)?;
                let username: String = r.try_get("username").map_err(map_err)?;
                let password: String = r.try_get("password").map_err(map_err)?;
                let auth_raw: String = r.try_get("auth").map_err(map_err)?;
                let mru: i32 = r.try_get("mru").map_err(map_err)?;
                let lcp_echo_interval_secs: i64 =
                    r.try_get("lcp_echo_interval_secs").map_err(map_err)?;
                let lcp_echo_max_failures: i32 =
                    r.try_get("lcp_echo_max_failures").map_err(map_err)?;
                let reconnect_delay_secs: i64 =
                    r.try_get("reconnect_delay_secs").map_err(map_err)?;

                let nft_enabled: bool = r.try_get("nft_enabled").unwrap_or(true);
                let nft_table_name: String = r
                    .try_get("nft_table_name")
                    .unwrap_or_else(|_| "lanforge".into());
                let nft_flow_offload: bool = r.try_get("nft_flow_offload").unwrap_or(true);
                let nft_mss_clamping: bool = r.try_get("nft_mss_clamping").unwrap_or(true);
                let nft_bypass_dns: bool = r.try_get("nft_bypass_dns").unwrap_or(true);
                let nft_bypass_vowifi: bool = r.try_get("nft_bypass_vowifi").unwrap_or(true);
                let nft_masquerade: bool = r.try_get("nft_masquerade").unwrap_or(true);
                let nft_custom_rules_file: Option<String> =
                    r.try_get("nft_custom_rules_file").ok().flatten();

                let service_name: Option<String> = r.try_get("service_name").ok().flatten();
                let ac_name: Option<String> = r.try_get("ac_name").ok().flatten();

                let send_padt_on_shutdown: bool =
                    r.try_get("send_padt_on_shutdown").unwrap_or(true);
                let discovery_padi_retries: u32 = r
                    .try_get("discovery_padi_retries")
                    .map(|v: i32| u32::try_from(v).unwrap_or(5))
                    .unwrap_or(5);
                let discovery_padi_timeout_secs: u64 = r
                    .try_get("discovery_padi_timeout_secs")
                    .map(|v: i64| u64::try_from(v).unwrap_or(3))
                    .unwrap_or(3);

                let auth = auth_raw
                    .parse::<AuthMethod>()
                    .unwrap_or(AuthMethod::ChapMd5);
                Ok(Some(PppoeConfig {
                    enabled,
                    wan_iface,
                    username,
                    password,
                    service_name,
                    ac_name,
                    auth,
                    mru: mru as u16,
                    lcp_echo_interval_secs: lcp_echo_interval_secs as u64,
                    lcp_echo_max_failures: lcp_echo_max_failures as u32,
                    reconnect_delay_secs: reconnect_delay_secs as u64,
                    send_padt_on_shutdown,
                    discovery_padi_retries,
                    discovery_padi_timeout_secs,
                    nftables: PppoeNftablesConfig {
                        enabled: nft_enabled,
                        table_name: nft_table_name,
                        flow_offload: nft_flow_offload,
                        mss_clamping: nft_mss_clamping,
                        bypass_dns: nft_bypass_dns,
                        bypass_vowifi: nft_bypass_vowifi,
                        masquerade: nft_masquerade,
                        custom_rules_file: nft_custom_rules_file,
                    },
                }))
            } else {
                Ok(None)
            }
        })
    }

    fn save_pppoe_config<'a>(&'a self, cfg: &'a PppoeConfig) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            let auth_str = cfg.auth.to_string();
            let mru = i32::from(cfg.mru);
            let echo_interval = cfg.lcp_echo_interval_secs as i64;
            let echo_max_failures = cfg.lcp_echo_max_failures as i32;
            let reconnect_delay = cfg.reconnect_delay_secs as i64;
            let padi_retries = cfg.discovery_padi_retries as i32;
            let padi_timeout = cfg.discovery_padi_timeout_secs as i64;

            sqlx::query(
                "INSERT INTO pppoe.config (id, enabled, wan_iface, username, password, auth, mru, \
                 lcp_echo_interval_secs, lcp_echo_max_failures, reconnect_delay_secs, \
                 send_padt_on_shutdown, discovery_padi_retries, discovery_padi_timeout_secs, \
                 nft_enabled, nft_table_name, nft_flow_offload, nft_mss_clamping, \
                 nft_bypass_dns, nft_bypass_vowifi, nft_custom_rules_file)
                 VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                 ON CONFLICT (id) DO UPDATE SET
                   enabled = EXCLUDED.enabled,
                   wan_iface = EXCLUDED.wan_iface,
                   username = EXCLUDED.username,
                   password = EXCLUDED.password,
                   auth = EXCLUDED.auth,
                   mru = EXCLUDED.mru,
                   lcp_echo_interval_secs = EXCLUDED.lcp_echo_interval_secs,
                   lcp_echo_max_failures = EXCLUDED.lcp_echo_max_failures,
                   reconnect_delay_secs = EXCLUDED.reconnect_delay_secs,
                   send_padt_on_shutdown = EXCLUDED.send_padt_on_shutdown,
                   discovery_padi_retries = EXCLUDED.discovery_padi_retries,
                   discovery_padi_timeout_secs = EXCLUDED.discovery_padi_timeout_secs,
                   nft_enabled = EXCLUDED.nft_enabled,
                   nft_table_name = EXCLUDED.nft_table_name,
                   nft_flow_offload = EXCLUDED.nft_flow_offload,
                   nft_mss_clamping = EXCLUDED.nft_mss_clamping,
                   nft_bypass_dns = EXCLUDED.nft_bypass_dns,
                   nft_bypass_vowifi = EXCLUDED.nft_bypass_vowifi,
                   nft_custom_rules_file = EXCLUDED.nft_custom_rules_file",
            )
            .bind(cfg.enabled)
            .bind(&cfg.wan_iface)
            .bind(&cfg.username)
            .bind(&cfg.password)
            .bind(&auth_str)
            .bind(mru)
            .bind(echo_interval)
            .bind(echo_max_failures)
            .bind(reconnect_delay)
            .bind(cfg.send_padt_on_shutdown)
            .bind(padi_retries)
            .bind(padi_timeout)
            .bind(cfg.nftables.enabled)
            .bind(&cfg.nftables.table_name)
            .bind(cfg.nftables.flow_offload)
            .bind(cfg.nftables.mss_clamping)
            .bind(cfg.nftables.bypass_dns)
            .bind(cfg.nftables.bypass_vowifi)
            .bind(&cfg.nftables.custom_rules_file)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;

            Ok(())
        })
    }
}

impl UserStore for PostgresDatabase {
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        password_hash: &'a str,
        role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<UserEntry, DbError>> {
        Box::pin(async move {
            let row = sqlx::query(
                "INSERT INTO auth.users (username, password_hash, role, created_at, updated_at) \
                 VALUES ($1, $2, $3::auth.user_role_t, to_timestamp($4), to_timestamp($4)) \
                 RETURNING id::BIGINT AS id, username, password_hash, role::text AS role, \
                           EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, \
                           EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, \
                           EXTRACT(EPOCH FROM last_login)::BIGINT AS last_login",
            )
            .bind(username)
            .bind(password_hash)
            .bind(role)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(map_err)?;

            Ok(UserEntry {
                id: row.try_get("id").map_err(map_err)?,
                username: row.try_get("username").map_err(map_err)?,
                password_hash: row.try_get("password_hash").map_err(map_err)?,
                role: row.try_get("role").map_err(map_err)?,
                created_at: row.try_get("created_at").map_err(map_err)?,
                updated_at: row.try_get("updated_at").map_err(map_err)?,
                last_login: row.try_get("last_login").map_err(map_err)?,
            })
        })
    }

    fn get_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id::BIGINT AS id, username, password_hash, role::text AS role, \
                        EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, \
                        EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, \
                        EXTRACT(EPOCH FROM last_login)::BIGINT AS last_login \
                 FROM auth.users WHERE username = $1",
            )
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;

            row.map(|r| {
                Ok(UserEntry {
                    id: r.try_get("id").map_err(map_err)?,
                    username: r.try_get("username").map_err(map_err)?,
                    password_hash: r.try_get("password_hash").map_err(map_err)?,
                    role: r.try_get("role").map_err(map_err)?,
                    created_at: r.try_get("created_at").map_err(map_err)?,
                    updated_at: r.try_get("updated_at").map_err(map_err)?,
                    last_login: r.try_get("last_login").map_err(map_err)?,
                })
            })
            .transpose()
        })
    }

    fn get_user_by_id(&self, id: i64) -> BoxFuture<'_, Result<Option<UserEntry>, DbError>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT id::BIGINT AS id, username, password_hash, role::text AS role, \
                        EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, \
                        EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, \
                        EXTRACT(EPOCH FROM last_login)::BIGINT AS last_login \
                 FROM auth.users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_err)?;

            row.map(|r| {
                Ok(UserEntry {
                    id: r.try_get("id").map_err(map_err)?,
                    username: r.try_get("username").map_err(map_err)?,
                    password_hash: r.try_get("password_hash").map_err(map_err)?,
                    role: r.try_get("role").map_err(map_err)?,
                    created_at: r.try_get("created_at").map_err(map_err)?,
                    updated_at: r.try_get("updated_at").map_err(map_err)?,
                    last_login: r.try_get("last_login").map_err(map_err)?,
                })
            })
            .transpose()
        })
    }

    fn list_users(&self) -> BoxFuture<'_, Result<Vec<UserEntry>, DbError>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT id::BIGINT AS id, username, password_hash, role::text AS role, \
                        EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, \
                        EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, \
                        EXTRACT(EPOCH FROM last_login)::BIGINT AS last_login \
                 FROM auth.users ORDER BY id ASC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;

            rows.into_iter()
                .map(|r| {
                    Ok(UserEntry {
                        id: r.try_get("id").map_err(map_err)?,
                        username: r.try_get("username").map_err(map_err)?,
                        password_hash: r.try_get("password_hash").map_err(map_err)?,
                        role: r.try_get("role").map_err(map_err)?,
                        created_at: r.try_get("created_at").map_err(map_err)?,
                        updated_at: r.try_get("updated_at").map_err(map_err)?,
                        last_login: r.try_get("last_login").map_err(map_err)?,
                    })
                })
                .collect()
        })
    }

    fn update_user_password<'a>(
        &'a self,
        username: &'a str,
        new_hash: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE auth.users SET password_hash = $1, updated_at = to_timestamp($2) WHERE username = $3",
            )
            .bind(new_hash)
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;

            Ok(())
        })
    }

    fn update_user_role<'a>(
        &'a self,
        username: &'a str,
        new_role: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE auth.users SET role = $1::auth.user_role_t, updated_at = to_timestamp($2) WHERE username = $3",
            )
            .bind(new_role)
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;

            Ok(())
        })
    }

    fn update_user_last_login<'a>(
        &'a self,
        username: &'a str,
        now: i64,
    ) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            sqlx::query("UPDATE auth.users SET last_login = to_timestamp($1) WHERE username = $2")
                .bind(now)
                .bind(username)
                .execute(&self.pool)
                .await
                .map_err(map_err)?;

            Ok(())
        })
    }

    fn delete_user<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<(), DbError>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM auth.users WHERE username = $1")
                .bind(username)
                .execute(&self.pool)
                .await
                .map_err(map_err)?;

            Ok(())
        })
    }

    fn count_users(&self) -> BoxFuture<'_, Result<i64, DbError>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT COUNT(*) FROM auth.users")
                .fetch_one(&self.pool)
                .await
                .map_err(map_err)?;

            let count: i64 = row.try_get(0).map_err(map_err)?;
            Ok(count)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_pg_str_removes_null_bytes() {
        assert_eq!(sanitize_pg_str("device\0"), "device");
        assert_eq!(sanitize_pg_str("my\0host\0name"), "myhostname");
        assert_eq!(sanitize_pg_str("\0\0\0"), "");
    }
}
