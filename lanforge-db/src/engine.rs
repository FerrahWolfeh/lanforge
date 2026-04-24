//! `LeaseDb` — Synchronous `SQLite` engine for `DeviceTable` persistence.
//!
//! Responsible for schema management, migrations, atomic saves (`UPSERT`),
//! and state reconstruction during loading.
//!
//! ## Schema
//!
//! The database consists of the following tables:
//!
//! | Table | Purpose |
//! | :--- | :--- |
//! | `devices` | Core device identity (`MAC`, `hostname`, `origin`, `DUID`) |
//! | `v4_leases` | Active `DHCPv4` leases (1 per `MAC`) |
//! | `v6_leases` | Active `DHCPv6` `IA_NA` leases (multiple per `MAC` via `IAID`) |
//! | `v6_prefixes` | Delegated `IA_PD` prefixes (multiple per `MAC` via `IAID`) |
//! | `slaac_addrs` | `SLAAC`-configured `IPv6` addresses (multiple per `MAC`) |
//! | `seen_v4` | `IPv4` addresses observed via `ARP`/`netlink` (multiple per `MAC`) |
//! | `lease_history` | Audit trail for lease events (assigned, renewed, released, expired) |
//!
//! All child tables use `ON DELETE CASCADE` so that deleting a device
//! automatically removes all associated leases, prefixes, and addresses.
//!
//! ## Write Strategy
//!
//! `save_table()` uses a **clear-then-insert** pattern inside a single transaction:
//! 1. Snapshot all existing MACs from the database
//! 2. UPSERT every device currently in memory
//! 3. DELETE any MACs that are no longer in memory (cascades to children)
//!
//! `upsert_device_internal()` uses DELETE + INSERT for child tables rather than
//! diff logic — this simplifies the code and naturally handles lease expirations.
//!
//! ## Migrations
//!
//! Three migrations are defined (via `rusqlite_migration`):
//!
//! 1. **v1** — Full schema (drop & recreate legacy tables, create all 6 tables)
//! 2. **v2** — `lease_history` table with indexes on `mac` and `timestamp`
//! 3. **v3** — `vendor` column added to `devices` (reserved for manufacturer lookup)
//!
//! ## `SQLite` Configuration
//!
//! | PRAGMA | Value | Rationale |
//! | :--- | :--- | :--- |
//! | `journal_mode` | `WAL` | Writes are append-only; reduces SD card wear |
//! | `synchronous` | `NORMAL` | Safe for SD cards in WAL mode; crash-consistent |
//! | `foreign_keys` | `ON` | Enables CASCADE deletes |

use rusqlite::{Connection, params};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::result::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

use lanforge_core::device::{
    Device, Hostname, HostnameOrigin, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin,
};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::State;
use lanforge_core::state::{DeviceUpdate, StaticEntry};

use crate::LeaseDbError;

// ---------------------------------------------------------------------------
// LeaseDb
// ---------------------------------------------------------------------------

use rusqlite_migration::{M, Migrations};

// ---------------------------------------------------------------------------
// Internal DB Row Models
// ---------------------------------------------------------------------------

/// Internal representation of a device row read from the `devices` table.
///
/// Used during `load_table()` to deserialize stored devices.
struct DeviceRow {
    mac: String,
    hostname: String,
    hostname_origin: i32,
    is_static: bool,
    duid: Option<Vec<u8>>,
    last_seen: i64,
    origin: String,
    managed_at: Option<i64>,
    v4_static: Option<String>,
    v6_suffix: Option<String>,
}

/// A handle to the `SQLite` database for network leases and devices.
///
/// `LeaseDb` manages synchronous I/O operations for persistent state.
/// It uses Write-Ahead Logging (WAL) mode to improve concurrency on
/// embedded systems like the Raspberry Pi.
///
/// # Key Operations
///
/// - **`open(path)`** — Opens or creates the database, runs migrations
/// - **`save_table(state)`** — Persists the entire `State` atomically
/// - **`load_table()`** — Reconstructs a `State` from disk
/// - **`upsert_device(device)`** — Persists a single device
/// - **`remove_device(mac)`** — Deletes a device and all child rows (CASCADE)
/// - **`vacuum()`** — Reclaims disk space from deleted entries
/// - **`prune_zombies()`** — Removes dynamic devices with no leases or traffic
pub struct LeaseDb {
    /// The underlying `SQLite` connection.
    pub conn: Connection,
}

/// Opens (or creates) the `SQLite` database at the specified path and runs migrations.
///
/// Ensures the parent directory exists (creating it if necessary), then opens
/// the database in WAL mode with `synchronous=NORMAL` and foreign keys enabled.
///
/// # Errors
///
/// Returns [`LeaseDbError::PathAccess`] if the parent directory cannot be created,
/// [`LeaseDbError::ConnectionOpen`] if `SQLite` fails to open, or
/// [`LeaseDbError::Migration`] if schema migrations fail.
impl LeaseDb {
    /// Opens (or creates) the `SQLite` database at the specified path and runs migrations.
    pub fn open(path: &Path) -> Result<Self, LeaseDbError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| LeaseDbError::PathAccess(parent.to_path_buf(), e))?;
        }

        let mut conn = Connection::open(path)
            .map_err(|e| LeaseDbError::ConnectionOpen(path.to_path_buf(), e))?;

        // WAL mode — writes don't block reads; NORMAL is safe for SD cards.
        // Enable foreign keys for CASCADE support.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;",
        )?;

        let migrations = Self::get_migrations();
        migrations
            .to_latest(&mut conn)
            .map_err(|e| LeaseDbError::Migration("applying migrations".into(), e.to_string()))?;

        info!("SQLite database opened at {}", path.display());
        Ok(Self { conn })
    }

    /// Creates an in-memory database — exclusively for unit tests.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, LeaseDbError> {
        let mut conn = Connection::open_in_memory()?;
        conn.execute("PRAGMA foreign_keys=ON;", [])?;

        let migrations = Self::get_migrations();
        migrations
            .to_latest(&mut conn)
            .map_err(|e| LeaseDbError::Migration("memory migrations".into(), e.to_string()))?;

        Ok(Self { conn })
    }

    fn get_migrations() -> Migrations<'static> {
        Migrations::new(vec![
            M::up(
                "DROP TABLE IF EXISTS seen_v4;
             DROP TABLE IF EXISTS slaac_addrs;
             DROP TABLE IF EXISTS v6_prefixes;
             DROP TABLE IF EXISTS v6_leases;
             DROP TABLE IF EXISTS v4_leases;
             DROP TABLE IF EXISTS devices;

             CREATE TABLE devices (
                mac             TEXT PRIMARY KEY,
                hostname        TEXT NOT NULL,
                hostname_origin INTEGER NOT NULL DEFAULT 0,
                is_static       INTEGER NOT NULL,
                duid            BLOB,
                last_seen       INTEGER NOT NULL,
                origin          TEXT NOT NULL DEFAULT 'dynamic',
                managed_at      INTEGER,
                v4_static       TEXT,
                v6_suffix       TEXT
             );

             CREATE TABLE v4_leases (
                mac     TEXT PRIMARY KEY REFERENCES devices(mac) ON DELETE CASCADE,
                ip      TEXT NOT NULL,
                expires INTEGER NOT NULL
             );

             CREATE TABLE v6_leases (
                mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
                iaid    INTEGER NOT NULL,
                ip      TEXT NOT NULL,
                expires INTEGER NOT NULL,
                PRIMARY KEY (mac, iaid)
             );

             CREATE TABLE v6_prefixes (
                mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
                iaid    INTEGER NOT NULL,
                prefix  TEXT NOT NULL,
                len     INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                PRIMARY KEY (mac, iaid)
             );

             CREATE TABLE slaac_addrs (
                mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
                ip      TEXT NOT NULL,
                PRIMARY KEY (mac, ip)
             );

             CREATE TABLE seen_v4 (
                mac     TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
                ip      TEXT NOT NULL,
                PRIMARY KEY (mac, ip)
             );",
            ),
            M::up(
                "CREATE TABLE lease_history (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                mac        TEXT NOT NULL,
                ip         TEXT NOT NULL,
                lease_type TEXT NOT NULL,
                action     TEXT NOT NULL,
                timestamp  INTEGER NOT NULL
             );
             CREATE INDEX idx_lease_history_mac ON lease_history(mac);
             CREATE INDEX idx_lease_history_timestamp ON lease_history(timestamp);",
            ),
            M::up("ALTER TABLE devices ADD COLUMN vendor TEXT;"),
        ])
    }

    // -----------------------------------------------------------------------
    // Save — Snapshot with UPSERT & CASCADE
    // -----------------------------------------------------------------------

    /// Persists the current state of the `DeviceTable` using structured updates.
    ///
    /// Uses SQL UPSERT for devices and relies on `ON DELETE CASCADE` for child tables.
    ///
    /// # Process
    ///
    /// 1. Snapshots all MAC strings currently in the database
    /// 2. UPSERTs every device from memory (INSERT ... ON CONFLICT DO UPDATE)
    /// 3. DELETEs any MACs from the database that no longer exist in memory
    ///    (this cascades to child tables: `v4_leases`, `v6_leases`, `v6_prefixes`,
    ///    `slaac_addrs`, `seen_v4`)
    ///
    /// All steps run inside a single transaction for atomicity.
    pub fn save_table(&self, table: &State) -> Result<(), LeaseDbError> {
        let tx = self.conn.unchecked_transaction()?;

        // 1. Snapshot all MAC strings to detect removals later
        let mut stmt = tx.prepare("SELECT mac FROM devices")?;
        let db_macs: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .collect();
        drop(stmt);

        // 2. Upsert current devices from memory
        for device in table.devices() {
            Self::upsert_device_internal(&tx, &device)?;
        }

        // 3. Remove devices that no longer exist in memory (Cascades automatically)
        for db_mac in db_macs {
            if !table.devices().any(|d| d.mac.to_string() == db_mac) {
                tx.execute("DELETE FROM devices WHERE mac = ?1", params![&db_mac])?;
            }
        }

        tx.commit().map_err(LeaseDbError::TransactionFailed)?;
        debug!("State persisted successfully");
        Ok(())
    }

    /// Persists a single device's state to the database atomically.
    ///
    /// Uses an UPSERT (INSERT ... ON CONFLICT DO UPDATE) for the `devices` table
    /// and clears + re-inserts all child table rows for this MAC.
    pub fn upsert_device(&self, device: &Device) -> Result<(), LeaseDbError> {
        Self::upsert_device_internal(&self.conn, device)
    }

    /// Batches multiple device upserts into a single transaction.
    ///
    /// More efficient than calling [`upsert_device`](Self::upsert_device) repeatedly,
    /// as all writes share one transaction.
    pub fn upsert_many<'a, I>(&self, devices: I) -> Result<(), LeaseDbError>
    where
        I: IntoIterator<Item = &'a Device>,
    {
        let tx = self.conn.unchecked_transaction()?;
        for device in devices {
            Self::upsert_device_internal(&tx, device)?;
        }
        tx.commit().map_err(LeaseDbError::TransactionFailed)?;
        Ok(())
    }

    /// Shared internal logic for upserting a device.
    /// Works with both raw Connections and Transactions.
    fn upsert_device_internal(conn: &Connection, device: &Device) -> Result<(), LeaseDbError> {
        let mac_str = device.mac.to_string();
        let row = DeviceRow {
            mac: mac_str.clone(),
            hostname: device.hostname.name.clone(),
            hostname_origin: device.hostname.origin as i32,
            is_static: device.is_static(),
            duid: device.duid.as_ref().map(|d| d.bytes.to_vec()),
            last_seen: system_time_to_unix(device.last_seen),
            origin: device.origin.as_str().to_string(),
            managed_at: device.managed_at.map(system_time_to_unix),
            v4_static: match &device.v4 {
                IPv4State::Static(ip) => Some(ip.to_string()),
                _ => None,
            },
            v6_suffix: device.v6.iter().find_map(|s| {
                if let IPv6State::Static(suf) = s {
                    Some(suf.to_string())
                } else {
                    None
                }
            }),
        };

        conn.execute(
            "INSERT INTO devices (mac, hostname, hostname_origin, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(mac) DO UPDATE SET
                hostname = excluded.hostname,
                hostname_origin = excluded.hostname_origin,
                is_static = excluded.is_static,
                duid = excluded.duid,
                last_seen = excluded.last_seen,
                origin = excluded.origin,
                managed_at = excluded.managed_at,
                v4_static = excluded.v4_static,
                v6_suffix = excluded.v6_suffix",
            params![
                row.mac,
                row.hostname,
                row.hostname_origin,
                i32::from(row.is_static),
                row.duid,
                row.last_seen,
                row.origin,
                row.managed_at,
                row.v4_static,
                row.v6_suffix,
            ],
        )?;

        // Atomic clear and re-populate child tables for this MAC
        conn.execute("DELETE FROM v4_leases WHERE mac = ?1", params![&mac_str])?;
        if let IPv4State::Dynamic(lease) = &device.v4 {
            conn.execute(
                "INSERT INTO v4_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                params![
                    mac_str,
                    lease.ip.to_string(),
                    system_time_to_unix(lease.expires)
                ],
            )?;
        }

        conn.execute("DELETE FROM v6_leases WHERE mac = ?1", params![&mac_str])?;
        for state in &device.v6 {
            if let IPv6State::Dynamic(lease) = state {
                conn.execute(
                    "INSERT INTO v6_leases (mac, iaid, ip, expires) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        mac_str,
                        lease.iaid,
                        lease.ip.to_string(),
                        system_time_to_unix(lease.expires)
                    ],
                )?;
            }
        }

        conn.execute("DELETE FROM v6_prefixes WHERE mac = ?1", params![&mac_str])?;
        for prefix in &device.v6_prefixes {
            conn.execute(
                "INSERT INTO v6_prefixes (mac, iaid, prefix, len, expires) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    mac_str,
                    prefix.iaid,
                    prefix.prefix.to_string(),
                    prefix.len,
                    system_time_to_unix(prefix.expires)
                ],
            )?;
        }

        conn.execute("DELETE FROM slaac_addrs WHERE mac = ?1", params![&mac_str])?;
        for state in &device.v6 {
            if let IPv6State::Slaac(ip) = state {
                conn.execute(
                    "INSERT INTO slaac_addrs (mac, ip) VALUES (?1, ?2)",
                    params![mac_str, ip.to_string()],
                )?;
            }
        }

        conn.execute("DELETE FROM seen_v4 WHERE mac = ?1", params![&mac_str])?;
        for ip in &device.seen_v4 {
            conn.execute(
                "INSERT INTO seen_v4 (mac, ip) VALUES (?1, ?2)",
                params![mac_str, ip.to_string()],
            )?;
        }

        Ok(())
    }

    /// Explicitly removes a device from the database by its MAC address.
    ///
    /// Triggers `ON DELETE CASCADE`, automatically removing all associated rows
    /// in `v4_leases`, `v6_leases`, `v6_prefixes`, `slaac_addrs`, and `seen_v4`.
    pub fn remove_device(&self, mac: MacAddr) -> Result<(), LeaseDbError> {
        let mac_str = mac.to_string();
        self.conn
            .execute("DELETE FROM devices WHERE mac = ?1", params![mac_str])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Load — Reconstructs State
    // -----------------------------------------------------------------------

    /// Loads the persisted state and returns a fully populated `State`.
    ///
    /// Reads all tables in sequence: `devices` → `v4_leases` → `v6_leases` →
    /// `v6_prefixes` → `slaac_addrs` → `seen_v4`, reconstructing each device
    /// and applying `DeviceUpdate` events for leases and addresses.
    ///
    /// Invalid rows (e.g., unparseable MACs or IPs) are silently skipped
    /// to tolerate partial corruption or migration artifacts.
    pub fn load_table(&self) -> Result<State, LeaseDbError> {
        let mut table = State::new();

        // 1. Load base devices
        let mut stmt = self.conn.prepare(
            "SELECT mac, hostname, hostname_origin, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix FROM devices"
        )?;

        let rows: Vec<DeviceRow> = stmt
            .query_map([], |row| {
                Ok(DeviceRow {
                    mac: row.get(0)?,
                    hostname: row.get(1)?,
                    hostname_origin: row.get(2)?,
                    is_static: row.get::<_, i32>(3)? != 0,
                    duid: row.get(4)?,
                    last_seen: row.get(5)?,
                    origin: row.get(6)?,
                    managed_at: row.get(7)?,
                    v4_static: row.get(8)?,
                    v6_suffix: row.get(9)?,
                })
            })?
            .filter_map(Result::ok)
            .collect();
        drop(stmt);

        for row in rows {
            let Some(mac) = MacAddr::parse(&row.mac) else {
                continue;
            };

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

            // Restore DUID if it was persisted
            if let Some(bytes) = &row.duid {
                device.duid = Some(Duid::new(bytes.clone()));
            }

            // Restore static entries for CLI-managed devices
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

        // 2. V4 leases
        let mut stmt = self
            .conn
            .prepare("SELECT mac, ip, expires FROM v4_leases")?;
        let v4_rows: Vec<(String, String, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(Result::ok)
            .collect();

        for (mac_str, ip_str, expires_unix) in v4_rows {
            if let Some(mac) = MacAddr::parse(&mac_str)
                && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
            {
                table.apply_update(DeviceUpdate::V4LeaseGranted {
                    mac,
                    ip,
                    expires: unix_to_system_time(expires_unix),
                });
            }
        }

        // 3. V6 leases
        let mut stmt = self
            .conn
            .prepare("SELECT mac, iaid, ip, expires FROM v6_leases")?;
        let v6_rows: Vec<(String, u32, String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(Result::ok)
            .collect();

        for (mac_str, iaid, ip_str, expires_unix) in v6_rows {
            if let Some(mac) = MacAddr::parse(&mac_str)
                && let Ok(ip) = ip_str.parse::<Ipv6Addr>()
            {
                let duid = table
                    .get_duid_by_mac(mac)
                    .cloned()
                    .unwrap_or_else(|| Duid::new(vec![]));
                table.apply_update(DeviceUpdate::V6LeaseGranted {
                    mac: Some(mac),
                    duid,
                    iaid,
                    ip,
                    expires: unix_to_system_time(expires_unix),
                });
            }
        }

        // 4. V6 prefixes
        let mut stmt = self
            .conn
            .prepare("SELECT mac, iaid, prefix, len, expires FROM v6_prefixes")?;
        let px_rows: Vec<(String, u32, String, u8, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .filter_map(Result::ok)
            .collect();

        for (mac_str, iaid, prefix_str, len, expires_unix) in px_rows {
            if let Some(mac) = MacAddr::parse(&mac_str)
                && let Ok(prefix) = prefix_str.parse::<Ipv6Addr>()
            {
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
                    expires: unix_to_system_time(expires_unix),
                });
            }
        }

        // 5. SLAAC & Seen V4
        let mut stmt = self.conn.prepare("SELECT mac, ip FROM slaac_addrs")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(Result::ok)
            .collect();
        for (m, i) in rows {
            if let Some(mac) = MacAddr::parse(&m)
                && let Ok(ip) = i.parse::<Ipv6Addr>()
            {
                table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });
            }
        }

        let mut stmt = self.conn.prepare("SELECT mac, ip FROM seen_v4")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(Result::ok)
            .collect();
        for (m, i) in rows {
            if let Some(mac) = MacAddr::parse(&m)
                && let Ok(ip) = i.parse::<Ipv4Addr>()
            {
                table.apply_update(DeviceUpdate::ArpSeen { mac, ip });
            }
        }

        info!("Loaded devices from SQLite");
        Ok(table)
    }

    /// Executes the `SQLite` `VACUUM` command to rebuild the database file,
    /// reclaiming space from deleted entries and defragmenting pages.
    ///
    /// This is an expensive operation that rewrites the entire database file.
    /// It should be run periodically during low-traffic windows.
    pub fn vacuum(&self) -> Result<(), LeaseDbError> {
        debug!("Running VACUUM on SQLite...");
        self.conn
            .execute("VACUUM", [])
            .map_err(LeaseDbError::VacuumFailed)?;
        Ok(())
    }

    /// Removes "zombie" entries from the database.
    ///
    /// A zombie is a `dynamic` device with:
    /// - No hostname
    /// - No active V4 or V6 leases
    /// - No delegated V6 prefixes
    /// - No SLAAC addresses
    /// - No observed ARP/IPv4 entries
    ///
    /// Returns the number of deleted rows.
    pub fn prune_zombies(&self) -> Result<usize, LeaseDbError> {
        debug!("[db] Pruning zombie entries...");
        let rows = self.conn.execute(
            "DELETE FROM devices
             WHERE origin = 'dynamic'
               AND hostname = ''
               AND mac NOT IN (SELECT mac FROM v4_leases)
               AND mac NOT IN (SELECT mac FROM v6_leases)
               AND mac NOT IN (SELECT mac FROM v6_prefixes)
               AND mac NOT IN (SELECT mac FROM slaac_addrs)
               AND mac NOT IN (SELECT mac FROM seen_v4)",
            [],
        )?;
        Ok(rows)
    }

    /// Records a lease-related event in the persistent `lease_history` table.
    pub fn record_lease_event(
        &self,
        mac: MacAddr,
        ip: &str,
        lease_type: &str,
        action: LeaseAction,
    ) -> Result<(), LeaseDbError> {
        let now = system_time_to_unix(SystemTime::now());
        self.conn.execute(
            "INSERT INTO lease_history (mac, ip, lease_type, action, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![mac.to_string(), ip, lease_type, action.as_str(), now],
        )?;
        Ok(())
    }

    /// Retrieves the lease history for a specific device.
    ///
    /// Returns up to 100 most recent entries, ordered newest-first.
    pub fn get_lease_history(&self, mac: MacAddr) -> Result<Vec<LeaseHistoryEntry>, LeaseDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, lease_type, action, timestamp FROM lease_history WHERE mac = ?1 ORDER BY timestamp DESC LIMIT 100"
        )?;

        let rows = stmt.query_map(params![mac.to_string()], |row| {
            Ok(LeaseHistoryEntry {
                ip: row.get(0)?,
                lease_type: row.get(1)?,
                action: row
                    .get::<_, String>(2)?
                    .parse()
                    .unwrap_or(LeaseAction::Assigned),
                timestamp: unix_to_system_time(row.get(3)?),
            })
        })?;

        let mut history = Vec::new();
        for row in rows {
            history.push(row?);
        }
        Ok(history)
    }
}

/// Represents the type of action taken on a lease.
///
/// Used in the `lease_history` table for audit and troubleshooting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseAction {
    /// A new lease was assigned to a device.
    #[default]
    Assigned,
    /// An existing lease was renewed (DHCP REQUEST/Renew).
    Renewed,
    /// A lease was explicitly released (DHCP RELEASE).
    Released,
    /// A lease expired naturally (timeout without renewal).
    Expired,
}

impl LeaseAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Renewed => "renewed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

impl std::str::FromStr for LeaseAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "assigned" => Ok(Self::Assigned),
            "renewed" => Ok(Self::Renewed),
            "released" => Ok(Self::Released),
            "expired" => Ok(Self::Expired),
            _ => Err(()),
        }
    }
}

/// A single entry in the lease history.
///
/// Returned by [`LeaseDb::get_lease_history`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaseHistoryEntry {
    /// The IP address involved in the event.
    pub ip: String,
    /// The type of lease (e.g., `"dhcpv4"`, `"dhcpv6"`, `"pd"`).
    pub lease_type: String,
    /// The action that was performed.
    pub action: LeaseAction,
    /// When the event occurred (UTC).
    pub timestamp: SystemTime,
}

impl Default for LeaseHistoryEntry {
    fn default() -> Self {
        Self {
            ip: String::new(),
            lease_type: String::new(),
            action: LeaseAction::Assigned,
            timestamp: UNIX_EPOCH,
        }
    }
}

// ---------------------------------------------------------------------------
// SystemTime <-> Unix timestamp conversion helpers
// ---------------------------------------------------------------------------

/// Converts a `SystemTime` to a Unix timestamp (seconds since epoch).
///
/// Returns `0` for times before the Unix epoch (1970-01-01).
pub(crate) fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

/// Converts a Unix timestamp (seconds since epoch) to `SystemTime`.
///
/// Returns `UNIX_EPOCH` for zero or negative values.
pub(crate) fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix > 0 {
        UNIX_EPOCH + Duration::from_secs(unix.cast_unsigned())
    } else {
        UNIX_EPOCH
    }
}
