//! `LeaseDb` — motor SQLite síncrono para persistência da `DeviceTable`.
//!
//! Responsável pelo schema, migrations, save (UPSERT) e load (reconstrução).

use rusqlite::{Connection, params};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use lanforge_core::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::{DeviceUpdate, StaticEntry};

use crate::{LeaseDbError, Result};

// ---------------------------------------------------------------------------
// LeaseDb
// ---------------------------------------------------------------------------

type DevTableRow = (
    String,
    String,
    bool,
    Option<Vec<u8>>,
    i64,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
);

/// Handle para o banco `SQLite` de leases.
///
/// Responsável pelas operações síncronas de I/O no banco de dados.
/// Utiliza o modo WAL para permitir leituras simultâneas a escritas.
pub struct LeaseDb {
    pub conn: Connection,
}

impl LeaseDb {
    /// Abre (ou cria) o banco `SQLite` no path indicado e executa migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LeaseDbError::PathAccess(parent.to_path_buf(), e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| LeaseDbError::ConnectionOpen(path.to_path_buf(), e))?;

        // WAL mode — escritas não bloqueiam leituras; NORMAL é seguro pra SD card
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        let db = Self { conn };
        db.create_tables()?;

        debug!("SQLite aberto em {}", path.display());
        Ok(db)
    }

    /// Cria o banco em memória — exclusivo para testes.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS devices (
                    mac         TEXT PRIMARY KEY,
                    hostname    TEXT NOT NULL,
                    is_static   INTEGER NOT NULL,
                    duid        BLOB,
                    last_seen   INTEGER NOT NULL,
                    origin      TEXT NOT NULL DEFAULT 'dynamic',
                    managed_at  INTEGER,
                    v4_static   TEXT,
                    v6_suffix   TEXT
                );

                CREATE TABLE IF NOT EXISTS v4_leases (
                    mac         TEXT PRIMARY KEY REFERENCES devices(mac),
                    ip          TEXT NOT NULL,
                    expires     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS v6_leases (
                    mac         TEXT NOT NULL REFERENCES devices(mac),
                    iaid        INTEGER NOT NULL,
                    ip          TEXT NOT NULL,
                    expires     INTEGER NOT NULL,
                    PRIMARY KEY (mac, iaid)
                );

                CREATE TABLE IF NOT EXISTS v6_prefixes (
                    mac         TEXT NOT NULL REFERENCES devices(mac),
                    iaid        INTEGER NOT NULL,
                    prefix      TEXT NOT NULL,
                    len         INTEGER NOT NULL,
                    expires     INTEGER NOT NULL,
                    PRIMARY KEY (mac, iaid)
                );

                CREATE TABLE IF NOT EXISTS slaac_addrs (
                    mac         TEXT NOT NULL REFERENCES devices(mac),
                    ip          TEXT NOT NULL,
                    PRIMARY KEY (mac, ip)
                );

                CREATE TABLE IF NOT EXISTS seen_v4 (
                    mac         TEXT NOT NULL REFERENCES devices(mac),
                    ip          TEXT NOT NULL,
                    PRIMARY KEY (mac, ip)
                );
                ",
            )
            .map_err(|e| LeaseDbError::Migration("setup tables".to_string(), e))?;

        // Simple migrations without schema tracking
        let _ = self.conn.execute(
            "ALTER TABLE devices ADD COLUMN origin TEXT NOT NULL DEFAULT 'dynamic'",
            [],
        );
        let _ = self
            .conn
            .execute("ALTER TABLE devices ADD COLUMN managed_at INTEGER", []);
        let _ = self
            .conn
            .execute("ALTER TABLE devices ADD COLUMN v4_static TEXT", []);
        let _ = self
            .conn
            .execute("ALTER TABLE devices ADD COLUMN v6_suffix TEXT", []);
        let _ = self.conn.execute(
            "CREATE TABLE IF NOT EXISTS v6_prefixes (
                mac TEXT NOT NULL REFERENCES devices(mac),
                iaid INTEGER NOT NULL,
                prefix TEXT NOT NULL,
                len INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                PRIMARY KEY (mac, iaid)
            )",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE v6_leases ADD COLUMN iaid INTEGER DEFAULT 0",
            [],
        );

        debug!("Schema verificado/criado");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Save — snapshot com UPSERT (Delta)
    // -----------------------------------------------------------------------

    /// Grava o estado atual minimizando escritas.
    /// Usa UPSERT para dispositivos e limpa cirurgicamente devices removidos.
    pub fn save_table(&self, table: &DeviceTable) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        // 1. Inserir ou atualizar os dispositivos atuais (UPSERT)
        for device in table.devices() {
            let mac_str = device.mac.to_string();
            let last_seen = system_time_to_unix(device.last_seen);
            let duid_blob: Option<Vec<u8>> = device.duid.as_ref().map(|d| d.bytes.clone());
            let managed_at_unix: Option<i64> = device.managed_at.map(system_time_to_unix);

            let (v4_static_str, v4_lease) = match &device.v4 {
                IPv4State::Static(ip) => (Some(ip.to_string()), None),
                IPv4State::Dynamic(l) => (None, Some(l.clone())),
                IPv4State::None => (None, None),
            };

            let mut v6_static_str = None;
            let mut v6_leases = Vec::new();
            let mut slaac_addrs = Vec::new();

            for state in &device.v6 {
                match state {
                    IPv6State::Static(s) => v6_static_str = Some(s.to_string()),
                    IPv6State::Dynamic(l) => v6_leases.push(l.clone()),
                    IPv6State::Slaac(ip) => slaac_addrs.push(ip),
                }
            }

            // Tabela principal
            tx.execute(
                "INSERT INTO devices (mac, hostname, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(mac) DO UPDATE SET
                    hostname = excluded.hostname,
                    is_static = excluded.is_static,
                    duid = excluded.duid,
                    last_seen = excluded.last_seen,
                    origin = excluded.origin,
                    managed_at = excluded.managed_at,
                    v4_static = excluded.v4_static,
                    v6_suffix = excluded.v6_suffix",
                params![
                    mac_str,
                    device.hostname,
                    i32::from(device.is_static()),
                    duid_blob,
                    last_seen,
                    device.origin.as_str(),
                    managed_at_unix,
                    v4_static_str,
                    v6_static_str
                ],
            )?;

            // Tabelas filhas: delete + reinsert per-mac
            tx.execute("DELETE FROM v4_leases WHERE mac = ?1", params![&mac_str])?;
            if let Some(v4) = v4_lease {
                tx.execute(
                    "INSERT INTO v4_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v4.ip.to_string(), system_time_to_unix(v4.expires)],
                )?;
            }

            tx.execute("DELETE FROM v6_leases WHERE mac = ?1", params![&mac_str])?;
            for v6 in v6_leases {
                tx.execute(
                    "INSERT INTO v6_leases (mac, iaid, ip, expires) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        mac_str,
                        v6.iaid,
                        v6.ip.to_string(),
                        system_time_to_unix(v6.expires)
                    ],
                )?;
            }

            tx.execute("DELETE FROM v6_prefixes WHERE mac = ?1", params![&mac_str])?;
            for prefix in &device.v6_prefixes {
                tx.execute(
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

            tx.execute("DELETE FROM slaac_addrs WHERE mac = ?1", params![&mac_str])?;
            for addr in slaac_addrs {
                tx.execute(
                    "INSERT INTO slaac_addrs (mac, ip) VALUES (?1, ?2)",
                    params![mac_str, addr.to_string()],
                )?;
            }

            tx.execute("DELETE FROM seen_v4 WHERE mac = ?1", params![&mac_str])?;
            for addr in &device.seen_v4 {
                tx.execute(
                    "INSERT INTO seen_v4 (mac, ip) VALUES (?1, ?2)",
                    params![mac_str, addr.to_string()],
                )?;
            }
        }

        // 2. Limpeza cirúrgica (Deletar do DB os devices que expiraram da memória)
        let mut stmt = tx.prepare("SELECT mac FROM devices")?;
        let db_macs: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for db_mac in db_macs {
            if !table.devices().any(|d| d.mac.to_string() == db_mac) {
                tx.execute("DELETE FROM slaac_addrs WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM seen_v4 WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM v6_leases WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM v6_prefixes WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM v4_leases WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM devices WHERE mac = ?1", params![&db_mac])?;
            }
        }

        tx.commit().map_err(LeaseDbError::TransactionFailed)?;
        debug!("DeviceTable persistida com sucesso (Delta Update)");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Load — reconstrói DeviceTable via apply_update
    // -----------------------------------------------------------------------

    /// Carrega o estado persistido e devolve uma `DeviceTable` populada.
    pub fn load_table(&self) -> Result<DeviceTable> {
        let mut table = DeviceTable::new();

        // 1. Devices base
        let mut stmt = self
            .conn
            .prepare("SELECT mac, hostname, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix FROM devices")?;

        let rows: Vec<DevTableRow> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)? != 0,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)
                        .unwrap_or_else(|_| "dynamic".to_string()),
                    row.get::<_, Option<i64>>(6).unwrap_or(None),
                    row.get::<_, Option<String>>(7).unwrap_or(None),
                    row.get::<_, Option<String>>(8).unwrap_or(None),
                ))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (
            mac_str,
            hostname,
            _is_static,
            duid_bytes,
            last_seen_unix,
            origin_str,
            managed_at,
            v4_static_str,
            v6_suffix_str,
        ) in rows
        {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                warn!("MAC inválido no DB: '{mac_str}', pulando");
                continue;
            };

            let dev = table.get_or_insert(mac);
            if !hostname.is_empty() {
                dev.hostname = hostname;
            }
            dev.last_seen = unix_to_system_time(last_seen_unix);

            dev.origin = match origin_str.as_str() {
                "toml" => Origin::Toml,
                "cli" => Origin::Cli,
                _ => Origin::Dynamic,
            };
            dev.managed_at = managed_at.map(unix_to_system_time);

            if let Some(v4_str) = v4_static_str
                && let Ok(ip) = v4_str.parse::<Ipv4Addr>()
            {
                dev.v4 = IPv4State::Static(ip);
            }
            if let Some(v6_str) = v6_suffix_str
                && let Some(suf) = Ipv6AddrOrSuffix::parse(&v6_str)
            {
                dev.v6.push(IPv6State::Static(suf));
            }

            // Restaura DUID via apply_update — reconstrói o duid_index
            if let Some(bytes) = duid_bytes {
                table.apply_update(DeviceUpdate::DuidAssociated {
                    mac: Some(mac),
                    duid: Duid::new(bytes),
                    iaid: 0,
                });
            }

            // Reconstrói static_entries para devices CLI-managed
            // Sem isso, DHCP pools perdem reservas CLI após restart.
            if origin_str == "cli" {
                let dev = table.get_or_insert(mac);
                let hostname = dev.hostname.clone();
                let v4_ip = match dev.v4 {
                    IPv4State::Static(ip) => Some(ip),
                    _ => None,
                };
                let v6_suffix = dev.v6.iter().find_map(|s| {
                    if let IPv6State::Static(suffix) = s {
                        Some(suffix.clone())
                    } else {
                        None
                    }
                });

                table.add_static_entry(
                    mac,
                    StaticEntry {
                        mac,
                        hostname,
                        v4_ip,
                        v6_suffix,
                    },
                );
            }
        }

        // 2. V4 leases
        let mut stmt = self
            .conn
            .prepare("SELECT mac, ip, expires FROM v4_leases")?;

        let v4_rows: Vec<(String, String, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (mac_str, ip_str, expires_unix) in v4_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                warn!("IPv4 inválido no DB: '{ip_str}', pulando");
                continue;
            };
            table.apply_update(DeviceUpdate::V4LeaseGranted {
                mac,
                ip,
                expires: unix_to_system_time(expires_unix),
            });
        }

        // 3. V6 leases
        let mut stmt = self
            .conn
            .prepare("SELECT mac, iaid, ip, expires FROM v6_leases")?;

        let v6_rows: Vec<(String, u32, String, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (mac_str, iaid, ip_str, expires_unix) in v6_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv6Addr>() else {
                warn!("IPv6 inválido no DB: '{ip_str}', pulando");
                continue;
            };
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

        // 3.1 V6 prefixes
        let mut stmt = self
            .conn
            .prepare("SELECT mac, iaid, prefix, len, expires FROM v6_prefixes")?;

        let prefix_rows: Vec<(String, u32, String, u8, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u8>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (mac_str, iaid, prefix_str, len, expires_unix) in prefix_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(prefix) = prefix_str.parse::<Ipv6Addr>() else {
                warn!("Prefixo inválido no DB: '{prefix_str}', pulando");
                continue;
            };
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

        // 4. SLAAC addresses
        let mut stmt = self.conn.prepare("SELECT mac, ip FROM slaac_addrs")?;

        let slaac_rows: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (mac_str, ip_str) in slaac_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv6Addr>() else {
                continue;
            };
            table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });
        }

        // 5. Seen IPv4 addresses (saved but previously never loaded)
        let mut stmt = self.conn.prepare("SELECT mac, ip FROM seen_v4")?;

        let seen_rows: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (mac_str, ip_str) in seen_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                continue;
            };
            table.apply_update(DeviceUpdate::ArpSeen { mac, ip });
        }

        let count = table.devices().count();
        info!("Carregados {count} dispositivos do SQLite");
        Ok(table)
    }

    /// Executa o comando VACUUM para otimizar o arquivo do banco de dados.
    pub fn vacuum(&self) -> Result<()> {
        debug!("Executando VACUUM no SQLite...");
        self.conn
            .execute("VACUUM", [])
            .map_err(LeaseDbError::VacuumFailed)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers de conversão SystemTime <-> unix timestamp
// ---------------------------------------------------------------------------

pub(crate) fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().cast_signed())
        .unwrap_or(0)
}

pub(crate) fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix > 0 {
        UNIX_EPOCH + Duration::from_secs(unix.cast_unsigned())
    } else {
        UNIX_EPOCH
    }
}
