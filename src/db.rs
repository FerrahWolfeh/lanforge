//! Persistência SQLite para a DeviceTable.
//!
//! Schema segue ARCHITECTURE.md: uma tabela por conceito (devices, v4_leases,
//! v6_leases, slaac_addrs). Todas as escritas são feitas dentro de uma única
//! transação para consistência.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::dhcp::v6::duid::Duid;
use crate::state::{DeviceTable, MacAddr, V4Lease, V6Lease};

// ---------------------------------------------------------------------------
// LeaseDb
// ---------------------------------------------------------------------------

type DeviceEntry = Vec<(String, String, bool, Option<Vec<u8>>, i64)>;

/// Handle para o banco SQLite de leases.
pub struct LeaseDb {
    conn: Connection,
}

impl LeaseDb {
    /// Abre (ou cria) o banco SQLite no path indicado e executa migrations.
    pub fn open(path: &Path) -> Result<Self> {
        // Cria diretórios pai se necessário
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("criando diretório para {}", path.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("abrindo SQLite em {}", path.display()))?;

        // WAL mode para escritas concorrentes e melhor performance em SD card
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        let db = LeaseDb { conn };
        db.create_tables()?;

        info!("[db] SQLite aberto em {}", path.display());
        Ok(db)
    }

    /// Cria o banco SQLite em memória (para testes).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = LeaseDb { conn };
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
                last_seen   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS v4_leases (
                mac         TEXT PRIMARY KEY REFERENCES devices(mac),
                ip          TEXT NOT NULL,
                expires     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS v6_leases (
                mac         TEXT PRIMARY KEY REFERENCES devices(mac),
                ip          TEXT NOT NULL,
                expires     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS slaac_addrs (
                mac         TEXT NOT NULL REFERENCES devices(mac),
                ip          TEXT NOT NULL,
                PRIMARY KEY (mac, ip)
            );
        ",
            )
            .context("[db] falha ao criar tabelas")?;

        debug!("[db] Schema verificado/criado");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Save — snapshot completo da DeviceTable
    // -----------------------------------------------------------------------

    /// Grava todos os dispositivos da DeviceTable no SQLite dentro de uma
    /// transação única. Usa INSERT OR REPLACE para simplificar.
    pub fn save_table(&self, table: &DeviceTable) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        // Limpa tabelas dependentes antes de popular
        tx.execute_batch(
            "DELETE FROM slaac_addrs; DELETE FROM v6_leases; DELETE FROM v4_leases; DELETE FROM devices;",
        )?;

        for device in table.devices() {
            let mac_str = device.mac.to_string();
            let last_seen = system_time_to_unix(device.last_seen);

            let duid_blob: Option<Vec<u8>> = device.duid.as_ref().map(|d| d.bytes.clone());

            tx.execute(
                "INSERT INTO devices (mac, hostname, is_static, duid, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![mac_str, device.hostname, device.is_static as i32, duid_blob, last_seen],
            )?;

            // V4 lease
            if let Some(v4) = &device.v4 {
                tx.execute(
                    "INSERT INTO v4_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v4.ip.to_string(), system_time_to_unix(v4.expires)],
                )?;
            }

            // V6 lease
            if let Some(v6) = &device.v6 {
                tx.execute(
                    "INSERT INTO v6_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v6.ip.to_string(), system_time_to_unix(v6.expires)],
                )?;
            }

            // SLAAC addresses
            for addr in &device.slaac {
                tx.execute(
                    "INSERT INTO slaac_addrs (mac, ip) VALUES (?1, ?2)",
                    params![mac_str, addr.to_string()],
                )?;
            }
        }

        tx.commit()?;
        debug!("[db] DeviceTable salva com sucesso");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Load — reconstrói DeviceTable do SQLite
    // -----------------------------------------------------------------------

    /// Carrega todos os dados do SQLite e retorna uma DeviceTable populada.
    /// Entradas estáticas *não* são carregadas do DB — serão carregadas do TOML
    /// separadamente e têm precedência.
    pub fn load_table(&self) -> Result<DeviceTable> {
        let mut table = DeviceTable::new();

        // 1. Carrega devices
        let mut stmt = self
            .conn
            .prepare("SELECT mac, hostname, is_static, duid, last_seen FROM devices")?;

        let devices: DeviceEntry = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i32>(2)? != 0,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (mac_str, hostname, is_static, duid_bytes, last_seen_unix) in &devices {
            let Some(mac) = MacAddr::parse(mac_str) else {
                warn!("[db] MAC inválido no DB: '{mac_str}', pulando");
                continue;
            };

            let dev = table.get_or_insert(mac);
            dev.hostname = hostname.clone();
            dev.is_static = *is_static;
            dev.last_seen = unix_to_system_time(*last_seen_unix);

            if let Some(bytes) = duid_bytes {
                let duid = Duid::new(bytes.clone());
                dev.duid = Some(duid.clone());
                // Also build the duid_index via set_duid
                // (we need to drop the mut ref first — use set_duid after)
            }
        }

        // Rebuild duid index
        for (mac_str, _, _, duid_bytes, _) in &devices {
            if let (Some(mac), Some(bytes)) = (MacAddr::parse(mac_str), duid_bytes) {
                table.set_duid(mac, Duid::new(bytes.clone()));
            }
        }

        // 2. Carrega v4 leases
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
            .filter_map(|r| r.ok())
            .collect();

        for (mac_str, ip_str, expires_unix) in v4_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
                warn!("[db] IPv4 inválido no DB: '{ip_str}'");
                continue;
            };
            let dev = table.get_or_insert(mac);
            dev.v4 = Some(V4Lease {
                ip,
                expires: unix_to_system_time(expires_unix),
            });
        }

        // 3. Carrega v6 leases
        let mut stmt = self
            .conn
            .prepare("SELECT mac, ip, expires FROM v6_leases")?;
        let v6_rows: Vec<(String, String, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (mac_str, ip_str, expires_unix) in v6_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv6Addr>() else {
                warn!("[db] IPv6 inválido no DB: '{ip_str}'");
                continue;
            };
            let dev = table.get_or_insert(mac);
            dev.v6 = Some(V6Lease {
                ip,
                expires: unix_to_system_time(expires_unix),
            });
        }

        // 4. Carrega SLAAC addresses
        let mut stmt = self.conn.prepare("SELECT mac, ip FROM slaac_addrs")?;
        let slaac_rows: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (mac_str, ip_str) in slaac_rows {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<Ipv6Addr>() else {
                continue;
            };
            table.record_slaac(mac, ip);
        }

        let count = table.devices().count();
        info!("[db] Carregados {count} dispositivos do SQLite");
        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// Helpers de conversão SystemTime <-> unix timestamp
// ---------------------------------------------------------------------------

fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix > 0 {
        UNIX_EPOCH + Duration::from_secs(unix as u64)
    } else {
        UNIX_EPOCH
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mac(last: u8) -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last])
    }

    #[test]
    fn create_and_load_empty() {
        let db = LeaseDb::open_in_memory().unwrap();
        let table = db.load_table().unwrap();
        assert_eq!(table.devices().count(), 0);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(1);
        let dev = table.get_or_insert(mac);
        dev.hostname = "TestDevice".into();
        dev.v4 = Some(V4Lease {
            ip: Ipv4Addr::new(192, 168, 0, 100),
            expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        });

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let loaded_dev = loaded.devices().next().unwrap();
        assert_eq!(loaded_dev.hostname, "TestDevice");
        assert_eq!(
            loaded_dev.v4.as_ref().unwrap().ip,
            Ipv4Addr::new(192, 168, 0, 100)
        );
    }

    #[test]
    fn handles_slaac_multiple_addrs() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(2);
        table.record_slaac(mac, "fd97:f00d:cafe:3731::1234".parse().unwrap());
        table.record_slaac(mac, "fd97:f00d:cafe:3731::5678".parse().unwrap());
        table.record_slaac(mac, "2001:db8::abcd".parse().unwrap());

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let loaded_dev = loaded.devices().next().unwrap();
        assert_eq!(loaded_dev.slaac.len(), 3);
    }

    #[test]
    fn handles_duid_persistence() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(3);
        let duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03,
        ]);

        let dev = table.get_or_insert(mac);
        dev.hostname = "DuidDevice".into();
        table.set_duid(mac, duid.clone());

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let loaded_dev = loaded.devices().next().unwrap();
        assert_eq!(loaded_dev.duid.as_ref().unwrap().bytes, duid.bytes);

        // Also verify DUID index works
        let found = loaded.find_by_duid(&duid);
        assert!(found.is_some());
        assert_eq!(found.unwrap().hostname, "DuidDevice");
    }

    #[test]
    fn handles_v6_lease() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(4);
        let dev = table.get_or_insert(mac);
        dev.hostname = "V6Device".into();
        dev.v6 = Some(V6Lease {
            ip: "fd97:f00d:cafe:3731::1057:cafe".parse().unwrap(),
            expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        });

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let loaded_dev = loaded.devices().next().unwrap();
        assert!(loaded_dev.v6.is_some());
        assert_eq!(
            loaded_dev.v6.as_ref().unwrap().ip,
            "fd97:f00d:cafe:3731::1057:cafe"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }

    #[test]
    fn save_overwrites_previous() {
        let db = LeaseDb::open_in_memory().unwrap();

        // Save first version
        let mut table = DeviceTable::new();
        let mac = make_mac(1);
        let dev = table.get_or_insert(mac);
        dev.hostname = "First".into();
        db.save_table(&table).unwrap();

        // Save second version with different hostname
        let mut table2 = DeviceTable::new();
        let dev = table2.get_or_insert(mac);
        dev.hostname = "Second".into();
        db.save_table(&table2).unwrap();

        let loaded = db.load_table().unwrap();
        let loaded_dev = loaded.devices().next().unwrap();
        assert_eq!(loaded_dev.hostname, "Second");
        assert_eq!(loaded.devices().count(), 1);
    }
}
