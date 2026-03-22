//! Persistência SQLite para a DeviceTable.
//!
//! ## Arquitetura
//!
//! O módulo tem duas camadas:
//!
//! - **`LeaseDb`** — motor SQLite síncrono (rusqlite). Responsável pelo
//!   schema, serialização e desserialização. Não sabe nada de async.
//!
//! - **`db_worker`** — task async que escuta `LanforgeEvent::DeviceTableDirty`
//!   no `EventBus` e persiste o estado com debounce, protegendo o SD card
//!   de escritas excessivas durante boot storms ou rajadas de leases.
//!
//! ## Fluxo
//!
//! ```text
//! ManagedTable::update()
//!     └─► EventBus::publish(DeviceTableDirty)
//!                   │
//!                   ▼
//!             db_worker (loop)
//!                   │ debounce 3s
//!                   ▼
//!             LeaseDb::save_table()   ← snapshot completo, transação única
//! ```
//!
//! ## Startup
//!
//! Na inicialização, `LeaseDb::load_table` reconstrói o `DeviceTable` do
//! SQLite via `apply_update` — o Manager recebe o estado persistido como se
//! fossem eventos normais de protocolo, mantendo as invariantes de merging.
//!
//! Entradas estáticas do TOML são carregadas *depois* via
//! `load_static_devices` e têm precedência sobre o que veio do DB.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::bus::{EventBus, LanforgeEvent, ManagedTable};
use crate::dhcp::v6::duid::Duid;
use crate::state::{DeviceTable, DeviceUpdate, MacAddr};

// ---------------------------------------------------------------------------
// LeaseDb — motor SQLite síncrono
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

/// Handle para o banco SQLite de leases.
///
/// Responsável pelas operações síncronas de I/O no banco de dados.
/// Utiliza o modo WAL para permitir leituras simultâneas a escritas.
pub struct LeaseDb {
    conn: Connection,
}

impl LeaseDb {
    /// Abre (ou cria) o banco SQLite no path indicado e executa migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("criando diretório para {}", path.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("abrindo SQLite em {}", path.display()))?;

        // WAL mode — escritas não bloqueiam leituras; NORMAL é seguro pra SD card
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        let db = LeaseDb { conn };
        db.create_tables()?;

        debug!("SQLite aberto em {}", path.display());
        Ok(db)
    }

    /// Cria o banco em memória — exclusivo para testes.
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
            .context("falha ao criar tabelas")?;

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

        debug!("Schema verificado/criado");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Save — snapshot completo
    // -----------------------------------------------------------------------

    /// Grava todos os devices do `DeviceTable` no SQLite em uma transação
    /// única. Operação idempotente — substitui o estado anterior integralmente.
    pub fn save_table(&self, table: &DeviceTable) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        tx.execute_batch(
            "DELETE FROM slaac_addrs;
             DELETE FROM v6_leases;
             DELETE FROM v4_leases;
             DELETE FROM devices;",
        )?;

        for device in table.devices() {
            let mac_str = device.mac.to_string();
            let last_seen = system_time_to_unix(device.last_seen);
            let duid_blob: Option<Vec<u8>> = device.duid.as_ref().map(|d| d.bytes.clone());
            let managed_at_unix: Option<i64> = device.managed_at.map(system_time_to_unix);
            let v4_static_str: Option<String> = device.v4_static.map(|ip| ip.to_string());

            tx.execute(
                "INSERT INTO devices (mac, hostname, is_static, duid, last_seen, origin, managed_at, v4_static, v6_suffix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    mac_str,
                    device.hostname,
                    device.is_static as i32,
                    duid_blob,
                    last_seen,
                    device.origin.as_str(),
                    managed_at_unix,
                    v4_static_str,
                    device.v6_suffix.clone()
                ],
            )?;

            if let Some(v4) = &device.v4 {
                tx.execute(
                    "INSERT INTO v4_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v4.ip.to_string(), system_time_to_unix(v4.expires)],
                )?;
            }

            if let Some(v6) = &device.v6 {
                tx.execute(
                    "INSERT INTO v6_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v6.ip.to_string(), system_time_to_unix(v6.expires)],
                )?;
            }

            for addr in &device.slaac {
                tx.execute(
                    "INSERT INTO slaac_addrs (mac, ip) VALUES (?1, ?2)",
                    params![mac_str, addr.to_string()],
                )?;
            }
        }

        tx.commit()?;
        debug!("DeviceTable salva ({} devices)", table.devices().count());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Load — reconstrói DeviceTable via apply_update
    // -----------------------------------------------------------------------

    /// Carrega o estado persistido e devolve uma `DeviceTable` populada.
    ///
    /// Usa `apply_update` para todas as escritas — as invariantes de merging
    /// do Manager (estático > dinâmico, etc.) são respeitadas mesmo no
    /// bootstrap. O índice de DUID é reconstruído automaticamente.
    ///
    /// Entradas estáticas do TOML **não** são carregadas aqui — serão
    /// aplicadas depois via `load_static_devices` e têm precedência.
    pub fn load_table(&self) -> Result<DeviceTable> {
        let mut table = DeviceTable::new();

        // 1. Devices base (hostname, is_static, last_seen)
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
            .filter_map(|r| r.ok())
            .collect();

        for (
            mac_str,
            hostname,
            is_static,
            duid_bytes,
            last_seen_unix,
            origin_str,
            managed_at,
            v4_static_str,
            v6_suffix,
        ) in rows
        {
            let Some(mac) = MacAddr::parse(&mac_str) else {
                warn!("MAC inválido no DB: '{mac_str}', pulando");
                continue;
            };

            let dev = table.get_or_insert(mac);
            // Restaura hostname se não vazio
            if !hostname.is_empty() {
                dev.hostname = hostname;
            }
            dev.is_static = is_static;
            dev.last_seen = unix_to_system_time(last_seen_unix);

            dev.origin = match origin_str.as_str() {
                "toml" => crate::state::Origin::Toml,
                "cli" => crate::state::Origin::Cli,
                _ => crate::state::Origin::Dynamic,
            };
            dev.managed_at = managed_at.map(unix_to_system_time);
            dev.v4_static = v4_static_str.and_then(|s| s.parse().ok());
            dev.v6_suffix = v6_suffix;

            // Restaura DUID via apply_update — reconstrói o duid_index
            if let Some(bytes) = duid_bytes {
                table.apply_update(DeviceUpdate::DuidAssociated {
                    mac,
                    duid: Duid::new(bytes),
                });
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
            .filter_map(|r| r.ok())
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
                warn!("IPv6 inválido no DB: '{ip_str}', pulando");
                continue;
            };
            // V6 lease sem DUID no contexto do load — usamos o DUID já indexado
            let duid = table
                .find_duid_by_mac(mac)
                .cloned()
                .unwrap_or_else(|| Duid::new(vec![]));
            table.apply_update(DeviceUpdate::V6LeaseGranted {
                mac,
                duid,
                ip,
                expires: unix_to_system_time(expires_unix),
            });
        }

        // 4. SLAAC addresses
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
            table.apply_update(DeviceUpdate::SlaacObserved { mac, addr: ip });
        }

        let count = table.devices().count();
        info!("Carregados {count} dispositivos do SQLite");
        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// db_worker — task reativa com debounce
// ---------------------------------------------------------------------------

/// Duração do debounce antes de persistir após um `DeviceTableDirty`.
///
/// Protege o SD card durante boot storms (muitos devices aparecendo em
/// sequência) e rajadas de leases. Ajustável via config futuramente.
const DEBOUNCE: Duration = Duration::from_secs(3);

/// Task async que persiste o `ManagedTable` reativamente.
///
/// Deve ser iniciada via `tokio::spawn` no startup. Loop principal:
///
/// 1. Aguarda `DeviceTableDirty` no barramento.
/// 2. Inicia janela de debounce — drena eventos adicionais por `DEBOUNCE`.
/// 3. Tira snapshot do `ManagedTable` (read lock breve).
/// 4. Persiste via `LeaseDb::save_table` em `spawn_blocking` (rusqlite é síncrono).
/// 5. Em `Shutdown`: flush imediato e encerra.
///
/// Se a tarefa de IO falhar, loga o erro e continua — uma falha de
/// persistência não deve derrubar o daemon.
/// Task assíncrona que persiste o `ManagedTable` reativamente.
///
/// Este worker implementa um loop de debounce para evitar micro-escritas no disco.
/// Ele escuta eventos `DeviceTableDirty` e, após uma janela de calma (`DEBOUNCE`),
/// dispara uma thread separada para salvar o estado atual no SQLite.
pub async fn db_worker(db_path: PathBuf, table: Arc<ManagedTable>, bus: Arc<EventBus>) {
    let mut rx = bus.subscribe();

    info!(
        "DB worker iniciado (debounce: {}s, path: {})",
        DEBOUNCE.as_secs(),
        db_path.display()
    );

    // 1. Cria o canal MPSC para enviar snapshots para a thread síncrona.
    // Um buffer pequeno (ex: 4) é mais que suficiente graças ao debounce.
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::channel::<DeviceTable>(4);

    // 2. Inicia a thread síncrona dedicada ao SQLite (Abre o banco APENAS UMA VEZ)
    let db_path_clone = db_path.clone();
    tokio::task::spawn_blocking(move || {
        let db = match LeaseDb::open(&db_path_clone) {
            Ok(db) => db,
            Err(e) => {
                warn!("DB thread: falha fatal ao abrir SQLite: {e:#}");
                return;
            }
        };

        // Fica escutando o canal. Quando o sender (snapshot_tx) for dropado no shutdown,
        // o blocking_recv() retornará None e a thread será encerrada naturalmente.
        while let Some(snapshot) = snapshot_rx.blocking_recv() {
            if let Err(e) = db.save_table(&snapshot) {
                warn!("DB thread: falha ao salvar snapshot: {e:#}");
            } else {
                debug!("DB worker: snapshot persistido");
            }
        }
        info!("DB thread: encerrando graciosamente");
    });

    // 3. Loop principal assíncrono reativo
    loop {
        // Aguarda o próximo evento relevante
        let should_flush = wait_for_dirty_or_shutdown(&mut rx).await;

        if !should_flush {
            // Shutdown sem dirty pendente — nada a fazer
            info!("DB worker encerrando (sem dirty pendente)");
            return;
        }

        // Drena eventos adicionais pelo período de debounce.
        // Se chegar um Shutdown durante o debounce, flush imediato.
        let shutdown_during_debounce = drain_with_debounce(&mut rx, DEBOUNCE).await;

        // Snapshot do estado atual (read lock breve)
        let snapshot = {
            let t = table.read().await;
            t.clone()
        };

        // Envia o snapshot para a thread do banco sem bloquear o loop do Tokio
        if snapshot_tx.send(snapshot).await.is_err() {
            warn!("DB worker: falha ao enviar snapshot - a thread do DB morreu");
            break;
        }

        if shutdown_during_debounce {
            info!("DB worker encerrando após flush de shutdown");
            return; // Retornar aqui dropa o snapshot_tx, o que encerra a thread síncrona
        }
    }
}

/// Aguarda o próximo `DeviceTableDirty` ou `Shutdown`.
/// Retorna `true` se deve persistir, `false` se deve encerrar sem flush.
async fn wait_for_dirty_or_shutdown(rx: &mut broadcast::Receiver<LanforgeEvent>) -> bool {
    loop {
        match rx.recv().await {
            Ok(LanforgeEvent::DeviceTableDirty) => return true,
            Ok(LanforgeEvent::Shutdown) => return false,
            Ok(_) => continue, // outros eventos — ignora
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("DB worker atrasado, pulou {n} eventos — forçando flush");
                return true;
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("DB worker: barramento encerrado");
                return false;
            }
        }
    }
}

/// Drena o canal pelo período de debounce, absorvendo Dirty extras.
/// Retorna `true` se um `Shutdown` chegou durante a espera.
async fn drain_with_debounce(
    rx: &mut broadcast::Receiver<LanforgeEvent>,
    debounce: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + debounce;

    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(LanforgeEvent::Shutdown)) => return true,
            Ok(Ok(LanforgeEvent::DeviceTableDirty)) => {} // absorve, reinicia janela não
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => return false,
            Err(_) => return false, // timeout expirou — hora de persistir
        }
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
    use crate::state::V4Lease;
    use std::time::UNIX_EPOCH;

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

        let dev = loaded.devices().next().unwrap();
        assert_eq!(dev.hostname, "TestDevice");
        assert_eq!(dev.v4.as_ref().unwrap().ip, Ipv4Addr::new(192, 168, 0, 100));
    }

    #[test]
    fn handles_slaac_multiple_addrs() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(2);
        table.apply_update(DeviceUpdate::SlaacObserved {
            mac,
            addr: "fd97:f00d:cafe:3731::1234".parse().unwrap(),
        });
        table.apply_update(DeviceUpdate::SlaacObserved {
            mac,
            addr: "fd97:f00d:cafe:3731::5678".parse().unwrap(),
        });
        table.apply_update(DeviceUpdate::SlaacObserved {
            mac,
            addr: "2001:db8::abcd".parse().unwrap(),
        });

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        assert_eq!(loaded.devices().next().unwrap().slaac.len(), 3);
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
        table.apply_update(DeviceUpdate::DuidAssociated {
            mac,
            duid: duid.clone(),
        });

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let dev = loaded.devices().next().unwrap();
        assert_eq!(dev.duid.as_ref().unwrap().bytes, duid.bytes);

        let found = loaded.find_by_duid(&duid);
        assert!(found.is_some());
        assert_eq!(found.unwrap().hostname, "DuidDevice");
    }

    #[test]
    fn handles_v6_lease() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();

        let mac = make_mac(4);
        let duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04,
        ]);
        let dev = table.get_or_insert(mac);
        dev.hostname = "V6Device".into();

        table.apply_update(DeviceUpdate::V6LeaseGranted {
            mac,
            duid,
            ip: "fd97:f00d:cafe:3731::1057:cafe".parse().unwrap(),
            expires: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        });

        db.save_table(&table).unwrap();
        let loaded = db.load_table().unwrap();

        let dev = loaded.devices().next().unwrap();
        assert!(dev.v6.is_some());
        assert_eq!(
            dev.v6.as_ref().unwrap().ip,
            "fd97:f00d:cafe:3731::1057:cafe"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }

    #[test]
    fn save_overwrites_previous() {
        let db = LeaseDb::open_in_memory().unwrap();
        let mut table = DeviceTable::new();
        let mac = make_mac(1);

        table.get_or_insert(mac).hostname = "First".into();
        db.save_table(&table).unwrap();

        table.get_or_insert(mac).hostname = "Second".into();
        db.save_table(&table).unwrap();

        let loaded = db.load_table().unwrap();
        assert_eq!(loaded.devices().next().unwrap().hostname, "Second");
        assert_eq!(loaded.devices().count(), 1);
    }

    #[test]
    fn skips_invalid_database_records_gracefully() {
        let db = LeaseDb::open_in_memory().unwrap();

        db.conn
            .execute(
                "INSERT INTO devices (mac, hostname, is_static, last_seen)
             VALUES ('bad-mac', 'Lixo', 0, 0)",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO devices (mac, hostname, is_static, last_seen)
             VALUES ('aa:bb:cc:dd:ee:ff', 'Valido', 0, 0)",
                [],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO v4_leases (mac, ip, expires)
             VALUES ('aa:bb:cc:dd:ee:ff', '999.999.999.999', 0)",
                [],
            )
            .unwrap();

        let table = db
            .load_table()
            .expect("banco com lixo não deve causar erro fatal");

        assert_eq!(table.devices().count(), 1, "MAC inválido deve ser ignorado");
        let dev = table.devices().next().unwrap();
        assert_eq!(dev.hostname, "Valido");
        assert!(dev.v4.is_none(), "IP inválido deve ser descartado");
    }

    #[tokio::test]
    async fn db_worker_persists_on_dirty_event() {
        use crate::bus::EventBus;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let bus = Arc::new(EventBus::new());
        let table = Arc::new(ManagedTable::new(bus.clone()));

        // Lança o worker ANTES de qualquer update — garante que está subscrito
        // quando o DeviceTableDirty chegar.
        let worker_table = Arc::clone(&table);
        let worker_bus = Arc::clone(&bus);
        let worker_path = db_path.clone();
        tokio::spawn(async move {
            db_worker(worker_path, worker_table, worker_bus).await;
        });

        // Yield para o worker ter chance de chamar bus.subscribe() antes do update
        tokio::task::yield_now().await;

        // Popula um device — ManagedTable publica DeviceTableDirty automaticamente
        let mac = make_mac(0xAB);
        table
            .update(DeviceUpdate::HostnameHint {
                mac,
                hostname: "worker-test".into(),
            })
            .await;

        // Aguarda debounce + margem para o spawn_blocking completar
        tokio::time::sleep(DEBOUNCE + Duration::from_millis(500)).await;

        // Verifica que o DB foi escrito
        let db = LeaseDb::open(&db_path).unwrap();
        let loaded = db.load_table().unwrap();
        assert_eq!(loaded.devices().count(), 1);
        assert_eq!(loaded.devices().next().unwrap().hostname, "worker-test");
    }
}
