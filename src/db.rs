//! Persistência `SQLite` para a `DeviceTable`.
//!
//! ## Arquitetura
//!
//! O módulo tem duas camadas:
//!
//! - **`LeaseDb`** — motor `SQLite` síncrono (rusqlite). Responsável pelo
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
//! `SQLite` via `apply_update` — o Manager recebe o estado persistido como se
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

/// Handle para o banco `SQLite` de leases.
///
/// Responsável pelas operações síncronas de I/O no banco de dados.
/// Utiliza o modo WAL para permitir leituras simultâneas a escritas.
pub struct LeaseDb {
    conn: Connection,
}

impl LeaseDb {
    /// Abre (ou cria) o banco `SQLite` no path indicado e executa migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("criando diretório para {}", path.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("abrindo SQLite em {}", path.display()))?;

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
                    mac         TEXT PRIMARY KEY REFERENCES devices(mac),
                    ip          TEXT NOT NULL,
                    expires     INTEGER NOT NULL
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
            let v4_static_str: Option<String> = device.v4_static.map(|ip| ip.to_string());

            // Tabela principal: Se o MAC já existir, atualiza apenas os dados.
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
                    i32::from(device.is_static),
                    duid_blob,
                    last_seen,
                    device.origin.as_str(),
                    managed_at_unix,
                    v4_static_str,
                    device.v6_suffix.clone()
                ],
            )?;

            // Tabelas filhas: É mais barato deletar as referências DESTE mac e recriar
            // do que tentar fazer diff SQL de arrays.
            tx.execute("DELETE FROM v4_leases WHERE mac = ?1", params![&mac_str])?;
            if let Some(v4) = &device.v4 {
                tx.execute(
                    "INSERT INTO v4_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v4.ip.to_string(), system_time_to_unix(v4.expires)],
                )?;
            }

            tx.execute("DELETE FROM v6_leases WHERE mac = ?1", params![&mac_str])?;
            if let Some(v6) = &device.v6 {
                tx.execute(
                    "INSERT INTO v6_leases (mac, ip, expires) VALUES (?1, ?2, ?3)",
                    params![mac_str, v6.ip.to_string(), system_time_to_unix(v6.expires)],
                )?;
            }

            tx.execute("DELETE FROM slaac_addrs WHERE mac = ?1", params![&mac_str])?;
            for addr in &device.slaac {
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
            .query_map([], |row| row.get(0))?
            .filter_map(Result::ok)
            .collect();
        drop(stmt); // Libera o statement para podermos usar o tx abaixo

        for db_mac in db_macs {
            // Se o MAC que está no banco não existe mais na memória, apagamos as trilhas dele
            if !table.devices().any(|d| d.mac.to_string() == db_mac) {
                tx.execute("DELETE FROM slaac_addrs WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM seen_v4 WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM v6_leases WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM v4_leases WHERE mac = ?1", params![&db_mac])?;
                tx.execute("DELETE FROM devices WHERE mac = ?1", params![&db_mac])?;
            }
        }

        tx.commit()?;
        debug!("DeviceTable persistida com sucesso (Delta Update)");
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
            .filter_map(std::result::Result::ok)
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
                    mac: Some(mac),
                    duid: Duid::new(bytes),
                    iaid: 0,
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
            .prepare("SELECT mac, ip, expires FROM v6_leases")?;

        let v6_rows: Vec<(String, String, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(std::result::Result::ok)
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
                mac: Some(mac),
                duid,
                iaid: 0,
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

        let count = table.devices().count();
        info!("Carregados {count} dispositivos do SQLite");
        Ok(table)
    }

    /// Executa o comando VACUUM para otimizar o arquivo do banco de dados.
    pub fn vacuum(&self) -> Result<()> {
        debug!("Executando VACUUM no SQLite...");
        self.conn
            .execute("VACUUM", [])
            .context("falha ao executar VACUUM")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// db_worker — task reativa com debounce
// ---------------------------------------------------------------------------

/// Duração do debounce antes de persistir após um `DeviceTableDirty`.
///
/// Protege o SD card durante boot storms (muitos devices aparecendo em
/// sequência) e rajadas de leases. Ajustável via config futuramente.
const DEBOUNCE_SILENCE: Duration = Duration::from_secs(5);
const MAX_DEBOUNCE_WAIT: Duration = Duration::from_secs(60);

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
/// dispara uma thread separada para salvar o estado atual no `SQLite`.
/// Task async que persiste o `ManagedTable` reativamente.
///
/// Este worker implementa um loop de debounce para evitar micro-escritas no disco.
/// Ele escuta eventos `DeviceTableDirty` e, após uma janela de calma (`DEBOUNCE`),
/// dispara uma thread separada para salvar o estado atual no `SQLite`.
///
/// Também processa `DbVacuum` para otimização do banco.
pub async fn db_worker(db_path: PathBuf, table: Arc<ManagedTable>, bus: Arc<EventBus>) {
    let mut rx = bus.subscribe();

    info!(
        "DB worker iniciado (debounce: {}s, path: {})",
        DEBOUNCE_SILENCE.as_secs(),
        db_path.display()
    );

    // 1. Cria o canal MPSC para enviar comandos para a thread síncrona.
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<DbWorkerCmd>(4);

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

        // Fica escutando o canal. Quando o sender (cmd_tx) for dropado no shutdown,
        // o blocking_recv() retornará None e a thread será encerrada naturalmente.
        while let Some(cmd) = cmd_rx.blocking_recv() {
            match cmd {
                DbWorkerCmd::Save(snapshot) => {
                    if let Err(e) = db.save_table(&snapshot) {
                        warn!("DB thread: falha ao salvar snapshot: {e:#}");
                    } else {
                        debug!("DB worker: snapshot persistido");
                    }
                }
                DbWorkerCmd::Vacuum => {
                    if let Err(e) = db.vacuum() {
                        warn!("DB thread: falha ao executar VACUUM: {e:#}");
                    } else {
                        info!("DB worker: VACUUM concluído");
                    }
                }
            }
        }
        info!("DB thread: encerrando graciosamente");
    });

    // 3. Loop principal assíncrono reativo
    loop {
        // Aguarda o próximo evento relevante
        let action = wait_for_db_action(&mut rx).await;

        match action {
            DbAction::Save => {
                // Drena eventos adicionais pelo período de debounce.
                // Se chegar um Shutdown durante o debounce, flush imediato.
                let shutdown_during_debounce = drain_with_debounce(&mut rx).await;

                // Snapshot do estado atual (read lock breve)
                let snapshot = {
                    let t = table.read();
                    t.clone()
                };

                // Envia o snapshot para a thread do banco
                if cmd_tx
                    .send(DbWorkerCmd::Save(Box::new(snapshot)))
                    .await
                    .is_err()
                {
                    warn!("DB worker: falha ao enviar snapshot - a thread do DB morreu");
                    break;
                }

                if shutdown_during_debounce {
                    info!("DB worker encerrando após flush de shutdown");
                    return;
                }
            }
            DbAction::Vacuum => {
                if cmd_tx.send(DbWorkerCmd::Vacuum).await.is_err() {
                    warn!("DB worker: falha ao enviar comando de vacuum");
                    break;
                }
            }
            DbAction::Shutdown => {
                info!("DB worker encerrando (shutdown recebido)");
                return;
            }
        }
    }
}

/// Comandos internos enviados para a thread síncrona do SQLite.
enum DbWorkerCmd {
    Save(Box<DeviceTable>),
    Vacuum,
}

/// Ações que o loop assíncrono do `db_worker` deve tomar.
enum DbAction {
    Save,
    Vacuum,
    Shutdown,
}

/// Aguarda o próximo evento de DB ou `Shutdown`.
async fn wait_for_db_action(rx: &mut broadcast::Receiver<LanforgeEvent>) -> DbAction {
    loop {
        match rx.recv().await {
            Ok(LanforgeEvent::DeviceTableDirty) => return DbAction::Save,
            Ok(LanforgeEvent::DbVacuum) => return DbAction::Vacuum,
            Ok(LanforgeEvent::Shutdown) => return DbAction::Shutdown,
            Ok(_) => {} // outros eventos — ignora
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("DB worker atrasado, pulou {n} eventos — forçando flush");
                return DbAction::Save;
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("DB worker: barramento encerrado");
                return DbAction::Shutdown;
            }
        }
    }
}

/// Drena o canal aplicando um "Trailing Edge Debounce".
/// Aguarda `DEBOUNCE_SILENCE` sem eventos novos antes de gravar.
/// Para evitar ficar preso num loop infinito se a rede estiver ruidosa,
/// força a saída após `MAX_DEBOUNCE_WAIT`.
/// Retorna `true` se um `Shutdown` chegou durante a espera.
async fn drain_with_debounce(rx: &mut broadcast::Receiver<LanforgeEvent>) -> bool {
    let start_time = tokio::time::Instant::now();
    let max_deadline = start_time + MAX_DEBOUNCE_WAIT;
    let mut current_deadline = start_time + DEBOUNCE_SILENCE;

    loop {
        match tokio::time::timeout_at(current_deadline, rx.recv()).await {
            Ok(Ok(LanforgeEvent::Shutdown)) => return true, // Prioridade máxima

            // Eventos normais ou atraso do canal (ruído na rede)
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                // Estende o prazo por mais 5s de silêncio, mas trava no limite de 60s
                let new_deadline = tokio::time::Instant::now() + DEBOUNCE_SILENCE;
                current_deadline = std::cmp::min(new_deadline, max_deadline);
            }

            Ok(Err(broadcast::error::RecvError::Closed)) => return false, // Barramento morreu

            // Ocorreu o Timeout!
            // Ou tivemos 5s de silêncio, ou batemos no teto de 60s de barulho contínuo.
            Err(_) => return false,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers de conversão SystemTime <-> unix timestamp
// ---------------------------------------------------------------------------

fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().cast_signed())
        .unwrap_or(0)
}

fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix > 0 {
        UNIX_EPOCH + Duration::from_secs(unix.cast_unsigned())
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
            mac: Some(mac),
            duid: duid.clone(),
            iaid: 0,
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
            mac: Some(mac),
            duid,
            iaid: 0,
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

        // Aguarda o período de silêncio + margem para o spawn_blocking completar a transação
        tokio::time::sleep(DEBOUNCE_SILENCE + Duration::from_millis(500)).await;

        // Verifica que o DB foi escrito
        let db = LeaseDb::open(&db_path).unwrap();
        let loaded = db.load_table().unwrap();
        assert_eq!(loaded.devices().count(), 1);
        assert_eq!(loaded.devices().next().unwrap().hostname, "worker-test");
    }

    #[tokio::test]
    async fn db_worker_handles_vacuum_event() {
        use crate::bus::EventBus;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_vacuum.db");

        let bus = Arc::new(EventBus::new());
        let table = Arc::new(ManagedTable::new(bus.clone()));

        let worker_path = db_path.clone();
        let worker_bus = Arc::clone(&bus);
        let worker_table = Arc::clone(&table);

        tokio::spawn(async move {
            db_worker(worker_path, worker_table, worker_bus).await;
        });

        // Yield para o worker iniciar
        tokio::task::yield_now().await;

        // Dispara o vacuum
        bus.publish(LanforgeEvent::DbVacuum);

        // Aguarda um pouco para processamento (não tem efeito visível fácil no arquivo vazio,
        // mas garante que o loop do worker não quebrou)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Se chegamos aqui sem pânico e o arquivo existe (foi criado pelo open do worker), sucess
        assert!(db_path.exists());
    }
}
