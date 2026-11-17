//! `lanforged --restore <file>`: puts an encrypted backup back with the daemon stopped.
//!
//! For a fresh box, or a daemon that will not start. It writes the same things the API restore
//! does, but straight to the config directory and the config database, and starts no service.

use std::env;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use lanforge_api::api::{BackupBundle, CONFIG_FILE_NAME};
use lanforge_api::config_file::ConfigFile;
use lanforge_crypto::backup::{BackupEnvelope, open};
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::{DeviceStore, LinkedAddressStore, NameBindingStore, UserStore};
use lanforge_types::device::Device;

use crate::config::CliArgs;

/// Environment variable holding the backup password.
pub const PASSWORD_ENV: &str = "LANFORGE_BACKUP_PASSWORD";

/// Restores the backup named by `--restore`; the line to print on success.
pub fn run(cli: &CliArgs, file: &str) -> Result<String> {
    let password = env::var(PASSWORD_ENV)
        .with_context(|| format!("set {PASSWORD_ENV} to the backup password"))?;
    let text = fs::read_to_string(file).with_context(|| format!("cannot read {file}"))?;
    restore_sealed(
        &password,
        &text,
        &cli.resolved_config_path(),
        cli.config_db_path.as_deref(),
    )
}

/// Opens the backup envelope `text` with `password` and restores it (see [`restore_offline`]).
pub fn restore_sealed(
    password: &str,
    text: &str,
    config_path: &Path,
    db_path: Option<&str>,
) -> Result<String> {
    let envelope: BackupEnvelope =
        serde_json::from_str(text).context("the file is not a lanforge backup")?;
    let plain = open(password, &envelope)?;
    let bundle: BackupBundle =
        serde_json::from_slice(&plain).context("the backup content is not readable")?;
    restore_offline(&bundle, config_path, db_path)
}

/// Writes `bundle` to the config directory of `config_path` and its redb part to the config
/// database.
///
/// The database is `db_path` if given, else the `[database] config_path` of the bundle's own
/// `lanforge.toml`. A refused bundle, or a database that is already open (a running daemon),
/// writes nothing.
pub fn restore_offline(
    bundle: &BackupBundle,
    config_path: &Path,
    db_path: Option<&str>,
) -> Result<String> {
    let issues = bundle.issues();
    if !issues.is_empty() {
        bail!("backup refused, nothing restored: {}", issues.join("; "));
    }
    let db_config = DatabaseConfig {
        config_path: match db_path {
            Some(path) => path.to_string(),
            None => bundle_database_path(bundle)?,
        },
        ..DatabaseConfig::default()
    };
    if db_config.is_in_memory() {
        bail!("the config database is in memory: there is nothing to restore into");
    }
    // Before any write: a running daemon holds the database, and nothing must change then.
    let db = LanforgeDb::open(&db_config).map_err(|e| {
        anyhow::anyhow!(
            "cannot open the config database {} ({e}); is lanforged running? Stop it first. Nothing was restored",
            db_config.config_db_path().display()
        )
    })?;

    bundle.write_files(config_path).with_context(|| {
        format!(
            "cannot write the configuration to {}",
            config_path.display()
        )
    })?;
    db.replace_auth(&bundle.users, &bundle.api_tokens)?;

    let mut devices = db.load_all_devices()?;
    for restored in &bundle.devices {
        let at = devices
            .iter()
            .position(|d| d.mac == restored.mac)
            .unwrap_or_else(|| {
                devices.push(Device::new(restored.mac));
                devices.len() - 1
            });
        let device = &mut devices[at];
        restored.apply_to(device.identity_mut());
        device
            .identity_mut()
            .managed_at
            .get_or_insert_with(SystemTime::now);
        db.upsert_device(device)?;
    }
    let mut bindings = db.load_name_bindings()?;
    bindings.extend(bundle.name_bindings.iter().cloned());
    db.save_name_bindings(&bindings)?;
    let mut links = db.load_linked_addresses()?;
    links.extend(bundle.linked_addresses.iter().copied());
    db.save_linked_addresses(&links)?;

    Ok(format!(
        "Backup restored to {} and {}: {} user(s), {} API token(s), {} device(s). Start lanforged.",
        config_path.display(),
        db_config.config_db_path().display(),
        bundle.users.len(),
        bundle.api_tokens.len(),
        bundle.devices.len()
    ))
}

/// `[database] config_path` of the bundle's `lanforge.toml` (checked by `issues`).
fn bundle_database_path(bundle: &BackupBundle) -> Result<String> {
    let file = bundle
        .files
        .iter()
        .find(|f| f.name == CONFIG_FILE_NAME)
        .context("lanforge.toml is missing from the backup")?;
    Ok(ConfigFile::parse(&file.content)?.database.config_path)
}
