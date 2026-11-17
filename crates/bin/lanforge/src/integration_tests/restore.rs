//! `lanforged --restore`: an encrypted backup goes into the config directory and the config
//! database with the daemon stopped, and nothing is written when anything is refused.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;

use lanforge_api::api::{BackupBundle, BackupDevice, BackupFile};
use lanforge_crypto::backup::seal;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_db::{
    ApiTokenStore, DeviceStore, LinkedAddressStore, NameBindingStore, UserEntry, UserStore,
};
use lanforge_types::auth::{ApiScope, ApiScopes, ApiTokenEntry, UserRole};
use lanforge_types::device::DeviceClass;
use lanforge_types::identifiers::MacAddr;

use crate::restore::{restore_offline, restore_sealed};

const CONFIG: &str = "[system]\nsearch_domains = [\"home\"]\n";
const SECRETS: &str = "[pppoe]\npassword = \"s3cret\"\n";
const TV: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);

fn file(name: &str, content: &str) -> BackupFile {
    BackupFile {
        name: name.into(),
        content: content.into(),
    }
}

fn bundle() -> BackupBundle {
    BackupBundle {
        files: vec![file("lanforge.toml", CONFIG), file("secrets.toml", SECRETS)],
        users: vec![UserEntry {
            id: 4,
            username: "alice".into(),
            password_hash: "hash".into(),
            role: UserRole::Admin,
            created_at: 1,
            updated_at: 2,
            last_login: None,
        }],
        api_tokens: vec![ApiTokenEntry {
            id: 2,
            token: lanforge_crypto::token_digest("lf_ak_raw"),
            name: "ci".into(),
            created_at: 1,
            last_used: None,
            scopes: ApiScopes::from_slice(&[ApiScope::Admin]),
            expires_at: None,
        }],
        devices: vec![BackupDevice {
            mac: TV,
            hostname: Some("tv".into()),
            class: DeviceClass::Media,
            dns_fallback: "host-020000000001".into(),
            boot_file: None,
            ignore_dns_log: true,
            ignored_log_domains: vec!["cdn.example".into()],
        }],
        name_bindings: vec![("tv".into(), TV)],
        linked_addresses: vec![(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), TV)],
    }
}

fn open(path: &str) -> LanforgeDb {
    LanforgeDb::open(&DatabaseConfig {
        config_path: path.to_string(),
        ..DatabaseConfig::default()
    })
    .expect("open")
}

#[test]
fn an_offline_restore_writes_the_files_and_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("etc/lanforge.toml");
    let db_path = dir
        .path()
        .join("config.redb")
        .to_string_lossy()
        .into_owned();

    let done = restore_offline(&bundle(), &config, Some(&db_path)).expect("restore");
    assert!(done.contains("1 user(s)"), "{done}");

    assert_eq!(fs::read_to_string(&config).unwrap(), CONFIG);
    let secrets = dir.path().join("etc/secrets.toml");
    assert_eq!(fs::read_to_string(&secrets).unwrap(), SECRETS);
    assert_eq!(
        fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let db = open(&db_path);
    assert_eq!(db.list_users().unwrap(), bundle().users);
    assert_eq!(db.load_api_tokens().unwrap(), bundle().api_tokens);
    assert!(db.validate_api_token("lf_ak_raw", 1).unwrap().is_some());
    let tv = db
        .load_all_devices()
        .unwrap()
        .into_iter()
        .find(|d| d.mac == TV)
        .expect("device settings restored");
    assert_eq!(tv.class, DeviceClass::Media);
    assert!(tv.ignore_dns_log);
    assert_eq!(tv.hostname.name, "tv");
    assert_eq!(db.load_name_bindings().unwrap().get("tv"), Some(&TV));
    assert_eq!(db.load_linked_addresses().unwrap().len(), 1);
}

#[test]
fn the_database_path_comes_from_the_backups_own_config_when_not_given() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("from-config.redb");
    let mut b = bundle();
    b.files[0].content = format!("[database]\nconfig_path = \"{}\"\n", db_path.display());
    restore_offline(&b, &dir.path().join("lanforge.toml"), None).expect("restore");
    assert_eq!(
        open(&db_path.to_string_lossy()).list_users().unwrap(),
        b.users
    );
}

/// A running daemon holds the database: the restore says so and writes no file.
#[test]
fn a_locked_database_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("lanforge.toml");
    let db_path = dir
        .path()
        .join("config.redb")
        .to_string_lossy()
        .into_owned();
    let running = open(&db_path);

    let err = restore_offline(&bundle(), &config, Some(&db_path)).expect_err("locked");
    assert!(err.to_string().contains("is lanforged running"), "{err}");
    assert!(!config.exists() && !dir.path().join("secrets.toml").exists());
    assert!(running.list_users().unwrap().is_empty());
}

#[test]
fn a_refused_bundle_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("lanforge.toml");
    let db_path = dir
        .path()
        .join("config.redb")
        .to_string_lossy()
        .into_owned();
    let mut b = bundle();
    b.files.push(file("../escape", "x"));

    let err = restore_offline(&b, &config, Some(&db_path)).expect_err("refused");
    assert!(err.to_string().contains("nothing restored"), "{err}");
    assert!(!config.exists());
    assert!(
        !dir.path().join("config.redb").exists(),
        "the database was not even created"
    );
}

#[test]
fn a_sealed_backup_needs_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("lanforge.toml");
    let db_path = dir
        .path()
        .join("config.redb")
        .to_string_lossy()
        .into_owned();
    let sealed =
        serde_json::to_string(&seal("right", &serde_json::to_vec(&bundle()).unwrap()).unwrap())
            .unwrap();

    assert!(restore_sealed("wrong", &sealed, &config, Some(&db_path)).is_err());
    assert!(!config.exists());
    assert!(restore_sealed("right", "not a backup", &config, Some(&db_path)).is_err());
    restore_sealed("right", &sealed, &config, Some(&db_path)).expect("restore");
    assert_eq!(fs::read_to_string(&config).unwrap(), CONFIG);
}
