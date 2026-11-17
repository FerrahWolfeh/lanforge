//! `lanforge config backup` / `restore` (`handle_backup`, `handle_restore`): the files travel
//! verbatim, users and tokens are replaced, hand-made device settings come back, and a refused
//! bundle writes nothing.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tokio::task::yield_now;

use super::reload::with_file;
use crate::ClientContext;
use lanforge_api::api::{BackupBundle, BackupFile, Response};
use lanforge_db_core::{DbError, Stores, UserEntry};
use lanforge_types::device::{DeviceClass, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};

const CONFIG: &str = "[system]\nsearch_domains = [\"home\"]\n\n[adblock]\nenabled = true\nrules = \"adblock/global.rules\"\n";
const RULES: &str = "||ads.example^\n";
const SECRETS: &str = "# kept verbatim\n[pppoe]\npassword = \"s3cret\"\n";
const TV: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);
const GUEST: MacAddr = MacAddr([2, 0, 0, 0, 0, 2]);

async fn ready(client: &ClientContext) {
    while client.ctx.storage_handle().is_none() {
        yield_now().await;
    }
}

async fn users(client: &ClientContext) -> Vec<UserEntry> {
    let storage = client.ctx.storage_handle().expect("storage");
    storage
        .call(|s: &Stores| -> Result<_, DbError> { s.auth().list_users() })
        .await
        .expect("users")
}

async fn token_is_valid(client: &ClientContext, raw: &'static str) -> bool {
    let storage = client.ctx.storage_handle().expect("storage");
    storage
        .call(move |s: &Stores| Ok::<_, DbError>(s.auth().validate_api_token(raw, 1)?.is_some()))
        .await
        .expect("validate")
}

/// A box with a config, secrets and rules file, one user, one API token, one hand-configured
/// device, one device that only holds a lease, and a linked address.
async fn configured_box() -> (ClientContext, tempfile::TempDir, String) {
    let (client, dir, _) = with_file(CONFIG);
    ready(&client).await;
    fs::create_dir(dir.path().join("adblock")).unwrap();
    fs::write(dir.path().join("adblock/global.rules"), RULES).unwrap();
    let secrets = dir.path().join("secrets.toml");
    fs::write(&secrets, SECRETS).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o600)).unwrap();

    let created = client
        .handle_user_create("alice".into(), "pw-pw-pw-pw".into(), Some("admin".into()))
        .await;
    assert!(matches!(created, Response::User(_)), "{created:?}");
    let Response::AuthToken(token) = client.handle_ak_generate("ci".into(), None, None).await
    else {
        panic!("token not generated");
    };

    let _ = client.ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: TV,
        update: Box::new(CliHostUpdate {
            class: FieldUpdate::Set(DeviceClass::Media),
            origin: Origin::Dynamic,
            ..CliHostUpdate::default()
        }),
    });
    let _ = client.ctx.apply(DeviceUpdate::IgnoreDnsLogSet {
        mac: TV,
        ignore: true,
    });
    let _ = client.ctx.apply(DeviceUpdate::LinkedAddressesSet {
        mac: TV,
        addresses: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7))],
    });
    let _ = client.ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac: GUEST,
        ip: Ipv4Addr::new(192, 168, 9, 9),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    (client, dir, token.token)
}

async fn backup_of(client: &ClientContext) -> BackupBundle {
    match client.handle_backup().await {
        Response::Backup(bundle) => *bundle,
        other => panic!("backup failed: {other:?}"),
    }
}

#[tokio::test]
async fn a_backup_restores_files_users_tokens_and_device_settings() {
    let (source, _source_dir, raw_token) = configured_box().await;
    let bundle = backup_of(&source).await;

    let names: Vec<_> = bundle.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        ["lanforge.toml", "secrets.toml", "adblock/global.rules"]
    );
    assert_eq!(
        bundle.files[1].content, SECRETS,
        "the secrets travel verbatim"
    );
    assert_eq!(bundle.users.len(), 1);
    assert_eq!(bundle.api_tokens.len(), 1);
    assert_ne!(
        bundle.api_tokens[0].token, raw_token,
        "only the digest is in the bundle"
    );
    let macs: Vec<_> = bundle.devices.iter().map(|d| d.mac).collect();
    assert_eq!(
        macs,
        [TV],
        "the device that only holds a lease is runtime state"
    );
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(!json.contains(&raw_token), "no raw token");
    assert!(!json.contains("192.168.9.9"), "no lease");

    // A fresh box: nothing configured, no users.
    let (target, target_dir, _) = with_file("");
    ready(&target).await;
    let restored = target.handle_restore(bundle.clone()).await;
    assert!(matches!(restored, Response::Success(_)), "{restored:?}");

    let dir = target_dir.path();
    assert_eq!(
        fs::read_to_string(dir.join("lanforge.toml")).unwrap(),
        CONFIG
    );
    assert_eq!(
        fs::read_to_string(dir.join("adblock/global.rules")).unwrap(),
        RULES
    );
    let secrets = dir.join("secrets.toml");
    assert_eq!(fs::read_to_string(&secrets).unwrap(), SECRETS);
    assert_eq!(
        fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
        0o600
    );

    assert_eq!(
        users(&target).await,
        bundle.users,
        "users with their password hashes"
    );
    assert!(token_is_valid(&target, Box::leak(raw_token.into_boxed_str())).await);

    let tv = target
        .ctx
        .get_device(&TV)
        .expect("device settings restored");
    assert_eq!(tv.class, DeviceClass::Media);
    assert!(tv.ignore_dns_log);
    assert!(target.ctx.get_device(&GUEST).is_none());
    assert_eq!(
        target
            .ctx
            .linked_addresses()
            .into_iter()
            .collect::<Vec<_>>(),
        [(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), TV)]
    );
    assert_eq!(
        target.ctx.get_site_domains().0,
        ["home", "lan"].map(String::from)
    );
}

#[tokio::test]
async fn a_restore_replaces_the_users_and_tokens_it_finds() {
    let (source, _dir, _) = configured_box().await;
    let bundle = backup_of(&source).await;

    let (target, _target_dir, _) = with_file("");
    ready(&target).await;
    let _ = target
        .handle_user_create("stale".into(), "pw-pw-pw-pw".into(), Some("admin".into()))
        .await;
    let _ = target.handle_ak_generate("stale".into(), None, None).await;
    let restored = target.handle_restore(bundle.clone()).await;
    assert!(matches!(restored, Response::Success(_)), "{restored:?}");

    let names: Vec<_> = users(&target)
        .await
        .into_iter()
        .map(|u| u.username)
        .collect();
    assert_eq!(names, ["alice"]);
    let Response::AuthTokens(tokens) = target.handle_ak_list().await else {
        panic!("tokens");
    };
    assert_eq!(tokens.tokens.len(), 1);
    assert_eq!(tokens.tokens[0].name, "ci");
}

fn read(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
}

/// A bundle refused for any reason writes nothing: not its valid files, not users or tokens.
#[tokio::test]
async fn a_refused_restore_writes_nothing() {
    let (target, dir, raw_token) = configured_box().await;
    let raw_token: &'static str = Box::leak(raw_token.into_boxed_str());
    let before = users(&target).await;
    let valid = |extra: Vec<BackupFile>| {
        let mut files = vec![BackupFile {
            name: "lanforge.toml".into(),
            content: "[system]\nsearch_domains = [\"restored\"]\n".into(),
        }];
        files.extend(extra);
        BackupBundle {
            files,
            ..BackupBundle::default()
        }
    };
    let file = |name: &str| BackupFile {
        name: name.into(),
        content: "x".into(),
    };

    let mut invalid_toml = valid(Vec::new());
    invalid_toml.files[0].content = "[system\nbroken".into();
    let mut set_aside = valid(Vec::new());
    set_aside.files[0].content = "[pppoe]\nenabled = \"yes\"\n".into();
    let mut users_changed = valid(vec![file("../escape")]);
    users_changed.users = Vec::new();
    for (case, bundle) in [
        ("invalid TOML", invalid_toml),
        ("a section that would be set aside", set_aside),
        ("a name leaving the directory", users_changed),
        (
            "a file nobody references",
            valid(vec![file("adblock/unlisted.rules")]),
        ),
        (
            "a nested secrets file",
            valid(vec![file("sub/secrets.toml")]),
        ),
    ] {
        let response = target.handle_restore(bundle).await;
        assert!(
            matches!(response, Response::Rejected { .. }),
            "{case}: {response:?}"
        );
        let d = dir.path();
        assert_eq!(read(d, "lanforge.toml").as_deref(), Some(CONFIG), "{case}");
        assert_eq!(read(d, "secrets.toml").as_deref(), Some(SECRETS), "{case}");
        assert_eq!(
            read(d, "adblock/global.rules").as_deref(),
            Some(RULES),
            "{case}"
        );
        assert!(!d.join("adblock/unlisted.rules").exists(), "{case}");
        assert!(!d.join("../escape").exists(), "{case}");
        assert_eq!(users(&target).await, before, "{case}: users untouched");
        assert!(
            token_is_valid(&target, raw_token).await,
            "{case}: token kept"
        );
    }
}
