//! The backup bundle: what `lanforge config backup` seals and `lanforge config restore` and
//! `lanforged --restore` put back.
//!
//! The configuration travels as the **files themselves** (never a second schema of the
//! config); the bundle adds the few pieces of redb state an admin cannot recreate from the
//! files: users, API-token digests and the settings an admin made by hand on known devices.
//! Dynamic devices, leases, telemetry and logs are runtime state and are not part of it.

use std::fs;
use std::io::{self, ErrorKind};
use std::iter;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use lanforge_types::auth::{ApiTokenEntry, UserEntry};
use lanforge_types::device::{Device, DeviceClass, DeviceIdentity, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::HostnameOrigin;
use lanforge_types::update::{CliHostUpdate, FieldUpdate};
use serde::{Deserialize, Serialize};

use super::common::{HttpDataResponse, HttpWrappedResponse};
use crate::config_file::{
    ConfigFile, SECRETS_FILE_NAME, SecretsFile, write_secrets_text, write_toml_atomically,
};

/// File name of the configuration file inside a bundle.
pub const CONFIG_FILE_NAME: &str = "lanforge.toml";

/// A file of the config directory, carried verbatim. `name` is relative to that directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    pub name: String,
    pub content: String,
}

/// What an admin set by hand on a known device and the files do not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupDevice {
    pub mac: MacAddr,
    /// The name an admin gave a discovered device (a static host's name is in `[hosts]`).
    pub hostname: Option<String>,
    pub class: DeviceClass,
    pub dns_fallback: String,
    pub boot_file: Option<String>,
    pub ignore_dns_log: bool,
    pub ignored_log_domains: Vec<String>,
}

/// The whole backup, before it is sealed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupBundle {
    pub files: Vec<BackupFile>,
    pub users: Vec<UserEntry>,
    /// Tokens as stored: `token` is the SHA-256 digest, never the raw key.
    pub api_tokens: Vec<ApiTokenEntry>,
    pub devices: Vec<BackupDevice>,
    /// Names bound to a device (lowercase name, MAC).
    pub name_bindings: Vec<(String, MacAddr)>,
    /// Addresses linked to a device (tailnet / VPN address, MAC).
    pub linked_addresses: Vec<(IpAddr, MacAddr)>,
}

impl HttpWrappedResponse for BackupBundle {
    type Wrapper = HttpDataResponse<BackupBundle>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl BackupDevice {
    /// The hand-made settings of `device`, `None` when it has none (or is the router).
    #[must_use]
    pub fn from_device(device: &Device) -> Option<Self> {
        if device.origin == Origin::System {
            return None;
        }
        let dynamic = device.origin == Origin::Dynamic;
        let hostname = (dynamic && device.hostname.origin == HostnameOrigin::Static)
            .then(|| device.hostname.name.clone())
            .filter(|name| !name.is_empty());
        let boot_file = dynamic.then(|| device.boot_file.clone()).flatten();
        let custom_fallback =
            device.dns_fallback != DeviceIdentity::default_dns_fallback(device.mac);
        let admin_set = hostname.is_some()
            || boot_file.is_some()
            || device.class != DeviceClass::None
            || custom_fallback
            || device.ignore_dns_log
            || !device.ignored_log_domains.is_empty();
        admin_set.then(|| Self {
            mac: device.mac,
            hostname,
            class: device.class,
            dns_fallback: device.dns_fallback.clone(),
            boot_file,
            ignore_dns_log: device.ignore_dns_log,
            ignored_log_domains: device.ignored_log_domains.clone(),
        })
    }

    /// Sets these settings on `identity` (offline restore).
    pub fn apply_to(&self, identity: &mut DeviceIdentity) {
        if let Some(name) = &self.hostname {
            identity.hostname.name.clone_from(name);
            identity.hostname.origin = HostnameOrigin::Static;
        }
        identity.class = self.class;
        identity.dns_fallback.clone_from(&self.dns_fallback);
        identity.boot_file.clone_from(&self.boot_file);
        identity.ignore_dns_log = self.ignore_dns_log;
        identity
            .ignored_log_domains
            .clone_from(&self.ignored_log_domains);
    }

    /// The admin update that sets these settings on a live device of `origin`.
    #[must_use]
    pub fn to_update(&self, origin: Origin) -> CliHostUpdate {
        CliHostUpdate {
            hostname: self
                .hostname
                .clone()
                .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
            boot_file: self
                .boot_file
                .clone()
                .map_or(FieldUpdate::Clear, FieldUpdate::Set),
            dns_fallback: FieldUpdate::Set(self.dns_fallback.clone()),
            class: FieldUpdate::Set(self.class),
            origin,
            ..CliHostUpdate::default()
        }
    }
}

/// `name` as a path inside the config directory (`a/b.rules`), `None` when it leaves it.
fn inside_config_dir(name: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

impl ConfigFile {
    /// The adblock rules files this configuration reads, relative to the config directory.
    #[must_use]
    pub fn adblock_rules_files(&self) -> Vec<String> {
        let global = self.adblock.rules.iter();
        let groups = self
            .adblock
            .groups
            .iter()
            .filter_map(|(_, g)| g.rules.as_ref());
        let mut names: Vec<String> = global
            .chain(groups)
            .filter_map(|rules| inside_config_dir(rules))
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

impl BackupBundle {
    /// The files of the config directory `config_path` is in: `lanforge.toml`, `secrets.toml`
    /// if there is one, and the adblock rules files the configuration names (one that does not
    /// exist is left out).
    ///
    /// # Errors
    /// `config_path` or the secrets file exists and cannot be read.
    pub fn read_files(config_path: &Path) -> io::Result<Vec<BackupFile>> {
        let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        let text = fs::read_to_string(config_path)?;
        let rules = ConfigFile::parse_lenient(&text)
            .map(|(file, _)| file.adblock_rules_files())
            .unwrap_or_default();
        let mut files = vec![BackupFile {
            name: CONFIG_FILE_NAME.to_string(),
            content: text,
        }];
        let optional = iter::once(SECRETS_FILE_NAME.to_string()).chain(rules);
        for name in optional {
            match fs::read_to_string(dir.join(&name)) {
                Ok(content) => files.push(BackupFile { name, content }),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(files)
    }

    /// Every reason this bundle must not be restored; empty when it can. Nothing is written
    /// by this: `lanforge.toml` must parse strictly (a section that does not fit is a reason,
    /// not a section set aside), `secrets.toml` must fit its form, and the files must be
    /// exactly `lanforge.toml`, `secrets.toml` and the rules files the configuration names.
    #[must_use]
    pub fn issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let mut rules = Vec::new();
        match self.files.iter().find(|f| f.name == CONFIG_FILE_NAME) {
            None => issues.push(format!("{CONFIG_FILE_NAME} is missing from the backup")),
            Some(file) => match ConfigFile::parse(&file.content) {
                Ok(parsed) => rules = parsed.adblock_rules_files(),
                Err(e) => issues.push(format!("{CONFIG_FILE_NAME}: {}", e.message().trim())),
            },
        }
        for (i, file) in self.files.iter().enumerate() {
            let name = file.name.as_str();
            if self.files[..i].iter().any(|f| f.name == name) {
                issues.push(format!("file \"{name}\" appears twice"));
            } else if name == SECRETS_FILE_NAME {
                if let Err(e) = toml::from_str::<SecretsFile>(&file.content) {
                    issues.push(format!("{SECRETS_FILE_NAME}: {}", e.message().trim()));
                }
            } else if name != CONFIG_FILE_NAME
                && !(inside_config_dir(name).as_deref() == Some(name)
                    && rules.iter().any(|r| r == name))
            {
                issues.push(format!(
                    "file \"{name}\" is not part of a backup (only {CONFIG_FILE_NAME}, {SECRETS_FILE_NAME} and the adblock rules files the configuration names)"
                ));
            }
        }
        for (i, user) in self.users.iter().enumerate() {
            if user.username.is_empty()
                || self.users[..i].iter().any(|u| u.username == user.username)
            {
                issues.push(format!(
                    "user \"{}\" is empty or listed twice",
                    user.username
                ));
            }
        }
        for (i, token) in self.api_tokens.iter().enumerate() {
            let digest = token.token.len() == 64
                && token
                    .token
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !digest || self.api_tokens[..i].iter().any(|t| t.token == token.token) {
                issues.push(format!(
                    "API token \"{}\" is not a unique SHA-256 digest",
                    token.name
                ));
            }
        }
        issues
    }

    /// Writes the files into the config directory of `config_path` (`lanforge.toml` goes to
    /// `config_path` itself). Each file is replaced atomically; `lanforge.toml` goes last, so a
    /// failure never leaves a configuration that names rules not yet written. Call
    /// [`Self::issues`] first: names are not checked here.
    ///
    /// # Errors
    /// Creating a directory or writing a file fails.
    pub fn write_files(&self, config_path: &Path) -> io::Result<()> {
        let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir)?;
        let target = |name: &str| -> PathBuf {
            if name == CONFIG_FILE_NAME {
                config_path.to_path_buf()
            } else {
                dir.join(name)
            }
        };
        let ordered = self
            .files
            .iter()
            .filter(|f| f.name != CONFIG_FILE_NAME)
            .chain(self.files.iter().filter(|f| f.name == CONFIG_FILE_NAME));
        for file in ordered {
            if file.name == SECRETS_FILE_NAME {
                write_secrets_text(&target(&file.name), &file.content)?;
            } else {
                write_toml_atomically(&target(&file.name), &file.content)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use lanforge_types::network::{Hostname, HostnameOrigin};

    use super::*;

    const CONFIG: &str = "[adblock]\nenabled = true\nrules = \"adblock/global.rules\"\n\n[adblock.groups.kids]\nrules = \"adblock/kids.rules\"\n";

    fn file(name: &str, content: &str) -> BackupFile {
        BackupFile {
            name: name.into(),
            content: content.into(),
        }
    }

    fn bundle(files: Vec<BackupFile>) -> BackupBundle {
        BackupBundle {
            files,
            ..BackupBundle::default()
        }
    }

    #[test]
    fn a_bundle_of_the_expected_files_has_no_issues() {
        let b = bundle(vec![
            file("lanforge.toml", CONFIG),
            file("secrets.toml", "[pppoe]\npassword = \"x\"\n"),
            file("adblock/global.rules", "||ads.example^\n"),
            file("adblock/kids.rules", ""),
        ]);
        assert_eq!(b.issues(), Vec::<String>::new());
    }

    #[test]
    fn unexpected_names_and_unreadable_files_are_refused() {
        for name in [
            "../evil",
            "/etc/passwd",
            "adblock/../../x",
            "./lanforge.toml.bak",
            "adblock/other.rules",
            "sub/secrets.toml",
            "",
        ] {
            let b = bundle(vec![file("lanforge.toml", CONFIG), file(name, "x")]);
            assert_eq!(b.issues().len(), 1, "{name:?}: {:?}", b.issues());
        }
        let duplicate = bundle(vec![
            file("lanforge.toml", CONFIG),
            file("lanforge.toml", CONFIG),
        ]);
        assert_eq!(duplicate.issues().len(), 1);
        assert_eq!(bundle(Vec::new()).issues().len(), 1, "no lanforge.toml");
        let bad_toml = bundle(vec![file("lanforge.toml", "[pppoe]\nenabled = \"yes\"\n")]);
        assert_eq!(
            bad_toml.issues().len(),
            1,
            "a wrong section is refused, not set aside"
        );
        let bad_secrets = bundle(vec![
            file("lanforge.toml", ""),
            file("secrets.toml", "[pppoe]\npassword = 5\n"),
        ]);
        assert_eq!(bad_secrets.issues().len(), 1);
    }

    #[test]
    fn users_and_tokens_must_be_unique_and_digests() {
        use lanforge_types::auth::UserRole;
        let user = |name: &str| UserEntry {
            id: 1,
            username: name.into(),
            password_hash: "h".into(),
            role: UserRole::Admin,
            created_at: 0,
            updated_at: 0,
            last_login: None,
        };
        let token = |digest: &str| ApiTokenEntry {
            id: 1,
            token: digest.into(),
            name: "t".into(),
            created_at: 0,
            last_used: None,
            scopes: Default::default(),
            expires_at: None,
        };
        let mut b = bundle(vec![file("lanforge.toml", "")]);
        b.users = vec![user("a"), user("a")];
        b.api_tokens = vec![token("lf_ak_raw")];
        assert_eq!(b.issues().len(), 2);
        b.users = vec![user("a")];
        b.api_tokens = vec![token(&"a".repeat(64))];
        assert!(b.issues().is_empty());
    }

    #[test]
    fn files_are_read_and_written_verbatim_with_a_private_secrets_file() {
        let src = tempfile::tempdir().unwrap();
        let path = src.path().join("lanforge.toml");
        fs::write(&path, CONFIG).unwrap();
        fs::create_dir(src.path().join("adblock")).unwrap();
        fs::write(src.path().join("adblock/global.rules"), "||a^\n").unwrap();
        fs::write(
            src.path().join(SECRETS_FILE_NAME),
            "# mine\n[pppoe]\npassword = \"p\"\n",
        )
        .unwrap();
        // adblock/kids.rules does not exist: left out, not an error.
        let read = bundle(BackupBundle::read_files(&path).unwrap());
        let names: Vec<_> = read.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["lanforge.toml", "secrets.toml", "adblock/global.rules"]
        );
        assert!(read.issues().is_empty());

        let dst = tempfile::tempdir().unwrap();
        let target = dst.path().join("etc/lanforge.toml");
        read.write_files(&target).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), CONFIG);
        assert_eq!(
            fs::read_to_string(dst.path().join("etc/adblock/global.rules")).unwrap(),
            "||a^\n"
        );
        let secrets = dst.path().join("etc").join(SECRETS_FILE_NAME);
        assert_eq!(
            fs::read_to_string(&secrets).unwrap(),
            "# mine\n[pppoe]\npassword = \"p\"\n"
        );
        assert_eq!(
            fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn only_hand_made_device_settings_are_backed_up() {
        let mac = MacAddr([0, 1, 2, 3, 4, 5]);
        let plain = Device::new(mac);
        assert_eq!(BackupDevice::from_device(&plain), None, "nothing admin-set");

        let mut named = Device::new(mac);
        named.identity_mut().hostname = Hostname {
            name: "tv".into(),
            origin: HostnameOrigin::Dhcp,
        };
        assert_eq!(
            BackupDevice::from_device(&named),
            None,
            "a learned name is not hand-made"
        );
        named.identity_mut().hostname.origin = HostnameOrigin::Static;
        assert_eq!(
            BackupDevice::from_device(&named).and_then(|d| d.hostname),
            Some("tv".to_string())
        );

        let mut set = Device::new(mac);
        let id = set.identity_mut();
        id.class = DeviceClass::Media;
        id.ignore_dns_log = true;
        id.ignored_log_domains = vec!["x.example".into()];
        let backed = BackupDevice::from_device(&set).expect("class and log flags are admin-set");
        let mut restored = DeviceIdentity::new(mac);
        backed.apply_to(&mut restored);
        assert_eq!(restored.class, DeviceClass::Media);
        assert!(restored.ignore_dns_log);
        assert_eq!(restored.ignored_log_domains, ["x.example"]);

        let mut system = set.clone();
        system.identity_mut().origin = Origin::System;
        assert_eq!(
            BackupDevice::from_device(&system),
            None,
            "the router itself"
        );
    }
}
