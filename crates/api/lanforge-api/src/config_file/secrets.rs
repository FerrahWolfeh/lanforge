//! `secrets.toml`: the credentials kept out of `lanforge.toml`, next to it in the same directory.
//!
//! The file is owner-only (mode 0600). One that group or others can read or write is refused
//! (`SecretsState::SetAside`): the secrets in it are not used and nothing is written over it.

use std::fs::{self, OpenOptions};
use std::io::{self, Error, ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;

use serde::{Deserialize, Serialize};

use super::ConfigFile;

/// File name of the secrets file, in the config file's directory.
pub const SECRETS_FILE_NAME: &str = "secrets.toml";

/// Bits of the file mode that make a secrets file readable or writable beyond its owner.
const GROUP_OTHER_BITS: u32 = 0o077;

/// File form of `secrets.toml`. Each kind of secret is its own section, so more can be added.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsFile {
    #[serde(default)]
    pub pppoe: PppoeSecrets,
}

/// `[pppoe]` of `secrets.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// What reading `secrets.toml` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsState {
    /// No such file: nothing to apply.
    Missing,
    /// Read and parsed.
    Loaded(SecretsFile),
    /// Refused (too open, unreadable or not valid): its secrets are not applied, the file is
    /// never written over. Carries the reason, worded for the admin.
    SetAside(String),
}

impl SecretsState {
    /// Whether the file was refused.
    #[must_use]
    pub fn is_set_aside(&self) -> bool {
        matches!(self, Self::SetAside(_))
    }
}

impl SecretsFile {
    /// Path of the secrets file that goes with the config file at `config_path`.
    #[must_use]
    pub fn path_for(config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(SECRETS_FILE_NAME)
    }

    /// Reads the secrets file that goes with `config_path`.
    #[must_use]
    pub fn load(config_path: &Path) -> SecretsState {
        let path = Self::path_for(config_path);
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return SecretsState::Missing,
            Err(e) => {
                return SecretsState::SetAside(format!("cannot read {}: {e}", path.display()));
            }
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & GROUP_OTHER_BITS != 0 {
            return SecretsState::SetAside(format!(
                "{} has mode {mode:04o}: group and others must have no access (chmod 600)",
                path.display()
            ));
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                return SecretsState::SetAside(format!("cannot read {}: {e}", path.display()));
            }
        };
        match toml::from_str(&text) {
            Ok(file) => SecretsState::Loaded(file),
            Err(e) => SecretsState::SetAside(format!(
                "{} is not valid: {}",
                path.display(),
                e.message().trim()
            )),
        }
    }

    /// Writes the secrets file that goes with `config_path`: a temporary file in the same
    /// directory (mode 0600 from creation) renamed over it.
    ///
    /// # Errors
    /// Serializing, writing or renaming fails.
    pub fn write(&self, config_path: &Path) -> io::Result<()> {
        let text = toml::to_string(self).map_err(Error::other)?;
        write_secrets_text(&Self::path_for(config_path), &text)
    }
}

/// Writes `text` to the secrets file `path`: a temporary file in the same directory (mode 0600
/// from creation) renamed over it.
///
/// # Errors
/// Writing or renaming fails.
pub fn write_secrets_text(path: &Path, text: &str) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(".{SECRETS_FILE_NAME}.tmp.{}", process::id()));
    let _ = fs::remove_file(&tmp);
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    })();
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

impl ConfigFile {
    /// Applies the secrets to the file's sections and returns what the admin should know.
    ///
    /// The secrets file wins. An inline `[pppoe] password` still applies when there is no secret
    /// for it (so a router set up before `secrets.toml` keeps running) but is reported.
    pub fn apply_secrets(&mut self, secrets: &SecretsState) -> Vec<String> {
        let mut issues = Vec::new();
        let secret = match secrets {
            SecretsState::Loaded(file) => file.pppoe.password.as_deref(),
            SecretsState::SetAside(reason) => {
                issues.push(format!(
                    "{SECRETS_FILE_NAME} was refused and its secrets are not applied: {reason}"
                ));
                None
            }
            SecretsState::Missing => None,
        };
        if !self.pppoe.password.is_empty() {
            issues.push(format!(
                "[pppoe] password is set in the configuration file: move it to [pppoe] in {SECRETS_FILE_NAME}"
            ));
        }
        if let Some(password) = secret {
            self.pppoe.password = password.to_string();
        }
        issues
    }
}

/// `lanforge.toml` text without the secrets it may still hold inline, for exports.
#[must_use]
pub fn without_secrets(text: &str) -> String {
    let Ok(mut doc) = text.parse::<toml_edit::DocumentMut>() else {
        return text.to_string();
    };
    let removed = doc
        .get_mut("pppoe")
        .and_then(toml_edit::Item::as_table_like_mut)
        .is_some_and(|pppoe| pppoe.remove("password").is_some());
    if removed {
        doc.to_string()
    } else {
        text.to_string()
    }
}
