use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use lanforge_api::config_file::{ConfigFile, Section, section_hashes, write_toml_atomically};
use lanforge_db::LanforgeDb;
use tracing::info;

/// Synchronizes configuration between `lanforge.toml` and `config.redb` during boot and reload.
pub fn sync_boot_config(
    config_path: &Path,
    db: &LanforgeDb,
    is_writable: bool,
) -> Result<ConfigFile> {
    let file_cfg = if config_path.exists() {
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read '{}'", config_path.display()))?;
        // Set-aside sections are file-owned (never synced); the loader already reported them.
        match ConfigFile::parse_lenient(&content) {
            Ok((c, _)) => c,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Invalid configuration '{}'; refusing to start config sync",
                        config_path.display()
                    )
                });
            }
        }
    } else {
        info!(
            "[config] Config file '{}' does not exist; initializing defaults.",
            config_path.display()
        );
        let def = ConfigFile::default();
        if is_writable {
            let rendered = def.render_full()?;
            write_toml_atomically(config_path, &rendered)
                .with_context(|| format!("Failed to initialize '{}'.", config_path.display()))?;
        }
        def
    };

    let file_hashes = section_hashes(&file_cfg);
    let mut hash_strings = BTreeMap::new();
    for (sec, h) in &file_hashes {
        hash_strings.insert(sec.name().to_string(), *h);
    }

    // 1. If meta has no hashes -> seed DB tables from the file, store hashes
    let has_hashes = db.has_config_section_hashes()?;
    if !has_hashes {
        info!("[config] Initializing configuration hashes in database metadata.");
        db.set_config_section_hashes(&hash_strings)?;
        return Ok(file_cfg);
    }

    // 2. Find offline edits before applying any, so the original file is backed up first.
    let mut offline_edits = Vec::new();
    for sec in Section::ALL.iter().filter(|s| s.is_dynamic()) {
        let stored_hash = db.get_config_section_hash(sec.name())?;
        let file_h = file_hashes.get(sec).copied();

        // hash == stored -> file was not modified offline: the DB is the source of truth.
        if file_h != stored_hash {
            // hash != stored -> user edited offline! Apply file section to DB.
            info!(
                "[config] Section [{}] was edited offline; applying file changes to database.",
                sec.name()
            );
            offline_edits.push(*sec);
        }
    }

    // 3. Back up the original before changing the database when write-back is enabled.
    // A failed required backup aborts reconciliation, preserving the only edited copy.
    if !offline_edits.is_empty() {
        if config_path.exists() && is_writable {
            let bak_path = config_path.with_extension("toml.bak");
            fs::copy(config_path, &bak_path).with_context(|| {
                format!(
                    "Failed to back up '{}' to '{}' before applying offline edits",
                    config_path.display(),
                    bak_path.display()
                )
            })?;
            info!(
                "[config] Created configuration backup at '{}'",
                bak_path.display()
            );
        } else if config_path.exists() {
            info!("[config] Skipping config backup because config write-back is disabled.");
        }

        // Store new hashes only after all edited sections have been applied.
        db.set_config_section_hashes(&hash_strings)?;
    }

    Ok(file_cfg)
}

#[cfg(all(test, feature = "dns"))]
mod tests {
    use super::*;
    use lanforge_db::config_keys::{
        ADBLOCK_CONFIG, ADBLOCK_RULES, ADBLOCK_URLS, DNS_ALLOWLIST, DNS_REVERSE_RESOLVERS,
        DNS_REWRITES, DNS_UPSTREAM_MODE, DNS_UPSTREAMS,
    };
    use tempfile::tempdir;

    /// `[dns]` and `[adblock]` are file-owned: neither the first boot nor an offline edit writes
    /// their keys, which a cut-over would read as config an older binary left. The `[adblock]`
    /// here is the old sync form (an allowlist in the file), which used to be copied to redb.
    #[test]
    fn dns_and_adblock_keys_are_never_written_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let db = LanforgeDb::open_in_memory().expect("open in-memory config DB");
        let dns = "[dns]\nupstream_mode = \"parallel\"\n\n[dns.upstreams.default]\n\
                   addresses = [\"udp://192.0.2.53:53\"]\n\n[dns.rewrites]\n\
                   \"nas.lan\" = \"192.0.2.10\"\n\n";
        let adblock = |domain: &str| {
            format!(
                "[adblock]\nenabled = true\nallowlist = [\"{domain}\"]\n\n[adblock.sources.s]\nurl = \"https://example.com/l\"\n"
            )
        };

        fs::write(&path, format!("{dns}{}", adblock("a.example"))).unwrap();
        sync_boot_config(&path, &db, true).unwrap();
        fs::write(&path, format!("{dns}{}", adblock("b.example"))).unwrap();
        sync_boot_config(&path, &db, true).unwrap();

        assert!(db.get(DNS_REWRITES).unwrap().is_none());
        assert!(db.get(DNS_UPSTREAMS).unwrap().is_none());
        assert!(db.get(DNS_UPSTREAM_MODE).unwrap().is_none());
        assert!(db.get(DNS_REVERSE_RESOLVERS).unwrap().is_none());
        assert!(db.get(DNS_ALLOWLIST).unwrap().is_none());
        assert!(db.get(ADBLOCK_CONFIG).unwrap().is_none());
        assert!(db.get(ADBLOCK_URLS).unwrap().is_none());
        assert!(db.get(ADBLOCK_RULES).unwrap().is_none());
    }
}
