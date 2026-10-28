use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use lanforge_api::api::SystemConfigExport;
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
        let sections: Vec<_> = Section::ALL
            .iter()
            .copied()
            .filter(Section::is_dynamic)
            .collect();
        apply_sections_to_db(db, &sections, &file_cfg)?;
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

        apply_sections_to_db(db, &offline_edits, &file_cfg)?;

        // Store new hashes only after all edited sections have been applied.
        db.set_config_section_hashes(&hash_strings)?;
    }

    Ok(file_cfg)
}

fn apply_sections_to_db(db: &LanforgeDb, sections: &[Section], cfg: &ConfigFile) -> Result<()> {
    // `[adblock]` is the only section still synced; `[dns]` is file-owned (config-storage step 2)
    // and its keys must not come back: the cut-over would read them as unmigrated config.
    if !sections.contains(&Section::Adblock) {
        return Ok(());
    }
    #[cfg(any(feature = "dns", feature = "adblock"))]
    {
        let export = SystemConfigExport::from(cfg);
        let allowlist: Vec<_> = export
            .dns_allowlist
            .iter()
            .map(|entry| entry.domain.clone())
            .collect();
        let rules = export.dns_adblock_rules.as_deref().unwrap_or_default();
        db.write(|tx| {
            tx.replace_adblock(
                &export.dns_adblock_config,
                &allowlist,
                &export.dns_adblock_urls,
                rules,
            )
        })?;
    }
    #[cfg(not(any(feature = "dns", feature = "adblock")))]
    let _ = (db, cfg);
    Ok(())
}

#[cfg(all(test, feature = "dns"))]
mod tests {
    use super::*;
    use lanforge_db::DnsStore;
    use lanforge_db::config_keys::{
        DNS_REVERSE_RESOLVERS, DNS_REWRITES, DNS_UPSTREAM_MODE, DNS_UPSTREAMS,
    };
    use tempfile::tempdir;

    fn config_with_allowlist(domain: &str) -> String {
        format!("[adblock]\nallowlist = [\"{domain}\"]\n")
    }

    fn allowlist(db: &LanforgeDb) -> Vec<String> {
        db.load_dns_allowlist()
            .unwrap()
            .into_iter()
            .map(|(_, d)| d)
            .collect()
    }

    fn open_db() -> LanforgeDb {
        LanforgeDb::open_in_memory().expect("open in-memory config DB")
    }

    #[test]
    fn first_boot_seeds_dynamic_config_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        fs::write(&path, config_with_allowlist("a.example")).unwrap();
        let db = open_db();

        sync_boot_config(&path, &db, true).unwrap();

        assert_eq!(allowlist(&db), ["a.example"]);
        assert!(db.has_config_section_hashes().unwrap());
    }

    #[test]
    fn offline_edit_is_backed_up_before_being_applied() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let db = open_db();

        fs::write(&path, config_with_allowlist("a.example")).unwrap();
        sync_boot_config(&path, &db, true).unwrap();

        let edited = config_with_allowlist("b.example");
        fs::write(&path, &edited).unwrap();
        sync_boot_config(&path, &db, true).unwrap();

        assert_eq!(
            fs::read_to_string(path.with_extension("toml.bak")).unwrap(),
            edited
        );
        assert_eq!(allowlist(&db), ["b.example"]);
    }

    #[test]
    fn backup_failure_does_not_apply_offline_edit_or_advance_hashes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let db = open_db();

        fs::write(&path, config_with_allowlist("a.example")).unwrap();
        sync_boot_config(&path, &db, true).unwrap();
        let old_hash = db.get_config_section_hash(Section::Adblock.name()).unwrap();

        fs::write(&path, config_with_allowlist("b.example")).unwrap();
        fs::create_dir(path.with_extension("toml.bak")).unwrap();
        assert!(sync_boot_config(&path, &db, true).is_err());

        assert_eq!(
            db.get_config_section_hash(Section::Adblock.name()).unwrap(),
            old_hash
        );
        assert_eq!(allowlist(&db), ["a.example"]);
    }

    #[test]
    fn read_only_config_mode_applies_edits_without_backup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let db = open_db();

        fs::write(&path, config_with_allowlist("a.example")).unwrap();
        sync_boot_config(&path, &db, false).unwrap();
        fs::write(&path, config_with_allowlist("b.example")).unwrap();

        sync_boot_config(&path, &db, false).unwrap();

        assert!(!path.with_extension("toml.bak").exists());
        assert_eq!(allowlist(&db), ["b.example"]);
    }

    /// `[dns]` is file-owned: neither the first boot nor an offline edit of `[adblock]` writes
    /// the DNS keys, which the cut-over would read as config an older binary left.
    #[test]
    fn dns_keys_are_never_written_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        let db = open_db();
        let dns = "[dns]\nupstream_mode = \"parallel\"\n\n[dns.upstreams.default]\n\
                   addresses = [\"udp://192.0.2.53:53\"]\n\n[dns.rewrites]\n\
                   \"nas.lan\" = \"192.0.2.10\"\n\n";

        fs::write(
            &path,
            format!("{dns}{}", config_with_allowlist("a.example")),
        )
        .unwrap();
        sync_boot_config(&path, &db, true).unwrap();
        fs::write(
            &path,
            format!("{dns}{}", config_with_allowlist("b.example")),
        )
        .unwrap();
        sync_boot_config(&path, &db, true).unwrap();

        assert_eq!(allowlist(&db), ["b.example"]);
        assert_eq!(db.get(DNS_REWRITES).unwrap(), None);
        assert!(db.get(DNS_UPSTREAMS).unwrap().is_none());
        assert_eq!(db.get(DNS_UPSTREAM_MODE).unwrap(), None);
        assert_eq!(db.get(DNS_REVERSE_RESOLVERS).unwrap(), None);
    }
}
