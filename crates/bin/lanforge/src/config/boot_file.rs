use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use lanforge_api::config_file::{ConfigFile, write_toml_atomically};
use tracing::info;

/// Checks the config file at boot.
///
/// A missing one is created with the defaults (when writable); one that is not TOML at all
/// stops the start (a section the file gets wrong is set aside by the loader instead).
pub fn ensure_boot_config(config_path: &Path, is_writable: bool) -> Result<()> {
    if config_path.exists() {
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read '{}'", config_path.display()))?;
        ConfigFile::parse_lenient(&content)
            .with_context(|| format!("Invalid configuration '{}'", config_path.display()))?;
        return Ok(());
    }
    info!(
        "[config] Config file '{}' does not exist; initializing defaults.",
        config_path.display()
    );
    if is_writable {
        let rendered = ConfigFile::default().render_full()?;
        write_toml_atomically(config_path, &rendered)
            .with_context(|| format!("Failed to initialize '{}'.", config_path.display()))?;
    }
    Ok(())
}
