use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::{env, process};

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;

use lanforge_api::api::{
    BackupBundle, ImportSection, SystemConfigExport, SystemConfigImportResponse,
};
use lanforge_api::config_file::ConfigFile;
use lanforge_crypto::backup::{BackupEnvelope, open, seal};

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: Option<ConfigSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigSubcommand {
    /// Show consolidated system configuration summary (default)
    Show,
    /// Export the configuration file as plain TOML (no secrets, no users: see `backup`)
    Export {
        /// Destination output file path (prints to stdout if omitted)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Import system configuration from a TOML file
    Import {
        /// Input configuration file path (.toml)
        #[arg(value_name = "FILE")]
        file: Option<String>,
        /// Alternative flag for input file
        #[arg(short = 'f', long = "file")]
        file_flag: Option<String>,
        /// Force overwrite existing records instead of merging
        #[arg(short = 'w', long)]
        overwrite: bool,
    },
    /// Save an encrypted backup: configuration files, secrets, users, API tokens and the
    /// settings made by hand on known devices
    Backup {
        /// Destination file (default: lanforge-backup-<date>.json in the current directory)
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Read the password from this environment variable instead of prompting
        #[arg(long, value_name = "VAR")]
        password_env: Option<String>,
    },
    /// Restore an encrypted backup into the running daemon (applied in place, no restart).
    /// With the daemon stopped, use `lanforged --restore FILE` instead.
    Restore {
        /// Backup file made by `lanforge config backup`
        #[arg(value_name = "FILE")]
        file: String,
        /// Read the password from this environment variable instead of prompting
        #[arg(long, value_name = "VAR")]
        password_env: Option<String>,
    },
    /// Validate a configuration file's syntax and structure without modifying the daemon
    Validate {
        /// Input configuration file path (.toml)
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// Edit configuration file in $EDITOR, validate, and optionally import
    Edit {
        /// Configuration file path (defaults to /etc/lanforge/lanforge.toml or lanforge.toml)
        #[arg(value_name = "FILE")]
        file: Option<String>,
        /// Skip prompt and immediately import after editing if validation succeeds
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

impl ConfigArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(ConfigSubcommand::Show) {
            ConfigSubcommand::Show => show_config(client, printer).await,
            ConfigSubcommand::Export { output } => export_config(client, printer, output).await,
            ConfigSubcommand::Import {
                file,
                file_flag,
                overwrite,
            } => {
                let target_file = file
                    .or(file_flag)
                    .ok_or_else(|| eyre!("Please specify an input file to import"))?;
                import_config(client, printer, &target_file, overwrite).await
            }
            ConfigSubcommand::Backup {
                output,
                password_env,
            } => backup_config(client, printer, output, password_env.as_deref()).await,
            ConfigSubcommand::Restore { file, password_env } => {
                restore_config(client, printer, &file, password_env.as_deref()).await
            }
            ConfigSubcommand::Validate { file } => validate_config(printer, &file),
            ConfigSubcommand::Edit { file, yes } => edit_config(client, printer, file, yes).await,
        }
    }
}

// ============================================================================
// Show Handler
// ============================================================================

async fn show_config(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let config = client.system_config_export().await?;

    if printer.json {
        return printer.print_json(&*config);
    }

    render_config_summary(&config, printer);
    Ok(())
}

fn render_config_summary(config: &SystemConfigExport, printer: &Printer) {
    println!();
    println!(
        " {}",
        "Lanforge System Configuration Summary".bold().white()
    );
    println!(" ─────────────────────────────────────────────────────────────");

    // Static Hosts
    println!(
        "   {:<22} {}",
        "Static Hosts:".bold(),
        format!("{} host(s) configured", config.hosts.len()).cyan()
    );

    // DNS
    let adblock_status = if config.dns_adblock_config.enabled {
        format!(
            "Enabled (mode: {}, {} sources, {} custom rules)",
            config.dns_adblock_config.blocking_mode,
            config.dns_adblock_urls.len(),
            config.dns_adblock_rules.as_ref().map_or(0, Vec::len)
        )
        .green()
    } else {
        "Disabled".bright_black()
    };
    println!("   {:<22} {adblock_status}", "DNS Adblocking:".bold());
    println!(
        "   {:<22} {}",
        "DNS Upstreams:".bold(),
        format!("{} server(s)", config.dns_upstreams.len()).cyan()
    );
    println!(
        "   {:<22} {}",
        "DNS Rewrites:".bold(),
        format!("{} local rule(s)", config.dns_rewrites.len()).cyan()
    );
    println!(
        "   {:<22} {}",
        "DNS Allowlist:".bold(),
        format!("{} domain(s)", config.dns_allowlist.len()).cyan()
    );

    // DHCP
    let v4_pools = config.dhcp_v4_pools.as_ref().map_or(0, Vec::len);
    let v6_pools = config.dhcp_v6_pools.as_ref().map_or(0, Vec::len);
    println!(
        "   {:<22} {}",
        "DHCPv4 Pools:".bold(),
        format!("{v4_pools} pool(s)").cyan()
    );
    println!(
        "   {:<22} {}",
        "DHCPv6 Pools:".bold(),
        format!("{v6_pools} pool(s)").cyan()
    );

    // IPv6 RA
    let ra_prefix_count = config.ra_prefixes.as_ref().map_or(0, Vec::len);
    let ra_rdnss_count = config.ra_rdnss.as_ref().map_or(0, Vec::len);
    let ra_dnssl_count = config.ra_dnssl.as_ref().map_or(0, Vec::len);
    println!(
        "   {:<22} {}",
        "IPv6 Router Adv:".bold(),
        format!("{ra_prefix_count} prefix(es), {ra_rdnss_count} RDNSS, {ra_dnssl_count} DNSSL")
            .cyan()
    );

    // PPPoE
    if let Some(ref pppoe) = config.pppoe_config {
        let status = if pppoe.enabled {
            format!("Enabled ({}, user: {})", pppoe.wan_iface, pppoe.username).green()
        } else {
            "Disabled".bright_black()
        };
        println!("   {:<22} {status}", "PPPoE WAN:".bold());
    } else {
        println!(
            "   {:<22} {}",
            "PPPoE WAN:".bold(),
            "Not configured".bright_black()
        );
    }

    // API Tokens
    let tokens_count = config.api_tokens.as_ref().map_or(0, Vec::len);
    println!(
        "   {:<22} {}",
        "API Tokens:".bold(),
        format!("{tokens_count} token(s)").cyan()
    );

    println!();
    printer.info("Use 'lanforge config backup' to save an encrypted backup, or 'lanforge config restore' to restore it.");
}

// ============================================================================
// File Path Resolution Helper
// ============================================================================

fn resolve_candidate_config_file(explicit: Option<&str>) -> PathBuf {
    if let Some(f) = explicit {
        return PathBuf::from(f);
    }
    for candidate in &["/etc/lanforge/lanforge.toml", "lanforge.toml"] {
        let p = Path::new(candidate);
        if p.exists() {
            return p.to_path_buf();
        }
    }
    PathBuf::from("/etc/lanforge/lanforge.toml")
}

// ============================================================================
// Export Handler
// ============================================================================

async fn export_config(
    client: &LanforgeClient,
    printer: &Printer,
    output: Option<String>,
) -> Result<()> {
    // The daemon's file itself: it holds the whole configuration (the adblock rules file
    // and the redb state aside).
    let rendered = client.system_config_toml().await?;
    if let Some(ref path) = output {
        fs::write(path, &rendered)?;
        printer.success(&format!("Exported system configuration to {path}"));
    } else {
        print!("{rendered}");
    }
    Ok(())
}

// ============================================================================
// Backup / Restore Handlers
// ============================================================================

/// The backup password: from `password_env`, or asked on the terminal (twice for a new backup).
fn backup_password(password_env: Option<&str>, confirm: bool) -> Result<String> {
    let password = if let Some(var) = password_env {
        env::var(var).map_err(|_| eyre!("environment variable {var} is not set"))?
    } else {
        let prompt = inquire::Password::new("Backup password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked);
        let prompt = if confirm {
            prompt.with_custom_confirmation_message("Repeat the password:")
        } else {
            prompt.without_confirmation()
        };
        prompt
            .prompt()
            .map_err(|e| eyre!("Password prompt cancelled or failed: {e}"))?
    };
    if password.is_empty() {
        bail!("the backup password must not be empty");
    }
    Ok(password)
}

/// The envelope (JSON text) holding `bundle`, sealed with `password`.
fn seal_bundle(password: &str, bundle: &BackupBundle) -> Result<String> {
    let envelope = seal(password, &serde_json::to_vec(bundle)?)?;
    Ok(serde_json::to_string_pretty(&envelope)?)
}

/// The bundle inside the envelope `text`.
fn open_bundle(password: &str, text: &str) -> Result<BackupBundle> {
    let envelope: BackupEnvelope =
        serde_json::from_str(text).map_err(|_| eyre!("the file is not a lanforge backup"))?;
    let plain = open(password, &envelope)?;
    serde_json::from_slice(&plain).map_err(|e| eyre!("the backup content is not readable: {e}"))
}

/// Writes `bytes` to `path`, readable by the owner only (an existing file is tightened too).
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    Ok(file.sync_all()?)
}

async fn backup_config(
    client: &LanforgeClient,
    printer: &Printer,
    output: Option<String>,
    password_env: Option<&str>,
) -> Result<()> {
    let password = backup_password(password_env, true)?;
    let bundle = client.backup().await?;
    let sealed = seal_bundle(&password, &bundle)?;
    let path = output.unwrap_or_else(|| {
        format!(
            "lanforge-backup-{}.json",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        )
    });
    write_private_file(Path::new(&path), sealed.as_bytes())?;
    printer.success(&format!(
        "Encrypted backup saved to {path}: {} file(s), {} user(s), {} API token(s), {} device(s)",
        bundle.files.len(),
        bundle.users.len(),
        bundle.api_tokens.len(),
        bundle.devices.len()
    ));
    Ok(())
}

async fn restore_config(
    client: &LanforgeClient,
    printer: &Printer,
    file: &str,
    password_env: Option<&str>,
) -> Result<()> {
    let text = fs::read_to_string(file).map_err(|e| eyre!("Failed to read '{file}': {e}"))?;
    let password = backup_password(password_env, false)?;
    let bundle = open_bundle(&password, &text)?;
    let done = client.restore(bundle).await?;
    if printer.json {
        return printer.print_json(&done);
    }
    printer.success(&done.message);
    Ok(())
}

// ============================================================================
// Import Handler
// ============================================================================

async fn import_config(
    client: &LanforgeClient,
    printer: &Printer,
    file_path: &str,
    overwrite: bool,
) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let cfg = ConfigFile::parse(&content)
        .map_err(|e| eyre!("Failed to parse TOML configuration '{file_path}': {e}"))?;
    let mut system_config = SystemConfigExport::from(&cfg);
    system_config.overwrite = overwrite;

    let resp = client.system_config_import(system_config).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    render_import_results(&resp, printer);
    Ok(())
}

fn render_import_results(resp: &SystemConfigImportResponse, printer: &Printer) {
    println!();
    if resp.total_success {
        printer.success("System configuration imported successfully:");
    } else {
        printer.error("System configuration import completed with errors:");
    }

    for res in &resp.results {
        let name = format_import_section(res.section);
        if res.success {
            if res.count > 0 || is_singleton_section(res.section) {
                println!("  {} Imported {} {}", "✓".green().bold(), res.count, name);
            }
        } else {
            let err_msg = res.error.as_deref().unwrap_or("unknown error");
            println!(
                "  {} Failed to import {}: {}",
                "✗".red().bold(),
                name,
                err_msg
            );
        }
    }
    println!();
}

// ============================================================================
// Validate Handler
// ============================================================================

fn validate_config(printer: &Printer, file_path: &str) -> Result<()> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| eyre!("Failed to read file '{file_path}': {e}"))?;
    let cfg = ConfigFile::parse(&content).map_err(|e| eyre!("TOML validation failed: {e}"))?;
    // Rules and addresses served (entries `[dns]` gets wrong are left out).
    let dns = cfg.dns.to_config().0;

    if printer.json {
        let json_report = serde_json::json!({
            "valid": true,
            "format": "toml",
            "hosts": cfg.hosts.len(),
            "dhcp_v4_pools": cfg.dhcp.v4.pools.len(),
            "dhcp_v6_pools": cfg.dhcp.v6.pools.len(),
            "dns_rewrites": dns.rewrites.len(),
            "dns_upstreams": dns.upstreams.len(),
            "adblock_sources": cfg.adblock.sources.len(),
        });
        return printer.print_json(&json_report);
    }

    println!();
    printer.success(&format!(
        "Configuration file '{file_path}' is structurally valid (TOML schema) and ready for import."
    ));
    println!("  · Static hosts: {}", cfg.hosts.len());
    println!("  · DHCPv4 pools: {}", cfg.dhcp.v4.pools.len());
    println!("  · DHCPv6 pools: {}", cfg.dhcp.v6.pools.len());
    println!("  · DNS rewrites: {}", dns.rewrites.len());
    println!("  · DNS upstreams: {}", dns.upstreams.len());
    println!("  · Adblock source URLs: {}", cfg.adblock.sources.len());
    println!();
    Ok(())
}

// ============================================================================
// Edit Handler
// ============================================================================

async fn edit_config(
    client: &LanforgeClient,
    printer: &Printer,
    file: Option<String>,
    auto_yes: bool,
) -> Result<()> {
    let target_path = resolve_candidate_config_file(file.as_deref());

    if !target_path.exists() {
        let rendered = client.system_config_toml().await.or_else(|_| {
            ConfigFile::default()
                .render_full()
                .map_err(|e| eyre!("Failed to render configuration: {e}"))
        })?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target_path, &rendered)?;
        printer.info(&format!(
            "Created initial configuration file at '{}'",
            target_path.display()
        ));
    }

    let editor = env::var("EDITOR")
        .or_else(|_| env::var("VISUAL"))
        .unwrap_or_else(|_| "nano".to_string());

    loop {
        let status = process::Command::new(&editor)
            .arg(&target_path)
            .status()
            .map_err(|e| eyre!("Failed to launch editor '{editor}': {e}"))?;

        if !status.success() {
            bail!("Editor exited with error status: {status}");
        }

        let content = fs::read_to_string(&target_path).map_err(|e| {
            eyre!(
                "Failed to read updated file '{}': {e}",
                target_path.display()
            )
        })?;

        match ConfigFile::parse(&content) {
            Ok(parsed) => {
                printer.success("Configuration syntax and schema validated successfully.");
                let should_import = if auto_yes {
                    true
                } else {
                    inquire::Confirm::new("Import edited configuration into daemon now?")
                        .with_default(true)
                        .prompt()
                        .unwrap_or(false)
                };

                if should_import {
                    let export = SystemConfigExport::from(&parsed);
                    let resp = client.system_config_import(export).await?;
                    render_import_results(&resp, printer);
                } else {
                    printer.info("Changes saved to file, but not imported into daemon.");
                }
                break;
            }
            Err(e) => {
                printer.error(&format!("Validation failed: {e}"));
                let retry =
                    inquire::Confirm::new("Do you want to re-open the editor to fix the errors?")
                        .with_default(true)
                        .prompt()
                        .unwrap_or(false);
                if !retry {
                    bail!(
                        "Configuration edit aborted due to validation errors. File preserved at '{}'",
                        target_path.display()
                    );
                }
            }
        }
    }

    Ok(())
}

#[must_use]
pub const fn format_import_section(section: ImportSection) -> &'static str {
    match section {
        ImportSection::Hosts => "hosts",
        ImportSection::DnsRewrites => "DNS rewrites",
        ImportSection::DnsUpstreams => "DNS upstreams",
        ImportSection::DnsAdblockConfig => "DNS adblock config",
        ImportSection::DnsAdblockUrls => "DNS adblock URLs",
        ImportSection::DnsAllowlist => "DNS allowlist entries",
        ImportSection::DnsAdblockRules => "DNS adblock rules",
        ImportSection::ApiTokens => "API tokens",
        ImportSection::DhcpV4Pools => "DHCPv4 pools",
        ImportSection::DhcpV6Pools => "DHCPv6 pools",
        ImportSection::RaPrefixes => "RA prefixes",
        ImportSection::RaRdnss => "RA RDNSS options",
        ImportSection::RaDnssl => "RA DNSSL options",
        ImportSection::PppoeConfig => "PPPoE configuration",
        ImportSection::DhcpOptions => "DHCP options",
        ImportSection::DnsReverseResolvers => "DNS reverse resolvers",
        ImportSection::FirewallConfig => "firewall configuration",
        ImportSection::TrafficConfig => "traffic configuration",
    }
}

#[must_use]
pub const fn is_singleton_section(section: ImportSection) -> bool {
    matches!(
        section,
        ImportSection::DnsAdblockConfig
            | ImportSection::PppoeConfig
            | ImportSection::DhcpOptions
            | ImportSection::FirewallConfig
            | ImportSection::TrafficConfig
    )
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_api::api::BackupFile;
    use lanforge_types::auth::{UserEntry, UserRole};

    #[test]
    fn test_format_import_section() {
        assert_eq!(format_import_section(ImportSection::Hosts), "hosts");
        assert_eq!(
            format_import_section(ImportSection::DnsRewrites),
            "DNS rewrites"
        );
        assert_eq!(
            format_import_section(ImportSection::PppoeConfig),
            "PPPoE configuration"
        );
        assert!(is_singleton_section(ImportSection::PppoeConfig));
        assert!(!is_singleton_section(ImportSection::Hosts));
    }

    #[test]
    fn test_validate_config_file() {
        use std::io::Write;
        let printer = Printer::new(false, true, true);

        let mut toml_tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("temp toml");
        let valid_toml = r#"
[system]
iface = "eth0"

[dhcp.v4.pools.lan]
range = "192.168.1.100-192.168.1.200"

[hosts.nas]
mac = "00:11:22:33:44:55"
v4 = "192.168.1.10"
"#;
        toml_tmp
            .write_all(valid_toml.as_bytes())
            .expect("write tmp toml");
        assert!(validate_config(&printer, toml_tmp.path().to_str().unwrap()).is_ok());

        let mut invalid_tmp = tempfile::NamedTempFile::new().expect("temp file");
        invalid_tmp
            .write_all(b"not json or toml {::")
            .expect("write tmp");
        assert!(validate_config(&printer, invalid_tmp.path().to_str().unwrap()).is_err());
    }

    fn sample_bundle() -> BackupBundle {
        BackupBundle {
            files: vec![BackupFile {
                name: "lanforge.toml".into(),
                content: "[system]\niface = \"lan0\"\n".into(),
            }],
            users: vec![UserEntry {
                id: 1,
                username: "admin".into(),
                password_hash: "$argon2id$hash".into(),
                role: UserRole::Admin,
                created_at: 10,
                updated_at: 11,
                last_login: None,
            }],
            ..BackupBundle::default()
        }
    }

    #[test]
    fn a_sealed_bundle_opens_with_its_password_only() {
        let bundle = sample_bundle();
        let sealed = seal_bundle("correct horse", &bundle).expect("seal");
        assert!(
            !sealed.contains("argon2id$hash") && !sealed.contains("lan0"),
            "the content is encrypted"
        );
        assert_eq!(open_bundle("correct horse", &sealed).expect("open"), bundle);
        assert!(open_bundle("wrong", &sealed).is_err());
        assert!(open_bundle("correct horse", "not json").is_err());
    }

    #[test]
    fn the_backup_file_is_owner_only_even_when_it_existed() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("backup.json");
        fs::write(&path, "old").expect("old file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private_file(&path, b"new").expect("write");
        assert_eq!(fs::read(&path).expect("read"), b"new");
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
