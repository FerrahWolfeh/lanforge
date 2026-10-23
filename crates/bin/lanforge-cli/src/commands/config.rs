use std::path::{Path, PathBuf};

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use rand::RngExt;
use serde::{Deserialize, Serialize};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use lanforge_api::api::devices::HostConfigEntry;
use lanforge_api::api::dns::{AllowlistEntry, DnsUpstreamConfig};
use lanforge_api::api::system::ExportedApiToken;
use lanforge_api::api::{ImportSection, SystemConfigExport, SystemConfigImportResponse};
use lanforge_api::config_file::{ConfigFile, Section, section_hashes};
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::firewall::FirewallConfig;
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::traffic::TrafficConfig;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: Option<ConfigSubcommand>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Toml,
    Json,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigSubcommand {
    /// Show consolidated system configuration summary (default)
    Show,
    /// Export system configuration snapshot to TOML or JSON
    Export {
        /// Destination output file path (prints to stdout if omitted)
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Export format (toml or json; defaults to toml, or auto-detected from output extension)
        #[arg(long, value_enum)]
        format: Option<ExportFormat>,
        /// Encrypt the API tokens secrets block with a password (JSON only)
        #[arg(short = 'e', long)]
        encrypt_secrets: bool,
        /// Encryption password (if omitted and --encrypt-secrets is set, you will be prompted)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Import system configuration from a TOML or JSON file
    Import {
        /// Input configuration file path (.toml or .json)
        #[arg(value_name = "FILE")]
        file: Option<String>,
        /// Alternative flag for input file
        #[arg(short = 'f', long = "file")]
        file_flag: Option<String>,
        /// Force overwrite existing records instead of merging
        #[arg(short = 'w', long)]
        overwrite: bool,
        /// Decryption password (if JSON file contains encrypted secrets and password is omitted, you will be prompted)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Validate configuration file syntax and structure without modifying the daemon
    Validate {
        /// Input configuration file path (.toml or .json)
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// Show differences between configuration file and live daemon database
    Diff {
        /// Configuration file path (defaults to /etc/lanforge/lanforge.toml or lanforge.toml)
        #[arg(value_name = "FILE")]
        file: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncryptedApiTokens {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ApiTokensExport {
    Encrypted(EncryptedApiTokens),
    Plain(Vec<ExportedApiToken>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileConfigExport {
    pub hosts: Vec<HostConfigEntry>,
    pub dns_rewrites: Vec<RewriteRule>,
    pub dns_upstreams: Vec<DnsUpstreamConfig>,
    pub dns_adblock_config: AdblockDbConfig,
    pub dns_adblock_urls: Vec<AdblockUrlEntry>,
    pub dns_allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    pub dns_adblock_rules: Option<Vec<AdblockRuleEntry>>,
    #[serde(default)]
    pub api_tokens: Option<ApiTokensExport>,
    pub dhcp_v4_pools: Option<Vec<Dhcpv4Pool>>,
    pub dhcp_v6_pools: Option<Vec<Dhcpv6Pool>>,
    pub ra_prefixes: Option<Vec<RAPrefix>>,
    pub ra_rdnss: Option<Vec<RdnssConfig>>,
    pub ra_dnssl: Option<Vec<DnsslConfig>>,
    pub pppoe_config: Option<Box<PppoeConfig>>,
    #[serde(default)]
    pub dhcp_options: Option<Box<DhcpOptionsConfig>>,
    #[serde(default)]
    pub dns_reverse_resolvers: Option<Vec<DnsReverseResolver>>,
    #[serde(default)]
    pub firewall_config: Option<Box<FirewallConfig>>,
    #[serde(default)]
    pub traffic_config: Option<Box<TrafficConfig>>,
    #[serde(default)]
    pub overwrite: bool,
}

impl ConfigArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(ConfigSubcommand::Show) {
            ConfigSubcommand::Show => show_config(client, printer).await,
            ConfigSubcommand::Export {
                output,
                format,
                encrypt_secrets,
                password,
            } => export_config(client, printer, output, format, encrypt_secrets, password).await,
            ConfigSubcommand::Import {
                file,
                file_flag,
                overwrite,
                password,
            } => {
                let target_file = file
                    .or(file_flag)
                    .ok_or_else(|| eyre!("Please specify an input file to import"))?;
                import_config(client, printer, &target_file, overwrite, password).await
            }
            ConfigSubcommand::Validate { file } => validate_config(printer, &file),
            ConfigSubcommand::Diff { file } => diff_config(client, printer, file).await,
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
    printer.info("Use 'lanforge config export' to save full JSON backup, or 'lanforge config import' to restore.");
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
    format_arg: Option<ExportFormat>,
    encrypt_secrets: bool,
    password: Option<String>,
) -> Result<()> {
    let resolved_format = format_arg.unwrap_or_else(|| {
        output.as_ref().map_or(ExportFormat::Toml, |path| {
            if Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                ExportFormat::Json
            } else {
                ExportFormat::Toml
            }
        })
    });

    let config = client.system_config_export().await?;

    if resolved_format == ExportFormat::Toml {
        let config_file = ConfigFile::from(&*config);
        let rendered = config_file
            .render_full()
            .map_err(|e| eyre!("Failed to render configuration TOML: {e}"))?;

        if let Some(ref path) = output {
            std::fs::write(path, &rendered)?;
            printer.success(&format!("Exported system configuration to {path}"));
        } else {
            print!("{rendered}");
        }
        return Ok(());
    }

    let api_tokens_section = if let Some(tokens) = config.api_tokens {
        if encrypt_secrets || password.is_some() {
            let pass = match password {
                Some(p) => p,
                None => prompt_password("Enter encryption password for secrets block:")?,
            };
            let plain_bytes = serde_json::to_vec(&tokens)?;
            let enc = encrypt_secrets_block(&pass, &plain_bytes)?;
            Some(ApiTokensExport::Encrypted(enc))
        } else {
            Some(ApiTokensExport::Plain(tokens))
        }
    } else {
        None
    };

    let file_export = FileConfigExport {
        hosts: config.hosts,
        dns_rewrites: config.dns_rewrites,
        dns_upstreams: config.dns_upstreams,
        dns_adblock_config: config.dns_adblock_config,
        dns_adblock_urls: config.dns_adblock_urls,
        dns_allowlist: config.dns_allowlist,
        dns_adblock_rules: config.dns_adblock_rules,
        api_tokens: api_tokens_section,
        dhcp_v4_pools: config.dhcp_v4_pools,
        dhcp_v6_pools: config.dhcp_v6_pools,
        ra_prefixes: config.ra_prefixes,
        ra_rdnss: config.ra_rdnss,
        ra_dnssl: config.ra_dnssl,
        pppoe_config: config.pppoe_config,
        dhcp_options: config.dhcp_options,
        dns_reverse_resolvers: config.dns_reverse_resolvers,
        firewall_config: config.firewall_config,
        traffic_config: config.traffic_config,
        overwrite: config.overwrite,
    };

    let json = serde_json::to_string_pretty(&file_export)?;

    if let Some(ref path) = output {
        std::fs::write(path, &json)?;
        printer.success(&format!("Exported system configuration to {path}"));
    } else {
        println!("{json}");
    }

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
    password: Option<String>,
) -> Result<()> {
    let content = std::fs::read_to_string(file_path)?;

    let is_json = Path::new(file_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || (serde_json::from_str::<serde_json::Value>(&content).is_ok()
            && !content.trim_start().starts_with('[')
            && !content.trim_start().starts_with('#'));

    let system_config = if is_json {
        let file_export: FileConfigExport = serde_json::from_str(&content)
            .map_err(|e| eyre!("Failed to parse JSON configuration file '{file_path}': {e}"))?;

        let api_tokens = match file_export.api_tokens {
            Some(ApiTokensExport::Encrypted(enc)) => {
                let pass = match password {
                    Some(p) => p,
                    None => prompt_password("Enter password to decrypt secrets block:")?,
                };
                let plain_bytes = decrypt_secrets_block(&pass, &enc)?;
                let tokens: Vec<ExportedApiToken> = serde_json::from_slice(&plain_bytes)
                    .map_err(|e| eyre!("Decrypted data is corrupted or invalid: {e}"))?;
                Some(tokens)
            }
            Some(ApiTokensExport::Plain(tokens)) => Some(tokens),
            None => None,
        };

        SystemConfigExport {
            hosts: file_export.hosts,
            dns_rewrites: file_export.dns_rewrites,
            dns_upstreams: file_export.dns_upstreams,
            dns_adblock_config: file_export.dns_adblock_config,
            dns_adblock_urls: file_export.dns_adblock_urls,
            dns_allowlist: file_export.dns_allowlist,
            dns_adblock_rules: file_export.dns_adblock_rules,
            api_tokens,
            dhcp_v4_pools: file_export.dhcp_v4_pools,
            dhcp_v6_pools: file_export.dhcp_v6_pools,
            ra_prefixes: file_export.ra_prefixes,
            ra_rdnss: file_export.ra_rdnss,
            ra_dnssl: file_export.ra_dnssl,
            pppoe_config: file_export.pppoe_config,
            dhcp_options: file_export.dhcp_options,
            dns_reverse_resolvers: file_export.dns_reverse_resolvers,
            firewall_config: file_export.firewall_config,
            traffic_config: file_export.traffic_config,
            overwrite,
        }
    } else {
        let cfg = ConfigFile::parse(&content)
            .map_err(|e| eyre!("Failed to parse TOML configuration '{file_path}': {e}"))?;
        let mut export = SystemConfigExport::from(&cfg);
        export.overwrite = overwrite;
        export
    };

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
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| eyre!("Failed to read file '{file_path}': {e}"))?;

    let is_json = Path::new(file_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || (serde_json::from_str::<serde_json::Value>(&content).is_ok()
            && !content.trim_start().starts_with('[')
            && !content.trim_start().starts_with('#'));

    if !is_json {
        let cfg = ConfigFile::parse(&content).map_err(|e| eyre!("TOML validation failed: {e}"))?;

        if printer.json {
            let json_report = serde_json::json!({
                "valid": true,
                "format": "toml",
                "hosts": cfg.hosts.len(),
                "dhcp_v4_pools": cfg.dhcp.v4.pools.len(),
                "dhcp_v6_pools": cfg.dhcp.v6.pools.len(),
                "dns_rewrites": cfg.dns.rewrites.len(),
                "dns_upstreams": cfg.dns.upstreams.len(),
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
        println!("  · DNS rewrites: {}", cfg.dns.rewrites.len());
        println!("  · DNS upstreams: {}", cfg.dns.upstreams.len());
        println!("  · Adblock source URLs: {}", cfg.adblock.sources.len());
        println!();
        return Ok(());
    }

    let file_export: FileConfigExport =
        serde_json::from_str(&content).map_err(|e| eyre!("JSON validation failed: {e}"))?;

    let secrets_encrypted =
        if let Some(ApiTokensExport::Encrypted(ref enc)) = file_export.api_tokens {
            if enc.salt.len() != 32 || hex::decode(&enc.salt).is_err() {
                bail!("Invalid secrets block: salt must be 32 hexadecimal characters (16 bytes)");
            }
            if enc.nonce.len() != 24 || hex::decode(&enc.nonce).is_err() {
                bail!("Invalid secrets block: nonce must be 24 hexadecimal characters (12 bytes)");
            }
            if enc.ciphertext.is_empty() || hex::decode(&enc.ciphertext).is_err() {
                bail!("Invalid secrets block: ciphertext contains invalid hex characters");
            }
            true
        } else {
            false
        };

    if printer.json {
        let json_report = serde_json::json!({
            "valid": true,
            "format": "json",
            "hosts": file_export.hosts.len(),
            "dns_rewrites": file_export.dns_rewrites.len(),
            "dns_upstreams": file_export.dns_upstreams.len(),
            "adblock_urls": file_export.dns_adblock_urls.len(),
            "secrets_encrypted": secrets_encrypted,
        });
        return printer.print_json(&json_report);
    }

    println!();
    printer.success(&format!(
        "Configuration file '{file_path}' is structurally valid (JSON schema) and ready for import."
    ));
    println!("  · Static hosts: {}", file_export.hosts.len());
    println!("  · DNS rewrites: {}", file_export.dns_rewrites.len());
    println!("  · DNS upstreams: {}", file_export.dns_upstreams.len());
    println!(
        "  · Adblock source URLs: {}",
        file_export.dns_adblock_urls.len()
    );
    if let Some(ref pools) = file_export.dhcp_v4_pools {
        println!("  · DHCPv4 pools: {}", pools.len());
    }
    if let Some(ref pools) = file_export.dhcp_v6_pools {
        println!("  · DHCPv6 pools: {}", pools.len());
    }
    if secrets_encrypted {
        println!("  · API secrets block: Encrypted with Argon2id + ChaCha20Poly1305");
    }
    println!();

    Ok(())
}

// ============================================================================
// Diff Handler
// ============================================================================

async fn diff_config(
    client: &LanforgeClient,
    printer: &Printer,
    file: Option<String>,
) -> Result<()> {
    let target_path = resolve_candidate_config_file(file.as_deref());
    if !target_path.exists() {
        bail!(
            "Configuration file '{}' does not exist",
            target_path.display()
        );
    }

    let content = std::fs::read_to_string(&target_path)
        .map_err(|e| eyre!("Failed to read '{}': {e}", target_path.display()))?;
    let file_cfg = ConfigFile::parse(&content)
        .map_err(|e| eyre!("Failed to parse '{}': {e}", target_path.display()))?;
    let file_hashes = section_hashes(&file_cfg);

    let live_export = client.system_config_export().await?;
    let live_cfg = ConfigFile::from(&*live_export);
    let live_hashes = section_hashes(&live_cfg);

    if printer.json {
        let mut diff_json = serde_json::Map::new();
        for sec in Section::ALL {
            let fh = file_hashes.get(&sec).copied();
            let lh = live_hashes.get(&sec).copied();
            let status = match (fh, lh) {
                (Some(a), Some(b)) if a == b => "in_sync",
                (Some(_), Some(_)) => "diverged",
                (Some(_), None) => "only_in_file",
                (None, Some(_)) => "only_in_db",
                (None, None) => "absent",
            };
            diff_json.insert(
                sec.name().to_string(),
                serde_json::json!({
                    "file_hash": fh,
                    "db_hash": lh,
                    "status": status,
                }),
            );
        }
        return printer.print_json(&serde_json::Value::Object(diff_json));
    }

    println!();
    println!(
        " {} {}",
        "Configuration Diff:".bold().white(),
        target_path.display().to_string().cyan()
    );
    println!(" ─────────────────────────────────────────────────────────────");

    let mut in_sync_count = 0;
    let mut diverged_count = 0;

    for sec in Section::ALL {
        let fh = file_hashes.get(&sec).copied();
        let lh = live_hashes.get(&sec).copied();

        let status_colored = match (fh, lh) {
            (Some(a), Some(b)) if a == b => {
                in_sync_count += 1;
                "In Sync".green()
            }
            (Some(_), Some(_)) => {
                diverged_count += 1;
                "DIVERGED".yellow().bold()
            }
            (Some(_), None) => {
                diverged_count += 1;
                "File only".cyan()
            }
            (None, Some(_)) => {
                diverged_count += 1;
                "DB only".magenta()
            }
            (None, None) => "Default".bright_black(),
        };

        let dyn_marker = if sec.is_dynamic() { " (dynamic)" } else { "" };
        println!(
            "   {:<24} {:<15} {}",
            format!("[{}]{dyn_marker}", sec.name()).bold(),
            status_colored,
            match (fh, lh) {
                (Some(a), Some(b)) if a != b => format!("file:{a:016x} ≠ db:{b:016x}")
                    .bright_black()
                    .to_string(),
                _ => String::new(),
            }
        );
    }

    println!(" ─────────────────────────────────────────────────────────────");
    if diverged_count == 0 {
        printer.success("All sections are completely in sync between file and live database.");
    } else {
        printer.warning(&format!("{diverged_count} section(s) differ between file and live database ({in_sync_count} in sync)."));
    }
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
        let live_export = client.system_config_export().await?;
        let live_cfg = ConfigFile::from(&*live_export);
        let rendered = live_cfg
            .render_full()
            .map_err(|e| eyre!("Failed to render configuration: {e}"))?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target_path, &rendered)?;
        printer.info(&format!(
            "Created initial configuration file at '{}'",
            target_path.display()
        ));
    }

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "nano".to_string());

    loop {
        let status = std::process::Command::new(&editor)
            .arg(&target_path)
            .status()
            .map_err(|e| eyre!("Failed to launch editor '{editor}': {e}"))?;

        if !status.success() {
            bail!("Editor exited with error status: {status}");
        }

        let content = std::fs::read_to_string(&target_path).map_err(|e| {
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

// ============================================================================
// Cryptographic Helpers
// ============================================================================

fn prompt_password(prompt: &str) -> Result<String> {
    inquire::Password::new(prompt)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| eyre!("Password prompt cancelled or failed: {e}"))
}

pub fn encrypt_secrets_block(password: &str, plaintext: &[u8]) -> Result<EncryptedApiTokens> {
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);

    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| eyre!("Key derivation failed: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);

    let key = Key::from(key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| eyre!("Encryption failed: {e}"))?;

    Ok(EncryptedApiTokens {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn decrypt_secrets_block(password: &str, enc: &EncryptedApiTokens) -> Result<Vec<u8>> {
    let salt = hex::decode(&enc.salt).map_err(|e| eyre!("Invalid salt hex: {e}"))?;
    let nonce_bytes = hex::decode(&enc.nonce).map_err(|e| eyre!("Invalid nonce hex: {e}"))?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| eyre!("Invalid nonce length, expected 12 bytes"))?;
    let ciphertext =
        hex::decode(&enc.ciphertext).map_err(|e| eyre!("Invalid ciphertext hex: {e}"))?;

    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| eyre!("Key derivation failed: {e}"))?;

    let key = Key::from(key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from(nonce_arr);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| eyre!("Decryption failed: check your password or corrupted data"))?;

    Ok(plaintext)
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
    use lanforge_types::auth::ApiScopes;

    #[test]
    fn test_encrypt_decrypt_secrets_roundtrip() {
        let dummy_tokens = vec![ExportedApiToken {
            token: "lf_live_9876543210fedcba".to_string(),
            name: "Admin Token".to_string(),
            created_at: 1_700_000_000,
            last_used: None,
            scopes: ApiScopes::default(),
            expires_at: None,
        }];

        let plaintext = serde_json::to_vec(&dummy_tokens).expect("serialize tokens");
        let password = "HomelabSuperSecretPassphrase!";

        let enc = encrypt_secrets_block(password, &plaintext).expect("encryption succeeds");
        assert_eq!(enc.salt.len(), 32);
        assert_eq!(enc.nonce.len(), 24);
        assert_ne!(enc.ciphertext, "");

        let decrypted_bytes =
            decrypt_secrets_block(password, &enc).expect("decryption succeeds with correct pass");
        assert_eq!(plaintext, decrypted_bytes);

        let decrypted_tokens: Vec<ExportedApiToken> =
            serde_json::from_slice(&decrypted_bytes).expect("deserialization succeeds");
        assert_eq!(decrypted_tokens.len(), 1);
        assert_eq!(decrypted_tokens[0].token, dummy_tokens[0].token);

        let failed_decrypt = decrypt_secrets_block("WrongPassword!", &enc);
        assert!(failed_decrypt.is_err());
    }

    #[test]
    fn test_file_config_export_serialization_json() {
        let export = FileConfigExport {
            hosts: Vec::new(),
            dns_rewrites: Vec::new(),
            dns_upstreams: Vec::new(),
            dns_adblock_config: AdblockDbConfig::default(),
            dns_adblock_urls: Vec::new(),
            dns_allowlist: Vec::new(),
            dns_adblock_rules: None,
            api_tokens: Some(ApiTokensExport::Encrypted(EncryptedApiTokens {
                salt: "00112233445566778899aabbccddeeff".to_string(),
                nonce: "0102030405060708090a0b0c".to_string(),
                ciphertext: "deadbeefcafebabe".to_string(),
            })),
            dhcp_v4_pools: None,
            dhcp_v6_pools: None,
            ra_prefixes: None,
            ra_rdnss: None,
            ra_dnssl: None,
            pppoe_config: None,
            dhcp_options: None,
            dns_reverse_resolvers: None,
            firewall_config: None,
            traffic_config: None,
            overwrite: false,
        };

        let json = serde_json::to_string(&export).expect("serialize export");
        let deserialized: FileConfigExport =
            serde_json::from_str(&json).expect("deserialize export");

        if let Some(ApiTokensExport::Encrypted(enc)) = deserialized.api_tokens {
            assert_eq!(enc.salt, "00112233445566778899aabbccddeeff");
            assert_eq!(enc.nonce, "0102030405060708090a0b0c");
            assert_eq!(enc.ciphertext, "deadbeefcafebabe");
        } else {
            panic!("Expected Encrypted tokens block");
        }
    }

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
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        let valid_json = r#"{
            "hosts": [],
            "dns_rewrites": [],
            "dns_upstreams": [],
            "dns_adblock_config": {
                "enabled": true,
                "blocking_mode": "nxdomain",
                "refresh_time": { "hour": 3, "minute": 0 }
            },
            "dns_adblock_urls": [],
            "dns_allowlist": []
        }"#;
        tmp.write_all(valid_json.as_bytes()).expect("write tmp");
        let printer = Printer::new(false, true, true);
        assert!(validate_config(&printer, tmp.path().to_str().unwrap()).is_ok());

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
}
