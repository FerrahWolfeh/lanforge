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
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::network::dhcp::{DhcpOptionsConfig, Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::dns::AdblockUrlEntry;
use lanforge_types::network::dns::adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};

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
    /// Export system configuration snapshot to JSON
    Export {
        /// Destination output file path (prints to stdout if omitted)
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Encrypt the API tokens secrets block with a password
        #[arg(short = 'e', long)]
        encrypt_secrets: bool,
        /// Encryption password (if omitted and --encrypt-secrets is set, you will be prompted)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Import system configuration from a JSON file
    Import {
        /// Input JSON configuration file path
        #[arg(value_name = "FILE")]
        file: Option<String>,
        /// Alternative flag for input file
        #[arg(short = 'f', long = "file")]
        file_flag: Option<String>,
        /// Force overwrite existing records instead of merging
        #[arg(short = 'w', long)]
        overwrite: bool,
        /// Decryption password (if file contains encrypted secrets and password is omitted, you will be prompted)
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Validate configuration file syntax and structure without modifying the daemon
    Validate {
        /// Input JSON configuration file path
        #[arg(value_name = "FILE")]
        file: String,
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
    pub overwrite: bool,
}

impl ConfigArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(ConfigSubcommand::Show) {
            ConfigSubcommand::Show => show_config(client, printer).await,
            ConfigSubcommand::Export {
                output,
                encrypt_secrets,
                password,
            } => export_config(client, printer, output, encrypt_secrets, password).await,
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
        println!("   {:<22} {}", "PPPoE WAN:".bold(), "Not configured".bright_black());
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
// Export Handler
// ============================================================================

async fn export_config(
    client: &LanforgeClient,
    printer: &Printer,
    output: Option<String>,
    encrypt_secrets: bool,
    password: Option<String>,
) -> Result<()> {
    let config = client.system_config_export().await?;

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
    let file_export: FileConfigExport = serde_json::from_str(&content)
        .map_err(|e| eyre!("Failed to parse configuration file '{file_path}': {e}"))?;

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

    let system_config = SystemConfigExport {
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
        overwrite,
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

    let file_export: FileConfigExport = serde_json::from_str(&content)
        .map_err(|e| eyre!("JSON validation failed: {e}"))?;

    let secrets_encrypted = if let Some(ApiTokensExport::Encrypted(ref enc)) = file_export.api_tokens {
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
        "Configuration file '{file_path}' is structurally valid and ready for import."
    ));
    println!("  · Static hosts: {}", file_export.hosts.len());
    println!("  · DNS rewrites: {}", file_export.dns_rewrites.len());
    println!("  · DNS upstreams: {}", file_export.dns_upstreams.len());
    println!("  · Adblock source URLs: {}", file_export.dns_adblock_urls.len());
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
    }
}

#[must_use]
pub const fn is_singleton_section(section: ImportSection) -> bool {
    matches!(
        section,
        ImportSection::DnsAdblockConfig
            | ImportSection::PppoeConfig
            | ImportSection::DhcpOptions
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
        assert!(!enc.ciphertext.is_empty());

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
                "refresh_hours": 24,
                "refresh_at_night": false
            },
            "dns_adblock_urls": [],
            "dns_allowlist": []
        }"#;
        tmp.write_all(valid_json.as_bytes()).expect("write tmp");
        let printer = Printer::new(false, true, true);
        assert!(validate_config(&printer, tmp.path().to_str().unwrap()).is_ok());

        let mut invalid_tmp = tempfile::NamedTempFile::new().expect("temp file");
        invalid_tmp.write_all(b"not json at all").expect("write tmp");
        assert!(validate_config(&printer, invalid_tmp.path().to_str().unwrap()).is_err());
    }
}
