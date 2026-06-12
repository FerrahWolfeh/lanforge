use crate::cli::{Execute, LanforgeClient};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Subcommand;
use color_eyre::eyre::{Result, bail};
use lanforge_api::api::SystemConfigExport;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Export system-wide database configuration to JSON.
    Export {
        /// Output file to save the JSON configuration. If omitted, prints to stdout.
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Encrypt API keys/secrets block with password.
        #[arg(short = 'e', long)]
        encrypt_secrets: bool,
        /// Password for encryption. If not provided and --encrypt-secrets is set, you will be prompted.
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Import system-wide database configuration from JSON.
    Import {
        /// Input file containing the JSON configuration to import.
        #[arg(short = 'o', long, value_name = "FILE")]
        file: Option<String>,
        /// Positional input file (fallback if -o is not used).
        #[arg(value_name = "FILE")]
        positional_file: Option<String>,
        /// Force overwrite existing configurations.
        #[arg(short = 'w', long)]
        overwrite: bool,
        /// Password for decrypting secrets block. If not provided and the file contains encrypted secrets, you will be prompted.
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedApiTokens {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ApiTokensSection {
    Plain(Vec<lanforge_api::api::ExportedApiToken>),
    Encrypted(EncryptedApiTokens),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileConfigExport {
    pub hosts: Vec<lanforge_api::api::devices::HostConfigEntry>,
    pub dns_rewrites: Vec<lanforge_types::network::dns::adblock::RewriteRule>,
    pub dns_upstreams: Vec<lanforge_api::api::dns::DnsUpstreamConfig>,
    pub dns_adblock_config: lanforge_types::network::dns::adblock::AdblockDbConfig,
    pub dns_adblock_urls: Vec<lanforge_types::network::dns::AdblockUrlEntry>,
    pub dns_allowlist: Vec<lanforge_api::api::dns::AllowlistEntry>,
    pub api_tokens: Option<ApiTokensSection>,
    pub dhcp_v4_pools: Option<Vec<lanforge_types::network::dhcp::Dhcpv4Pool>>,
    pub dhcp_v6_pools: Option<Vec<lanforge_types::network::dhcp::Dhcpv6Pool>>,
    pub ra_prefixes: Option<Vec<lanforge_types::network::ra::RAPrefix>>,
    pub ra_rdnss: Option<Vec<lanforge_types::network::ra::RdnssConfig>>,
    pub ra_dnssl: Option<Vec<lanforge_types::network::ra::DnsslConfig>>,
    #[serde(default)]
    pub overwrite: bool,
}

fn prompt_password(prompt: &str) -> Result<String> {
    let password = inquire::Password::new(prompt)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| color_eyre::eyre::eyre!("Password prompt failed: {e}"))?;
    Ok(password)
}

fn encrypt_secrets_block(password: &str, plaintext: &[u8]) -> Result<EncryptedApiTokens> {
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);

    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| color_eyre::eyre::eyre!("Key derivation failed: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);

    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| color_eyre::eyre::eyre!("Encryption failed: {e}"))?;

    Ok(EncryptedApiTokens {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

fn decrypt_secrets_block(password: &str, enc: &EncryptedApiTokens) -> Result<Vec<u8>> {
    let salt =
        hex::decode(&enc.salt).map_err(|e| color_eyre::eyre::eyre!("Invalid salt hex: {e}"))?;
    let nonce_bytes =
        hex::decode(&enc.nonce).map_err(|e| color_eyre::eyre::eyre!("Invalid nonce hex: {e}"))?;
    let ciphertext = hex::decode(&enc.ciphertext)
        .map_err(|e| color_eyre::eyre::eyre!("Invalid ciphertext hex: {e}"))?;

    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| color_eyre::eyre::eyre!("Key derivation failed: {e}"))?;

    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| color_eyre::eyre::eyre!("Decryption failed. Check your password."))?;

    Ok(plaintext)
}

async fn execute_export(
    client: &LanforgeClient,
    output: Option<String>,
    encrypt_secrets: bool,
    password: Option<String>,
) -> Result<()> {
    let config = client.system_config_export().await?;

    let api_tokens_section = if let Some(tokens) = config.api_tokens {
        if encrypt_secrets || password.is_some() {
            let pass = if let Some(p) = password {
                p
            } else {
                let p1 = prompt_password("Enter encryption password:")?;
                let p2 = prompt_password("Confirm encryption password:")?;
                if p1 != p2 {
                    bail!("Passwords do not match.");
                }
                p1
            };
            let plain_bytes = serde_json::to_vec(&tokens)?;
            let enc = encrypt_secrets_block(&pass, &plain_bytes)?;
            Some(ApiTokensSection::Encrypted(enc))
        } else {
            Some(ApiTokensSection::Plain(tokens))
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
        api_tokens: api_tokens_section,
        dhcp_v4_pools: config.dhcp_v4_pools,
        dhcp_v6_pools: config.dhcp_v6_pools,
        ra_prefixes: config.ra_prefixes,
        ra_rdnss: config.ra_rdnss,
        ra_dnssl: config.ra_dnssl,
        overwrite: config.overwrite,
    };

    let json = serde_json::to_string_pretty(&file_export)?;
    if let Some(path) = output {
        std::fs::write(&path, json)?;
        println!("✓ Exported system configuration to {path}");
    } else {
        println!("{json}");
    }
    Ok(())
}

async fn execute_import(
    client: &LanforgeClient,
    file: Option<String>,
    positional_file: Option<String>,
    overwrite: bool,
    password: Option<String>,
) -> Result<()> {
    let path = match (file, positional_file) {
        (Some(f), _) => f,
        (None, Some(pf)) => pf,
        (None, None) => {
            bail!("Please specify the file to import using -o <file> or as a positional argument.")
        }
    };

    let content = std::fs::read_to_string(&path)?;
    let file_export: FileConfigExport = serde_json::from_str(&content)?;

    let api_tokens = if let Some(sec) = file_export.api_tokens {
        match sec {
            ApiTokensSection::Plain(tokens) => Some(tokens),
            ApiTokensSection::Encrypted(enc) => {
                let pass = match password {
                    Some(p) => p,
                    None => prompt_password("Enter decryption password:")?,
                };
                let plain_bytes = decrypt_secrets_block(&pass, &enc)?;
                let tokens = serde_json::from_slice(&plain_bytes)?;
                Some(tokens)
            }
        }
    } else {
        None
    };

    let system_config = SystemConfigExport {
        hosts: file_export.hosts,
        dns_rewrites: file_export.dns_rewrites,
        dns_upstreams: file_export.dns_upstreams,
        dns_adblock_config: file_export.dns_adblock_config,
        dns_adblock_urls: file_export.dns_adblock_urls,
        dns_allowlist: file_export.dns_allowlist,
        api_tokens,
        dhcp_v4_pools: file_export.dhcp_v4_pools,
        dhcp_v6_pools: file_export.dhcp_v6_pools,
        ra_prefixes: file_export.ra_prefixes,
        ra_rdnss: file_export.ra_rdnss,
        ra_dnssl: file_export.ra_dnssl,
        overwrite,
    };

    let resp = client.system_config_import(system_config).await?;
    println!("✓ {}", resp.message);
    Ok(())
}

impl Execute for ConfigArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            ConfigAction::Export {
                output,
                encrypt_secrets,
                password,
            } => execute_export(client, output, encrypt_secrets, password).await,
            ConfigAction::Import {
                file,
                positional_file,
                overwrite,
                password,
            } => execute_import(client, file, positional_file, overwrite, password).await,
        }
    }
}
