//! Configuration for the TFTP server.

use serde::{Deserialize, Serialize};
use lanforge_macros::ServiceConfig;
use std::path::PathBuf;

/// Configuration for the TFTP service.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "tftp")]
#[serde(default)]
pub struct TftpConfig {
    /// Whether the TFTP service is enabled.
    pub enabled: bool,
    /// Address to listen on (e.g., "0.0.0.0:69").
    pub listen_addr: String,
    /// Root directory for served files.
    pub root_dir: PathBuf,
    /// Default block size for transfers (bytes).
    pub block_size: u16,
    /// Timeout for retransmissions (seconds).
    pub timeout: u64,
    /// Maximum number of retries per block.
    pub max_retries: u8,
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:69".to_string(),
            root_dir: "/var/lib/lanforge/tftp".into(),
            block_size: 512,
            timeout: 5,
            max_retries: 3,
        }
    }
}
