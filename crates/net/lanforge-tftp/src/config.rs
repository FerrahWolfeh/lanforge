use lanforge_types::network::ListenConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the TFTP service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TftpConfig {
    /// Whether the TFTP service is enabled.
    pub enabled: bool,
    /// Address(es) to listen on (e.g., `"[::]:69"` or `["192.168.1.1:69", "[fd00::1]:69"]`).
    #[serde(alias = "listen_addr")]
    pub listen: ListenConfig,
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
            listen: ListenConfig::dual_stack(69),
            root_dir: "/var/lib/lanforge/tftp".into(),
            block_size: 512,
            timeout: 5,
            max_retries: 3,
        }
    }
}
