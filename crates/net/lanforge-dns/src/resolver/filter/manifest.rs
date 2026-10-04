use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use lanforge_types::network::dns::adblock::AdblockSourceFormat;
use serde::{Deserialize, Serialize};

use crate::error::DnsError;
use crate::resolver::filter::parse::ParseStats;

pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Entry in the manifest tracking state of an individual blocklist source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceManifestEntry {
    pub id: i64,
    pub url: String,
    pub format_configured: AdblockSourceFormat,
    pub format_detected: AdblockSourceFormat,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_attempt: u64,
    pub last_success: u64,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub stats: ParseStats,
    pub unsupported_samples: Vec<String>,
    pub content_hash: u64,
}

/// Global adblock cache manifest describing the current compiled filter state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdblockManifest {
    pub format_version: u32,
    pub fingerprint: u64,
    pub last_merge: u64,
    pub merged_blocks: usize,
    pub merged_exceptions: usize,
    pub pruned_rules: usize,
    pub source_index: Vec<i64>,
    pub sources: HashMap<i64, SourceManifestEntry>,
}

impl Default for AdblockManifest {
    fn default() -> Self {
        Self {
            format_version: CURRENT_FORMAT_VERSION,
            fingerprint: 0,
            last_merge: 0,
            merged_blocks: 0,
            merged_exceptions: 0,
            pruned_rules: 0,
            source_index: Vec::new(),
            sources: HashMap::new(),
        }
    }
}

impl AdblockManifest {
    /// Loads manifest from the given path. Returns default empty manifest if not present or corrupt.
    pub fn load_or_default(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        File::open(path)
            .ok()
            .and_then(|file| serde_json::from_reader(BufReader::new(file)).ok())
            .unwrap_or_default()
    }

    /// Saves the manifest atomically to disk.
    pub fn save_atomic(&self, path: &Path) -> Result<(), DnsError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }

        let tmp_file = tempfile::Builder::new()
            .prefix("manifest-")
            .suffix(".json.tmp")
            .tempfile_in(parent)
            .map_err(|e| DnsError::Generic(format!("Failed to create manifest tempfile: {e}")))?;

        {
            let writer = BufWriter::new(&tmp_file);
            serde_json::to_writer_pretty(writer, self)
                .map_err(|e| DnsError::Generic(format!("Failed to serialize manifest: {e}")))?;
        }

        tmp_file
            .persist(path)
            .map_err(|e| DnsError::Generic(format!("Atomic manifest persist failed: {e}")))?;

        Ok(())
    }

    /// Computes stable fingerprint of all active source hashes and format version.
    #[must_use]
    pub fn compute_fingerprint(sources: &[(i64, u64)]) -> u64 {
        let mut sorted = sources.to_vec();
        sorted.sort_unstable_by_key(|s| s.0);

        // FNV-1a 64-bit hash
        let mut hash = 0xcbf29ce484222325u64;
        for b in CURRENT_FORMAT_VERSION.to_le_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for (id, content_hash) in sorted {
            for b in id.to_le_bytes() {
                hash ^= b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            for b in content_hash.to_le_bytes() {
                hash ^= b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
        }
        hash
    }
}
