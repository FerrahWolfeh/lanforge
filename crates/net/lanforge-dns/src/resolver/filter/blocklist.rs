use std::collections::HashSet;
use std::path::Path;

use crate::error::DnsError;
use crate::resolver::filter::engine::{
    DiskFilterMap, MatchCandidate, build_fst_map, encode_reversed_domain, encode_val,
    reverse_domain_key,
};
use crate::resolver::filter::parse::MatchFlags;

use std::sync::Arc;

/// High-performance adblock filter engine backed by memory-mapped reversed FST Maps.
/// Operates with zero heap allocations and zero lock contention during lookups.
pub struct DiskBlocklist {
    pub block_map: DiskFilterMap,
    pub allow_map: Option<DiskFilterMap>,
    pub source_index: Arc<[i64]>,
}

impl DiskBlocklist {
    /// Build from a set of domains, convert to reversed keys with wildcard flags, and write to disk.
    pub fn build(domains: HashSet<String>, path: &Path, _lru_cap: usize) -> Result<Self, DnsError> {
        let mut rules = Vec::with_capacity(domains.len());
        for domain in domains {
            if let Some(rev_key) = reverse_domain_key(&domain) {
                rules.push((rev_key, encode_val(MatchFlags::wildcard(), 0)));
            }
        }

        build_fst_map(rules, path)?;
        Self::load(path, _lru_cap)
    }

    /// Load from an existing FST file on disk.
    pub fn load(path: &Path, _lru_cap: usize) -> Result<Self, DnsError> {
        let block_map = DiskFilterMap::open(path)?;
        let allow_path = path.with_file_name("allow.fst");
        let allow_map = if allow_path.exists() {
            DiskFilterMap::open(&allow_path).ok()
        } else {
            None
        };

        let manifest_path = path.with_file_name("manifest.json");
        let source_index = if manifest_path.exists() {
            let manifest =
                crate::resolver::filter::manifest::AdblockManifest::load_or_default(&manifest_path);
            Arc::from(manifest.source_index.into_boxed_slice())
        } else {
            Arc::from([])
        };

        Ok(Self {
            block_map,
            allow_map,
            source_index,
        })
    }

    /// Check if a domain matches the blocklist (including wildcard subdomains).
    #[inline]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn contains(&self, domain: &str) -> bool {
        self.block_map.match_domain(domain).is_some()
    }

    /// Match against the block map returning candidate flags and source attribution.
    #[inline]
    pub fn match_block(&self, domain: &str) -> Option<MatchCandidate> {
        self.block_map.match_domain(domain)
    }

    /// Encodes the reversed domain once and matches against both allow and block maps.
    #[inline]
    pub fn match_domain_pair(
        &self,
        domain: &str,
    ) -> (Option<MatchCandidate>, Option<MatchCandidate>) {
        let mut key_buf = [0u8; 256];
        let Some(len) = encode_reversed_domain(domain, &mut key_buf) else {
            return (None, None);
        };
        let rev_key = &key_buf[..len];
        let allow_cand = self
            .allow_map
            .as_ref()
            .and_then(|m| m.match_reversed(rev_key));
        let block_cand = self.block_map.match_reversed(rev_key);
        (allow_cand, block_cand)
    }

    /// Match against the source allow/exception map.
    #[inline]
    pub fn match_allow(&self, domain: &str) -> Option<MatchCandidate> {
        self.allow_map.as_ref().and_then(|m| m.match_domain(domain))
    }

    /// Resolves internal source index to database source ID.
    #[inline]
    pub fn resolve_source_id(&self, source_idx: u16) -> i64 {
        self.source_index
            .get(source_idx as usize)
            .copied()
            .unwrap_or(source_idx as i64)
    }

    /// Get the number of domains in the blocklist.
    #[inline]
    pub fn len(&self) -> usize {
        self.block_map.len()
    }

    /// Check if the blocklist is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.block_map.is_empty()
    }
}
