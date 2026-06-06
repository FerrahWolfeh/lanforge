use std::collections::HashSet;
use std::fs::File;
use std::io::BufWriter;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use bloomfilter::Bloom;
use fst::{Set, SetBuilder, Streamer};
use lru::LruCache;
use memmap2::Mmap;
use parking_lot::Mutex;

use crate::error::DnsError;

/// Memory-efficient blocklist using a Bloom filter, an LRU cache, and a disk-backed FST.
pub struct DiskBlocklist {
    /// Bloom filter for fast negative lookups (0.5% FP rate).
    bloom: Bloom<str>,
    /// LRU cache of recent lookup results (domain -> blocked?).
    lru: Arc<Mutex<LruCache<Box<str>, bool>>>,
    /// Memory-mapped FST (Finite State Transducer) set of domains.
    fst: Set<Mmap>,
}

impl DiskBlocklist {
    /// Build from a set of domains, deduplicate, sort, write to disk as FST, and build bloom filter.
    pub fn build(domains: HashSet<String>, path: &Path, lru_cap: usize) -> Result<Self, DnsError> {
        let mut sorted_domains: Vec<String> = domains.into_iter().collect();
        sorted_domains.sort_unstable();

        let tmp_file = tempfile::Builder::new()
            .prefix("lanforge-dns-")
            .suffix(".fst.tmp")
            .tempfile()
            .map_err(|e| DnsError::Generic(format!("Failed to create tempfile: {e}")))?;

        let mut writer = BufWriter::new(tmp_file);
        let mut builder = SetBuilder::new(&mut writer)
            .map_err(|e| DnsError::Generic(format!("FST builder creation failed: {e}")))?;

        for domain in &sorted_domains {
            builder
                .insert(domain)
                .map_err(|e| DnsError::Generic(format!("FST insertion failed: {e}")))?;
        }

        builder
            .finish()
            .map_err(|e| DnsError::Generic(format!("FST finalization failed: {e}")))?;

        std::io::Write::flush(&mut writer)
            .map_err(|e| DnsError::Generic(format!("FST flush failed: {e}")))?;

        let tmp_file = writer
            .into_inner()
            .map_err(|e| DnsError::Generic(format!("FST buffer unwrap failed: {e}")))?;

        match tmp_file.persist(path) {
            Ok(_) => {}
            Err(e) => {
                let tmp_file = e.file;
                std::fs::copy(tmp_file.path(), path).map_err(|err| {
                    DnsError::Generic(format!("FST cross-device copy failed: {err}"))
                })?;
            }
        }

        Self::load(path, lru_cap)
    }

    /// Load from an existing FST file on disk.
    pub fn load(path: &Path, lru_cap: usize) -> Result<Self, DnsError> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let fst = Set::new(mmap).map_err(|e| DnsError::Generic(format!("FST load failed: {e}")))?;
        let domain_count = fst.len();

        if domain_count > 50_000_000 {
            return Err(DnsError::Generic(format!(
                "FST file corrupted or unreasonably large (reported {domain_count} domains)"
            )));
        }

        // Build Bloom filter from the FST contents
        let mut bloom = Bloom::new_for_fp_rate(domain_count.max(100), 0.005)
            .map_err(|e| DnsError::Generic(format!("Bloom filter creation failed: {e}")))?;

        let mut stream = fst.stream();
        while let Some(domain_bytes) = stream.next() {
            if let Ok(domain_str) = std::str::from_utf8(domain_bytes) {
                bloom.set(domain_str);
            }
        }

        Ok(Self {
            bloom,
            lru: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(lru_cap).unwrap(),
            ))),
            fst,
        })
    }

    /// Check if a domain is in the blocklist.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn contains(&self, domain: &str) -> bool {
        // 1. Check LRU cache
        {
            let mut lru = self.lru.lock();
            if let Some(&blocked) = lru.get(domain) {
                return blocked;
            }
        }

        // 2. Check Bloom filter
        if !self.bloom.check(domain) {
            self.lru.lock().put(Box::from(domain), false);
            return false;
        }

        // 3. FST Lookup
        let result = self.fst.contains(domain);

        // 4. Update LRU
        self.lru.lock().put(Box::from(domain), result);

        result
    }

    /// Get the number of domains in the blocklist.
    pub fn len(&self) -> usize {
        self.fst.len()
    }

    /// Check if the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.fst.is_empty()
    }
}
