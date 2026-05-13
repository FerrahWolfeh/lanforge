use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use bloomfilter::Bloom;
use lru::LruCache;
use memmap2::Mmap;
use parking_lot::Mutex;
use rkyv::rancor::Error;
use rkyv::{Archive, Archived, Deserialize, Serialize};

use crate::error::DnsError;

/// Memory-efficient blocklist using a Bloom filter, an LRU cache, and a disk-backed sorted list.
pub struct DiskBlocklist {
    /// Bloom filter for fast negative lookups (0.5% FP rate).
    bloom: Bloom<str>,
    /// LRU cache of recent lookup results (domain -> blocked?).
    lru: Arc<Mutex<LruCache<Box<str>, bool>>>,
    /// Memory-mapped rkyv file with sorted domains.
    mmap: Mmap,
    /// Total number of domains in the blocklist.
    domain_count: usize,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(crate = rkyv)]
pub struct BlocklistData {
    pub domains: Vec<String>,
}

impl DiskBlocklist {
    /// Build from a set of domains, deduplicate, sort, write to disk, and build bloom filter.
    pub fn build(domains: HashSet<String>, path: &Path, lru_cap: usize) -> Result<Self, DnsError> {
        let mut sorted_domains: Vec<String> = domains.into_iter().collect();
        sorted_domains.sort_unstable();

        let data = BlocklistData {
            domains: sorted_domains,
        };

        // Serialize to disk using rkyv
        let bytes = rkyv::to_bytes::<Error>(&data)
            .map_err(|e| DnsError::Generic(format!("Serialization failed: {}", e)))?;

        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        file.flush()?;

        Self::load(path, lru_cap)
    }

    /// Load from an existing rkyv file on disk.
    pub fn load(path: &Path, lru_cap: usize) -> Result<Self, DnsError> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Access archived data
        let archived = unsafe { rkyv::access_unchecked::<Archived<BlocklistData>>(&mmap) };
        let domain_count = archived.domains.len();

        // Build Bloom filter from the sorted list in the mmap
        let mut bloom = Bloom::new_for_fp_rate(domain_count.max(100), 0.005)
            .map_err(|e| DnsError::Generic(format!("Bloom filter creation failed: {}", e)))?;

        for domain in archived.domains.iter() {
            bloom.set(domain.as_str());
        }

        Ok(Self {
            bloom,
            lru: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(lru_cap).unwrap(),
            ))),
            mmap,
            domain_count,
        })
    }

    /// Check if a domain is in the blocklist.
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

        // 3. Binary search in the memory-mapped sorted list
        let archived = unsafe { rkyv::access_unchecked::<Archived<BlocklistData>>(&self.mmap) };
        let domains = &archived.domains;

        // Binary search using rkyv's ArchivedVec
        let result = domains
            .binary_search_by(|probe| probe.as_str().cmp(domain))
            .is_ok();

        // 4. Update LRU
        self.lru.lock().put(Box::from(domain), result);

        result
    }

    /// Get the number of domains in the blocklist.
    pub fn len(&self) -> usize {
        self.domain_count
    }

    /// Check if the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.domain_count == 0
    }
}
