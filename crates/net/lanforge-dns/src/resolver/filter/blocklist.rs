use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use lanforge_types::network::dns::adblock::AdblockUrlKind;
use lanforge_types::network::dns::adblock::syntax::MatchFlags;
use tracing::{error, warn};

use crate::error::DnsError;
use crate::resolver::filter::engine::{
    DiskFilterMap, build_fst_map, encode_reversed_domain, encode_val, reverse_domain_key,
};

/// Most lists one index holds: one bit each in a `u64` mask.
pub const MAX_LISTS: usize = 64;

/// One compiled list (its own memory-mapped FSTs) and its kind.
struct ListIndex {
    id: i64,
    /// An allowlist source: its rules allow, whatever their syntax says.
    allowlist: bool,
    block: DiskFilterMap,
    /// `None` when the list has no exception rules: never walked.
    allow: Option<DiskFilterMap>,
}

/// Which lists matched a name, one bit per list (bit = position in the index).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListMatches {
    pub allow: u64,
    pub block: u64,
    pub allow_important: u64,
    pub block_important: u64,
}

impl ListMatches {
    /// Only the lists of `mask`.
    #[inline]
    #[must_use]
    pub const fn masked(self, mask: u64) -> Self {
        Self {
            allow: self.allow & mask,
            block: self.block & mask,
            allow_important: self.allow_important & mask,
            block_important: self.block_important & mask,
        }
    }
}

/// Adblock lists, each queried in place from its own memory-mapped FSTs: no merged copy.
/// Lookups allocate nothing and take no lock.
pub struct DiskBlocklist {
    lists: Box<[ListIndex]>,
    /// Reversed keys disabled by a `$badfilter` rule of any list.
    badfilter: HashSet<Box<[u8]>>,
}

impl DiskBlocklist {
    /// Opens the compiled lists `{id}.block.fst` / `{id}.allow.fst` / `{id}.bad` in `sources_dir`,
    /// in order (the order sets the bits). A list that cannot be opened is skipped and returned,
    /// so the caller can drop its artifacts and fetch it again.
    pub fn load(sources_dir: &Path, sources: &[(i64, AdblockUrlKind)]) -> (Self, Vec<i64>) {
        if sources.len() > MAX_LISTS {
            error!(
                configured = sources.len(),
                max = MAX_LISTS,
                "Adblock: too many lists, the extra ones are ignored"
            );
        }
        let mut lists = Vec::with_capacity(sources.len().min(MAX_LISTS));
        let mut failed = Vec::new();
        let mut badfilter = HashSet::new();
        for &(id, kind) in sources.iter().take(MAX_LISTS) {
            let block = match DiskFilterMap::open(&sources_dir.join(format!("{id}.block.fst"))) {
                Ok(map) => map,
                Err(e) => {
                    warn!(source = id, error = %e, "Adblock: compiled list unreadable, refetching");
                    failed.push(id);
                    continue;
                }
            };
            let allow = DiskFilterMap::open(&sources_dir.join(format!("{id}.allow.fst")))
                .ok()
                .filter(|m| !m.is_empty());
            if let Ok(file) = File::open(sources_dir.join(format!("{id}.bad"))) {
                for line in BufReader::new(file).lines().map_while(Result::ok) {
                    let key = line.trim();
                    if !key.is_empty() {
                        badfilter.insert(key.as_bytes().into());
                    }
                }
            }
            lists.push(ListIndex {
                id,
                allowlist: kind == AdblockUrlKind::Allowlist,
                block,
                allow,
            });
        }
        (
            Self {
                lists: lists.into_boxed_slice(),
                badfilter,
            },
            failed,
        )
    }

    /// A single block list from a set of domains (wildcard rules), written to `path`.
    pub fn build(domains: HashSet<String>, path: &Path, _lru_cap: usize) -> Result<Self, DnsError> {
        let mut rules = Vec::with_capacity(domains.len());
        for domain in domains {
            if let Some(rev_key) = reverse_domain_key(&domain) {
                rules.push((rev_key, encode_val(MatchFlags::wildcard(), 0)));
            }
        }
        build_fst_map(rules, path)?;
        Ok(Self {
            lists: Box::new([ListIndex {
                id: 0,
                allowlist: false,
                block: DiskFilterMap::open(path)?,
                allow: None,
            }]),
            badfilter: HashSet::new(),
        })
    }

    /// The lists matching `domain` (itself, or a parent through a subdomain rule).
    #[inline]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[must_use]
    pub fn match_lists(&self, domain: &str) -> ListMatches {
        let mut m = ListMatches::default();
        let mut key_buf = [0u8; 256];
        let Some(len) = encode_reversed_domain(domain, &mut key_buf) else {
            return m;
        };
        let key = &key_buf[..len];
        let skip = |prefix: &[u8]| !self.badfilter.is_empty() && self.badfilter.contains(prefix);
        for (i, list) in self.lists.iter().enumerate() {
            let bit = 1u64 << i;
            if let Some(c) = list.block.match_reversed(key, skip) {
                let important = if c.flags.is_important() { bit } else { 0 };
                if list.allowlist {
                    m.allow |= bit;
                    m.allow_important |= important;
                } else {
                    m.block |= bit;
                    m.block_important |= important;
                }
            }
            if let Some(c) = list
                .allow
                .as_ref()
                .and_then(|a| a.match_reversed(key, skip))
            {
                m.allow |= bit;
                if c.flags.is_important() {
                    m.allow_important |= bit;
                }
            }
        }
        m
    }

    /// The bits of the lists with these source ids (those not loaded have none).
    #[must_use]
    pub fn mask_of(&self, ids: &[i64]) -> u64 {
        self.lists
            .iter()
            .enumerate()
            .filter(|(_, l)| ids.contains(&l.id))
            .fold(0, |acc, (bit, _)| acc | (1 << bit))
    }

    /// Source id of the list at bit `bit`.
    #[inline]
    #[must_use]
    pub fn source_id(&self, bit: u32) -> i64 {
        self.lists.get(bit as usize).map_or(-1, |l| l.id)
    }

    /// Block entries over all lists (a domain in two lists counts twice).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lists
            .iter()
            .filter(|l| !l.allowlist)
            .map(|l| l.block.len())
            .sum()
    }

    /// Exception entries over all lists, allowlist sources included.
    #[must_use]
    pub fn exceptions_len(&self) -> usize {
        self.lists
            .iter()
            .map(|l| {
                l.allow.as_ref().map_or(0, DiskFilterMap::len)
                    + if l.allowlist { l.block.len() } else { 0 }
            })
            .sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }
}
