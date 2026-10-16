use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use fst::raw::{Fst, Output};
use fst::{Map, MapBuilder};
use memmap2::Mmap;

use crate::error::DnsError;
use crate::resolver::filter::parse::MatchFlags;

pub const LABEL_SEPARATOR: u8 = b'\x01';

const SOURCE_IDX_SHIFT: u32 = 16;

#[inline]
pub fn encode_val(flags: MatchFlags, source_idx: u16) -> u64 {
    (flags.0 as u64) | ((source_idx as u64) << SOURCE_IDX_SHIFT)
}

#[inline]
pub fn decode_val(val: u64) -> (MatchFlags, u16) {
    let flags = MatchFlags((val & 0xFF) as u8);
    let source_idx = ((val >> SOURCE_IDX_SHIFT) & 0xFFFF) as u16;
    (flags, source_idx)
}

/// Reverses domain labels separated by `\x01` into a stack buffer.
/// E.g. "sub.example.com" -> "com\x01example\x01sub".
/// Returns the number of bytes written, or None if domain exceeds buffer or is invalid.
#[inline]
pub fn encode_reversed_domain(domain: &str, out: &mut [u8; 256]) -> Option<usize> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }

    let mut pos = 0;
    let mut first = true;
    for label in domain.rsplit('.') {
        if label.is_empty() {
            return None;
        }
        if !first {
            if pos >= out.len() {
                return None;
            }
            out[pos] = LABEL_SEPARATOR;
            pos += 1;
        }
        first = false;
        let bytes = label.as_bytes();
        let next_pos = pos + bytes.len();
        if next_pos > out.len() {
            return None;
        }
        let dest = &mut out[pos..next_pos];
        dest.copy_from_slice(bytes);
        dest.make_ascii_lowercase();
        pos = next_pos;
    }

    Some(pos)
}

/// Helper returning the reversed domain key as an owned `String`.
#[must_use]
pub fn reverse_domain_key(domain: &str) -> Option<String> {
    let mut buf = [0u8; 256];
    let len = encode_reversed_domain(domain, &mut buf)?;
    // Input is ASCII only + 0x01 separator, thus valid UTF-8
    Some(String::from_utf8(buf[..len].to_vec()).unwrap())
}

/// A matched rule result from the FST engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchCandidate {
    pub flags: MatchFlags,
    pub source_idx: u16,
}

/// Walks an FST Map checking for ancestor wildcards and exact match.
/// Zero allocations, zero heap locks.
pub fn match_reversed_key<D: AsRef<[u8]>>(
    fst: &Fst<D>,
    key: &[u8],
) -> Option<MatchCandidate> {
    if fst.is_empty() {
        return None;
    }

    let mut node = fst.root();
    let mut output = Output::zero();
    let mut best_candidate: Option<MatchCandidate> = None;

    for &b in key {
        // If we are at a separator boundary, check if the preceding node is a final state
        // with SUBDOMAINS wildcard flag set.
        if b == LABEL_SEPARATOR && node.is_final() {
            let val = output.cat(node.final_output()).value();
            let (flags, source_idx) = decode_val(val);
            if flags.is_subdomains() {
                let candidate = MatchCandidate { flags, source_idx };
                if flags.is_important() || best_candidate.is_none() {
                    best_candidate = Some(candidate);
                }
            }
        }

        let Some(trans_idx) = node.find_input(b) else {
            return best_candidate;
        };
        let trans = node.transition(trans_idx);
        output = output.cat(trans.out);
        node = fst.node(trans.addr);
    }

    // End of key: check for exact match on the final node
    if node.is_final() {
        let val = output.cat(node.final_output()).value();
        let (flags, source_idx) = decode_val(val);
        if flags.is_self() {
            let candidate = MatchCandidate { flags, source_idx };
            if flags.is_important() || best_candidate.as_ref().is_none_or(|c| !c.flags.is_important()) {
                best_candidate = Some(candidate);
            }
        }
    }

    best_candidate
}

/// Memory-mapped FST map backed by disk.
pub struct DiskFilterMap {
    map: Map<Mmap>,
}

impl DiskFilterMap {
    pub fn open(path: &Path) -> Result<Self, DnsError> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let map = Map::new(mmap).map_err(|e| DnsError::Generic(format!("FST map load failed: {e}")))?;
        Ok(Self { map })
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn match_domain(&self, domain: &str) -> Option<MatchCandidate> {
        let mut key_buf = [0u8; 256];
        let len = encode_reversed_domain(domain, &mut key_buf)?;
        self.match_reversed(&key_buf[..len])
    }

    #[inline]
    pub fn match_reversed(&self, rev_key: &[u8]) -> Option<MatchCandidate> {
        match_reversed_key(self.map.as_fst(), rev_key)
    }
}

/// Builds an FST Map from parsed rules into a file atomically.
pub fn build_fst_map(
    mut rules: Vec<(String, u64)>, // (reversed_key, encoded_val)
    target_path: &Path,
) -> Result<(), DnsError> {
    // Sort uniquely by reversed key
    rules.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_file = tempfile::Builder::new()
        .prefix("lanforge-filter-")
        .suffix(".fst.tmp")
        .tempfile_in(parent)
        .map_err(|e| DnsError::Generic(format!("Failed to create tempfile: {e}")))?;

    let mut writer = BufWriter::new(tmp_file);
    let mut builder = MapBuilder::new(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder creation failed: {e}")))?;

    let mut last_key: Option<String> = None;
    let mut last_val: u64 = 0;

    for (key, val) in rules {
        if let Some(prev) = &last_key {
            if prev == &key {
                // Combine flags for duplicate key
                let (prev_flags, prev_src) = decode_val(last_val);
                let (cur_flags, _) = decode_val(val);
                let combined_flags = MatchFlags(prev_flags.0 | cur_flags.0);
                last_val = encode_val(combined_flags, prev_src);
                continue;
            } else {
                builder
                    .insert(prev.as_bytes(), last_val)
                    .map_err(|e| DnsError::Generic(format!("FST insertion error: {e}")))?;
            }
        }
        last_key = Some(key);
        last_val = val;
    }

    if let Some(prev) = last_key {
        builder
            .insert(prev.as_bytes(), last_val)
            .map_err(|e| DnsError::Generic(format!("FST insertion error: {e}")))?;
    }

    builder
        .finish()
        .map_err(|e| DnsError::Generic(format!("MapBuilder finish failed: {e}")))?;

    std::io::Write::flush(&mut writer)
        .map_err(|e| DnsError::Generic(format!("MapBuilder flush failed: {e}")))?;

    let tmp_file = writer
        .into_inner()
        .map_err(|e| DnsError::Generic(format!("Buffer unwrap failed: {e}")))?;

    tmp_file
        .persist(target_path)
        .map_err(|e| DnsError::Generic(format!("Atomic persist failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_reversed_domain() {
        let mut buf = [0u8; 256];
        let len = encode_reversed_domain("sub.example.com", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"com\x01example\x01sub");

        let rev = reverse_domain_key("ads.google.com.").unwrap();
        assert_eq!(rev, "com\x01google\x01ads");
    }

    #[test]
    fn test_engine_matching() {
        let dir = tempfile::tempdir().unwrap();
        let fst_path = dir.path().join("test.fst");

        let mut entries = Vec::new();

        // 1. Wildcard: example.com (SELF | SUBDOMAINS)
        let k1 = reverse_domain_key("example.com").unwrap();
        entries.push((k1, encode_val(MatchFlags::wildcard(), 1)));

        // 2. Exact only: exact-only.com (SELF)
        let k2 = reverse_domain_key("exact-only.com").unwrap();
        entries.push((k2, encode_val(MatchFlags::exact(), 2)));

        // 3. Subdomains only: *.subonly.com (SUBDOMAINS)
        let k3 = reverse_domain_key("subonly.com").unwrap();
        entries.push((k3, encode_val(MatchFlags::subdomains_only(), 3)));

        // 4. Important: important.com (SELF | SUBDOMAINS | IMPORTANT)
        let k4 = reverse_domain_key("important.com").unwrap();
        entries.push((k4, encode_val(MatchFlags::wildcard().with_important(), 4)));

        build_fst_map(entries, &fst_path).unwrap();

        let filter = DiskFilterMap::open(&fst_path).unwrap();

        // Check 1: example.com -> matches exact
        let m = filter.match_domain("example.com").unwrap();
        assert_eq!(m.source_idx, 1);
        assert!(m.flags.is_self());

        // Check 1b: sub.example.com -> matches wildcard
        let m = filter.match_domain("sub.example.com").unwrap();
        assert_eq!(m.source_idx, 1);
        assert!(m.flags.is_subdomains());

        // Check 1c: deep.sub.example.com -> matches wildcard
        let m = filter.match_domain("deep.sub.example.com").unwrap();
        assert_eq!(m.source_idx, 1);
        assert!(m.flags.is_subdomains());

        // Check 2: exact-only.com -> matches exact
        let m = filter.match_domain("exact-only.com").unwrap();
        assert_eq!(m.source_idx, 2);
        assert!(m.flags.is_self());

        // Check 2b: sub.exact-only.com -> SHOULD NOT MATCH (exact only!)
        assert_eq!(filter.match_domain("sub.exact-only.com"), None);

        // Check 3: subonly.com -> SHOULD NOT MATCH (subdomains only!)
        assert_eq!(filter.match_domain("subonly.com"), None);

        // Check 3b: sub.subonly.com -> matches!
        let m = filter.match_domain("sub.subonly.com").unwrap();
        assert_eq!(m.source_idx, 3);
        assert!(m.flags.is_subdomains());

        // Check 4: important.com and sub.important.com -> matches with important
        let m = filter.match_domain("sub.important.com").unwrap();
        assert_eq!(m.source_idx, 4);
        assert!(m.flags.is_important());

        // Check clean domain -> None
        assert_eq!(filter.match_domain("google.com"), None);
        assert_eq!(filter.match_domain("notexample.com"), None);
        assert_eq!(filter.match_domain("example.com.org"), None);
    }
}
