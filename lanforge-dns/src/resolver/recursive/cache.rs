use bytes::Bytes;
use dashmap::DashMap;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::wire::{WireDecoder, WireQuestion};
use lanforge_types::network::dns::DnsRecordType;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey {
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone)]
pub struct CachedResponse {
    pub data: Bytes,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub ttl_offsets: Vec<usize>,
    pub is_block: bool,
}

pub struct DnsCache {
    pub cache: DashMap<CacheKey, CachedResponse>,
    capacity: u64,
    min_ttl: u32,
}

impl DnsCache {
    #[must_use]
    pub fn new(capacity: u64, min_ttl: u32) -> Self {
        Self {
            cache: DashMap::with_capacity(capacity as usize),
            capacity,
            min_ttl,
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[must_use]
    pub fn get_wire(
        &self,
        query_data: &[u8],
        question: &WireQuestion<'_>,
    ) -> Option<(Vec<u8>, bool)> {
        let mut qname = question.qname_raw().to_vec();
        qname.make_ascii_lowercase();

        let key = CacheKey {
            qname,
            qtype: question.qtype(),
            qclass: question.qclass(),
        };

        let entry = self.cache.get(&key)?;
        let now = Instant::now();
        if now >= entry.expires_at {
            drop(entry);
            self.cache.remove(&key);
            return None;
        }

        let elapsed = now.duration_since(entry.created_at).as_secs() as u32;
        let mut owned_data = entry.data.to_vec();

        // 1. Patch ID
        if owned_data.len() >= 2 {
            owned_data[0] = query_data[0];
            owned_data[1] = query_data[1];
        }

        // 2. TTL Scrubbing
        if elapsed > 0 {
            for &offset in &entry.ttl_offsets {
                if offset + 4 <= owned_data.len() {
                    let current_ttl = u32::from_be_bytes([
                        owned_data[offset],
                        owned_data[offset + 1],
                        owned_data[offset + 2],
                        owned_data[offset + 3],
                    ]);
                    let new_ttl = current_ttl.saturating_sub(elapsed);
                    let ttl_bytes = new_ttl.to_be_bytes();
                    owned_data[offset..offset + 4].copy_from_slice(&ttl_bytes);
                }
            }
        }

        Some((owned_data, entry.is_block))
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn insert(
        &self,
        mut key: CacheKey,
        response_data: Vec<u8>,
        ttl_offsets: Vec<usize>,
        min_ttl_found: u32,
        is_block: bool,
    ) {
        key.qname.make_ascii_lowercase();
        // Enforce capacity (batch random eviction if full)
        if self.cache.len() as u64 >= self.capacity && self.capacity > 0 {
            let mut evicted = 0;
            let batch_size = 10;
            let now = Instant::now();

            // First try to find expired ones
            self.cache.retain(|_, v| v.expires_at > now);

            // If still over capacity, remove random ones
            while self.cache.len() as u64 >= self.capacity && evicted < batch_size {
                if let Some(entry) = self.cache.iter().next() {
                    let k = entry.key().clone();
                    drop(entry);
                    self.cache.remove(&k);
                    evicted += 1;
                } else {
                    break;
                }
            }
        }

        let now = Instant::now();

        // Use original TTL if found, otherwise default to 24h (86400s).
        // Floor at config min_ttl.
        let effective_ttl = if min_ttl_found == 0 {
            86400
        } else {
            min_ttl_found
        };

        let ttl_secs = u64::from(effective_ttl.max(self.min_ttl));

        let cached_response = CachedResponse {
            data: Bytes::from(response_data),
            created_at: now,
            expires_at: now + Duration::from_secs(ttl_secs),
            ttl_offsets,
            is_block,
        };
        self.cache.insert(key, cached_response);
        #[cfg(feature = "hotpath")]
        {
            hotpath::gauge!("dns_cache_size").set(self.cache.len() as f64);
        }
    }

    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    #[must_use]
    pub fn dump(&self) -> Vec<(String, DnsRecordType, String, u64)> {
        let now = Instant::now();
        self.cache
            .iter()
            .map(|entry| {
                let (key, value) = entry.pair();
                let mut name_decoder = WireDecoder::new(&key.qname);
                let name = name_decoder
                    .decode_name()
                    .map_or_else(|| "invalid".to_string(), |n| n.to_string());
                let kind = DnsRecordType::from(key.qtype);

                let mut msg_decoder = WireDecoder::new(&value.data);
                let data = if let Some(msg) = msg_decoder.decode_message() {
                    msg.answers
                        .first()
                        .map_or_else(|| "no-data".to_string(), |r| format!("{:?}", r.rdata))
                } else {
                    "wire-error".to_string()
                };
                let ttl = value.expires_at.saturating_duration_since(now).as_secs();
                (name, kind, data, ttl)
            })
            .collect()
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.cache.retain(|_, v| v.expires_at > now);
        #[cfg(feature = "hotpath")]
        {
            hotpath::gauge!("dns_cache_size").set(self.cache.len() as f64);
        }
    }

    #[must_use]
    pub fn get_stats_ext(&self) -> (u64, HashMap<DnsRecordType, u64>, u64, u64) {
        let mut stats = HashMap::new();
        let mut total_mem = 0;
        let mut total_ttl = 0;
        let count = self.cache.len() as u64;
        let now = Instant::now();

        for entry in self.cache.iter() {
            let (key, value) = entry.pair();
            let kind = DnsRecordType::from(key.qtype);
            *stats.entry(kind).or_insert(0) += 1;

            // Heuristic memory usage: key size + data size + fixed overhead
            total_mem += (key.qname.len() + value.data.len() + 64) as u64;
            total_ttl += value.expires_at.saturating_duration_since(now).as_secs();
        }

        let avg_ttl = total_ttl.checked_div(count).unwrap_or(0);
        (count, stats, total_mem, avg_ttl)
    }
}
