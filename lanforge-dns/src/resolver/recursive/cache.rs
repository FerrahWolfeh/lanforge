use bytes::Bytes;
use dashmap::DashMap;
use std::time::{Duration, Instant};

use crate::wire::{WireDecoder, WireQuestion};
use lanforge_core::types::DnsRecordType;

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
}

pub struct DnsCache {
    pub cache: DashMap<CacheKey, CachedResponse>,
}

impl DnsCache {
    #[must_use]
    pub fn new(_capacity: u64) -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    #[must_use]
    pub fn get_wire(&self, query_data: &[u8], question: &WireQuestion<'_>) -> Option<Vec<u8>> {
        let key = CacheKey {
            qname: question.qname_raw().to_vec(),
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

        Some(owned_data)
    }

    pub fn insert(
        &self,
        key: CacheKey,
        response_data: Vec<u8>,
        ttl_offsets: Vec<usize>,
        min_ttl: u32,
    ) {
        let now = Instant::now();
        let ttl_secs = u64::from(min_ttl.clamp(5, 3600));

        let cached_response = CachedResponse {
            data: Bytes::from(response_data),
            created_at: now,
            expires_at: now + Duration::from_secs(ttl_secs),
            ttl_offsets,
        };
        self.cache.insert(key, cached_response);
    }

    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    #[must_use]
    pub fn dump(&self) -> Vec<(String, String, String, u64)> {
        let now = Instant::now();
        self.cache
            .iter()
            .map(|entry| {
                let (key, value) = entry.pair();
                let mut name_decoder = WireDecoder::new(&key.qname);
                let name = name_decoder
                    .decode_name()
                    .map_or_else(|| "invalid".to_string(), |n| n.to_string());
                let kind = DnsRecordType::from(key.qtype).to_string();

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
    }
}
