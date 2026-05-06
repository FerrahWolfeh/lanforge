//! DNS response cache with TTL-based expiry.
//!
//! Uses Moka's synchronous cache to store upstream DNS responses as raw
//! wire-format bytes, avoiding re-parsing on cache hits. The cache key is
//! `(Name, RecordType, DNSClass)` and the value is the serialized response
//! with its computed minimum TTL.
//!
//! ## Design
//!
//! - **Sync cache:** No `.await` overhead in the hot path — `get()` is fully synchronous
//! - **Raw bytes:** Responses are stored as `Vec<u8>` (wire format), not parsed `Message`
//! - **TTL extraction:** The minimum TTL from all answer/NS/additional records is used
//! - **ID rewriting:** On cache hit, the query ID is patched in-place (bytes 0-1)

use hickory_proto::rr::{Name, RData};
use hickory_proto::{
    op::Message,
    serialize::binary::{BinDecodable, BinEncodable},
};
use moka::Expiry;
use moka::sync::Cache;
use std::time::{Duration, Instant};

use crate::wire::{WireQuestion, qtypes::QType};

/// Cache key for DNS responses.
///
/// Uniquely identifies a query by its raw QNAME bytes, type, and class.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey {
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

/// A cached DNS response with its pre-computed TTL.
///
/// Stores the raw wire-format response bytes and the minimum TTL extracted
/// from all records in the response.
#[derive(Clone)]
pub struct CachedResponse {
    /// The serialized DNS response message (wire format).
    pub data: Vec<u8>,
    /// The minimum TTL (in seconds) found in the response records.
    pub ttl: Duration,
}

struct DnsExpiry;

/// Custom TTL expiry policy for the Moka cache.
///
/// Uses the TTL pre-computed from the DNS response records rather than
/// relying on Moka's default time-based expiry. Returns `None` for
/// `expire_after_read` and `expire_after_update` to preserve the original TTL.
impl Expiry<CacheKey, CachedResponse> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedResponse,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    // Keep the original TTL — don't reset on read
    fn expire_after_read(
        &self,
        _k: &CacheKey,
        _v: &CachedResponse,
        _d: Instant,
        _c: Option<Duration>,
        _n: Instant,
    ) -> Option<Duration> {
        None
    }

    // Keep the original TTL — don't reset on update
    fn expire_after_update(
        &self,
        _k: &CacheKey,
        _v: &CachedResponse,
        _d: Instant,
        _c: Option<Duration>,
    ) -> Option<Duration> {
        None
    }
}

/// Synchronous cache for upstream DNS responses.
///
/// Stores serialized wire-format responses to avoid re-parsing on cache hits.
/// When a cached response is returned, only the DNS query ID (bytes 0-1) is
/// patched to match the incoming query.
pub struct DnsCache {
    cache: Cache<CacheKey, CachedResponse>,
}

impl DnsCache {
    /// Creates a new cache with the given maximum capacity (number of entries).
    #[must_use]
    pub fn new(capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(DnsExpiry)
                .build(),
        }
    }

    /// Looks up a cached response for the given query.
    ///
    /// Returns `Some(wire_bytes)` if a match is found. The query ID in the
    /// cached response is patched to match the incoming query before returning.
    ///
    /// This is fully synchronous — no `.await` required.
    #[must_use]
    pub fn get(&self, query: &Message) -> Option<Vec<u8>> {
        let question = query.queries.first()?;
        let key = CacheKey {
            qname: question.name().to_bytes().ok()?,
            qtype: question.query_type().into(),
            qclass: question.query_class().into(),
        };

        let mut owned_data = self.cache.get(&key)?.data;

        if owned_data.len() >= 2 {
            let id_bytes = query.id.to_be_bytes();
            owned_data[0] = id_bytes[0];
            owned_data[1] = id_bytes[1];
        }

        Some(owned_data)
    }

    /// Optimized lookup using wire-parsed question data.
    ///
    /// Avoids full Message parsing for cache hits.
    #[must_use]
    pub fn get_wire(&self, data: &[u8], question: &WireQuestion<'_>) -> Option<Vec<u8>> {
        let key = CacheKey {
            qname: question.qname_raw().to_vec(),
            qtype: question.qtype(),
            qclass: question.qclass(),
        };

        let mut owned_data = self.cache.get(&key)?.data;

        if owned_data.len() >= 2 {
            // Patch ID directly from the wire data
            owned_data[0] = data[0];
            owned_data[1] = data[1];
        }

        Some(owned_data)
    }

    /// Inserts a response into the cache with a computed minimum TTL.
    ///
    /// The TTL is extracted from all answer, NS, and additional records.
    /// For negative responses (NXDOMAIN/NODATA), the TTL is derived from the
    /// SOA record per RFC 2308.
    ///
    /// TTL is clamped to a range of 5-3600 seconds.
    pub fn insert(&self, key: CacheKey, response_msg: &Message, response_data: Vec<u8>) {
        let mut min_ttl = 3600;
        let mut found = false;

        for record in response_msg
            .answers
            .iter()
            .chain(response_msg.authorities.iter())
            .chain(response_msg.additionals.iter())
        {
            if record.ttl < min_ttl {
                min_ttl = record.ttl;
            }
            found = true;
        }

        if !found {
            min_ttl = 60; // Default fallback

            // RFC 2308: Negative caching TTL comes from the minimum of
            // the SOA's TTL and the SOA's MINIMUM field
            for record in &response_msg.authorities {
                if let RData::SOA(soa) = &record.data {
                    min_ttl = std::cmp::min(record.ttl, soa.minimum);
                    break;
                }
            }
        }

        let cached_response = CachedResponse {
            data: response_data,
            ttl: Duration::from_secs(u64::from(min_ttl.clamp(5, 3600))),
        };

        self.cache.insert(key, cached_response);
    }

    /// Invalidates all entries in the cache.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Returns a dump of all cache entries.
    pub fn dump(&self) -> Vec<(String, String, String, u64)> {
        self.cache
            .iter()
            .map(|(key, value)| {
                let name = Name::from_bytes(&key.qname)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| "invalid".to_string());
                let kind = QType::from(key.qtype).to_string();

                // Try to parse RData from response bytes for display
                let data = if let Ok(msg) = Message::from_bytes(&value.data) {
                    msg.answers
                        .first()
                        .map(|r| r.data.to_string())
                        .unwrap_or_else(|| "no-data".to_string())
                } else {
                    "wire-error".to_string()
                };

                (name, kind, data, value.ttl.as_secs())
            })
            .collect()
    }
}
