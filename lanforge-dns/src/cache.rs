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

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use moka::Expiry;
use moka::sync::Cache;
use std::time::{Duration, Instant};

/// Cache key for DNS responses.
///
/// Uniquely identifies a query by its name, type, and class.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: DNSClass,
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
            name: question.name().clone(),
            qtype: question.query_type(),
            qclass: question.query_class(),
        };

        // Clone is unavoidable since we need to mutate the ID bytes,
        // but cloning ~100 bytes is far faster than full parsing.
        let mut owned_data = self.cache.get(&key)?.data;

        if owned_data.len() >= 2 {
            let id_bytes = query.id.to_be_bytes();
            owned_data[0] = id_bytes[0];
            owned_data[1] = id_bytes[1];
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
    pub fn insert(&self, query: &Message, response_msg: &Message, response_data: Vec<u8>) {
        let Some(question) = query.queries.first() else {
            return;
        };

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

        let key = CacheKey {
            name: question.name().clone(),
            qtype: question.query_type(),
            qclass: question.query_class(),
        };

        let cached_response = CachedResponse {
            data: response_data,
            ttl: Duration::from_secs(u64::from(min_ttl.clamp(5, 3600))),
        };

        self.cache.insert(key, cached_response);
    }
}
