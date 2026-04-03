use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use moka::Expiry;
use moka::sync::Cache; // DICA: Use a versão sync! (Explicação abaixo)
use std::time::{Duration, Instant};

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: DNSClass,
}

// 1. Criamos um envelope para guardar os dados e o TTL já calculado
#[derive(Clone)]
pub struct CachedResponse {
    pub data: Vec<u8>,
    pub ttl: Duration,
}

struct DnsExpiry;

// 2. A expiração agora tem complexidade O(1) absoluta, sem alocações
impl Expiry<CacheKey, CachedResponse> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedResponse,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    // O Moka exige essas duas funções na trait, basta retornar None para manter o TTL original
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

pub struct DnsCache {
    // Trocamos para sync::Cache e para o nosso CachedResponse
    cache: Cache<CacheKey, CachedResponse>,
}

impl DnsCache {
    pub fn new(capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(DnsExpiry)
                .build(),
        }
    }

    // 3. get() passa a ser síncrono, removendo o overhead do .await
    pub fn get(&self, query: &Message) -> Option<Vec<u8>> {
        let question = query.queries().first()?;
        let key = CacheKey {
            name: question.name().clone(),
            qtype: question.query_type(),
            qclass: question.query_class(),
        };

        // O clone aqui é inevitável pois precisamos mutar o ID,
        // mas clonar um Vec de 100 bytes é infinitamente mais rápido que fazer parsing.
        let mut owned_data = self.cache.get(&key)?.data.clone();

        if owned_data.len() >= 2 {
            let id_bytes = query.id().to_be_bytes();
            owned_data[0] = id_bytes[0];
            owned_data[1] = id_bytes[1];
        }

        Some(owned_data)
    }

    // 4. O TTL é extraído FORA do cache, e passado pronto
    pub fn insert(&self, query: &Message, response_msg: &Message, response_data: Vec<u8>) {
        let question = match query.queries().first() {
            Some(q) => q,
            None => return,
        };

        let mut min_ttl = 3600;
        let mut found = false;

        for record in response_msg
            .answers()
            .iter()
            .chain(response_msg.name_servers())
            .chain(response_msg.additionals())
        {
            if record.ttl() < min_ttl {
                min_ttl = record.ttl();
            }
            found = true;
        }

        if !found {
            min_ttl = 60; // Default fallback

            // RFC 2308: Negative caching TTL comes from the minimum of the SOA's TTL and the SOA's MINIMUM field
            for record in response_msg.name_servers() {
                if let hickory_proto::rr::RData::SOA(soa) = record.data() {
                    min_ttl = std::cmp::min(record.ttl(), soa.minimum());
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
            ttl: Duration::from_secs(min_ttl.clamp(5, 3600) as u64),
        };

        self.cache.insert(key, cached_response);
    }
}
