#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use lanforge_dns::resolver::recursive::cache::{DnsCache, CacheKey};
use lanforge_dns_wire::WireQuestion;

#[derive(Arbitrary, Debug)]
enum CacheAction {
    Insert {
        qname: Vec<u8>,
        qtype: u16,
        qclass: u16,
        response_data: Vec<u8>,
        min_ttl_found: u32,
        is_block: bool,
        ttl_offsets: Vec<usize>,
    },
    GetWire {
        query_data: Vec<u8>,
    },
    Cleanup,
    InvalidateAll,
    Dump,
    GetStatsExt,
}

#[derive(Arbitrary, Debug)]
struct FuzzDnsCacheInput {
    capacity: u64,
    min_ttl: u32,
    actions: Vec<CacheAction>,
}

fuzz_target!(|input: FuzzDnsCacheInput| {
    // Clamp capacity to a sensible range to avoid out-of-memory issues in fuzzing
    let cap = input.capacity.clamp(1, 1000);
    let cache = DnsCache::new(cap, input.min_ttl, None);

    for action in input.actions {
        match action {
            CacheAction::Insert {
                qname,
                qtype,
                qclass,
                response_data,
                min_ttl_found,
                is_block,
                ttl_offsets,
            } => {
                let key = CacheKey { qname, qtype, qclass };
                cache.insert(key, response_data, ttl_offsets, min_ttl_found, is_block);
            }
            CacheAction::GetWire { query_data } => {
                if let Some(question) = WireQuestion::parse(&query_data) {
                    let _ = cache.get_wire(&query_data, &question);
                }
            }
            CacheAction::Cleanup => {
                cache.cleanup();
            }
            CacheAction::InvalidateAll => {
                cache.invalidate_all();
            }
            CacheAction::Dump => {
                let _ = cache.dump();
            }
            CacheAction::GetStatsExt => {
                let _ = cache.get_stats_ext();
            }
        }
    }
});
