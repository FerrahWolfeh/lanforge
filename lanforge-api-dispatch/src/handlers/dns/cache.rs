use crate::ClientContext;
use lanforge_api::api::{
    DnsCacheEntry, DnsCacheResponse, DnsCacheStatsExtResponse, Response, SimpleSuccess,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_dns::server::DnsContext;

impl ClientContext {
    pub async fn handle_dns_cache_flush(&self) -> Response {
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Dns(DnsEvent::CacheFlush));
        Response::Success(SimpleSuccess {
            message: "DNS cache flush triggered".to_string(),
        })
    }

    pub async fn handle_dns_cache_dump(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Response {
        if let Some(dns_ctx_any) = self.ctx.get_dns_context()
            && let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>()
        {
            let mut entries = Vec::new();
            for (name, kind, data, expires_in_secs) in dns_ctx.cache.dump() {
                entries.push(DnsCacheEntry {
                    name,
                    kind,
                    data,
                    expires_in_secs,
                });
            }
            let total = entries.len();
            let start = offset.unwrap_or(0).min(total);
            let end = (start + limit.unwrap_or(total)).min(total);
            let paginated = entries[start..end].to_vec();

            return Response::DnsCache(DnsCacheResponse {
                entries: paginated,
                total,
            });
        }

        Response::Error {
            error: "DNS service or cache not available".into(),
        }
    }

    pub async fn handle_dns_cache_stats_ext(&self) -> Response {
        if let Some(dns_ctx_any) = self.ctx.get_dns_context()
            && let Some(dns_ctx) = dns_ctx_any.downcast_ref::<DnsContext>()
        {
            let (total_entries, entries_by_type, memory_usage_bytes, average_ttl_secs) =
                dns_ctx.cache.get_stats_ext();

            return Response::DnsCacheStatsExt(DnsCacheStatsExtResponse {
                total_entries,
                entries_by_type,
                memory_usage_bytes,
                average_ttl_secs,
            });
        }

        Response::Error {
            error: "DNS service or cache not available".into(),
        }
    }
}
