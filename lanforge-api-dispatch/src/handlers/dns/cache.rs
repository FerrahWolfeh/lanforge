use crate::ClientContext;
use lanforge_api::api::{
    DnsCacheEntry, DnsCacheResponse, DnsCacheStatsExtResponse, Response, SimpleSuccess,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};

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
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::CacheDump(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::CacheDump {
                    limit,
                    offset,
                })
                .await
        {
            return Response::DnsCache(DnsCacheResponse {
                entries: res
                    .entries
                    .into_iter()
                    .map(|e| DnsCacheEntry {
                        name: e.name,
                        kind: e.kind,
                        data: e.data,
                        expires_in_secs: e.expires_in_secs,
                    })
                    .collect(),
                total: res.total,
            });
        }

        Response::Error {
            error: "DNS service or cache not available".into(),
        }
    }

    pub async fn handle_dns_cache_stats_ext(&self) -> Response {
        if let Some(handle) = self.ctx.dns_handle()
            && let Ok(lanforge_types::network::dns::DnsResponse::CacheStatsExt(res)) = handle
                .send_request(lanforge_types::network::dns::DnsRequest::CacheStatsExt)
                .await
        {
            return Response::DnsCacheStatsExt(DnsCacheStatsExtResponse {
                total_entries: res.total_entries,
                entries_by_type: res.entries_by_type,
                memory_usage_bytes: res.memory_usage_bytes,
                average_ttl_secs: res.average_ttl_secs,
            });
        }

        Response::Error {
            error: "DNS service or cache not available".into(),
        }
    }
}
