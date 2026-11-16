use crate::ClientContext;
use lanforge_api::api::{DeviceDnsBucket, DeviceDnsResponse, Response, TopDomainEntry};
use lanforge_types::identifiers::MacAddr;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Window of the device DNS view: the last day, in hourly buckets.
const WINDOW_SECS: u64 = 86_400;
const BUCKET_SECS: u64 = 3_600;
const TOP_DOMAINS: usize = 10;

impl ClientContext {
    /// A device's DNS activity over the last day. A query line is the device's when it carries
    /// the device's MAC, or, without a MAC, when its source address is the device's (LAN or
    /// linked), as the top clients count it.
    pub async fn handle_device_dns(&self, mac: MacAddr) -> Response {
        let Some(device) = self.ctx.get_device(&mac) else {
            return Response::NotFound {
                error: format!("Device {mac} not found"),
            };
        };
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };
        // Queries still buffered by the database worker count too, as in the query log.
        if let Err(e) = storage.flush_dns_log().await {
            debug!("DNS log flush before the device DNS view failed: {e}");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let since = now.saturating_sub(WINDOW_SECS);
        let ctx = self.ctx.clone();
        let activity = storage
            .call(move |s: &lanforge_db_core::Stores| {
                ctx.with_state(|state| {
                    let mut owner = HashMap::new();
                    s.log().get_dns_client_activity(
                        since,
                        now,
                        BUCKET_SECS,
                        TOP_DOMAINS,
                        &mut |ip, src_mac| match src_mac {
                            Some(m) => m == mac,
                            None => *owner
                                .entry(ip)
                                .or_insert_with(|| state.client_device(ip) == Some(mac)),
                        },
                    )
                })
            })
            .await;
        let activity = match activity {
            Ok(activity) => activity,
            Err(e) => {
                return Response::Error {
                    error: format!("Failed to read the DNS log: {e}"),
                };
            }
        };
        let domains = |rows: Vec<(String, u64)>| {
            rows.into_iter()
                .map(|(domain, count)| TopDomainEntry { domain, count })
                .collect()
        };
        Response::DeviceDns(Box::new(DeviceDnsResponse {
            since,
            bucket_secs: BUCKET_SECS,
            total: activity.total,
            blocked: activity.blocked,
            rate: activity
                .rate
                .into_iter()
                .map(|(timestamp, total, blocked)| DeviceDnsBucket {
                    timestamp,
                    total,
                    blocked,
                })
                .collect(),
            top_domains: domains(activity.top_domains),
            top_blocked_domains: domains(activity.top_blocked_domains),
            logging_off: device.ignore_dns_log,
        }))
    }
}
