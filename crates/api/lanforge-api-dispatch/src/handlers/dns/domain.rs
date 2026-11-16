use crate::ClientContext;
use lanforge_api::api::{DeviceDnsBucket, DnsDomainClient, DnsDomainResponse, Response};
use lanforge_types::identifiers::MacAddr;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Window of the domain view: the last day, in hourly buckets.
const WINDOW_SECS: u64 = 86_400;
const BUCKET_SECS: u64 = 3_600;
const TOP_CLIENTS: usize = 25;

/// A domain name as the query log stores it (lowercase, no trailing dot), or `None` when
/// `raw` cannot be a domain name: empty, over 253 bytes, an empty or over-long label, or a
/// character no host name carries (`_` is allowed, service names use it).
fn normalize(raw: &str) -> Option<String> {
    let name = raw.trim();
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let plausible = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    plausible.then_some(name)
}

/// One device's (or one unknown address's) share of a domain's queries.
struct Row {
    mac: Option<MacAddr>,
    name: Option<String>,
    /// `(address, queries)` per address counted in the row.
    addresses: HashMap<IpAddr, u64>,
    total: u64,
    blocked: u64,
    last_seen: u64,
}

impl ClientContext {
    /// A domain's DNS activity over the last day. Query lines of one device (its MAC, or, for
    /// a line without one, the device its source address belongs to: LAN or linked) are one row.
    pub async fn handle_dns_domain(&self, domain: String) -> Response {
        let Some(domain) = normalize(&domain) else {
            return Response::Rejected {
                error: "Not a valid domain name".into(),
            };
        };
        let Some(storage) = self.ctx.storage_handle() else {
            return Response::Error {
                error: "Storage service not available".into(),
            };
        };
        // Queries still buffered by the database worker count too, as in the query log.
        if let Err(e) = storage.flush_dns_log().await {
            debug!("DNS log flush before the domain view failed: {e}");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let since = now.saturating_sub(WINDOW_SECS);
        let wanted = domain.clone();
        let activity = storage
            .call(move |s: &lanforge_db_core::Stores| {
                s.log()
                    .get_dns_domain_activity(since, now, BUCKET_SECS, &wanted)
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

        let mut rows: Vec<Row> = Vec::new();
        let mut row_of: HashMap<MacAddr, usize> = HashMap::new();
        self.ctx.with_state(|state| {
            for c in &activity.clients {
                let (mac, name) = state.client_identity(c.ip, c.mac);
                let at = match mac.and_then(|m| row_of.get(&m).copied()) {
                    Some(at) => at,
                    None => {
                        if let Some(m) = mac {
                            row_of.insert(m, rows.len());
                        }
                        rows.push(Row {
                            mac,
                            name,
                            addresses: HashMap::new(),
                            total: 0,
                            blocked: 0,
                            last_seen: 0,
                        });
                        rows.len() - 1
                    }
                };
                let row = &mut rows[at];
                row.total += c.total;
                row.blocked += c.blocked;
                row.last_seen = row.last_seen.max(c.last_seen);
                *row.addresses.entry(c.ip).or_default() += c.total;
            }
        });
        let mut clients: Vec<DnsDomainClient> = rows
            .into_iter()
            .map(|row| {
                let mut addresses: Vec<(IpAddr, u64)> = row.addresses.into_iter().collect();
                addresses.sort_by_key(|&(ip, n)| (Reverse(n), ip));
                DnsDomainClient {
                    mac: row.mac.map(|m| m.to_string()),
                    name: row.name,
                    addresses: addresses
                        .into_iter()
                        .map(|(ip, _)| ip.to_string())
                        .collect(),
                    total: row.total,
                    blocked: row.blocked,
                    last_seen: row.last_seen,
                }
            })
            .collect();
        clients.sort_by(|a, b| {
            b.total
                .cmp(&a.total)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.addresses.cmp(&b.addresses))
        });
        clients.truncate(TOP_CLIENTS);

        Response::DnsDomain(Box::new(DnsDomainResponse {
            domain,
            since,
            bucket_secs: BUCKET_SECS,
            total: activity.total,
            blocked: activity.blocked,
            last_seen: activity.last_seen,
            rate: activity
                .rate
                .into_iter()
                .map(|(timestamp, total, blocked)| DeviceDnsBucket {
                    timestamp,
                    total,
                    blocked,
                })
                .collect(),
            clients,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn normalize_folds_case_and_the_trailing_dot() {
        assert_eq!(normalize(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(
            normalize("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
    }

    #[test]
    fn normalize_refuses_what_is_no_domain() {
        for bad in [
            "",
            ".",
            "a..b",
            "a b.com",
            "..",
            "exa/mple.com",
            &"a".repeat(64),
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }
}
