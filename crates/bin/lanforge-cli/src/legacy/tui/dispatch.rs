use crate::cli::LanforgeClient;
use crate::tui::action::{ActionResult, PendingAction};

/// Executes the given `PendingAction` using the `LanforgeClient` and returns an `ActionResult`.
pub async fn execute_action(client: &LanforgeClient, action: PendingAction) -> ActionResult {
    macro_rules! handle {
        ($expr:expr) => {
            match $expr {
                Ok(r) => ActionResult::Success(r.message),
                Err(e) => ActionResult::Error(e.to_string()),
            }
        };
    }

    match action {
        PendingAction::Reload => handle!(client.reload().await),
        PendingAction::Shutdown => handle!(client.shutdown().await),
        PendingAction::DnsCacheFlush => handle!(client.dns_cache_flush().await),
        PendingAction::Wol { mac, .. } => handle!(client.wol(mac.to_string()).await),
        PendingAction::Purge { mac, .. } => handle!(client.purge(mac).await),
        PendingAction::AdblockToggle { enable } => {
            handle!(client.dns_adblock_set(enable, None).await)
        }
        PendingAction::AdblockTimedDisable { duration_secs } => {
            handle!(client.dns_adblock_set(false, Some(duration_secs)).await)
        }
        PendingAction::AdblockReload => handle!(client.dns_adblock_reload().await),
        PendingAction::AdblockAllow { domain } => handle!(client.dns_allow(domain).await),
        PendingAction::AdblockUnallow { domain } => handle!(client.dns_unallow(domain).await),
        PendingAction::AdblockBlock { domain } => handle!(client.dns_block(domain).await),
        PendingAction::LeaseRenew { mac, .. } => handle!(client.lease_renew(mac, None).await),
        PendingAction::LeaseRelease { mac, .. } => handle!(client.lease_release(mac, None).await),
        PendingAction::DnsRewriteAdd { rule } => handle!(client.dns_rewrite_add(rule).await),
        PendingAction::DnsRewriteRemove { id, .. } => handle!(client.dns_rewrite_remove(id).await),
        PendingAction::HostAdd { entry } => handle!(client.host_add(entry).await),
        PendingAction::HostRemove { mac, .. } => handle!(client.host_remove(mac).await),
        PendingAction::DnsUpstreamAdd { target } => {
            handle!(
                client
                    .dns_upstream_add(target.addr, target.protocol, target.hostname)
                    .await
            )
        }
        PendingAction::DnsUpstreamRemove { target } => {
            handle!(
                client
                    .dns_upstream_remove(target.addr, target.protocol, target.domain)
                    .await
            )
        }
        PendingAction::AdblockSourceAdd { url, kind } => {
            handle!(client.dns_adblock_url_add(url, kind).await)
        }
        PendingAction::AdblockSourceRemove { url } => {
            handle!(client.dns_adblock_url_remove(url).await)
        }
        PendingAction::ServiceControl { id, action, .. } => {
            handle!(client.service_control(id, action).await)
        }
    }
}
